//! LD_PRELOAD KCOV coverage shim (port of `mode/kcov.c`).
//!
//! Interposes `fork`/`vfork`/`pthread_create` so every task (the initial
//! process, forked children and pthreads) sets up its own per-thread KCOV
//! instance for both *local* (direct syscall) and *remote* (softirq /
//! workqueue) coverage. On teardown each task writes `local-<TID>.log` and
//! `remote-<TID>.log`; the initial process then merges every per-TID log into
//! `kerncov.log` (unless `VOCK_NO_MERGE` is set, i.e. `--ordered`).

use libc::{c_int, c_void};
use std::cell::Cell;
use std::ffi::CStr;
use std::io::Write;

// 2M entries (16 MiB map): a 64K buffer saturates during process startup
// alone (dynamic linking easily produces 65535 entries), silently losing the
// PCs of everything the target does afterwards - observed as a Rust misc
// device whose executed write path never appeared in coverage. Rust-enabled
// kernels emit denser coverage still (~200K entries for a small target), so
// leave an order of magnitude of headroom; the kernel accepts KCOV_INIT_TRACE
// sizes up to INT_MAX/8 entries.
const COVER_SZ: usize = 2 << 20;

// KCOV ioctl encodings (asm-generic).
const KCOV_INIT_TRACE: libc::c_ulong = 0x8008_6301; // _IOR('c', 1, unsigned long)
const KCOV_ENABLE: libc::c_ulong = 0x6364; // _IO('c', 100)
const KCOV_DISABLE: libc::c_ulong = 0x6365; // _IO('c', 101)
const KCOV_REMOTE_ENABLE: libc::c_ulong = 0x4018_6366; // _IOW('c', 102, kcov_remote_arg)
const KCOV_TRACE_PC: libc::c_ulong = 0;

const KCOV_SUBSYSTEM_COMMON: u64 = 0x00 << 56;
const KCOV_INSTANCE_MASK: u64 = 0xffff_ffff;

#[repr(C)]
struct KcovRemoteArg {
    trace_mode: u32,
    area_size: u32,
    num_handles: u32,
    common_handle: u64,
    // handles[0] omitted (num_handles == 0)
}

fn kcov_handle(subsys: u64, inst: u64) -> u64 {
    subsys | (inst & KCOV_INSTANCE_MASK)
}

const MAP_FAILED: *mut u64 = usize::MAX as *mut u64;

thread_local! {
    static LOCAL_FD: Cell<c_int> = const { Cell::new(-1) };
    static LOCAL_AREA: Cell<*mut u64> = const { Cell::new(MAP_FAILED) };
    static REMOTE_FD: Cell<c_int> = const { Cell::new(-1) };
    static REMOTE_AREA: Cell<*mut u64> = const { Cell::new(MAP_FAILED) };
    static KCOV_TID: Cell<libc::pid_t> = const { Cell::new(0) };
}

static mut INITIAL_PID: libc::pid_t = 0;

// ─── thread-exit safety net ─────────────────────────────────────────────────
//
// `kcov_thread_entry` flushes a thread by calling `kcov_disable()` after its
// start routine returns, which covers only threads that *do* return. A thread
// that leaves through `pthread_exit()` or that is cancelled skips that call
// entirely and throws away everything it collected - it enabled KCOV and
// discarded the result. Both are forced unwinds that pass straight through
// the wrapper's frame.
//
// The fix is a thread-specific-data key with a destructor: glibc runs those
// from `__nptl_deallocate_tsd` on the way out of a thread however it leaves,
// so one registration covers every route. That is preferred over interposing
// `pthread_exit` (which would catch only one of the two) and over
// `pthread_cleanup_push` (a macro over `setjmp` and an unwind buffer, not
// something to hand-roll from Rust). `kcov_disable` is idempotent - it clears
// the fd and area it consumed - so the normal path flushing explicitly and
// then the destructor running is harmless.
//
// The initial thread is not covered by this: glibc does not run TSD
// destructors for it at process exit. It does not need to be, since
// `kcov_dtor` in the fini array runs on that thread.

static mut TSD_KEY: libc::pthread_key_t = 0;
static mut TSD_READY: bool = false;

unsafe extern "C" fn kcov_thread_dtor(_: *mut c_void) {
    kcov_disable();
}

/// Create the TSD key once, from the constructor.
unsafe fn init_thread_dtor() {
    if libc::pthread_key_create(std::ptr::addr_of_mut!(TSD_KEY), Some(kcov_thread_dtor)) == 0 {
        TSD_READY = true;
    }
}

/// Mark this thread as having coverage to flush. The value only has to be
/// non-null for glibc to call the destructor.
unsafe fn register_thread_dtor() {
    if TSD_READY {
        libc::pthread_setspecific(TSD_KEY, 1 as *const c_void);
    }
}

const KCOV_PATH: &[u8] = b"/sys/kernel/debug/kcov\0";
/// Same path, for comparing `/proc/self/fd` link targets.
const KCOV_LINK: &str = "/sys/kernel/debug/kcov";

/// Move a freshly opened kcov fd above the range shells hand out. A plain
/// `open` returns the lowest free fd (3, 4, …), exactly where a target's
/// `3<file`-style redirection dup2()s to, which would silently replace the
/// kcov fd and make the exec hook close the target's own file instead.
unsafe fn raise_fd(fd: c_int) -> c_int {
    let high = libc::fcntl(fd, libc::F_DUPFD, 700);
    if high < 0 {
        return fd;
    }
    libc::close(fd);
    high
}

unsafe fn map_area(fd: c_int) -> *mut u64 {
    libc::mmap(
        std::ptr::null_mut(),
        COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    ) as *mut u64
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Every open fd that resolves to `link_target`, except `skip`.
///
/// Split out from the recovery below so it can be tested without a kcov
/// device: the directory handle the iteration itself holds resolves to
/// `/proc/<pid>/fd` and is filtered out by the comparison like any other
/// unrelated fd.
fn fds_pointing_at(link_target: &str, skip: c_int) -> Vec<c_int> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc/self/fd") else {
        return v;
    };
    for ent in rd.flatten() {
        let Some(fd) = ent
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<c_int>().ok())
        else {
            continue;
        };
        if fd == skip {
            continue;
        }
        if std::fs::read_link(ent.path()).ok().as_deref()
            == Some(std::path::Path::new(link_target))
        {
            v.push(fd);
        }
    }
    v
}

/// Reclaim a KCOV instance this task left attached across an `exec` that was
/// not interposed, and salvage what it collected.
///
/// The kernel keeps `current->kcov` set across `execve` (closing the fd only
/// drops the file reference), so `KCOV_ENABLE` in the new image returns
/// `EBUSY` and the exec'd program then collects *nothing for its entire
/// life*. The `exec*` interposers below prevent that by dumping and detaching
/// first, but they only see the spellings that resolve through the PLT:
/// glibc's `execl`, `execle`, `execlp` and `fexecve` all call `__execve`
/// internally and reach none of them, and a raw `execve` syscall never could.
/// Rather than chase spellings - three of those four are varargs, which is
/// the last thing worth hand-marshalling inside a preloaded `.so` - recover
/// here, once, in the one place that can observe the damage.
///
/// The kcov fds are deliberately opened without `O_CLOEXEC`, so the stale
/// instance survives the exec and is still reachable through
/// `/proc/self/fd`. Each candidate is probed with `KCOV_DISABLE`, which the
/// kernel accepts only for the instance belonging to the *calling* task: that
/// single ioctl both identifies ours and detaches it. Another thread's fd
/// fails with `EINVAL`, costs nothing and is left open. Whatever the stale
/// instance recorded before the exec is appended to this task's log instead
/// of being discarded.
///
/// Returns true when something was detached, i.e. when retrying is worthwhile.
unsafe fn recover_stale_kcov(skip: c_int, tid: libc::pid_t) -> bool {
    let mut recovered = false;
    for fd in fds_pointing_at(KCOV_LINK, skip) {
        if libc::ioctl(fd, KCOV_DISABLE, 0) != 0 {
            continue; // not this task's instance
        }
        recovered = true;
        eprintln!("kcov[{tid}]: reclaimed a KCOV instance stranded by exec");
        // Detached, so the mode is back to KCOV_MODE_INIT and the area can be
        // mapped again to read what it collected. Best effort: if the mapping
        // fails the dump is skipped, but the instance stays detached, which is
        // the part that matters.
        let area = map_area(fd);
        if area == MAP_FAILED {
            libc::close(fd);
            continue;
        }
        write_coverage(&format!("local-{tid}.log"), area, fd, tid);
    }
    recovered
}

unsafe fn kcov_enable() {
    let tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
    KCOV_TID.with(|c| c.set(tid));

    let local_fd = libc::open(KCOV_PATH.as_ptr() as *const libc::c_char, libc::O_RDWR);
    if local_fd < 0 {
        return;
    }
    let local_fd = raise_fd(local_fd);

    if libc::ioctl(local_fd, KCOV_INIT_TRACE, COVER_SZ as libc::c_ulong) != 0 {
        libc::close(local_fd);
        return;
    }

    let local_area = map_area(local_fd);
    if local_area == libc::MAP_FAILED as *mut u64 {
        libc::close(local_fd);
        return;
    }

    // EBUSY means this task already has a KCOV instance attached - the only
    // way that happens to a freshly enabling task is an exec that bypassed
    // the interposers below. Reclaim it and try once more.
    let mut armed = libc::ioctl(local_fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0;
    if !armed && errno() == libc::EBUSY && recover_stale_kcov(local_fd, tid) {
        armed = libc::ioctl(local_fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0;
    }
    if !armed {
        eprintln!(
            "kcov[{tid}]: KCOV_ENABLE: {}",
            std::io::Error::last_os_error()
        );
        libc::munmap(
            local_area as *mut c_void,
            COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        );
        libc::close(local_fd);
        return;
    }

    std::ptr::write_volatile(local_area, 0);
    LOCAL_FD.with(|c| c.set(local_fd));
    LOCAL_AREA.with(|c| c.set(local_area));

    // Arm the thread-exit safety net now that there is something to flush.
    register_thread_dtor();

    // Remote coverage (softirqs / workqueues attributed to this task).
    let remote_fd = libc::open(KCOV_PATH.as_ptr() as *const libc::c_char, libc::O_RDWR);
    if remote_fd < 0 {
        done(tid);
        return;
    }
    let remote_fd = raise_fd(remote_fd);
    if libc::ioctl(remote_fd, KCOV_INIT_TRACE, COVER_SZ as libc::c_ulong) != 0 {
        libc::close(remote_fd);
        done(tid);
        return;
    }
    let remote_area = map_area(remote_fd);
    if remote_area == libc::MAP_FAILED as *mut u64 {
        libc::close(remote_fd);
        done(tid);
        return;
    }

    let arg = KcovRemoteArg {
        trace_mode: KCOV_TRACE_PC as u32,
        area_size: COVER_SZ as u32,
        num_handles: 0,
        common_handle: kcov_handle(KCOV_SUBSYSTEM_COMMON, tid as u64),
    };
    if libc::ioctl(remote_fd, KCOV_REMOTE_ENABLE, &arg as *const _) != 0 {
        libc::munmap(
            remote_area as *mut c_void,
            COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        );
        libc::close(remote_fd);
        done(tid);
        return;
    }
    std::ptr::write_volatile(remote_area, 0);
    REMOTE_FD.with(|c| c.set(remote_fd));
    REMOTE_AREA.with(|c| c.set(remote_area));

    done(tid);
}

fn done(tid: libc::pid_t) {
    eprintln!("kcov[{tid}]: coverage enabled");
}

/// Shift a raw KCOV PC back onto the calling instruction, matching syzkaller's
/// `backend.PreviousInstructionPC` (pkg/cover/backend/pc.go).
///
/// KCOV records the address *after* the call, so symbolizing it unshifted can
/// attribute coverage to the following source line. Every vock coverage
/// producer applies this shift, so all logs share one convention.
#[inline]
fn previous_instruction_pc(pc: u64) -> u64 {
    if cfg!(target_arch = "aarch64") {
        pc.wrapping_sub(4)
    } else {
        pc.wrapping_sub(1)
    }
}

unsafe fn write_coverage(path: &str, area: *mut u64, fd: c_int, tid: libc::pid_t) {
    if fd < 0 || area == MAP_FAILED {
        return;
    }
    libc::ioctl(fd, KCOV_DISABLE, 0);
    let n = std::ptr::read_volatile(area) as usize;

    // Append, never truncate: one task can dump more than once and each dump
    // is a distinct segment of its execution. A task that execs is dumped by
    // `kcov_pre_exec` and then again by the new image's destructor under the
    // *same* tid, so creating the file would have thrown the pre-exec segment
    // away - the fork+exec path inside a shell target, for instance. The same
    // applies to a segment recovered by `recover_stale_kcov`. Appending keeps
    // both, in execution order, which is also what `--ordered` wants. Stale
    // files from an earlier run cannot accumulate here: the parent deletes
    // every `local-*`/`remote-*` log before it forks the target.
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let mut w = std::io::BufWriter::new(f);
        for i in 0..n {
            let pc = std::ptr::read_volatile(area.add(i + 1));
            let _ = writeln!(w, "0x{:x}", previous_instruction_pc(pc));
        }
        let _ = w.flush();
        if n > 0 {
            eprintln!("kcov[{tid}]: {n} PCs → {path}");
        }
    }

    libc::munmap(
        area as *mut c_void,
        COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
    );
    libc::close(fd);
}

unsafe fn kcov_disable() {
    let tid = KCOV_TID.with(|c| c.get());

    let local_area = LOCAL_AREA.with(|c| c.get());
    let local_fd = LOCAL_FD.with(|c| c.get());
    write_coverage(&format!("local-{tid}.log"), local_area, local_fd, tid);
    LOCAL_AREA.with(|c| c.set(MAP_FAILED));
    LOCAL_FD.with(|c| c.set(-1));

    let remote_area = REMOTE_AREA.with(|c| c.get());
    let remote_fd = REMOTE_FD.with(|c| c.get());
    write_coverage(&format!("remote-{tid}.log"), remote_area, remote_fd, tid);
    REMOTE_AREA.with(|c| c.set(MAP_FAILED));
    REMOTE_FD.with(|c| c.set(-1));
}

unsafe fn kcov_child_reinit() {
    let local_fd = LOCAL_FD.with(|c| c.get());
    if local_fd >= 0 {
        libc::close(local_fd);
        LOCAL_FD.with(|c| c.set(-1));
    }
    let remote_fd = REMOTE_FD.with(|c| c.get());
    if remote_fd >= 0 {
        libc::close(remote_fd);
        REMOTE_FD.with(|c| c.set(-1));
    }
    LOCAL_AREA.with(|c| c.set(MAP_FAILED));
    REMOTE_AREA.with(|c| c.set(MAP_FAILED));
    kcov_enable();
}

// ─── fork / vfork interception ──────────────────────────────────────────────

unsafe fn real_sym(name: &[u8]) -> *mut c_void {
    libc::dlsym(libc::RTLD_NEXT, name.as_ptr() as *const libc::c_char)
}

/// # Safety
/// Interposes libc `fork`.
#[no_mangle]
pub unsafe extern "C" fn fork() -> libc::pid_t {
    let real: extern "C" fn() -> libc::pid_t = std::mem::transmute(real_sym(b"fork\0"));
    let pid = real();
    if pid == 0 {
        kcov_child_reinit();
    }
    pid
}

/// # Safety
/// Interposes libc `vfork` (routed through `fork` semantics like the C shim).
#[no_mangle]
pub unsafe extern "C" fn vfork() -> libc::pid_t {
    fork()
}

/// # Safety
/// Interposes libc `daemon`.
///
/// `daemon()` forks inside glibc, where the call binds to the internal
/// `__fork` alias and never reaches the interposer above. The child is
/// therefore the one kind of missed fork that is *not* rescued by a following
/// exec - a daemon does not exec - so it would run its entire life with no
/// KCOV instance of its own while still holding the parent's inherited fds,
/// area and tid, and would overwrite the parent's log on the way out.
///
/// Wrap rather than reimplement: let glibc do the fork, the setsid, the chdir
/// and the /dev/null plumbing, then notice that we came back in a different
/// process and re-arm. The parent is gone by then (glibc `_exit`s it
/// internally), which does mean the segment it collected before the call is
/// lost; that is a handful of PCs against a child that is otherwise invisible
/// for as long as it runs.
#[no_mangle]
pub unsafe extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    let real: extern "C" fn(c_int, c_int) -> c_int = std::mem::transmute(real_sym(b"daemon\0"));
    let before = libc::getpid();
    let ret = real(nochdir, noclose);
    if ret == 0 && libc::getpid() != before {
        kcov_child_reinit();
    }
    ret
}

// ─── _exit interception ─────────────────────────────────────────────────────
//
// Per-task logs are written by the ELF destructor, which only runs for a
// task that leaves through exit(). A task that calls _exit() skips every
// fini_array entry and its coverage would be lost outright: that is the
// normal way a forked child ends (calling exit() there would run the
// parent's atexit handlers), and dash ends that way too. Interpose both
// spellings and flush this task's buffers first.

/// # Safety
/// Interposes libc `_exit`.
#[no_mangle]
pub unsafe extern "C" fn _exit(status: libc::c_int) -> ! {
    kcov_disable();
    let real: extern "C" fn(libc::c_int) -> ! = std::mem::transmute(real_sym(b"_exit\0"));
    real(status)
}

/// # Safety
/// Interposes libc `_Exit`, the C99 spelling of the same call.
#[no_mangle]
pub unsafe extern "C" fn _Exit(status: libc::c_int) -> ! {
    kcov_disable();
    let real: extern "C" fn(libc::c_int) -> ! = std::mem::transmute(real_sym(b"_Exit\0"));
    real(status)
}

// ─── exec interception ───────────────────────────────────────────────────────
//
// The kernel keeps a task's KCOV attachment across execve (kcov_close only
// drops the file reference; t->kcov stays set until task exit), while the fds
// and mappings that could dump or detach it die with the old image. Left
// alone, the new image's constructor gets -EBUSY from KCOV_ENABLE and the
// exec'd program collects nothing, a shell target (`/bin/sh script.sh`)
// therefore loses all of its children's coverage. Dump + detach before the
// real exec; if the exec fails, re-enable and keep collecting.

unsafe fn kcov_pre_exec() {
    kcov_disable();
}

/// # Safety
/// Interposes libc `execve`.
#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> c_int {
    type RealFn = extern "C" fn(
        *const libc::c_char,
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> c_int;
    let real: RealFn = std::mem::transmute(real_sym(b"execve\0"));
    kcov_pre_exec();
    let ret = real(path, argv, envp);
    kcov_enable();
    ret
}

/// # Safety
/// Interposes libc `execv`.
#[no_mangle]
pub unsafe extern "C" fn execv(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> c_int {
    type RealFn = extern "C" fn(*const libc::c_char, *const *const libc::c_char) -> c_int;
    let real: RealFn = std::mem::transmute(real_sym(b"execv\0"));
    kcov_pre_exec();
    let ret = real(path, argv);
    kcov_enable();
    ret
}

/// # Safety
/// Interposes libc `execvp`.
#[no_mangle]
pub unsafe extern "C" fn execvp(
    file: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> c_int {
    type RealFn = extern "C" fn(*const libc::c_char, *const *const libc::c_char) -> c_int;
    let real: RealFn = std::mem::transmute(real_sym(b"execvp\0"));
    kcov_pre_exec();
    let ret = real(file, argv);
    kcov_enable();
    ret
}

/// # Safety
/// Interposes libc `execvpe`.
#[no_mangle]
pub unsafe extern "C" fn execvpe(
    file: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> c_int {
    type RealFn = extern "C" fn(
        *const libc::c_char,
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> c_int;
    let real: RealFn = std::mem::transmute(real_sym(b"execvpe\0"));
    kcov_pre_exec();
    let ret = real(file, argv, envp);
    kcov_enable();
    ret
}

// ─── pthread_create interception ────────────────────────────────────────────

struct ThreadWrap {
    fn_ptr: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
}

extern "C" fn kcov_thread_entry(p: *mut c_void) -> *mut c_void {
    unsafe {
        let w = Box::from_raw(p as *mut ThreadWrap);
        kcov_enable();
        let ret = (w.fn_ptr)(w.arg);
        kcov_disable();
        ret
    }
}

/// # Safety
/// Interposes libc `pthread_create`.
#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> c_int {
    type RealFn = extern "C" fn(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        extern "C" fn(*mut c_void) -> *mut c_void,
        *mut c_void,
    ) -> c_int;
    let real: RealFn = std::mem::transmute(real_sym(b"pthread_create\0"));

    let w = Box::into_raw(Box::new(ThreadWrap {
        fn_ptr: start_routine,
        arg,
    }));
    real(thread, attr, kcov_thread_entry, w as *mut c_void)
}

// ─── constructor / destructor ───────────────────────────────────────────────

extern "C" fn kcov_ctor() {
    unsafe {
        INITIAL_PID = libc::getpid();
        init_thread_dtor();
        kcov_enable();
    }
}

extern "C" fn kcov_dtor() {
    unsafe {
        kcov_disable();

        if libc::getpid() != INITIAL_PID {
            return;
        }
        // Skip merge in ordered mode.
        if !libc::getenv(b"VOCK_NO_MERGE\0".as_ptr() as *const libc::c_char).is_null() {
            return;
        }
        merge_logs();
    }
}

fn merge_logs() {
    let Ok(merged) = std::fs::File::create("kerncov.log") else {
        return;
    };
    let mut w = std::io::BufWriter::new(merged);
    if let Ok(rd) = std::fs::read_dir(".") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let is_log = (name.starts_with("local-") || name.starts_with("remote-"))
                && name.contains(".log");
            if !is_log {
                continue;
            }
            if let Ok(data) = std::fs::read(ent.path()) {
                let _ = w.write_all(&data);
                // Keep a truncated log (task killed mid-write) from gluing
                // onto the next file's first PC line.
                if !data.is_empty() && !data.ends_with(b"\n") {
                    let _ = w.write_all(b"\n");
                }
            }
        }
    }
    let _ = w.flush();
}

// Register constructor/destructor via ELF init/fini arrays.
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = kcov_ctor;

#[used]
#[link_section = ".fini_array"]
static FINI: extern "C" fn() = kcov_dtor;

// Silence unused warning for CStr import if the tooling changes.
#[allow(dead_code)]
fn _keep_cstr(_: &CStr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::io::IntoRawFd;

    /// A unique scratch path, since these tests touch the filesystem.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kcov-preload-{}-{}", tag, unsafe {
            libc::syscall(libc::SYS_gettid)
        }));
        p
    }

    /// The recovery scan finds a non-CLOEXEC fd by its link target, which is
    /// how a KCOV instance stranded by an un-interposed exec is located.
    #[test]
    fn scan_finds_fd_by_link_target() {
        let path = scratch("scan");
        std::fs::write(&path, b"x").unwrap();
        let target = path.to_str().unwrap().to_string();

        assert!(
            fds_pointing_at(&target, -1).is_empty(),
            "nothing should match before the file is opened"
        );

        let fd = std::fs::File::open(&path).unwrap().into_raw_fd();
        assert_eq!(fds_pointing_at(&target, -1), vec![fd]);

        // `skip` excludes the caller's own freshly opened descriptor, which is
        // what keeps the recovery from detaching the instance it just created.
        assert!(fds_pointing_at(&target, fd).is_empty());

        unsafe { libc::close(fd) };
        assert!(fds_pointing_at(&target, -1).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    /// Two fds on the same file are both reported: several descriptors can
    /// refer to one kcov instance, and the ioctl probe is what distinguishes
    /// them, not the scan.
    #[test]
    fn scan_reports_every_matching_fd() {
        let path = scratch("dup");
        std::fs::write(&path, b"x").unwrap();
        let target = path.to_str().unwrap().to_string();

        let a = std::fs::File::open(&path).unwrap().into_raw_fd();
        let b = unsafe { libc::fcntl(a, libc::F_DUPFD, 700) };
        assert!(b >= 0, "F_DUPFD failed: {}", std::io::Error::last_os_error());

        let mut found = fds_pointing_at(&target, -1);
        found.sort_unstable();
        assert_eq!(found, vec![a, b]);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The scan must not report the directory handle its own iteration holds,
    /// nor unrelated descriptors.
    #[test]
    fn scan_ignores_unrelated_fds() {
        let path = scratch("other");
        std::fs::write(&path, b"x").unwrap();
        let keep = std::fs::File::open(&path).unwrap();

        assert!(fds_pointing_at("/sys/kernel/debug/kcov", -1).is_empty());
        assert!(fds_pointing_at("/proc/self/fd", -1).is_empty());

        drop(keep);
        let _ = std::fs::remove_file(&path);
    }

    /// Per-task logs are appended, not truncated. A task that execs is dumped
    /// before the exec and again by the new image under the same tid, so
    /// creating the file would silently drop the first segment.
    #[test]
    fn log_writes_append() {
        let path = scratch("append");
        let p = path.to_str().unwrap();
        for round in 0..3u64 {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .unwrap();
            use std::io::Write;
            writeln!(&mut { f }, "0x{round:x}").unwrap();
        }
        let mut s = String::new();
        std::fs::File::open(p).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "0x0\n0x1\n0x2\n", "segments must accumulate");
        let _ = std::fs::remove_file(&path);
    }

    /// `previous_instruction_pc` is the shift every vock coverage producer
    /// applies; recovery writes through the same path, so it must agree.
    #[test]
    fn pc_shift_matches_architecture() {
        let step = if cfg!(target_arch = "aarch64") { 4 } else { 1 };
        assert_eq!(previous_instruction_pc(0xffff_ffff_8100_0010), 0xffff_ffff_8100_0010 - step);
        assert_eq!(previous_instruction_pc(0), 0u64.wrapping_sub(step));
    }

    /// The thread-exit safety net: a TSD destructor runs however a thread
    /// leaves. This is the property `kcov_thread_entry`'s explicit
    /// `kcov_disable()` does not have, and the reason the key exists.
    ///
    /// Raw pthreads on purpose: that is the production shape (the start
    /// routine is the target's `extern "C"` function, reached through
    /// `kcov_thread_entry`). Driving `pthread_exit` out of a Rust
    /// `std::thread` closure instead would abort in Rust's own join
    /// machinery, which cannot catch a forced unwind - a property of the test
    /// harness, not of the shim.
    #[test]
    fn tsd_destructor_runs_on_every_thread_exit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        static KEY: AtomicUsize = AtomicUsize::new(usize::MAX);
        // What the destructor saw, per flush: (tid it was running as, value
        // read back out of a Rust `thread_local!`).
        static SEEN: Mutex<Vec<(i32, i32)>> = Mutex::new(Vec::new());

        thread_local! {
            // Stands in for LOCAL_FD / KCOV_TID: the destructor has to be able
            // to read *this thread's* value, which is the whole mechanism
            // `kcov_disable` relies on when it runs from the destructor.
            static MARK: Cell<i32> = const { Cell::new(0) };
        }

        fn tid() -> i32 {
            unsafe { libc::syscall(libc::SYS_gettid) as i32 }
        }

        unsafe extern "C" fn dtor(_: *mut c_void) {
            let mark = MARK.with(|c| c.get());
            SEEN.lock().unwrap().push((tid(), mark));
        }
        unsafe fn arm() {
            MARK.with(|c| c.set(tid()));
            let key = KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
            libc::pthread_setspecific(key, 1 as *const c_void);
        }

        // Each start routine stands in for a target thread that enabled
        // coverage and then left by a different route. `C-unwind` models the
        // target's own code faithfully: a C or C++ start routine is
        // unwind-transparent, whereas a plain `extern "C"` Rust body aborts
        // when a forced unwind *originates* inside it. (The shim's real
        // `kcov_thread_entry` is only ever unwound *through*, which Rust's
        // personality routine permits - verified against a C target.)
        extern "C-unwind" fn returns(_: *mut c_void) -> *mut c_void {
            unsafe { arm() };
            std::ptr::null_mut()
        }
        extern "C-unwind" fn exits(_: *mut c_void) -> *mut c_void {
            unsafe {
                arm();
                libc::pthread_exit(std::ptr::null_mut())
            }
        }
        extern "C-unwind" fn blocks(_: *mut c_void) -> *mut c_void {
            unsafe {
                arm();
                loop {
                    libc::sleep(1); // a cancellation point
                }
            }
        }

        let mut key: libc::pthread_key_t = 0;
        assert_eq!(unsafe { libc::pthread_key_create(&mut key, Some(dtor)) }, 0);
        KEY.store(key as usize, Ordering::SeqCst);

        let spawn = |f: extern "C-unwind" fn(*mut c_void) -> *mut c_void| unsafe {
            let mut h: libc::pthread_t = 0;
            assert_eq!(
                libc::pthread_create(
                    &mut h,
                    std::ptr::null(),
                    std::mem::transmute::<
                        extern "C-unwind" fn(*mut c_void) -> *mut c_void,
                        extern "C" fn(*mut c_void) -> *mut c_void,
                    >(f),
                    std::ptr::null_mut()
                ),
                0
            );
            h
        };

        // 1. returns normally - the path the explicit flush already covers
        let h = spawn(returns);
        unsafe { libc::pthread_join(h, std::ptr::null_mut()) };
        assert_eq!(SEEN.lock().unwrap().len(), 1, "normal return");

        // 2. leaves through pthread_exit, skipping every frame above it
        let h = spawn(exits);
        unsafe { libc::pthread_join(h, std::ptr::null_mut()) };
        assert_eq!(SEEN.lock().unwrap().len(), 2, "pthread_exit");

        // 3. is cancelled - the other forced unwind
        let h = spawn(blocks);
        unsafe {
            libc::usleep(100_000);
            assert_eq!(libc::pthread_cancel(h), 0);
            libc::pthread_join(h, std::ptr::null_mut());
        }
        assert_eq!(SEEN.lock().unwrap().len(), 3, "pthread_cancel");

        // Every flush ran on the dying thread and could still read that
        // thread's own TLS - not the main thread's, and not a zeroed block.
        let seen = SEEN.lock().unwrap();
        let me = tid();
        for (i, (ran_as, mark)) in seen.iter().enumerate() {
            assert_eq!(ran_as, mark, "flush {i} read another thread's TLS");
            assert_ne!(*ran_as, me, "flush {i} ran on the main thread");
        }
        drop(seen);

        unsafe { libc::pthread_key_delete(key) };
    }
}
