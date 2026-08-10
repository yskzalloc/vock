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

const COVER_SZ: usize = 64 << 10;

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

const KCOV_PATH: &[u8] = b"/sys/kernel/debug/kcov\0";

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

unsafe fn kcov_enable() {
    let tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
    KCOV_TID.with(|c| c.set(tid));

    let local_fd = libc::open(KCOV_PATH.as_ptr() as *const libc::c_char, libc::O_RDWR);
    if local_fd < 0 {
        return;
    }

    if libc::ioctl(local_fd, KCOV_INIT_TRACE, COVER_SZ as libc::c_ulong) != 0 {
        libc::close(local_fd);
        return;
    }

    let local_area = map_area(local_fd);
    if local_area == libc::MAP_FAILED as *mut u64 {
        libc::close(local_fd);
        return;
    }

    if libc::ioctl(local_fd, KCOV_ENABLE, KCOV_TRACE_PC) != 0 {
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

    // Remote coverage (softirqs / workqueues attributed to this task).
    let remote_fd = libc::open(KCOV_PATH.as_ptr() as *const libc::c_char, libc::O_RDWR);
    if remote_fd < 0 {
        done(tid);
        return;
    }
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

    if let Ok(f) = std::fs::File::create(path) {
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
