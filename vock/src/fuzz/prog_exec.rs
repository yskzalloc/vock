//! Execute a deserialised syzkaller program.
//!
//! This is the in-VM half of syzkaller's `syz-executor`: it drives the calls of
//! a program in-process (so coverage can be attributed to individual calls),
//! performs resource copyout, honours the `fail_nth` / `async` call properties,
//! and enforces syzkaller's timeout tiers.
//!
//! Coverage is collected with a *per-thread* KCOV fd, reset immediately before
//! each call and drained immediately after (`executor.cc:1216,1566`), which is
//! what makes per-call attribution possible. A second, *remote* KCOV handle
//! captures background work done on this process's behalf by other tasks,
//! which syzkaller reports separately as `.extra`.
//!
//! All coverage output follows syzkaller's convention: PCs are shifted with
//! `PreviousInstructionPC` (`pc-1` on x86_64, `pc-4` on arm64) before being
//! written. KCOV records the address *after* the call, so the shift is what
//! makes a PC symbolize to the call site rather than the following line. Every
//! vock producer — this module, `mode/kcov.rs`, and the `mode/kcov.so` preload
//! shim — applies it, so all logs share one convention.

#![allow(dead_code)]

use crate::prog_decode::{prepare_args, Arena, Call, Ctx, Prepared, Prog};
use std::io::Write;
use std::time::{Duration, Instant};

// ─── per-syscall watchdog ───────────────────────────────────────────────────

extern "C" fn on_alarm(_sig: libc::c_int) {}

/// Install a SIGALRM handler *without* `SA_RESTART`, so a blocking syscall is
/// interrupted with EINTR instead of being restarted. Without this a single
/// blocking call (`read` on an empty pipe, `accept`, `epoll_wait(-1)`) would
/// hang the whole replay — the program-level deadline is only checked between
/// calls.
pub fn install_watchdog() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as *const () as usize;
        sa.sa_flags = 0; // deliberately no SA_RESTART
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }
}

/// Arm the per-syscall watchdog, rounding up to at least one second (the
/// finest granularity `alarm()` offers).
fn arm(timeout: Duration) {
    let secs = timeout.as_secs().max(1).min(u32::MAX as u64) as u32;
    unsafe { libc::alarm(secs) };
}

fn disarm() {
    unsafe { libc::alarm(0) };
}

// ─── KCOV ───────────────────────────────────────────────────────────────────

const KCOV_INIT_TRACE: libc::c_ulong = 0x8008_6301;
const KCOV_ENABLE: libc::c_ulong = 0x6364;
const KCOV_DISABLE: libc::c_ulong = 0x6365;
const KCOV_TRACE_PC: libc::c_ulong = 0;
const COVER_SIZE: usize = 2 << 20; // 16 MiB map; Rust kernels emit dense coverage

/// Shift a raw KCOV PC back onto the calling instruction.
/// (`backend.PreviousInstructionPC`, pkg/cover/backend/pc.go.)
#[inline]
pub fn previous_instruction_pc(pc: u64) -> u64 {
    if cfg!(target_arch = "aarch64") {
        pc.wrapping_sub(4)
    } else {
        pc.wrapping_sub(1)
    }
}

/// Inverse of [`previous_instruction_pc`], used when handing PCs to a
/// symbolizer that performs its own adjustment.
#[inline]
pub fn next_instruction_pc(pc: u64) -> u64 {
    if cfg!(target_arch = "aarch64") {
        pc.wrapping_add(4)
    } else {
        pc.wrapping_add(1)
    }
}

/// A per-thread KCOV trace buffer.
pub struct Kcov {
    fd: libc::c_int,
    area: *mut u64,
}

impl Kcov {
    /// Open and enable KCOV for the *calling thread*. Returns `None` when the
    /// kernel lacks CONFIG_KCOV or debugfs is not mounted — the caller then
    /// runs without coverage rather than failing the program.
    pub fn open() -> Option<Kcov> {
        unsafe {
            let fd = libc::open(
                b"/sys/kernel/debug/kcov\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            );
            if fd < 0 {
                return None;
            }
            if libc::ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE as libc::c_ulong) != 0 {
                libc::close(fd);
                return None;
            }
            let area = libc::mmap(
                std::ptr::null_mut(),
                COVER_SIZE * std::mem::size_of::<u64>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if area == libc::MAP_FAILED {
                libc::close(fd);
                return None;
            }
            if libc::ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) != 0 {
                libc::munmap(area, COVER_SIZE * std::mem::size_of::<u64>());
                libc::close(fd);
                return None;
            }
            Some(Kcov { fd, area: area as *mut u64 })
        }
    }

    /// Drop everything traced so far (`cover_reset`).
    #[inline]
    pub fn reset(&self) {
        unsafe { std::ptr::write_volatile(self.area, 0) };
    }

    /// Drain the PCs traced since the last [`reset`](Self::reset).
    ///
    /// These are **raw** KCOV PCs, i.e. the address after the call. vock's own
    /// `kerncov.log` and report pipeline works in raw PCs throughout (the
    /// preload shim writes them unmodified); the `PreviousInstructionPC` shift
    /// is applied only when writing syzkaller-format per-call files.
    pub fn collect(&self) -> Vec<u64> {
        let n = unsafe { std::ptr::read_volatile(self.area) } as usize;
        let n = n.min(COVER_SIZE - 1);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(unsafe { std::ptr::read_volatile(self.area.add(i + 1)) });
        }
        out
    }
}

impl Drop for Kcov {
    fn drop(&mut self) {
        unsafe {
            libc::ioctl(self.fd, KCOV_DISABLE, 0);
            libc::munmap(self.area as *mut libc::c_void, COVER_SIZE * std::mem::size_of::<u64>());
            libc::close(self.fd);
        }
    }
}

const KCOV_REMOTE_ENABLE: libc::c_ulong = 0x4018_6366;

#[repr(C)]
struct KcovRemoteArg {
    trace_mode: u32,
    area_size: u32,
    num_handles: u32,
    common_handle: u64,
}

/// Background ("extra") coverage: kernel work done on behalf of this process
/// by another task — workqueues, softirqs, USB/net completion handlers — which
/// per-task KCOV cannot see. syzkaller reports it separately as `.extra`
/// because it belongs to no single call.
pub struct RemoteKcov {
    inner: Kcov,
}

impl RemoteKcov {
    pub fn open() -> Option<RemoteKcov> {
        unsafe {
            let fd = libc::open(
                b"/sys/kernel/debug/kcov\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            );
            if fd < 0 {
                return None;
            }
            if libc::ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE as libc::c_ulong) != 0 {
                libc::close(fd);
                return None;
            }
            let area = libc::mmap(
                std::ptr::null_mut(),
                COVER_SIZE * std::mem::size_of::<u64>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if area == libc::MAP_FAILED {
                libc::close(fd);
                return None;
            }
            let arg = KcovRemoteArg {
                trace_mode: KCOV_TRACE_PC as u32,
                area_size: COVER_SIZE as u32,
                num_handles: 0,
                // Subsystem 0, instance = our pid (mirrors mode/kcov.rs).
                common_handle: libc::getpid() as u64 & 0xffff_ffff,
            };
            if libc::ioctl(fd, KCOV_REMOTE_ENABLE, &arg as *const _) != 0 {
                libc::munmap(area, COVER_SIZE * std::mem::size_of::<u64>());
                libc::close(fd);
                return None;
            }
            Some(RemoteKcov { inner: Kcov { fd, area: area as *mut u64 } })
        }
    }
    pub fn reset(&self) {
        self.inner.reset();
    }
    pub fn collect(&self) -> Vec<u64> {
        self.inner.collect()
    }
}

// ─── timeout tiers (sys/targets/targets.go:850-884) ─────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub syscall: Duration,
    pub program: Duration,
    /// Extra grace for calls that keep running past the program (remote cover).
    pub prog_extra: Duration,
}

impl Timeouts {
    pub fn new(slowdown: u32) -> Timeouts {
        let slowdown = slowdown.max(1);
        let scale = slowdown.min(3);
        Timeouts {
            syscall: Duration::from_millis(50) * slowdown,
            program: Duration::from_secs(5) * scale,
            prog_extra: Duration::from_millis(500) * slowdown,
        }
    }
    /// Deadline for draining calls that have not returned when the program
    /// ends (`executor.cc:1135-1161`).
    pub fn unfinished_grace(&self) -> Duration {
        let by_syscall = self.syscall * 2;
        let by_program = self.program / 6;
        by_syscall.max(by_program).max(self.prog_extra)
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts::new(1)
    }
}

// ─── fault injection ────────────────────────────────────────────────────────

/// Arm `fail_nth` for the calling thread (`common_linux.h:5166`).
fn fault_inject(nth: i32) {
    if let Ok(mut f) = std::fs::File::create("/proc/thread-self/fail-nth") {
        let _ = write!(f, "{nth}");
    }
}

fn fault_disable() {
    if let Ok(mut f) = std::fs::File::create("/proc/thread-self/fail-nth") {
        let _ = write!(f, "0");
    }
}

// ─── execution ──────────────────────────────────────────────────────────────

/// What one call produced.
#[derive(Clone, Debug, Default)]
pub struct CallResult {
    pub index: usize,
    pub name: String,
    pub ret: i64,
    pub errno: i32,
    pub cover: Vec<u64>,
    /// The call had not returned when the program ended.
    pub unfinished: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub collect_cover: bool,
    /// Run each call on its own thread and do not wait for `async` calls.
    pub threaded: bool,
    /// Pair adjacent calls so they overlap (`prog/collide.go`).
    pub collide: bool,
    pub timeouts: Timeouts,
    pub procid: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            collect_cover: false,
            threaded: false,
            collide: false,
            timeouts: Timeouts::default(),
            procid: 0,
        }
    }
}

/// Perform one call and return `(ret, errno)`.
fn do_call(call: &Call, args: &[i64; crate::prog_decode::MAX_ARGS], arena: &Arena, ctx: &Ctx) -> (i64, i32) {
    if call.is_pseudo() {
        return crate::pseudo_ext::dispatch(call, args, arena, ctx);
    }
    let Some(nr) = call.nr else {
        return (-1, libc::ENOSYS);
    };
    unsafe {
        *libc::__errno_location() = 0;
        let ret = libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
        let err = *libc::__errno_location();
        (ret, err)
    }
}

/// Execute one call with coverage and fault injection around it.
#[allow(clippy::too_many_arguments)]
fn exec_call(
    idx: usize,
    call: &Call,
    args: &[i64; crate::prog_decode::MAX_ARGS],
    arena: &Arena,
    ctx: &Ctx,
    kcov: Option<&Kcov>,
    timeout: Duration,
) -> CallResult {
    if let Some(n) = call.fail_nth {
        fault_inject(n);
    }
    if let Some(k) = kcov {
        k.reset();
    }
    arm(timeout);
    let (ret, errno) = do_call(call, args, arena, ctx);
    disarm();
    let cover = kcov.map(|k| k.collect()).unwrap_or_default();
    if call.fail_nth.is_some() {
        fault_disable();
    }
    CallResult {
        index: idx,
        name: call.name.clone(),
        ret,
        errno,
        cover,
        unfinished: false,
    }
}

/// Does any call after `idx` consume the resource that call `idx` produces?
/// Such a call must not be overlapped, because its result has to be in `ctx`
/// before the consumer's arguments are materialised.
fn result_used_later(prog: &Prog, idx: usize) -> bool {
    let Some(slot) = prog.calls[idx].res else { return false };
    prog.calls[idx + 1..]
        .iter()
        .any(|c| c.args.iter().any(|a| references(a, slot)))
}

fn references(arg: &crate::prog_decode::Arg, slot: usize) -> bool {
    use crate::prog_decode::Arg;
    match arg {
        Arg::Res { idx, .. } => *idx == slot,
        Arg::Struct(fs) | Arg::Array(fs) => fs.iter().any(|f| references(f, slot)),
        Arg::Union(i) | Arg::Out { inner: i, .. } => references(i, slot),
        Arg::Ptr { inner: Some(i), .. } => references(i, slot),
        _ => false,
    }
}

/// Run a whole program once. Returns one [`CallResult`] per call, in order.
/// Everything one execution of a program produced.
pub struct ProgResult {
    pub calls: Vec<CallResult>,
    /// Background coverage attributable to no single call (`.extra`).
    pub extra: Vec<u64>,
}

pub fn run_prog(prog: &mut Prog, arena: &mut Arena, opts: &Opts) -> ProgResult {
    let mut ctx = Ctx::new();
    let mut out: Vec<CallResult> = Vec::with_capacity(prog.calls.len());
    let started = Instant::now();

    // Reserve every fixed address and assign the `&AUTO` ones before laying
    // anything out, so objects cannot overlap (syzkaller's analyze() pass).
    arena.reset();
    crate::prog_decode::note_fixed(arena, prog);
    install_watchdog();

    let kcov = if opts.collect_cover { Kcov::open() } else { None };
    // Background coverage runs for the whole program, not per call.
    let remote = if opts.collect_cover { RemoteKcov::open() } else { None };
    if let Some(r) = &remote {
        r.reset();
    }

    // Threads spawned for overlapped calls, drained before the program ends.
    let mut pending: Vec<(usize, std::thread::JoinHandle<(i64, i32, Vec<u64>)>)> = Vec::new();

    for i in 0..prog.calls.len() {
        if started.elapsed() > opts.timeouts.program {
            break;
        }
        let call = prog.calls[i].clone();
        let Prepared { args, copyouts } = prepare_args(arena, &call, &ctx);

        // Overlap a call only when doing so cannot change the program's
        // meaning: a pseudo-syscall needs the in-process dispatcher, and a
        // call whose result feeds a later call must publish it first.
        let overlap = (call.is_async || (opts.collide && i % 2 == 1))
            && opts.threaded
            && !call.is_pseudo()
            && !result_used_later(prog, i);

        if overlap {
            // Only plain integers cross the thread boundary; the arena is
            // shared through raw addresses, which stay valid because every
            // thread is joined before the arena is reset or unmapped.
            let nr = call.nr;
            let collect = opts.collect_cover;
            let syscall_timeout = opts.timeouts.syscall;
            let h = std::thread::spawn(move || {
                // KCOV is per-task, so each thread opens its own fd.
                let k = if collect { Kcov::open() } else { None };
                if let Some(k) = &k {
                    k.reset();
                }
                install_watchdog();
                arm(syscall_timeout);
                let (ret, errno) = match nr {
                    Some(nr) => unsafe {
                        *libc::__errno_location() = 0;
                        let r = libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
                        (r, *libc::__errno_location())
                    },
                    None => (-1, libc::ENOSYS),
                };
                disarm();
                let cov = k.as_ref().map(|k| k.collect()).unwrap_or_default();
                (ret, errno, cov)
            });
            pending.push((i, h));
            // Placeholder, filled in when the thread is joined.
            out.push(CallResult {
                index: i,
                name: call.name.clone(),
                ret: 0,
                errno: 0,
                cover: Vec::new(),
                unfinished: true,
            });
            continue;
        }

        let r = exec_call(i, &call, &args, arena, &ctx, kcov.as_ref(), opts.timeouts.syscall);
        // Copyout: the return value fills this call's resource slot, and any
        // `<rN=>` field is read back out of the arena.
        if let Some(slot) = call.res {
            ctx.set(slot, r.ret as u64);
        }
        for co in &copyouts {
            if let Some(v) = arena.read_scalar(co.off, co.size) {
                ctx.set(co.slot, v);
            }
        }
        out.push(r);
    }

    // Every thread must be joined before we return: the caller resets and
    // eventually unmaps the arena these threads hold addresses into, and a new
    // program would be mapped at the same fixed base. The per-syscall SIGALRM
    // guarantees a blocked thread wakes up, so this cannot deadlock.
    for (i, h) in pending {
        let Ok((ret, errno, cover)) = h.join() else { continue };
        if let Some(slot) = prog.calls[i].res {
            ctx.set(slot, ret as u64);
        }
        if let Some(slot) = out.iter_mut().find(|r| r.index == i) {
            slot.ret = ret;
            slot.errno = errno;
            slot.cover = cover;
            slot.unfinished = false;
        }
    }
    let extra = remote.as_ref().map(|r| r.collect()).unwrap_or_default();
    ProgResult { calls: out, extra }
}

// ─── coverage output ────────────────────────────────────────────────────────

/// Write per-call cover files plus a merged `kerncov.log`, mirroring the
/// `<prefix>_prog1.<call>` / `.extra` layout `syz-execprog` produces
/// (pkg/instance/execprog.go:388).
///
/// Every file uses syzkaller's convention: PCs are `PreviousInstructionPC`-
/// shifted. That is what `syz-execprog` writes (so the per-call files are
/// drop-in compatible with syzkaller tooling, which undoes the shift with
/// `NextInstructionPC` before symbolizing, execprog.go:413-424), and it is
/// also the more accurate input for vock's own report: KCOV records the
/// address *after* the call, so an unshifted PC can symbolize to the
/// following source line.
///
/// `extra_cover` is background/remote coverage not attributable to a single
/// call; it becomes `<prefix>_prog1.extra`.
pub fn write_cover(
    results: &[CallResult],
    extra_cover: &[u64],
    prefix: &str,
) -> std::io::Result<usize> {
    let mut merged: Vec<u64> = Vec::new();
    for r in results {
        let path = format!("{prefix}_prog1.{}", r.index);
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for pc in &r.cover {
            writeln!(f, "0x{:x}", previous_instruction_pc(*pc))?;
        }
        f.flush()?;
        merged.extend_from_slice(&r.cover);
    }
    // syzkaller always emits the .extra file, even when empty, so a consumer
    // can tell "no background coverage" from "file missing".
    let path = format!("{prefix}_prog1.extra");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&path)?);
    for pc in extra_cover {
        writeln!(f, "0x{:x}", previous_instruction_pc(*pc))?;
    }
    f.flush()?;
    merged.extend_from_slice(extra_cover);

    let mut merged: Vec<u64> = merged.iter().map(|pc| previous_instruction_pc(*pc)).collect();
    merged.sort_unstable();
    merged.dedup();
    let mut f = std::io::BufWriter::new(std::fs::File::create("kerncov.log")?);
    for pc in &merged {
        writeln!(f, "0x{pc:x}")?;
    }
    f.flush()?;
    Ok(merged.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_shift_roundtrips() {
        let pc = 0xffff_ffff_8123_4567u64;
        assert_eq!(next_instruction_pc(previous_instruction_pc(pc)), pc);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(previous_instruction_pc(pc), pc - 1);
        }
    }

    #[test]
    fn all_cover_files_use_syzkaller_pc_convention() {
        let dir = std::env::temp_dir().join(format!("vock-cov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let raw = 0xffff_ffff_8123_4568u64;
        let results = vec![CallResult {
            index: 0,
            name: "openat".into(),
            ret: 3,
            errno: 0,
            cover: vec![raw],
            unfinished: false,
        }];
        write_cover(&results, &[raw], "t").unwrap();

        // Per-call file: syzkaller convention, shifted.
        let per_call = std::fs::read_to_string("t_prog1.0").unwrap();
        assert_eq!(per_call.trim(), format!("0x{:x}", previous_instruction_pc(raw)));
        // .extra is always emitted, also shifted.
        let extra = std::fs::read_to_string("t_prog1.extra").unwrap();
        assert_eq!(extra.trim(), format!("0x{:x}", previous_instruction_pc(raw)));
        // kerncov.log follows the same convention, so a report generated from
        // it attributes to the call site and matches the preload-shim path.
        let merged = std::fs::read_to_string("kerncov.log").unwrap();
        assert_eq!(merged.trim(), format!("0x{:x}", previous_instruction_pc(raw)));

        std::env::set_current_dir(cwd).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timeout_tiers_scale() {
        let t = Timeouts::new(1);
        assert_eq!(t.syscall, Duration::from_millis(50));
        assert_eq!(t.program, Duration::from_secs(5));
        // Program timeout scales with a cap of 3; syscall timeout does not.
        let t10 = Timeouts::new(10);
        assert_eq!(t10.syscall, Duration::from_millis(500));
        assert_eq!(t10.program, Duration::from_secs(15));
    }

    #[test]
    fn unfinished_grace_takes_the_max_tier() {
        let t = Timeouts::new(1);
        // program/6 ≈ 833ms dominates 2*50ms and 500ms.
        assert_eq!(t.unfinished_grace(), Duration::from_secs(5) / 6);
    }
}
