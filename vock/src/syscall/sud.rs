//! SUD (SYSCALL_USER_DISPATCH / zpoline) syscall backend.
//!
//! # What this is a port of
//!
//! The C backend lives in `syscall/sud/`. It has two layers:
//!
//!   1. `sud.c` (`vock_sud_run`): a thin launcher that `fork()`s and `execvp()`s
//!      the target with `LD_PRELOAD=libbootstrap.so`, `LIBLAZYPOLINE=liblazypoline.so`
//!      and `VOCK_SUD_OUTPUT=<trace>`.
//!   2. `liblazypoline.so` (`sud_core.c` + `zpoline.c` + `lazypoline.c` + the
//!      nolibc trampolines in `asm_syscall_hook.S` / `restore_selector_trampoline.S`
//!      + `setup_new_thread.c` + `virtualize_signals.c`): the machinery that runs
//!      *inside the target process* after exec. It enables SUD
//!      (`prctl(PR_SET_SYSCALL_USER_DISPATCH, ON, .., &selector)`), installs a
//!      `SIGSYS` handler, and (optionally) rewrites `syscall` instructions to jump
//!      to a zero-page trampoline (zpoline) for speed. On each intercepted syscall
//!      it logs a line and re-issues the real syscall.
//!
//! # What is ported here (faithfully) and what is not
//!
//! Ported: the *core SUD interception mechanism* from `sud_core.c`,
//!   * `enable_sud()`         -> `prctl(PR_SET_SYSCALL_USER_DISPATCH, ON, 0,0,&SELECTOR)`
//!   * `set_privilege_level()`-> volatile writes to the selector byte
//!   * `handle_sigsys()`      -> the `SIGSYS`/`SA_SIGINFO` handler that reads
//!                               `nr`/args from `ucontext->uc_mcontext.gregs`,
//!                               emits an strace line via `decode_syscall`, and
//!                               re-issues the real syscall (emulate-in-handler),
//!                               restoring the BLOCK selector so the next syscall
//!                               traps again.
//! The trace lines are produced by the shared Rust `decode_syscall`, so they are
//! the richer `name(args...) = <ret>` form (the C SUD path used a cruder
//! `name(0x..) = ?` printer in `lazypoline.c`). Both contain `) = `.
//!
//! NOT ported (deliberately, large and out of scope for a single std+libc file):
//!   * zpoline binary rewriting (`zpoline.c`, `asm_syscall_hook.S`): rewriting
//!     `0f 05` syscall bytes to `ff d0` and the zero-page trampoline table. This is
//!     a pure performance optimization; correctness does not depend on it.
//!   * The lazypoline `LD_PRELOAD` injection (`bootstrap.c`, `libbootstrap.so`) and
//!     nolibc runtime (`nolibc_util.h`, `gsreldata.h`, GS-relative data, per-thread
//!     stacks).
//!   * clone/vfork thread re-arming (`setup_new_thread.c`) and signal
//!     virtualization (`virtualize_signals.c`, `signal_handlers.h`).
//!
//! # The fundamental limitation (measured, not assumed)
//!
//! `execve` resets both the `PR_SET_SYSCALL_USER_DISPATCH` state *and* the `SIGSYS`
//! signal disposition. I verified this empirically: enabling SUD then `execve`ing
//! `/bin/echo` yields exactly ONE interception (the `execve` itself) and the new
//! image then runs with zero further SIGSYS traps. This is precisely why the C
//! backend injects `liblazypoline.so` via `LD_PRELOAD`, so SUD is *re-established
//! inside the target* after exec. Without that injected library (which we do not
//! re-port here), an in-process interceptor cannot follow the target across exec.
//!
//! Consequence for `run()`: we install the SUD interceptor in the forked child and
//! `execvp` the target. Every syscall the child issues from the moment SUD is
//! enabled until the successful `execve` is traced through `decode_syscall` into
//! `trace_log` (in practice: the `execve`, plus any PATH-search syscalls glibc's
//! `execvp` performs). After the exec the target runs untraced. This matches the
//! C behavior for the launcher itself but not for deep target tracing; deep target
//! tracing requires the injected preload library, which is documented above as not
//! re-ported. This is the "SIGSYS is infeasible past exec -> partial trace + run
//! the target" path the task allows, made as faithful as the constraints permit.
//!
//! aarch64: the interceptor is x86_64-only (it reads x86_64 `gregs` and uses the
//! x86_64 syscall ABI). On other arches `run()` falls back to running the target
//! directly (arm64 SUD is handled in a later prompt).

use crate::syscall::decode::decode_syscall;
use crate::syscall::Syscall;

// prctl(2) SYSCALL_USER_DISPATCH constants (glibc's libc crate only exposes these
// under the android module, so we define them locally, the values are stable ABI).
const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;
const PR_SYS_DISPATCH_OFF: libc::c_long = 0;
const PR_SYS_DISPATCH_ON: libc::c_long = 1;
const SYSCALL_DISPATCH_FILTER_ALLOW: u8 = 0;
const SYSCALL_DISPATCH_FILTER_BLOCK: u8 = 1;

/// SUD needs kernel >= 5.11 (SYSCALL_USER_DISPATCH). We probe two ways, mirroring
/// the C `vock_sud_available()` (a live `prctl` probe) and additionally keeping a
/// uname version gate.
pub fn available() -> bool {
    // Live probe: turning dispatch OFF is a no-op on a supporting kernel and
    // fails with EINVAL on one that lacks the feature (faithful to sud_core.c).
    let ret = unsafe {
        libc::prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_OFF,
            0,
            0,
            0,
        )
    };
    let probe_ok = ret == 0 || unsafe { *libc::__errno_location() } != libc::EINVAL;
    probe_ok && kernel_at_least_5_11()
}

fn kernel_at_least_5_11() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }
    let release: String = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8 as char)
        .collect();
    let mut it = release.split('.');
    let major: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = it
        .next()
        .and_then(|s| s.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok())
        .unwrap_or(0);
    major > 5 || (major == 5 && minor >= 11)
}

/// Run the target under SUD, emitting `trace_log`, returning the target exit code.
#[cfg(target_arch = "x86_64")]
pub fn run(cmd: &[String], trace_log: &str) -> i32 {
    sud::run(cmd, trace_log)
}

/// Non-x86_64: the SIGSYS interceptor reads x86_64 `gregs` and uses the x86_64
/// syscall ABI, so we cannot run it here. Fall back to running the target directly
/// (arm64 SUD support is a later prompt). Documented so nothing is silently dropped.
#[cfg(not(target_arch = "x86_64"))]
pub fn run(cmd: &[String], trace_log: &str) -> i32 {
    let _ = trace_log;
    eprintln!("[vock] sud: SIGSYS interceptor is x86_64-only; running target directly");
    run_target_directly(cmd)
}

/// Shared fallback: fork+exec the target with no interception, return its exit code.
#[cfg(not(target_arch = "x86_64"))]
fn run_target_directly(cmd: &[String]) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        crate::exec::execvp(cmd);
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        return 1;
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

#[cfg(target_arch = "x86_64")]
mod sud {
    //! x86_64 in-process SUD (SYSCALL_USER_DISPATCH) syscall interceptor.

    use super::*;
    use std::cell::UnsafeCell;
    use std::io::Write;
    use std::sync::atomic::{AtomicI32, Ordering};

    // SA_RESTORER: required when we install the handler with a raw rt_sigaction and
    // supply our own return trampoline. (Not exported by the libc crate for gnu.)
    const SA_RESTORER: libc::c_int = 0x0400_0000;
    const NR_RT_SIGACTION: i64 = 13;
    const SIGSETSIZE: usize = 8; // _NSIG/8 on x86_64

    // Our own signal return trampoline. glibc's `sigaction()` ignores a
    // user-supplied `sa_restorer`, so we install the handler via a raw
    // rt_sigaction (below) pointing here. Crucially, we register this stub as the
    // SUD dispatcher allow-window, so the `rt_sigreturn` it issues is ALWAYS
    // permitted, even while the selector is BLOCK. Without this, exiting the
    // handler would itself trap on rt_sigreturn under BLOCK and the kernel would
    // kill us with SIGSYS. This is the pure-SUD analogue of the C
    // `restore_selector_trampoline.S` / virtualize_signals machinery.
    core::arch::global_asm!(
        ".globl vock_sud_restorer",
        ".p2align 4",
        "vock_sud_restorer:",
        "mov eax, 15", // __NR_rt_sigreturn
        "syscall",
    );
    extern "C" {
        fn vock_sud_restorer();
    }

    // ─── Global interceptor state (lives in the forked child) ──────────────────

    /// The SUD selector byte. The kernel reads `*SELECTOR` before every syscall:
    /// ALLOW (0) lets it through, BLOCK (1) raises SIGSYS. Its address is handed to
    /// `prctl`, so it must be a stable static. (Port of the `sud_selector` byte.)
    #[repr(transparent)]
    struct Selector(UnsafeCell<u8>);
    unsafe impl Sync for Selector {}
    static SELECTOR: Selector = Selector(UnsafeCell::new(SYSCALL_DISPATCH_FILTER_ALLOW));

    static TRACE_FD: AtomicI32 = AtomicI32::new(-1);
    static TRACE_PID: AtomicI32 = AtomicI32::new(0);

    #[inline(always)]
    fn set_privilege_level(v: u8) {
        // Volatile: the kernel reads this byte out from under us on each syscall.
        unsafe { std::ptr::write_volatile(SELECTOR.0.get(), v) };
    }

    // ─── A tiny signal-safe-ish writer over the raw trace fd ────────────────────
    //
    // decode_syscall wants a std::io::Write. We buffer the (short) line on the
    // stack and emit it with a single write(2). Inside the handler the selector is
    // ALLOW, so these writes are not re-intercepted.

    struct FdWriter {
        fd: i32,
        buf: [u8; 4096],
        len: usize,
    }
    impl FdWriter {
        fn new(fd: i32) -> Self {
            FdWriter { fd, buf: [0u8; 4096], len: 0 }
        }
        fn commit(&mut self) {
            let mut off = 0usize;
            while off < self.len {
                let n = unsafe {
                    libc::write(
                        self.fd,
                        self.buf[off..self.len].as_ptr() as *const libc::c_void,
                        self.len - off,
                    )
                };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
            self.len = 0;
        }
    }
    impl Write for FdWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let space = self.buf.len() - self.len;
            let take = space.min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            Ok(take)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // ─── Raw syscall re-issue (x86_64 ABI) ─────────────────────────────────────
    //
    // Returns the raw kernel return value (negative errno on failure), matching
    // `inline_syscall6` in the C nolibc util so decode_syscall sees true returns.
    #[inline(always)]
    unsafe fn raw_syscall6(
        nr: i64,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64,
    ) -> i64 {
        let ret: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        ret
    }

    // x86_64 syscall numbers whose successful invocation does not return to us
    // (so we must log *before* re-issuing rather than after).
    const NR_RT_SIGRETURN: i64 = 15;
    const NR_EXECVE: i64 = 59;
    const NR_EXIT: i64 = 60;
    const NR_EXECVEAT: i64 = 322;
    const NR_EXIT_GROUP: i64 = 231;

    fn does_not_return(nr: i64) -> bool {
        matches!(
            nr,
            NR_EXECVE | NR_EXECVEAT | NR_EXIT | NR_EXIT_GROUP | NR_RT_SIGRETURN
        )
    }

    // ─── The SIGSYS handler (port of sud_core.c:handle_sigsys) ──────────────────

    extern "C" fn handle_sigsys(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        ucontextv: *mut libc::c_void,
    ) {
        // First thing, exactly as the C handler: drop to ALLOW so everything we do
        // below (writes, the re-issued syscall) is not itself intercepted.
        set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);

        let uctxt = ucontextv as *mut libc::ucontext_t;
        // uc_mcontext.gregs is [greg_t; 23]; indices come from libc::REG_*.
        let gregs = unsafe { (*uctxt).uc_mcontext.gregs };
        let g = |i: libc::c_int| gregs[i as usize] as i64;

        let nr = g(libc::REG_RAX);
        let args = [
            g(libc::REG_RDI),
            g(libc::REG_RSI),
            g(libc::REG_RDX),
            g(libc::REG_R10),
            g(libc::REG_R8),
            g(libc::REG_R9),
        ];

        let fd = TRACE_FD.load(Ordering::Relaxed);
        let pid = TRACE_PID.load(Ordering::Relaxed);

        // On entry the saved RIP already points *past* the trapping `syscall`
        // instruction (in the C handler, `si_call_addr[-1]` is the syscall insn),
        // so we emulate the syscall in-handler and return; the app resumes after it.
        if does_not_return(nr) {
            // Can't observe a return (success replaces/exits the process), so log
            // first with a placeholder ret of 0, then re-issue.
            if fd >= 0 {
                let mut w = FdWriter::new(fd);
                let sc = Syscall { nr, args, ret: 0 };
                decode_syscall(&mut w, pid, &sc);
                w.commit();
            }
            let ret = unsafe {
                raw_syscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5])
            };
            // Only reached if it actually returned (e.g. execve failed): write the
            // real return into RAX and restore BLOCK so the next syscall traps.
            unsafe {
                (*uctxt).uc_mcontext.gregs[libc::REG_RAX as usize] = ret;
            }
            set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
            return;
        }

        // Normal case: run the real syscall, capture the true return, log it, and
        // write the return back into RAX for the interrupted context.
        let ret =
            unsafe { raw_syscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };

        if fd >= 0 {
            let mut w = FdWriter::new(fd);
            let sc = Syscall { nr, args, ret };
            decode_syscall(&mut w, pid, &sc);
            w.commit();
        }

        unsafe {
            (*uctxt).uc_mcontext.gregs[libc::REG_RAX as usize] = ret;
        }

        // Restore BLOCK so the next syscall traps again (port of the selector
        // toggle around the SUD scope in sud_core.c).
        set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
    }

    // ─── Setup + run ────────────────────────────────────────────────────────────

    /// Install the SIGSYS handler and enable SUD in the current (child) process.
    /// Returns false on failure (caller falls back to running directly).
    unsafe fn enable_sud() -> bool {
        // Install the SIGSYS handler via a RAW rt_sigaction with our own restorer
        // and SA_RESTORER. glibc's sigaction() wrapper forces its own __restore_rt
        // (which lies outside our allow-window), so we must bypass it. The kernel
        // rt_sigaction struct layout on x86_64 is: handler, flags, restorer, mask.
        #[repr(C)]
        struct KAction {
            handler: usize,
            flags: u64,
            restorer: usize,
            mask: u64,
        }
        let ka = KAction {
            handler: handle_sigsys as *const () as usize,
            flags: (libc::SA_SIGINFO | SA_RESTORER) as u64,
            restorer: vock_sud_restorer as *const () as usize,
            mask: 0,
        };
        let r = raw_syscall6(
            NR_RT_SIGACTION,
            libc::SIGSYS as i64,
            &ka as *const _ as i64,
            0,
            SIGSETSIZE as i64,
            0,
            0,
        );
        if r != 0 {
            return false;
        }

        // Enable syscall user dispatch (port of enable_sud). The dispatcher
        // allow-window is set to our restorer stub so its rt_sigreturn is always
        // permitted; every other syscall is gated by the selector byte.
        set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);
        let win = vock_sud_restorer as *const () as usize;
        let r = libc::prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_ON,
            win,      // dispatcher_offset: start of the always-allowed window
            0x40usize, // dispatcher_len: covers the small restorer stub
            SELECTOR.0.get() as usize,
        );
        if r != 0 {
            return false;
        }
        true
    }

    pub fn run(cmd: &[String], trace_log: &str) -> i32 {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("[vock] sud: fork failed");
            return 1;
        }

        if pid == 0 {
            // ── Child: set up the interceptor, then exec the target ──
            // Open the trace file BEFORE enabling SUD (this open must not trap).
            let path = std::ffi::CString::new(trace_log).unwrap_or_default();
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o644,
                )
            };
            if fd >= 0 {
                TRACE_FD.store(fd, Ordering::Relaxed);
            }
            // decode_syscall reads argument strings from this process via
            // process_vm_readv; since we trace in-process, the pid is our own.
            TRACE_PID.store(unsafe { libc::getpid() }, Ordering::Relaxed);

            let armed = unsafe { enable_sud() };
            if !armed {
                // Could not arm SUD: run the target uninstrumented.
                eprintln!("[vock] sud: could not enable SYSCALL_USER_DISPATCH; running directly");
                crate::exec::execvp(cmd);
                unsafe { libc::_exit(127) };
            }

            // Arm the trap. From here every syscall the child makes (glibc's
            // execvp path: the execve, and any PATH-search stat/access) is
            // intercepted, logged via decode_syscall, and re-issued. The
            // successful execve then tears SUD down and the target runs untraced
            // (see module docs, this is the execve limitation the C code sidesteps
            // with its injected liblazypoline.so preload, which is not re-ported).
            set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
            crate::exec::execvp(cmd);
            // exec failed: drop back to ALLOW so _exit does not trap into a
            // now-teardown-in-progress handler, then bail.
            set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);
            unsafe { libc::_exit(127) };
        }

        // ── Parent: wait and report (port of the tail of vock_sud_run) ──
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        eprintln!("[vock] sud trace written to {trace_log}");
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        }
    }
}
