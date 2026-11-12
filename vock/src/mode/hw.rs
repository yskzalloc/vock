//! Hardware-trace coverage mode (`--mode hw`): run the target under a
//! kernel-only hardware trace and produce kerncov.log + report. Port of
//! mode/hw.c (backend dispatcher) and the run_hw_mode orchestration in vock.c.
//!
//! The CPU-specific backends live in:
//!   - streaming::intel  Intel PT (x86_64)
//!   - sampling::amd     AMD LBR + IBS (x86_64)
//!   - streaming::arm    Arm CoreSight ETM/ETE (aarch64), TODO
//!
//! all built on the shared per-CPU, child-following perf plumbing in
//! mode::perf.

use super::sampling::amd::Amd;
use super::streaming::arm::CoreSight;
use super::streaming::intel::IntelPt;
use super::{sampling, streaming};
use crate::report;

/// The armed backend. Selection order (mode/hw.c): Intel PT if its PMU
/// exists, else AMD if the vendor matches, else CoreSight. If the preferred
/// backend fails to start the session aborts rather than trying the next.
enum Backend {
    IntelPt(IntelPt),
    Amd(Amd),
    CoreSight(CoreSight),
}

impl Backend {
    fn start(pid: libc::pid_t) -> Option<Backend> {
        if streaming::intel::available() {
            return IntelPt::start(pid).map(Backend::IntelPt);
        }
        if sampling::amd::available() {
            return Amd::start(pid).map(Backend::Amd);
        }
        if streaming::arm::available() {
            return CoreSight::start(pid).map(Backend::CoreSight);
        }
        eprintln!("hw_trace: no hardware trace PMU found");
        None
    }

    fn stop(&mut self) {
        match self {
            Backend::IntelPt(b) => b.stop(),
            Backend::Amd(b) => b.stop(),
            Backend::CoreSight(b) => b.stop(),
        }
    }

    /// Decode the captured trace into kerncov.log (one "0x<pc>" per line).
    fn decode(&mut self, vmlinux: Option<&str>) {
        match self {
            Backend::IntelPt(b) => b.decode(vmlinux),
            Backend::Amd(b) => b.decode(),
            Backend::CoreSight(b) => b.decode(vmlinux),
        }
    }
}

/// Trace `cmd` and every task it creates, then generate the report.
/// Returns the target's exit status.
#[allow(clippy::too_many_arguments)]
pub fn run(
    cmd: &[String],
    vmlinux: Option<&str>,
    kernel_src: Option<&str>,
    filter: Option<&str>,
    btf: bool,
    ctx_after: i32,
    ctx_before: i32,
    ordered: bool,
) -> i32 {
    // Fork the target, stopped on a pipe until tracing is armed.
    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } < 0 {
        eprintln!("pipe: {}", std::io::Error::last_os_error());
        return 1;
    }

    // The perf events follow every descendant of the target (inherit), so
    // the trace must stay armed until the last of them exits, not just the
    // direct child. As a child subreaper, descendants orphaned by an exiting
    // parent (daemonized, double-forked) are reparented to us and can be
    // waited for below.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(pipefd[1]);
            let mut c = 0u8;
            libc::read(pipefd[0], &mut c as *mut _ as *mut libc::c_void, 1);
            libc::close(pipefd[0]);
        }
        crate::exec::execvp(cmd);
        eprintln!("target: execvp failed");
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        eprintln!("target: fork failed: {}", std::io::Error::last_os_error());
        return 1;
    }
    unsafe { libc::close(pipefd[0]) };

    let mut backend = match Backend::start(pid) {
        Some(b) => b,
        None => {
            eprintln!("hw_trace: start failed");
            unsafe {
                libc::close(pipefd[1]);
                libc::kill(pid, libc::SIGKILL);
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0);
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
            }
            return 1;
        }
    };

    // Signal the child to exec now that tracing is armed.
    unsafe {
        libc::write(pipefd[1], b"g".as_ptr() as *const libc::c_void, 1);
        libc::close(pipefd[1]);
    }

    let mut status = 0;
    unsafe {
        while libc::waitpid(pid, &mut status, 0) < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
    }
    reap_descendants();
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
    backend.stop();
    backend.decode(vmlinux);
    drop(backend);

    // Generate report from kerncov.log. Both decoders emit the log in
    // timestamp order with duplicates preserved, so with --ordered the
    // report renders the execution sequence as-is; without it the normal
    // deduplicated source-annotated report is produced.
    let opts = report::Options {
        kernel_src: kernel_src.map(String::from),
        vmlinux: vmlinux.map(String::from),
        log: "kerncov.log".to_string(),
        filter: filter.map(String::from),
        quiet: false,
        ctx_after: if ctx_after >= 0 { ctx_after } else { 3 },
        ctx_before: if ctx_before >= 0 { ctx_before } else { 3 },
        output: "coverage.html".to_string(),
        btf,
        ordered,
        parts: Vec::new(),
    };
    report::run(&opts);

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

/// Wait for every remaining child: descendants of the target reparented to
/// us as subreaper. Their exit status does not affect ours.
fn reap_descendants() {
    let mut st = 0;
    let mut announced = false;
    loop {
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r == 0 {
            if !announced {
                eprintln!("[vock] target exited; waiting for its remaining descendants");
                announced = true;
            }
            let r = unsafe { libc::waitpid(-1, &mut st, 0) };
            if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return;
            }
        } else if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return; // ECHILD: none left
        }
    }
}
