//! Hardware-trace coverage mode: Intel PT / AMD LBR (x86_64), CoreSight
//! (aarch64). Port of mode/hw.c + intel_pt.c + pt_decode.c + amd_lbr.c and the
//! run_hw_mode orchestration in vock.c.
//!
//! Public surface (kept stable across the backend port):
//!   - `available()` — is any hardware-trace PMU usable?
//!   - `run(...)`     — trace the target and produce kerncov.log + report.

#![allow(clippy::too_many_arguments)]

#[path = "engine.rs"]
mod engine;

use crate::report;

/// Whether any supported hardware-trace PMU is present.
pub fn available() -> bool {
    engine::available()
}

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

    let mut session = match engine::Session::start(pid) {
        Some(s) => s,
        None => {
            eprintln!("hw_trace: start failed");
            unsafe {
                libc::close(pipefd[1]);
                libc::kill(pid, libc::SIGKILL);
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0);
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
    unsafe { libc::waitpid(pid, &mut status, 0) };
    session.stop();
    session.decode(vmlinux);
    drop(session);

    // Generate report from kerncov.log. The AMD decoder emits the log in
    // timestamp order with duplicates preserved, so with --ordered the
    // report renders the execution sequence as-is (Intel PT trace output is
    // inherently ordered too); without it the normal deduplicated
    // source-annotated report is produced.
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
    };
    report::run(&opts);

    if unsafe { libc::WIFEXITED(status) } {
        unsafe { libc::WEXITSTATUS(status) }
    } else {
        1
    }
}
