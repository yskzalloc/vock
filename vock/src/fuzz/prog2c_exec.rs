//! Program execution for the fuzzer (port of prog2c_exec / prog2c_exec_kcov
//! from prog2c/prog2c.c). Two paths:
//!   - direct: fork + unshare + raw syscall() replay (no coverage collected),
//!   - kcov:   generate C, compile, exec under LD_PRELOAD=mode/kcov.so, which
//!             dumps kernel PCs to `kerncov.log`.
#![allow(dead_code)]

use crate::syscall::Syscall;
use std::ffi::CString;

/// Direct execution: fork + unshare + raw syscall replay.
/// Returns the child exit status, or -1 on failure.
pub fn exec_direct(trace: &[Syscall]) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWPID);
            for c in trace {
                libc::syscall(
                    c.nr, c.args[0], c.args[1], c.args[2], c.args[3], c.args[4], c.args[5],
                );
            }
            libc::_exit(0);
        }
    }
    if pid < 0 {
        return -1;
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

fn kcov_so_path() -> String {
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::readlink(
            b"/proc/self/exe\0".as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() - 1,
        )
    };
    if n > 0 {
        let exe = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
        let dir = std::path::Path::new(&exe)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        format!("{dir}/mode/kcov.so")
    } else {
        "./mode/kcov.so".to_string()
    }
}

/// KCOV mode: generate + compile + exec with LD_PRELOAD=mode/kcov.so.
/// The preloaded library writes `kerncov.log`. Returns the child exit status,
/// or -1 on failure.
pub fn exec_kcov(trace: &[Syscall]) -> i32 {
    let pid_self = unsafe { libc::getpid() };
    let src = format!("/tmp/vock_{pid_self}.c");
    let bin = format!("/tmp/vock_{pid_self}");

    if crate::prog2c::generate(trace, &src).is_err() {
        return -1;
    }

    // Compile (no -static: LD_PRELOAD requires a dynamic executable).
    let compile = std::process::Command::new("cc")
        .args(["-w", "-O0", "-o", &bin, &src])
        .stderr(std::process::Stdio::null())
        .status();
    let ok = matches!(compile, Ok(s) if s.success());
    if !ok {
        let _ = std::fs::remove_file(&src);
        return -1;
    }

    let preload = kcov_so_path();
    let bin_c = CString::new(bin.as_bytes()).unwrap();
    let preload_name = CString::new("LD_PRELOAD").unwrap();
    let preload_val = CString::new(preload.as_bytes()).unwrap();

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::setenv(preload_name.as_ptr(), preload_val.as_ptr(), 1);
            let argv = [bin_c.as_ptr(), std::ptr::null()];
            libc::execv(bin_c.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    if pid < 0 {
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&bin);
        return -1;
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&bin);
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}
