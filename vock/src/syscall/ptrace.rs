//! ptrace-based syscall tracer (port of syscall/ptrace/ptrace.c).

use super::Syscall;
use std::mem;

pub struct Tracer {
    pub pid: libc::pid_t,
    in_syscall: bool,
}

#[cfg(target_arch = "x86_64")]
fn regs_syscall(regs: &libc::user_regs_struct) -> Syscall {
    Syscall {
        nr: regs.orig_rax as i64,
        args: [
            regs.rdi as i64,
            regs.rsi as i64,
            regs.rdx as i64,
            regs.r10 as i64,
            regs.r8 as i64,
            regs.r9 as i64,
        ],
        ret: 0,
    }
}

#[cfg(target_arch = "x86_64")]
fn regs_ret(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

#[cfg(target_arch = "aarch64")]
fn regs_syscall(regs: &libc::user_regs_struct) -> Syscall {
    Syscall {
        nr: regs.regs[8] as i64,
        args: [
            regs.regs[0] as i64,
            regs.regs[1] as i64,
            regs.regs[2] as i64,
            regs.regs[3] as i64,
            regs.regs[4] as i64,
            regs.regs[5] as i64,
        ],
        ret: 0,
    }
}

#[cfg(target_arch = "aarch64")]
fn regs_ret(regs: &libc::user_regs_struct) -> i64 {
    regs.regs[0] as i64
}

unsafe fn get_regs(pid: libc::pid_t) -> Option<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = mem::zeroed();
    #[cfg(target_arch = "x86_64")]
    {
        if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs as *mut _) < 0 {
            return None;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: mem::size_of::<libc::user_regs_struct>(),
        };
        if libc::ptrace(libc::PTRACE_GETREGSET, pid, libc::NT_PRSTATUS, &mut iov as *mut _) < 0 {
            return None;
        }
    }
    Some(regs)
}

impl Tracer {
    /// Attach to a freshly-`TRACEME`'d child that has raised `SIGSTOP`.
    pub fn start(pid: libc::pid_t) -> Option<Tracer> {
        let mut status = 0;
        unsafe {
            if libc::waitpid(pid, &mut status, 0) < 0 {
                perror("ptrace: initial waitpid");
                return None;
            }
            if libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                0,
                (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL) as *mut libc::c_void,
            ) < 0
            {
                perror("ptrace: setoptions");
                return None;
            }
            if libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) < 0 {
                perror("ptrace: initial syscall");
                return None;
            }
        }
        Some(Tracer {
            pid,
            in_syscall: false,
        })
    }

    /// Advance to the next completed syscall (entry args + exit return value).
    /// Returns `None` when the tracee exits.
    pub fn next_syscall(&mut self) -> Option<Syscall> {
        let mut pending = Syscall::default();
        loop {
            let mut status = 0;
            unsafe {
                if libc::waitpid(self.pid, &mut status, 0) < 0 {
                    return None;
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    return None;
                }
                if !libc::WIFSTOPPED(status) || (libc::WSTOPSIG(status) & 0x80) == 0 {
                    libc::ptrace(libc::PTRACE_SYSCALL, self.pid, 0, 0);
                    continue;
                }

                let regs = match get_regs(self.pid) {
                    Some(r) => r,
                    None => return None,
                };

                if !self.in_syscall {
                    pending = regs_syscall(&regs);
                    self.in_syscall = true;
                } else {
                    pending.ret = regs_ret(&regs);
                    self.in_syscall = false;
                    libc::ptrace(libc::PTRACE_SYSCALL, self.pid, 0, 0);
                    return Some(pending);
                }

                libc::ptrace(libc::PTRACE_SYSCALL, self.pid, 0, 0);
            }
        }
    }

    pub fn stop(&self) {
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0);
        }
    }
}

fn perror(msg: &str) {
    let e = std::io::Error::last_os_error();
    eprintln!("{msg}: {e}");
}

/// Run the target under ptrace, writing `trace.log` (and `trace.syz` when
/// `syzlang`). Port of run_ptrace_mode in vock.c.
pub fn run(cmd: &[String], syzlang: bool) -> i32 {
    use crate::syzlang::SyzWriter;

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }
        crate::exec::execvp(cmd);
        eprintln!("target: execvp failed");
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        perror("target: fork failed");
        return 1;
    }

    let mut tracer = match Tracer::start(pid) {
        Some(t) => t,
        None => {
            eprintln!("ptrace: start failed");
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            return 1;
        }
    };

    let mut log = match SyzWriter::create("trace.log", pid) {
        Ok(w) => w,
        Err(_) => {
            tracer.stop();
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            return 1;
        }
    };
    let mut syz = if syzlang {
        SyzWriter::create("trace.syz", pid).ok()
    } else {
        None
    };

    while let Some(sc) = tracer.next_syscall() {
        log.emit(&sc);
        if let Some(s) = syz.as_mut() {
            s.emit(&sc);
        }
    }
    log.flush();
    if let Some(s) = syz.as_mut() {
        s.flush();
    }

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    eprintln!("[vock] ptrace trace written to trace.log");
    if syzlang {
        eprintln!("[vock] syzlang output written to trace.syz");
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        0
    }
}
