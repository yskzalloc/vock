//! Syscall model shared across backends: the `Syscall` record, arch name
//! tables, strace-format decoding, and the ptrace tracer.

pub mod decode;
pub mod ptrace;
pub mod tables;

pub use tables::{syscall_name, MAX_SYSCALL_NR};

/// A single observed syscall (entry args + exit return value).
#[derive(Clone, Copy, Debug)]
pub struct Syscall {
    pub nr: i64,
    pub args: [i64; 6],
    pub ret: i64,
}

impl Default for Syscall {
    fn default() -> Self {
        Syscall {
            nr: 0,
            args: [0; 6],
            ret: 0,
        }
    }
}

/// Reverse lookup: syscall name → number (mirrors the C loop `for n in 0..500`).
pub fn syscall_nr(name: &str) -> Option<i64> {
    for n in 0..=MAX_SYSCALL_NR {
        if syscall_name(n) == Some(name) {
            return Some(n);
        }
    }
    None
}

/// Read a NUL-terminated string from another process's address space via
/// `process_vm_readv`. Returns the bytes up to (not including) the first NUL,
/// or `None` on failure / obviously bogus pointers.
pub fn read_str(pid: libc::pid_t, addr: u64, size: usize) -> Option<Vec<u8>> {
    if addr == 0 || addr > 0x0000_ffff_ffff_ffff {
        return None;
    }
    let mut buf = vec![0u8; size];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: size,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: size,
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return None;
    }
    // Truncate at first NUL, capped at the bytes actually read.
    let got = (n as usize).min(size);
    let end = buf[..got].iter().position(|&b| b == 0).unwrap_or(got);
    buf.truncate(end);
    Some(buf)
}
