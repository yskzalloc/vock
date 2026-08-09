//! strace-format syscall decoding (port of syscall/decode.c + arch decode.c).
//!
//! Reads strings from the traced process via `process_vm_readv` and renders
//! `name(args...) = ret` lines byte-for-byte compatible with the original.

use super::{read_str, syscall_name, Syscall};
use std::io::Write;

fn print_str<W: Write>(out: &mut W, pid: libc::pid_t, addr: u64) {
    match read_str(pid, addr, 256) {
        Some(buf) if !buf.is_empty() => {
            let _ = write!(out, "\"");
            for &c in buf.iter().take(64) {
                if (32..127).contains(&c) {
                    let _ = out.write_all(&[c]);
                } else {
                    let _ = write!(out, "\\x{c:02x}");
                }
            }
            let _ = write!(out, "\"");
        }
        _ => {
            if addr == 0 {
                let _ = write!(out, "NULL");
            } else {
                let _ = write!(out, "0x{addr:x}");
            }
        }
    }
}

fn print_open_flags<W: Write>(out: &mut W, flags: i64) {
    let mut flags = flags;
    let mode = (flags & 3) as usize;
    let m = ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_RDWR"];
    let _ = write!(out, "{}", m[mode]);
    flags &= !3;
    for (bit, name) in [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NONBLOCK, "O_NONBLOCK"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_LARGEFILE, "O_LARGEFILE"),
    ] {
        let bit = bit as i64;
        if flags & bit != 0 {
            let _ = write!(out, "|{name}");
            flags &= !bit;
        }
    }
    if flags != 0 {
        let _ = write!(out, "|0x{flags:x}");
    }
}

fn print_mmap_prot<W: Write>(out: &mut W, prot: i64) {
    let mut prot = prot;
    if prot == 0 {
        let _ = write!(out, "PROT_NONE");
        return;
    }
    let mut first = true;
    for (bit, name) in [(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")] {
        if prot & bit != 0 {
            let _ = write!(out, "{}{}", if first { "" } else { "|" }, name);
            first = false;
            prot &= !bit;
        }
    }
    if prot != 0 {
        let _ = write!(out, "|0x{prot:x}");
    }
}

fn print_mmap_flags<W: Write>(out: &mut W, flags: i64) {
    let mut flags = flags;
    if flags & libc::MAP_PRIVATE as i64 != 0 {
        let _ = write!(out, "MAP_PRIVATE");
    } else if flags & libc::MAP_SHARED as i64 != 0 {
        let _ = write!(out, "MAP_SHARED");
    } else {
        let _ = write!(out, "0x{:x}", flags & 0xf);
    }
    flags &= !0xf;
    for (bit, name) in [
        (libc::MAP_ANONYMOUS as i64, "MAP_ANONYMOUS"),
        (libc::MAP_FIXED as i64, "MAP_FIXED"),
        (libc::MAP_POPULATE as i64, "MAP_POPULATE"),
    ] {
        if flags & bit != 0 {
            let _ = write!(out, "|{name}");
            flags &= !bit;
        }
    }
    if flags != 0 {
        let _ = write!(out, "|0x{flags:x}");
    }
}

fn print_socket_domain<W: Write>(out: &mut W, d: i64) {
    let s = match d {
        x if x == libc::AF_UNIX as i64 => "AF_UNIX",
        x if x == libc::AF_INET as i64 => "AF_INET",
        x if x == libc::AF_INET6 as i64 => "AF_INET6",
        x if x == libc::AF_NETLINK as i64 => "AF_NETLINK",
        x if x == libc::AF_PACKET as i64 => "AF_PACKET",
        _ => {
            let _ = write!(out, "{d}");
            return;
        }
    };
    let _ = write!(out, "{s}");
}

fn print_socket_type<W: Write>(out: &mut W, ty: i64) {
    let base = ty & 0xf;
    let s = match base {
        x if x == libc::SOCK_STREAM as i64 => "SOCK_STREAM",
        x if x == libc::SOCK_DGRAM as i64 => "SOCK_DGRAM",
        x if x == libc::SOCK_RAW as i64 => "SOCK_RAW",
        x if x == libc::SOCK_SEQPACKET as i64 => "SOCK_SEQPACKET",
        _ => "",
    };
    if s.is_empty() {
        let _ = write!(out, "{base}");
    } else {
        let _ = write!(out, "{s}");
    }
    if ty & libc::SOCK_NONBLOCK as i64 != 0 {
        let _ = write!(out, "|SOCK_NONBLOCK");
    }
    if ty & libc::SOCK_CLOEXEC as i64 != 0 {
        let _ = write!(out, "|SOCK_CLOEXEC");
    }
}

// ─── Per-syscall formatters ─────────────────────────────────────────────────

fn is_at_fdcwd(v: i64) -> bool {
    v == -100 || (v as u64) == 0xffff_ff9c || (v as u64) == 0xffff_ffff_ffff_ff9c
}

fn fmt_openat<W: Write>(out: &mut W, pid: libc::pid_t, a: &[i64; 6], ret: i64) {
    if is_at_fdcwd(a[0]) {
        let _ = write!(out, "openat(AT_FDCWD, ");
    } else {
        let _ = write!(out, "openat({}, ", a[0]);
    }
    print_str(out, pid, a[1] as u64);
    let _ = write!(out, ", ");
    print_open_flags(out, a[2]);
    if a[2] & libc::O_CREAT as i64 != 0 {
        let _ = write!(out, ", {:04o}", a[3]);
    }
    let _ = writeln!(out, ") = {ret}");
}

fn fmt_open<W: Write>(out: &mut W, pid: libc::pid_t, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "open(");
    print_str(out, pid, a[0] as u64);
    let _ = write!(out, ", ");
    print_open_flags(out, a[1]);
    if a[1] & libc::O_CREAT as i64 != 0 {
        let _ = write!(out, ", {:04o}", a[2]);
    }
    let _ = writeln!(out, ") = {ret}");
}

fn fmt_read<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = writeln!(out, "read({}, 0x{:x}, {}) = {}", a[0], a[1] as u64, a[2] as u64, ret);
}

fn fmt_write<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = writeln!(out, "write({}, 0x{:x}, {}) = {}", a[0], a[1] as u64, a[2] as u64, ret);
}

fn fmt_close<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = writeln!(out, "close({}) = {}", a[0], ret);
}

fn fmt_mmap<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "mmap(");
    if a[0] == 0 {
        let _ = write!(out, "NULL");
    } else {
        let _ = write!(out, "0x{:x}", a[0] as u64);
    }
    let _ = write!(out, ", {}, ", a[1] as u64);
    print_mmap_prot(out, a[2]);
    let _ = write!(out, ", ");
    print_mmap_flags(out, a[3]);
    let _ = writeln!(out, ", {}, {}) = 0x{:x}", a[4], a[5], ret as u64);
}

fn fmt_mprotect<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "mprotect(0x{:x}, {}, ", a[0] as u64, a[1] as u64);
    print_mmap_prot(out, a[2]);
    let _ = writeln!(out, ") = {ret}");
}

fn fmt_socket<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "socket(");
    print_socket_domain(out, a[0]);
    let _ = write!(out, ", ");
    print_socket_type(out, a[1]);
    let _ = writeln!(out, ", {}) = {}", a[2], ret);
}

fn fmt_connect<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    let _ = writeln!(out, "connect({}, 0x{:x}, {}) = {}", a[0], a[1] as u64, a[2] as u64, ret);
}

fn fmt_execve<W: Write>(out: &mut W, pid: libc::pid_t, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "execve(");
    print_str(out, pid, a[0] as u64);
    let _ = writeln!(out, ", 0x{:x}, 0x{:x}) = {}", a[1] as u64, a[2] as u64, ret);
}

fn fmt_access<W: Write>(out: &mut W, pid: libc::pid_t, a: &[i64; 6], ret: i64) {
    let _ = write!(out, "access(");
    print_str(out, pid, a[0] as u64);
    let _ = write!(out, ", ");
    let mut m = a[1];
    if m == 0 {
        let _ = write!(out, "F_OK");
    } else {
        let mut first = true;
        for (bit, name) in [(4, "R_OK"), (2, "W_OK"), (1, "X_OK")] {
            if m & bit != 0 {
                let _ = write!(out, "{}{}", if first { "" } else { "|" }, name);
                first = false;
                m &= !bit;
            }
        }
    }
    let _ = writeln!(out, ") = {ret}");
}

fn fmt_brk<W: Write>(out: &mut W, a: &[i64; 6], ret: i64) {
    if a[0] == 0 {
        let _ = writeln!(out, "brk(NULL) = 0x{:x}", ret as u64);
    } else {
        let _ = writeln!(out, "brk(0x{:x}) = 0x{:x}", a[0] as u64, ret as u64);
    }
}

fn fmt_generic<W: Write>(out: &mut W, nr: i64, args: &[i64; 6], ret: i64) {
    match syscall_name(nr) {
        Some(name) => {
            let _ = write!(out, "{name}(");
        }
        None => {
            let _ = write!(out, "syscall_{nr}(");
        }
    }
    for (i, &arg) in args.iter().enumerate() {
        if i != 0 {
            let _ = write!(out, ", ");
        }
        if arg == 0 {
            let _ = write!(out, "0");
        } else {
            let _ = write!(out, "0x{:x}", arg as u64);
        }
    }
    let _ = writeln!(out, ") = {ret}");
}

// ─── Arch dispatch (x86_64 has legacy syscalls absent on aarch64) ───────────

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const OPEN: i64 = 2;
    pub const CLOSE: i64 = 3;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const BRK: i64 = 12;
    pub const ACCESS: i64 = 21;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const EXECVE: i64 = 59;
    pub const OPENAT: i64 = 257;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const OPENAT: i64 = 56;
    pub const CLOSE: i64 = 57;
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const BRK: i64 = 214;
    pub const MMAP: i64 = 222;
    pub const MPROTECT: i64 = 226;
    pub const EXECVE: i64 = 221;
    pub const SOCKET: i64 = 198;
    pub const CONNECT: i64 = 203;
}

/// Decode one syscall into strace format, writing a single line to `out`.
#[cfg(target_arch = "x86_64")]
pub fn decode_syscall<W: Write>(out: &mut W, pid: libc::pid_t, sc: &Syscall) {
    let a = &sc.args;
    match sc.nr {
        nr::READ => fmt_read(out, a, sc.ret),
        nr::WRITE => fmt_write(out, a, sc.ret),
        nr::OPEN => fmt_open(out, pid, a, sc.ret),
        nr::CLOSE => fmt_close(out, a, sc.ret),
        nr::MMAP => fmt_mmap(out, a, sc.ret),
        nr::MPROTECT => fmt_mprotect(out, a, sc.ret),
        nr::BRK => fmt_brk(out, a, sc.ret),
        nr::ACCESS => fmt_access(out, pid, a, sc.ret),
        nr::SOCKET => fmt_socket(out, a, sc.ret),
        nr::CONNECT => fmt_connect(out, a, sc.ret),
        nr::EXECVE => fmt_execve(out, pid, a, sc.ret),
        nr::OPENAT => fmt_openat(out, pid, a, sc.ret),
        _ => fmt_generic(out, sc.nr, a, sc.ret),
    }
}

#[cfg(target_arch = "aarch64")]
pub fn decode_syscall<W: Write>(out: &mut W, pid: libc::pid_t, sc: &Syscall) {
    let a = &sc.args;
    match sc.nr {
        nr::READ => fmt_read(out, a, sc.ret),
        nr::WRITE => fmt_write(out, a, sc.ret),
        nr::OPENAT => fmt_openat(out, pid, a, sc.ret),
        nr::CLOSE => fmt_close(out, a, sc.ret),
        nr::MMAP => fmt_mmap(out, a, sc.ret),
        nr::MPROTECT => fmt_mprotect(out, a, sc.ret),
        nr::BRK => fmt_brk(out, a, sc.ret),
        nr::SOCKET => fmt_socket(out, a, sc.ret),
        nr::CONNECT => fmt_connect(out, a, sc.ret),
        nr::EXECVE => fmt_execve(out, pid, a, sc.ret),
        _ => fmt_generic(out, sc.nr, a, sc.ret),
    }
}
