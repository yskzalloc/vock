//! Syzlang / strace trace emitter (port of syzlang/syzlang.c).
//!
//! The original `vock_syz_emit` simply renders the decoded syscall, so
//! `trace.log` and `trace.syz` share the same strace-style format.

use crate::syscall::{decode::decode_syscall, Syscall};
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct SyzWriter {
    out: BufWriter<File>,
    pub pid: libc::pid_t,
}

impl SyzWriter {
    pub fn create(path: &str, pid: libc::pid_t) -> std::io::Result<SyzWriter> {
        Ok(SyzWriter {
            out: BufWriter::new(File::create(path)?),
            pid,
        })
    }

    pub fn emit(&mut self, sc: &Syscall) {
        decode_syscall(&mut self.out, self.pid, sc);
    }

    pub fn flush(&mut self) {
        let _ = self.out.flush();
    }
}
