//! Fallback signal: (syscall_nr, errno) pairs (port of fuzz/signal.c).
//!
//! syzkaller analysis.go style. Each signal packs the low 16 bits of the
//! syscall number and the magnitude of a negative return (errno) into one u64.
#![allow(dead_code)]

pub const MAX_SIGNAL: usize = 8192;

pub struct SignalSet {
    pub sigs: Vec<u64>,
    pub cap: usize,
}

impl SignalSet {
    pub fn new(cap: usize) -> SignalSet {
        SignalSet {
            sigs: Vec::new(),
            cap,
        }
    }

    pub fn count(&self) -> i32 {
        self.sigs.len() as i32
    }

    pub fn add(&mut self, nr: i64, ret: i64) {
        let errno = if ret < 0 { -ret } else { 0 } as u64 & 0xffff_ffff;
        let sig = (((nr & 0xffff) as u64) << 32) | errno;
        if self.sigs.len() < self.cap {
            self.sigs.push(sig);
        }
    }

    pub fn sort_dedup(&mut self) {
        if self.sigs.len() <= 1 {
            return;
        }
        self.sigs.sort_unstable();
        self.sigs.dedup();
    }

    /// Number of signals in `self` not present in `other` (both sorted).
    pub fn novel(&self, other: &SignalSet) -> i32 {
        let (a, b) = (&self.sigs, &other.sigs);
        let (mut i, mut j, mut n) = (0usize, 0usize, 0i32);
        while i < a.len() && j < b.len() {
            if a[i] == b[j] {
                i += 1;
                j += 1;
            } else if a[i] < b[j] {
                n += 1;
                i += 1;
            } else {
                j += 1;
            }
        }
        n + (a.len() - i) as i32
    }
}
