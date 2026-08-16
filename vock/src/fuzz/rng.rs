//! Small deterministic PRNG standing in for C's `rand()`/`srand()`.
//!
//! The C fuzzer/mutator relies on `rand()` returning a non-negative 31-bit
//! `int` (POSIX `RAND_MAX == 2147483647`) and seeds workers with
//! `time ^ getpid() ^ worker_id`. We do not need bit-exact reproduction of
//! glibc's sequence, only the same range and a good distribution so the
//! weighted mutation logic behaves identically. A xorshift64 generator
//! reduced to 31 bits provides that.
#![allow(dead_code)]

pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // Avoid an all-zero state (xorshift fixed point).
        Rng {
            state: seed ^ 0x9e3779b97f4a7c15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Equivalent of C `rand()`: a value in `0..=0x7fff_ffff`.
    pub fn rand(&mut self) -> u64 {
        self.next_u64() >> 33
    }

    /// `rand() % n` with `n` treated as a positive C `int`. Returns 0 if n<=0.
    pub fn below(&mut self, n: i64) -> i64 {
        if n <= 0 {
            return 0;
        }
        (self.rand() % n as u64) as i64
    }
}
