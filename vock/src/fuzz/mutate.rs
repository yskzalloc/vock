//! Mutation engine (port of fuzz/mutate.c), syzkaller rand.go + mutation.go.
//!
//! Strategies: splice from corpus, mutate arg (fd-aware), multi-mutate,
//! reorder, squash, remove, weighted like syzkaller.
#![allow(dead_code)]

use super::rng::Rng;
use super::state::FdState;
use crate::syscall::Syscall;

pub const MAX_SYSCALLS: usize = 4096;

/// A corpus entry: a kept syscall sequence plus its scoring metadata
/// (port of `struct corpus_entry`).
pub struct CorpusEntry {
    pub calls: Vec<Syscall>,
    pub score: f64,
    pub coverage: i32,
    pub novelty: i32,
    pub signal_novelty: i32,
}

/// Special integers (syzkaller rand.go).
const SPECIAL_INTS: [u64; 48] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    64, 127, 128, 129, 255, 256, 257, 511, 512,
    1023, 1024, 1025, 2047, 2048, 4095, 4096,
    0x7fff, 0x8000, 0x8001, 0xffff, 0x10000, 0x10001,
    0x7fffffff, 0x80000000, 0x80000001,
    0xffffffff, 0x100000000, 0x100000001,
    0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
];
const N_SPECIAL: usize = 48;

/// syzkaller-style random integer with a weighted distribution.
pub fn rand_int(rng: &mut Rng) -> u64 {
    let mut v: u64 = (rng.rand() << 32) | rng.rand();
    let r = rng.below(182);
    if r < 100 {
        v %= 10;
    } else if r < 150 {
        v = SPECIAL_INTS[(rng.below(N_SPECIAL as i64)) as usize];
    } else if r < 160 {
        v %= 256;
    } else if r < 170 {
        v %= 4096;
    } else if r < 180 {
        v %= 65536;
    } else {
        v %= 0x8000_0000;
    }
    let p = rng.below(107);
    if (100..105).contains(&p) {
        v = (v as i64).wrapping_neg() as u64;
    } else if p >= 105 {
        v = v.wrapping_shl((rng.below(64)) as u32);
    }
    v
}

fn is_fd_arg(nr: i64, ai: usize) -> bool {
    if ai != 0 {
        return false;
    }
    matches!(
        nr,
        0 | 1 | 3 | 5 | 7 | 8 | 16 | 17 | 18 | 19 | 20 | 72 | 73 | 74 | 75
    )
}

fn mutate_arg(val: u64, nr: i64, ai: usize, fds: &FdState, rng: &mut Rng) -> u64 {
    // Skip userspace pointers, they don't exist in the forked child.
    if (val >= 0x100000 && val <= 0x7fff_ffff_ffff)
        || (val >= 0x7f00_0000_0000 && val <= 0x7fff_ffff_ffff_ffff)
    {
        return val;
    }

    if is_fd_arg(nr, ai) && fds.nfds() > 0 && rng.below(4) < 3 {
        return fds.get_valid(rng) as u64;
    }

    let s = rng.below(100);
    if s < 30 {
        return rand_int(rng);
    }
    if s < 50 {
        let d = rng.below(35) as u64 + 1;
        return if rng.rand() & 1 == 1 {
            val.wrapping_add(d)
        } else {
            val.wrapping_sub(d)
        };
    }
    if s < 70 {
        return val ^ (1u64 << (rng.below(64) as u32));
    }
    if s < 85 {
        let w = 1u32 << (rng.below(3) as u32);
        let mask: u64 = if w == 4 {
            0xffff_ffff
        } else if w == 2 {
            0xffff
        } else {
            0xff
        };
        return (val & !mask) | (rand_int(rng) & mask);
    }
    SPECIAL_INTS[(rng.below(N_SPECIAL as i64)) as usize]
}

/// Biased call index (syzkaller prio.go biasedRand): favours later calls.
fn biased_idx(n: i64, rng: &mut Rng) -> usize {
    if n <= 0 {
        return 0;
    }
    let r = rng.below(n * n) as f64;
    let idx = (n - 1) - (r.sqrt() as i64);
    if idx < 0 {
        0
    } else {
        idx as usize
    }
}

/// Mutate a syscall sequence, producing a new one. Uses the corpus for
/// splicing and fd state for valid-fd args.
pub fn mutate_sequence(
    src: &[Syscall],
    corpus: &[CorpusEntry],
    fds: &FdState,
    rng: &mut Rng,
) -> Vec<Syscall> {
    let nsrc = src.len();
    let mut dst: Vec<Syscall> = src.to_vec();

    // Weights: splice_corpus=200, mutate=100, multi=100, reorder=100,
    // squash=50, remove=10 => total 560.
    let w = rng.below(560);

    if w < 200 && !corpus.is_empty() {
        // SPLICE FROM CORPUS
        let donor = &corpus[(rng.below(corpus.len() as i64)) as usize];
        let cut = if nsrc > 0 { rng.below(nsrc as i64) as usize } else { 0 };
        let ds = if donor.calls.len() > 1 {
            rng.below(donor.calls.len() as i64) as usize
        } else {
            0
        };
        let mut dl = donor.calls.len() - ds;
        if cut + dl > MAX_SYSCALLS {
            dl = MAX_SYSCALLS - cut;
        }
        dst.truncate(cut);
        dst.extend_from_slice(&donor.calls[ds..ds + dl]);
    } else if w < 300 {
        // MUTATE ONE ARG
        if nsrc > 0 {
            let ci = biased_idx(nsrc as i64, rng);
            let ai = rng.below(6) as usize;
            dst[ci].args[ai] =
                mutate_arg(dst[ci].args[ai] as u64, dst[ci].nr, ai, fds, rng) as i64;
        }
    } else if w < 400 {
        // MUTATE MULTIPLE ARGS
        let mut m = rng.below(3) + 1;
        while m > 0 && nsrc > 0 {
            let ci = biased_idx(nsrc as i64, rng);
            let ai = rng.below(6) as usize;
            dst[ci].args[ai] =
                mutate_arg(dst[ci].args[ai] as u64, dst[ci].nr, ai, fds, rng) as i64;
            m -= 1;
        }
    } else if w < 500 {
        // REORDER (reverse suffix)
        if nsrc > 1 {
            let cut = rng.below(nsrc as i64) as usize;
            dst[cut..].reverse();
        }
    } else if w < 550 {
        // SQUASH
        if nsrc > 0 {
            let ci = rng.below(nsrc as i64) as usize;
            for a in 0..6 {
                dst[ci].args[a] = rand_int(rng) as i64;
            }
        }
    } else {
        // REMOVE
        if nsrc > 1 {
            let ci = rng.below(nsrc as i64) as usize;
            dst.remove(ci);
        }
    }

    dst
}

/// Minimize a trace by removing unneeded calls (syzkaller minimization.go).
pub fn minimize_trace(trace: &mut Vec<Syscall>, rng: &mut Rng) {
    if trace.len() <= 3 {
        return;
    }
    let mut i = trace.len() as i64 - 1;
    while i > 0 && trace.len() > 3 {
        let idx = i as usize;
        let mut needed = false;
        let ret = trace[idx].ret;
        if ret >= 0 && ret < 256 {
            'outer: for j in idx + 1..trace.len() {
                for a in 0..6 {
                    if trace[j].args[a] == ret {
                        needed = true;
                        break 'outer;
                    }
                }
            }
        }
        if !needed && rng.below(3) == 0 {
            trace.remove(idx);
        }
        i -= 1;
    }
}
