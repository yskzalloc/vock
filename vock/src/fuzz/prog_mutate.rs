//! Program mutation for `vock execprog -stress`.
//!
//! syzkaller's stress mode (`createStressProg`, tools/syz-execprog/execprog.go)
//! either generates a fresh random program from the syscall descriptions or
//! clones a corpus program and calls `prog.Mutate`. vock carries no
//! descriptions, so generating a well-typed program from nothing is not
//! possible here; instead the input program is the corpus and mutation works
//! directly on the decoded argument tree.
//!
//! The mutations are deliberately structure-preserving: pointers keep pointing
//! at their objects and `rN` wiring is left alone, so a mutated program is
//! still a runnable variant of the original rather than noise. Only leaf
//! values, buffer contents and the call sequence change.

#![allow(dead_code)]

use crate::prog_decode::{Arg, Prog};

/// xorshift64*, same shape as `fuzz/rng.rs`, kept local so this module does
/// not depend on the fuzzer's private submodules.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in.max(1)) == 0
    }
}

/// Values that disproportionately trigger kernel edge cases.
const INTERESTING: [u64; 16] = [
    0,
    1,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff,
    0x7fff_ffff,
    0x8000_0000,
    0xffff,
    0x8000,
    0x7f,
    0x80,
    0x100,
    0x1000,
    0x4000,
    0xffff_ff00,
];

fn mutate_int(v: u64, rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => INTERESTING[rng.below(INTERESTING.len())],
        1 => v ^ (1u64 << rng.below(64)),          // single bit flip
        2 => v.wrapping_add(1 + rng.below(4) as u64), // small delta
        _ => v.wrapping_sub(1 + rng.below(4) as u64),
    }
}

fn mutate_data(d: &mut Vec<u8>, rng: &mut Rng) {
    if d.is_empty() {
        d.push(rng.next() as u8);
        return;
    }
    match rng.below(4) {
        // Flip a bit somewhere in the buffer.
        0 => {
            let i = rng.below(d.len());
            d[i] ^= 1 << rng.below(8);
        }
        // Overwrite a byte with an interesting value.
        1 => {
            let i = rng.below(d.len());
            d[i] = INTERESTING[rng.below(INTERESTING.len())] as u8;
        }
        // Grow, but keep buffers bounded.
        2 if d.len() < 64 << 10 => {
            let b = rng.next() as u8;
            d.push(b);
        }
        // Shrink.
        _ => {
            if d.len() > 1 {
                d.truncate(d.len() - 1);
            }
        }
    }
}

/// Number of mutable leaves (integers and byte buffers) in an argument.
fn count_leaves(a: &Arg) -> usize {
    match a {
        Arg::Int(_) | Arg::Data(_) => 1,
        Arg::Ptr { inner: Some(i), .. } => count_leaves(i),
        Arg::Union(i) | Arg::Out { inner: i, .. } => count_leaves(i),
        Arg::Struct(fs) | Arg::Array(fs) => fs.iter().map(count_leaves).sum(),
        // Resources, csums and nil are left alone: mutating them would break
        // the wiring that makes the program run at all.
        _ => 0,
    }
}

/// Mutate the `n`th leaf, counting down as it descends.
fn mutate_nth(a: &mut Arg, n: &mut usize, rng: &mut Rng) -> bool {
    match a {
        Arg::Int(v) => {
            if *n == 0 {
                *v = mutate_int(*v, rng);
                return true;
            }
            *n -= 1;
        }
        Arg::Data(d) => {
            if *n == 0 {
                mutate_data(d, rng);
                return true;
            }
            *n -= 1;
        }
        Arg::Ptr { inner: Some(i), .. } => return mutate_nth(i, n, rng),
        Arg::Union(i) | Arg::Out { inner: i, .. } => return mutate_nth(i, n, rng),
        Arg::Struct(fs) | Arg::Array(fs) => {
            for f in fs.iter_mut() {
                if mutate_nth(f, n, rng) {
                    return true;
                }
            }
        }
        _ => {}
    }
    false
}

/// Apply one round of mutation in place. Returns the number of edits made.
pub fn mutate(prog: &mut Prog, rng: &mut Rng) -> usize {
    if prog.calls.is_empty() {
        return 0;
    }
    let mut edits = 0;

    // Drop a call. Kept rare, and never down to an empty program.
    if prog.calls.len() > 1 && rng.chance(10) {
        let i = rng.below(prog.calls.len());
        prog.calls.remove(i);
        edits += 1;
    }

    // Duplicate a call, which is how use-after-free and double-free paths get
    // exercised. Bounded so a long stress run cannot grow without limit.
    if prog.calls.len() < 512 && rng.chance(10) {
        let i = rng.below(prog.calls.len());
        let c = prog.calls[i].clone();
        prog.calls.insert(i, c);
        edits += 1;
    }

    // Mutate one to three argument leaves.
    let rounds = 1 + rng.below(3);
    for _ in 0..rounds {
        let ci = rng.below(prog.calls.len());
        let total: usize = prog.calls[ci].args.iter().map(count_leaves).sum();
        if total == 0 {
            continue;
        }
        let mut n = rng.below(total);
        for a in prog.calls[ci].args.iter_mut() {
            if mutate_nth(a, &mut n, rng) {
                edits += 1;
                break;
            }
        }
    }
    edits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prog_decode::parse_prog;

    fn seeded() -> Rng {
        Rng::new(0x1234_5678)
    }

    #[test]
    fn mutation_changes_the_program_but_keeps_it_runnable() {
        let text = "r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='/dev/null\\x00', 0x2, 0x0)\n\
                    write(r0, &(0x7f0000000100)=\"68656c6c6f\", 0x5)\n\
                    close(r0)\n";
        let base = parse_prog(text);
        let mut rng = seeded();
        let mut changed = 0;
        for _ in 0..200 {
            let mut p = base.clone();
            if mutate(&mut p, &mut rng) > 0 {
                changed += 1;
            }
            // Whatever happened, the program must stay non-empty and every
            // call must keep a resolvable name.
            assert!(!p.calls.is_empty());
            for c in &p.calls {
                assert!(!c.name.is_empty());
            }
        }
        assert!(changed > 100, "mutation should almost always edit something");
    }

    #[test]
    fn resource_wiring_survives_mutation() {
        // r0 must still be produced and consumed; mutating it away would make
        // every stress iteration run on a -1 fd.
        let base = parse_prog(
            "r0 = socket$inet(0x2, 0x1, 0x0)\nsetsockopt(r0, 0x1, 0x2, &(0x7f0000000000)={0x1}, 0x4)\n",
        );
        let mut rng = seeded();
        for _ in 0..200 {
            let mut p = base.clone();
            mutate(&mut p, &mut rng);
            for c in &p.calls {
                for a in &c.args {
                    if let Arg::Res { idx, .. } = a {
                        assert_eq!(*idx, 0, "resource index must not be rewritten");
                    }
                }
            }
        }
    }

    #[test]
    fn empty_program_is_handled() {
        let mut p = Prog::default();
        assert_eq!(mutate(&mut p, &mut seeded()), 0);
    }

    #[test]
    fn buffers_stay_bounded() {
        let base = parse_prog("write(0x1, &(0x7f0000000000)=\"00\", 0x1)\n");
        let mut rng = seeded();
        let mut p = base.clone();
        for _ in 0..5000 {
            mutate(&mut p, &mut rng);
        }
        assert!(p.calls.len() <= 512, "call count must stay bounded");
        for c in &p.calls {
            for a in &c.args {
                if let Arg::Ptr { inner: Some(i), .. } = a {
                    if let Arg::Data(d) = &**i {
                        assert!(d.len() <= 64 << 10, "buffer grew unbounded: {}", d.len());
                    }
                }
            }
        }
    }
}
