//! Edge-based signal tracking + corpus minimization (port of fuzz/signal_edge.c).
//!
//! Signal = hash(PC ^ prev_PC) for each consecutive PC pair in a KCOV trace.
//! The corpus keeps only programs that contribute at least one unique edge;
//! minimization removes programs whose edges are all covered by others.
//!
//! This mirrors the standalone `signal_edge_test` engine. It is not on the
//! main fuzz loop's hot path (fuzz.c uses the simpler `signal` set), but is
//! ported here in full for parity with the C sources.
#![allow(dead_code)]

pub const SIGNAL_MAP_BITS: u32 = 16;
pub const SIGNAL_MAP_SIZE: usize = 1 << SIGNAL_MAP_BITS;

/// Global max signal, union of all edges ever seen.
pub struct EdgeSignal {
    pub map: Vec<u8>, // hit count per edge bucket (SIGNAL_MAP_SIZE)
    pub total_edges: u32,
}

impl EdgeSignal {
    fn new() -> EdgeSignal {
        EdgeSignal {
            map: vec![0u8; SIGNAL_MAP_SIZE],
            total_edges: 0,
        }
    }
}

/// Per-program signal, the sorted set of edges the program contributes.
pub struct ProgSignal {
    pub edges: Vec<u32>,
}

/// Fast mixing hash of `pc ^ prev_pc` reduced to the edge-map index space.
fn edge_hash(pc: u64, prev_pc: u64) -> u32 {
    let mut h = pc ^ prev_pc;
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    (h & (SIGNAL_MAP_SIZE as u64 - 1)) as u32
}

/// Compute the edge signal from a raw KCOV PC array (deduped within-program,
/// sorted ascending).
pub fn edge_signal_from_pcs(pcs: &[u64]) -> ProgSignal {
    let mut seen = vec![0u8; SIGNAL_MAP_SIZE / 8 + 1];
    let mut edges: Vec<u32> = Vec::new();
    let mut prev: u64 = 0;
    for &pc in pcs {
        let edge = edge_hash(pc, prev);
        prev = pc;
        let (byte, bit) = ((edge / 8) as usize, (edge % 8) as u8);
        if seen[byte] & (1 << bit) != 0 {
            continue;
        }
        seen[byte] |= 1 << bit;
        edges.push(edge);
    }
    edges.sort_unstable();
    ProgSignal { edges }
}

pub struct SignalCorpusEntry {
    pub prog_id: i32,
    pub sig: ProgSignal,
    pub unique_edges: i32,
}

pub struct SignalCorpus {
    pub entries: Vec<SignalCorpusEntry>,
    pub max_signal: EdgeSignal,
}

impl SignalCorpus {
    pub fn new() -> SignalCorpus {
        SignalCorpus {
            entries: Vec::new(),
            max_signal: EdgeSignal::new(),
        }
    }

    /// How many edges in `sig` are new vs the global max signal.
    pub fn new_count(&self, sig: &ProgSignal) -> i32 {
        let mut new = 0;
        for &e in &sig.edges {
            if self.max_signal.map[e as usize] == 0 {
                new += 1;
            }
        }
        new
    }

    /// Add a program to the corpus if it contributes new signal.
    /// Returns true if added.
    pub fn add(&mut self, prog_id: i32, sig: ProgSignal) -> bool {
        let new_edges = self.new_count(&sig);
        if new_edges == 0 {
            return false; // no new signal, reject
        }
        for &e in &sig.edges {
            let e = e as usize;
            if self.max_signal.map[e] < 255 {
                self.max_signal.map[e] += 1;
            }
            if self.max_signal.map[e] == 1 {
                self.max_signal.total_edges += 1;
            }
        }
        self.entries.push(SignalCorpusEntry {
            prog_id,
            sig,
            unique_edges: new_edges,
        });
        true
    }

    /// Remove programs whose signal is a subset of others. Returns the count
    /// of removed programs.
    pub fn minimize(&mut self) -> i32 {
        if self.entries.len() <= 1 {
            return 0;
        }
        let mut edge_refcount = vec![0u16; SIGNAL_MAP_SIZE];
        for e in &self.entries {
            for &edge in &e.sig.edges {
                if edge_refcount[edge as usize] < u16::MAX {
                    edge_refcount[edge as usize] += 1;
                }
            }
        }

        let mut removed = 0;
        let mut i = 0;
        while i < self.entries.len() {
            let has_unique = self.entries[i]
                .sig
                .edges
                .iter()
                .any(|&edge| edge_refcount[edge as usize] == 1);
            if !has_unique {
                for &edge in &self.entries[i].sig.edges {
                    edge_refcount[edge as usize] -= 1;
                }
                // swap-remove and re-check the swapped-in entry (i unchanged)
                self.entries.swap_remove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }

        for e in self.entries.iter_mut() {
            let unique = e
                .sig
                .edges
                .iter()
                .filter(|&&edge| edge_refcount[edge as usize] == 1)
                .count() as i32;
            e.unique_edges = unique;
        }
        removed
    }

    pub fn total_edges(&self) -> i32 {
        self.max_signal.total_edges as i32
    }

    pub fn size(&self) -> i32 {
        self.entries.len() as i32
    }
}
