//! Coverage set operations (port of fuzz/covset.c).
//!
//! A `Covset` is a bounded, sortable/dedup-able set of PC/hash values with
//! sorted intersection and novelty counting against a baseline set.
#![allow(dead_code)]

pub const MAX_COVERAGE: usize = 65536;

pub struct Covset {
    pub pcs: Vec<u64>,
    pub cap: usize,
}

impl Covset {
    pub fn new(cap: usize) -> Covset {
        Covset {
            pcs: Vec::new(),
            cap,
        }
    }

    pub fn count(&self) -> i32 {
        self.pcs.len() as i32
    }

    /// Append `pc` unless the set is at capacity (mirrors covset_add).
    pub fn add(&mut self, pc: u64) {
        if self.pcs.len() < self.cap {
            self.pcs.push(pc);
        }
    }

    pub fn sort_dedup(&mut self) {
        if self.pcs.len() <= 1 {
            return;
        }
        self.pcs.sort_unstable();
        self.pcs.dedup();
    }

    /// Number of elements present in both sorted sets.
    pub fn intersect(&self, other: &Covset) -> i32 {
        let (a, b) = (&self.pcs, &other.pcs);
        let (mut i, mut j, mut n) = (0usize, 0usize, 0i32);
        while i < a.len() && j < b.len() {
            if a[i] == b[j] {
                n += 1;
                i += 1;
                j += 1;
            } else if a[i] < b[j] {
                i += 1;
            } else {
                j += 1;
            }
        }
        n
    }

    /// Number of elements in `self` not present in `other` (both sorted).
    pub fn novel(&self, other: &Covset) -> i32 {
        let (a, b) = (&self.pcs, &other.pcs);
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

    /// Load hex PC values (one per line, e.g. "0x1234") produced by kcov.so's
    /// `kerncov.log`. Sorts+dedups on success. Returns false if the file is
    /// missing/unreadable (mirrors covset_load_file's -1).
    pub fn load_file(&mut self, path: &str) -> bool {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return false,
        };
        for line in data.lines() {
            let s = line.trim();
            let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            if let Ok(pc) = u64::from_str_radix(hex, 16) {
                if pc != 0 {
                    self.add(pc);
                }
            }
        }
        self.sort_dedup();
        true
    }
}
