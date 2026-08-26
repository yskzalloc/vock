//! Process-wide handle on the in-process symbolizer (`crate::dwarf`).

use std::sync::{Mutex, OnceLock};

pub use crate::dwarf::Symbolizer as Dwarf;

/// The symbolizer for `path`. Opened once (possibly by a pre-warm thread
/// while the traced program is still running); later callers block on the
/// same OnceLock until it is ready. A failure is remembered so callers can
/// fall back without retrying the load.
pub fn get(path: &str) -> Result<&'static Mutex<Dwarf>, String> {
    static OPEN: OnceLock<(String, Result<Mutex<Dwarf>, String>)> = OnceLock::new();
    let (p, r) = OPEN.get_or_init(|| (path.to_string(), Dwarf::open(path).map(Mutex::new)));
    if p != path {
        // A second vmlinux in one process (not a path vock takes today):
        // open it independently and leak it, keeping the first cached.
        return Dwarf::open(path).map(|d| &*Box::leak(Box::new(Mutex::new(d))));
    }
    r.as_ref().map_err(|e| e.clone())
}
