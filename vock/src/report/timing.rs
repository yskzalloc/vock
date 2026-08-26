//! Wall-clock marks for finding where a run actually spends its time.
//!
//! `VOCK_TIMING=1` prints one stderr line per mark, `[timing] <seconds since
//! the first mark> <label>`, from every stage of a run: the collector (target
//! start/exit, per-TID merge) and every phase of the report (log parse,
//! KASLR, DWARF load, symbolization, each artifact, the terminal print).
//! `VOCK_TIMING=<path>` appends the marks to that file instead, for guests
//! whose console drops early output. The labels are stable so runs can be
//! diffed.

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

enum Sink {
    Off,
    Stderr,
    File(Mutex<std::fs::File>),
}

fn sink() -> &'static Sink {
    static S: OnceLock<Sink> = OnceLock::new();
    S.get_or_init(|| match std::env::var("VOCK_TIMING") {
        Ok(v) if v.is_empty() || v == "0" => Sink::Off,
        Ok(v) if v == "1" => Sink::Stderr,
        Ok(v) => match std::fs::OpenOptions::new().create(true).append(true).open(&v) {
            Ok(f) => Sink::File(Mutex::new(f)),
            Err(_) => Sink::Stderr,
        },
        Err(_) => Sink::Off,
    })
}

fn start() -> Instant {
    static T0: OnceLock<Instant> = OnceLock::new();
    *T0.get_or_init(Instant::now)
}

/// Emit a mark. Cheap when timing is off (one atomic load).
pub fn mark(label: &str) {
    let line = match sink() {
        Sink::Off => return,
        _ => format!("[timing] {:9.3}s {label}\n", start().elapsed().as_secs_f64()),
    };
    match sink() {
        Sink::File(f) => {
            if let Ok(mut f) = f.lock() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        _ => {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }
}

/// Force the clock to start now (call once at process start so marks are
/// relative to the run, not to the first mark).
pub fn init() {
    let _ = start();
}
