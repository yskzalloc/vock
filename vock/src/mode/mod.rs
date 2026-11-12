//! Coverage modes: hardware trace (Intel PT / AMD LBR / CoreSight) and KCOV.

pub mod hw;
pub mod kcov;

// `--mode hw` backends and their shared perf_event plumbing.
mod perf;
mod sampling;
mod streaming;
