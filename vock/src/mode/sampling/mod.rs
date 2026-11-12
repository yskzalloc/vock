//! Sample-based `--mode hw` backends: the PMU interrupts periodically and
//! perf records a sample (IP, timestamp, optionally a branch stack) into a
//! per-CPU ring, so coverage is statistical rather than a full trace.
//!
//!   - `amd`: AMD LBR branch stacks + IBS op (x86_64)

pub mod amd;
