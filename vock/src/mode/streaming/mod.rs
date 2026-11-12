//! Instruction-trace ("streaming") `--mode hw` backends: the CPU writes a
//! continuous packet stream into a per-CPU perf AUX area, which is decoded
//! into kernel PCs after the run.
//!
//!   - `intel`: Intel PT (x86_64)
//!   - `arm`:   Arm CoreSight ETM/ETE (aarch64), TODO
//!
//! Shared here: raw-trace file handling and the timestamp merge of the
//! per-CPU decoded streams into one chronological kerncov.log.

pub mod arm;
pub mod intel;

use std::io::Write;

/// One decoded per-CPU stream: `out` holds "0x<pc>\n" lines, `segs` the
/// (timestamp, byte offset into `out`) of every timestamp packet seen.
#[derive(Default)]
pub(crate) struct Stream {
    pub(crate) out: String,
    pub(crate) segs: Vec<(u64, usize)>,
    pub(crate) pcs: i32,
}

/// Merge per-CPU decoded streams into one chronological log. Each stream is
/// cut at its timestamp packets and the pieces are ordered by timestamp. The
/// sort is stable and timestamps are monotonic within a stream, so each
/// stream keeps its own order; streams without any timestamp are
/// concatenated in CPU order. Output before a stream's first timestamp takes
/// that timestamp.
pub(crate) fn merge_streams(streams: &[Stream]) -> String {
    let mut pieces: Vec<(u64, &str)> = Vec::new();
    for s in streams {
        let mut tsc = s.segs.first().map_or(0, |seg| seg.0);
        let mut start = 0usize;
        for &(t, off) in &s.segs {
            if off > start {
                pieces.push((tsc, &s.out[start..off]));
                start = off;
            }
            tsc = t;
        }
        if s.out.len() > start {
            pieces.push((tsc, &s.out[start..]));
        }
    }
    pieces.sort_by_key(|p| p.0);
    let mut out = String::with_capacity(streams.iter().map(|s| s.out.len()).sum());
    for (_, p) in pieces {
        out.push_str(p);
    }
    out
}

/// Remove raw traces of a previous run so stale CPUs don't linger.
pub(crate) fn clear_raw_traces() {
    if let Ok(rd) = std::fs::read_dir(".") {
        for e in rd.flatten() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n == "hw_trace.bin" || (n.starts_with("hw_trace.cpu") && n.ends_with(".bin")) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Save one CPU's raw AUX stream (streams cannot be concatenated, so one
/// file each: hw_trace.cpu<N>.bin, or hw_trace.bin for the single-task
/// fallback).
pub(crate) fn save_raw_trace(cpu: i32, data: &[u8]) {
    let name = if cpu < 0 {
        "hw_trace.bin".to_string()
    } else {
        format!("hw_trace.cpu{cpu}.bin")
    };
    let _ = std::fs::write(name, data);
}

/// Write the merged log to kerncov.log.
pub(crate) fn write_kerncov(out: &str) -> bool {
    match std::fs::File::create("kerncov.log") {
        Ok(mut f) => f.write_all(out.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(out: &str, segs: &[(u64, usize)]) -> Stream {
        Stream { out: out.to_string(), segs: segs.to_vec(), pcs: 0 }
    }

    #[test]
    fn streams_interleave_by_timestamp_and_keep_their_own_order() {
        // cpu0: a@10 b@30, cpu1: x@20 y@40
        let a = stream("a\nb\n", &[(10, 0), (30, 2)]);
        let b = stream("x\ny\n", &[(20, 0), (40, 2)]);
        assert_eq!(merge_streams(&[a, b]), "a\nx\nb\ny\n");
    }

    #[test]
    fn output_before_the_first_timestamp_takes_it() {
        let a = stream("p\nq\n", &[(50, 2)]);
        let b = stream("x\n", &[(40, 0)]);
        assert_eq!(merge_streams(&[a, b]), "x\np\nq\n");
    }

    #[test]
    fn untimed_streams_concatenate_in_cpu_order() {
        let a = stream("a\n", &[]);
        let b = stream("b\n", &[]);
        assert_eq!(merge_streams(&[a, b]), "a\nb\n");
    }
}
