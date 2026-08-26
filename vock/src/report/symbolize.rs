//! Address → source transform layer.
//!
//! Raw PCs are the machine format, but a human checking a log should see
//! kernel code, not addresses. This module writes the source-line twin of a
//! raw-PC log (`kerncov.log` → `srccov.log`, `0x<pc> <file>:<line>` per
//! line, order and duplicates preserved), and renders assembly PCs together
//! with the actual source text of their `.S` line for `asmcov.log`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Where the source-line twin of a raw-PC log lives: `kerncov.log` gets
/// `srccov.log`, any other log (e.g. a per-TID `local-<TID>.log`) gets a
/// `srccov-` prefixed sibling.
pub fn srccov_path(log: &Path) -> PathBuf {
    let name = log.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    let sym = if name == "kerncov.log" {
        "srccov.log".to_string()
    } else {
        format!("srccov-{name}")
    };
    // Always in the working directory - with -d/--output-dir that is the
    // chosen artifact directory even when the input log lives elsewhere.
    PathBuf::from(sym)
}

/// Write the source-line twin of `log`: one `0x<pc> <function> <file>:<line>`
/// per input PC, order and duplicates preserved. `seq` is the log's PC
/// sequence as read by the report (so the log is parsed once, not twice);
/// the raw log is left untouched, its addresses are per-boot (KASLR) values
/// and the machine format other tools consume; the srccov file is the
/// human-readable view.
pub fn write_srccov(log: &Path, seq: &[u64], loc_of: &HashMap<u64, String>) {
    use std::io::Write;
    let Ok(f) = std::fs::File::create(srccov_path(log)) else {
        return;
    };
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    for &pc in seq {
        let r = match loc_of.get(&pc) {
            Some(loc) => writeln!(w, "0x{pc:x} {loc}"),
            None => writeln!(w, "0x{pc:x} ??"),
        };
        if r.is_err() {
            return;
        }
    }
    let _ = w.flush();
}

/// The srccov form of one resolution: `<function> <kernel-relative file>:<line>`,
/// or `None` when the PC did not resolve (`??`).
pub fn location_string(func: &str, loc: &str, kernel_src: &str) -> Option<String> {
    if loc.is_empty() || loc.starts_with("??") {
        return None;
    }
    // Same clean kernel-relative path everywhere, KCOV-style.
    let l = match loc.rfind(':') {
        Some(colon) => format!(
            "{}:{}",
            crate::report::resolve::rel_kernel_path(&loc[..colon], kernel_src),
            &loc[colon + 1..]
        ),
        None => loc.to_string(),
    };
    Some(if func.is_empty() || func == "??" {
        l
    } else {
        format!("{func} {l}")
    })
}

/// Build the PC → location map from parallel slices of log PCs and their
/// addr2line resolutions, skipping unresolved (`??`) entries.
pub fn location_map(
    pcs: &[u64],
    resolved: &[(String, String)],
    kernel_src: &str,
) -> HashMap<u64, String> {
    let mut m = HashMap::with_capacity(pcs.len());
    for (&a, (f, l)) in pcs.iter().zip(resolved.iter()) {
        if let Some(v) = location_string(f, l, kernel_src) {
            m.insert(a, v);
        }
    }
    m
}
