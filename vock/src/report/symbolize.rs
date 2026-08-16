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

/// Write the source-line twin of `log`: one `0x<pc> <file>:<line>` per input
/// line, order and duplicates preserved. The raw log is left untouched, its
/// addresses are per-boot (KASLR) values and the machine format other tools
/// consume; the srccov file is the human-readable view.
pub fn write_srccov(log: &Path, loc_of: &HashMap<String, String>) {
    let Ok(data) = std::fs::read_to_string(log) else {
        return;
    };
    let mut out = String::with_capacity(data.len() * 2);
    for line in data.lines() {
        let addr = match line.split_whitespace().next() {
            Some(a) if !a.is_empty() => a,
            _ => continue,
        };
        let key = if addr.starts_with("0x") {
            addr.to_string()
        } else {
            format!("0x{addr}")
        };
        match loc_of.get(&key) {
            Some(loc) => out.push_str(&format!("{key} {loc}\n")),
            None => out.push_str(&format!("{key} ??\n")),
        }
    }
    let _ = std::fs::write(srccov_path(log), out);
}

/// Build the address → location map from parallel slices of file addresses
/// and their addr2line resolutions, skipping unresolved (`??`) entries.
pub fn location_map(
    file_addrs: &[String],
    resolved: &[(String, String)],
    kernel_src: &str,
) -> HashMap<String, String> {
    let mut m = HashMap::with_capacity(file_addrs.len());
    for (a, (f, l)) in file_addrs.iter().zip(resolved.iter()) {
        if !l.is_empty() && !l.starts_with("??") {
            // Same clean kernel-relative path everywhere, KCOV-style.
            let loc = match l.rfind(':') {
                Some(colon) => format!(
                    "{}:{}",
                    crate::report::resolve::rel_kernel_path(&l[..colon], kernel_src),
                    &l[colon + 1..]
                ),
                None => l.clone(),
            };
            let v = if f.is_empty() || f == "??" {
                loc
            } else {
                format!("{f} {loc}")
            };
            m.insert(a.clone(), v);
        }
    }
    m
}
