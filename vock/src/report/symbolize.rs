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
/// line, order and duplicates preserved. The raw log is left untouched — its
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

/// Source-file cache for pulling individual lines of kernel code, so that an
/// assembly PC can be shown with the instruction text it resolves to.
pub struct SourceCache {
    kernel_src: PathBuf,
    files: HashMap<String, Option<Vec<String>>>,
}

impl SourceCache {
    pub fn new(kernel_src: &str) -> Self {
        SourceCache {
            kernel_src: PathBuf::from(kernel_src),
            files: HashMap::new(),
        }
    }

    /// The text of `file:lineno` (1-based), if the file can be found either
    /// at its recorded path or re-rooted under the kernel source tree.
    pub fn line(&mut self, file: &str, lineno: usize) -> Option<String> {
        if !self.files.contains_key(file) {
            let content = self.load(file);
            self.files.insert(file.to_string(), content);
        }
        let lines = self.files.get(file)?.as_ref()?;
        lines.get(lineno.checked_sub(1)?).map(|s| s.trim().to_string())
    }

    fn load(&self, file: &str) -> Option<Vec<String>> {
        // As recorded (absolute build path), then re-rooted at kernel_src by
        // the first recognizable kernel directory component.
        let mut candidates: Vec<PathBuf> = vec![PathBuf::from(file)];
        for kd in crate::report::resolve::KERNEL_DIRS {
            if let Some(idx) = file.find(&format!("/{kd}")) {
                candidates.push(self.kernel_src.join(&file[idx + 1..]));
                break;
            }
        }
        if !file.starts_with('/') {
            candidates.push(self.kernel_src.join(file));
        }
        for c in candidates {
            if let Ok(s) = std::fs::read_to_string(&c) {
                return Some(s.lines().map(|l| l.to_string()).collect());
            }
        }
        None
    }
}

/// Split a `file:line[ (discriminator ..)]` location into its parts.
pub fn split_location(loc: &str) -> Option<(&str, usize)> {
    let colon = loc.rfind(':')?;
    let (file, rest) = (&loc[..colon], &loc[colon + 1..]);
    let lineno: usize = rest.split_whitespace().next()?.parse().ok()?;
    Some((file, lineno))
}
