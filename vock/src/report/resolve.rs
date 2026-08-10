//! addr2line resolution + aggregation (port of report/resolve.py).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `addr2line -e vmlinux` over the addresses, returning one line each.
pub fn run_addr2line(vmlinux: &str, addrs: &[String]) -> Vec<String> {
    if addrs.is_empty() || !Path::new(vmlinux).is_file() {
        return Vec::new();
    }
    let mut child = match Command::new("addr2line")
        .arg("-e")
        .arg(vmlinux)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(addrs.join("\n").as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let t = s.trim();
            if t.is_empty() {
                Vec::new()
            } else {
                t.lines().map(|l| l.to_string()).collect()
            }
        }
        Err(_) => Vec::new(),
    }
}

const KERNEL_DIRS: &[&str] = &[
    "arch/", "fs/", "net/", "drivers/", "kernel/", "mm/", "block/", "security/",
    "crypto/", "lib/", "ipc/", "init/", "include/", "sound/", "virt/", "io_uring/",
];

/// Group `file:line` results into {relative source path → set of line numbers}.
pub fn aggregate(lines: &[String], kernel_src: &str) -> BTreeMap<String, BTreeSet<usize>> {
    let mut cov: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();

    for line in lines {
        // Match "<file>:<lineno>" (lineno may be followed by " (discriminator N)").
        let Some(colon) = line.rfind(':') else { continue };
        let (file_path, rest) = (&line[..colon], &line[colon + 1..]);
        let lineno: usize = match rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
            Some(n) => n,
            None => continue,
        };
        if file_path == "??" {
            continue;
        }

        let mut rel = relpath(file_path, kernel_src);
        if rel.starts_with("..") {
            let mut matched = false;
            for kd in KERNEL_DIRS {
                if let Some(idx) = file_path.find(&format!("/{kd}")) {
                    rel = file_path[idx + 1..].to_string();
                    matched = true;
                    break;
                }
            }
            if !matched {
                rel = match file_path.rsplit_once('/') {
                    Some((_, base)) => base.to_string(),
                    None => file_path.to_string(),
                };
            }
        }
        cov.entry(rel).or_default().insert(lineno);
    }
    cov
}

/// Best-effort equivalent of Python's os.path.relpath(file, start).
fn relpath(file: &str, start: &str) -> String {
    let f = Path::new(file);
    let s = Path::new(start);
    let fc: Vec<_> = f.components().collect();
    let sc: Vec<_> = s.components().collect();
    let mut i = 0;
    while i < fc.len() && i < sc.len() && fc[i] == sc[i] {
        i += 1;
    }
    // If nothing shared and both absolute, relpath still works; if the file is
    // outside `start`, we get leading "..".
    let ups = sc.len().saturating_sub(i);
    let mut parts: Vec<String> = std::iter::repeat("..".to_string()).take(ups).collect();
    for c in &fc[i..] {
        parts.push(c.as_os_str().to_string_lossy().into());
    }
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}
