//! addr2line resolution + aggregation (port of report/resolve.py).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `addr2line -e vmlinux` over the addresses, returning one line each.
///
/// The addresses are fed in chunks, one addr2line process per chunk:
/// addr2line caches every DWARF compilation unit it touches and resolving a
/// whole run against a DWARF5 vmlinux peaks around 1 GiB RSS — inside a small
/// VM the OOM killer takes it mid-run and the tail of the coverage silently
/// disappears. The input is sorted, so consecutive addresses cluster by CU
/// and the per-chunk re-parsing costs little.
const ADDR2LINE_CHUNK: usize = 2048;

/// Resolutions come back as (function, file:line) pairs — `-f` makes
/// addr2line emit the function name on its own line before each location,
/// so every consumer (report hunks, srccov, asmcov, the ordered table) can
/// show kernel-patch-style function context.
pub fn run_addr2line(vmlinux: &str, addrs: &[String]) -> Vec<(String, String)> {
    if addrs.is_empty() || !Path::new(vmlinux).is_file() {
        return Vec::new();
    }
    let mut lines = Vec::with_capacity(addrs.len());
    for chunk in addrs.chunks(ADDR2LINE_CHUNK) {
        lines.extend(addr2line_batch(vmlinux, chunk));
    }
    lines
}

fn addr2line_batch(vmlinux: &str, addrs: &[String]) -> Vec<(String, String)> {
    let mut child = match Command::new("addr2line")
        .arg("-f")
        .arg("-C")
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
    // Feed stdin from a separate thread while the main thread drains stdout:
    // writing everything first deadlocks once addr2line has produced a pipe
    // buffer's worth of output (~64K) and blocks, no longer reading stdin —
    // any log beyond a few thousand PCs would hang forever.
    let mut stdin = child.stdin.take();
    let input = addrs.join("\n");
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(input.as_bytes());
        }
        // stdin drops here → EOF for addr2line
    });
    let out = child.wait_with_output();
    let _ = writer.join();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut v = Vec::new();
            let mut it = s.lines();
            // -f output alternates: function name line, then file:line.
            while let (Some(func), Some(loc)) = (it.next(), it.next()) {
                v.push((func.to_string(), loc.to_string()));
            }
            v
        }
        Err(_) => Vec::new(),
    }
}

pub(crate) const KERNEL_DIRS: &[&str] = &[
    "arch/", "fs/", "net/", "drivers/", "kernel/", "mm/", "block/", "security/",
    "crypto/", "lib/", "ipc/", "init/", "include/", "sound/", "virt/", "io_uring/",
];

/// Group (function, file:line) results into {relative source path → set of
/// line numbers} plus {relative source path → {line → function}} so the
/// renderers can show kernel-patch-style function context per hunk.
#[allow(clippy::type_complexity)]
pub fn aggregate(
    lines: &[(String, String)],
    kernel_src: &str,
) -> (
    BTreeMap<String, BTreeSet<usize>>,
    BTreeMap<String, BTreeMap<usize, String>>,
) {
    let mut cov: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut funcs: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();

    for (func, line) in lines {
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

        let rel = rel_kernel_path(file_path, kernel_src);
        cov.entry(rel.clone()).or_default().insert(lineno);
        if func != "??" && !func.is_empty() {
            funcs.entry(rel).or_default().insert(lineno, func.clone());
        }
    }
    (cov, funcs)
}

/// Normalize a DWARF build path onto the kernel tree: relative to
/// `kernel_src` when possible, else re-rooted at the first recognizable
/// kernel directory ("debian/build/.../fs/open.c" becomes "fs/open.c"),
/// else the bare file name. This is what makes hw-mode output read like
/// KCOV's: every consumer shows the same clean kernel-relative paths.
pub(crate) fn rel_kernel_path(file_path: &str, kernel_src: &str) -> String {
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
    rel
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
