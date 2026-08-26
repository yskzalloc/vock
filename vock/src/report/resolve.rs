//! Symbolization front-end + aggregation.
//!
//! PCs are resolved in-process by default (`dwarf.rs`: the vmlinux is
//! mmap'd and its DWARF parsed lazily, no external program). Setting
//! `VOCK_ADDR2LINE=<tool>` forces an external addr2line-compatible tool
//! instead (GNU or LLVM), which is also the fallback when the vmlinux cannot
//! be read in-process (compressed debug sections). Every consumer sees the
//! same (function, file:line) pairs either way.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, Once, OnceLock};

use super::dwarf::{self, Dwarf};
use super::timing;

/// An external addr2line-compatible tool.
#[derive(Debug, Clone)]
pub enum Resolver {
    /// `llvm-addr2line` (a symlink of llvm-symbolizer in addr2line mode).
    LlvmAddr2line(PathBuf),
    /// `llvm-symbolizer`, driven with the flags that make it print GNU style.
    LlvmSymbolizer(PathBuf),
    /// GNU binutils `addr2line`.
    Gnu(PathBuf),
}

impl Resolver {
    fn command(&self, vmlinux: &str) -> Command {
        let mut c = match self {
            Resolver::LlvmAddr2line(p) | Resolver::Gnu(p) => Command::new(p),
            Resolver::LlvmSymbolizer(p) => {
                let mut c = Command::new(p);
                c.arg("--output-style=GNU").arg("--no-inlines");
                c
            }
        };
        c.arg("-f").arg("-C").arg("-e").arg(vmlinux);
        c
    }

    /// Short name for progress output.
    pub fn name(&self) -> String {
        match self {
            Resolver::LlvmAddr2line(p) | Resolver::LlvmSymbolizer(p) | Resolver::Gnu(p) => p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }

    fn is_gnu(&self) -> bool {
        matches!(self, Resolver::Gnu(_))
    }
}

/// Classify a symbolizer binary by its file name.
fn classify(path: PathBuf) -> Resolver {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.starts_with("llvm-symbolizer") {
        Resolver::LlvmSymbolizer(path)
    } else if name.starts_with("llvm-addr2line") {
        Resolver::LlvmAddr2line(path)
    } else {
        Resolver::Gnu(path)
    }
}

/// Find `<stem>` or the highest-numbered `<stem>-N` on PATH. Distributions
/// ship versioned LLVM binaries (`llvm-addr2line-19`) and the unversioned
/// name only through a metapackage, so both spellings are looked for.
fn find_on_path(stem: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let mut best: Option<(u32, PathBuf)> = None;
    for dir in std::env::split_paths(&path) {
        let exact = dir.join(stem);
        if exact.is_file() {
            // The unversioned name is the distribution's chosen default.
            return Some(exact);
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let Some(rest) = name.strip_prefix(stem) else { continue };
            let Some(ver) = rest.strip_prefix('-') else { continue };
            let Ok(v) = ver.parse::<u32>() else { continue };
            if best.as_ref().is_none_or(|(bv, _)| v > *bv) {
                best = Some((v, ent.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// `$VOCK_ADDR2LINE`, when set: the user wants an external tool.
fn forced_external() -> Option<Resolver> {
    let v = std::env::var_os("VOCK_ADDR2LINE")?;
    if v.is_empty() {
        return None;
    }
    Some(classify(PathBuf::from(v)))
}

/// The external tool used when in-process resolution is unavailable: the
/// first of llvm-addr2line, llvm-symbolizer, addr2line found on PATH.
fn external_tool() -> &'static Resolver {
    static S: OnceLock<Resolver> = OnceLock::new();
    S.get_or_init(|| {
        if let Some(r) = forced_external() {
            return r;
        }
        if let Some(p) = find_on_path("llvm-addr2line") {
            return Resolver::LlvmAddr2line(p);
        }
        if let Some(p) = find_on_path("llvm-symbolizer") {
            return Resolver::LlvmSymbolizer(p);
        }
        Resolver::Gnu(PathBuf::from("addr2line"))
    })
}

/// How PCs get resolved against `vmlinux` in this process.
pub enum Backend {
    InProcess(&'static Mutex<Dwarf>),
    External(&'static Resolver),
}

pub fn backend(vmlinux: &str) -> Backend {
    if forced_external().is_some() {
        return Backend::External(external_tool());
    }
    match dwarf::get(vmlinux) {
        Ok(d) => Backend::InProcess(d),
        Err(e) => {
            static WARN: Once = Once::new();
            WARN.call_once(|| {
                eprintln!(
                    "report: in-process symbolization unavailable ({e}); using {}",
                    external_tool().name()
                );
            });
            Backend::External(external_tool())
        }
    }
}

/// Name of the resolver for progress output.
pub fn backend_name(vmlinux: &str) -> String {
    match backend(vmlinux) {
        Backend::InProcess(_) => String::from("in-process DWARF"),
        Backend::External(r) => r.name(),
    }
}

/// Open the DWARF for `vmlinux` on a background thread so it is ready by
/// the time the report needs it (the load is mostly I/O: a 1.3 GB vmlinux
/// over a VM guest's shared filesystem). Nothing here is traced: the parent
/// never enables local KCOV, and remote handles only collect from kernel
/// code that explicitly annotates itself with them.
pub fn prewarm(vmlinux: &str) {
    if forced_external().is_some() || !Path::new(vmlinux).is_file() {
        return;
    }
    let v = vmlinux.to_string();
    std::thread::Builder::new()
        .name("vock-dwarf-prewarm".into())
        .spawn(move || {
            timing::mark("prewarm: start");
            if let Ok(m) = dwarf::get(&v) {
                // The index is ready; the report can use it now. Keep
                // fetching the tables it will read scattered pieces of.
                let (tables, threads) = {
                    let d = m.lock().unwrap_or_else(|e| e.into_inner());
                    (d.tables(), d.threads())
                };
                timing::mark("prewarm: index ready");
                crate::dwarf::populate_parallel(&tables, threads);
            }
            timing::mark("prewarm: done");
        })
        .ok();
}

/// Resolve `pcs` to (function, file:line) pairs, one per input, in order.
/// Unresolved entries come back as ("??", "??:0"), the addr2line convention.
pub fn symbolize(vmlinux: &str, pcs: &[u64]) -> Vec<(String, String)> {
    if pcs.is_empty() || !Path::new(vmlinux).is_file() {
        return Vec::new();
    }
    match backend(vmlinux) {
        Backend::InProcess(d) => {
            let d = d.lock().unwrap_or_else(|e| e.into_inner());
            timing::mark("symbolize: dwarf ready");
            if pcs.len() > 16 {
                d.prefault_units(pcs);
            }
            let out: Vec<(String, String)> = pcs.iter().map(|&pc| d.resolve(pc)).collect();
            timing::mark(&format!("symbolize: {} resolved", pcs.len()));
            out
        }
        Backend::External(r) => {
            let addrs: Vec<String> = pcs.iter().map(|pc| format!("0x{pc:x}")).collect();
            let out = symbolize_external(r, vmlinux, &addrs);
            timing::mark("symbolize: resolved (external)");
            out
        }
    }
}

/// Location-only probe (`file:line` per PC), what KASLR detection needs.
pub fn probe_locations(vmlinux: &str, pcs: &[u64]) -> Vec<String> {
    symbolize(vmlinux, pcs).into_iter().map(|(_, l)| l).collect()
}

/// Address of a text symbol in the vmlinux (`_stext`, `_text`).
pub fn symbol_address(vmlinux: &str, name: &str) -> Option<u64> {
    if let Backend::InProcess(d) = backend(vmlinux) {
        return d.lock().unwrap_or_else(|e| e.into_inner()).symbol_address(name);
    }
    let nm = Command::new("nm").arg(vmlinux).output().ok()?;
    let s = String::from_utf8_lossy(&nm.stdout);
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(addr), Some(t), Some(n)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if n == name && t.eq_ignore_ascii_case("t") {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

/// GNU addr2line caches every DWARF compilation unit it touches; resolving a
/// whole run against a DWARF5 vmlinux peaks around 1 GiB RSS, and inside a
/// small VM the OOM killer takes it mid-run, silently dropping the tail of
/// the coverage. It is therefore fed in chunks, one process per chunk. The
/// input is sorted, so consecutive addresses cluster by CU and the re-parse
/// per chunk costs little. The LLVM symbolizer is lazy per CU and gets the
/// whole input in one process.
const GNU_ADDR2LINE_CHUNK: usize = 2048;

fn symbolize_external(sym: &Resolver, vmlinux: &str, addrs: &[String]) -> Vec<(String, String)> {
    let mut lines = Vec::with_capacity(addrs.len());
    if sym.is_gnu() {
        for chunk in addrs.chunks(GNU_ADDR2LINE_CHUNK) {
            lines.extend(symbolize_batch(sym, vmlinux, chunk));
        }
    } else {
        lines = symbolize_batch(sym, vmlinux, addrs);
    }
    lines
}

/// Pad a batch's output to one pair per input address. A symbolizer that
/// dies mid-run (OOM-killed in a small guest, an I/O error on a 9p-mounted
/// vmlinux) leaves a short list; consumers zip results with addresses, so a
/// short list used to shift every later resolution onto the wrong PC and
/// drop the tail without a word.
fn pad_batch(mut v: Vec<(String, String)>, sym: &Resolver, want: usize) -> Vec<(String, String)> {
    if v.len() < want {
        eprintln!(
            "report: {} resolved {} of {} addresses; the rest are reported as ??",
            sym.name(),
            v.len(),
            want
        );
        v.resize(want, (String::from("??"), String::from("??:0")));
    }
    v.truncate(want);
    v
}

fn symbolize_batch(sym: &Resolver, vmlinux: &str, addrs: &[String]) -> Vec<(String, String)> {
    let mut child = match sym
        .command(vmlinux)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return pad_batch(Vec::new(), sym, addrs.len()),
    };
    // Feed stdin from a separate thread while the main thread drains stdout:
    // writing everything first deadlocks once the symbolizer has produced a
    // pipe buffer's worth of output (~64K) and blocks, no longer reading
    // stdin, any log beyond a few thousand PCs would hang forever.
    let mut stdin = child.stdin.take();
    let mut input = addrs.join("\n");
    input.push('\n');
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(input.as_bytes());
        }
        // stdin drops here → EOF for the symbolizer
    });
    let out = child.wait_with_output();
    let _ = writer.join();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut v = Vec::with_capacity(addrs.len());
            let mut it = s.lines();
            // -f output alternates: function name line, then file:line.
            while let (Some(func), Some(loc)) = (it.next(), it.next()) {
                v.push((canonical_function(func).to_string(), loc.to_string()));
            }
            pad_batch(v, sym, addrs.len())
        }
        Err(_) => pad_batch(Vec::new(), sym, addrs.len()),
    }
}

/// Symbol-table names carry compiler clone suffixes (`foo.constprop.0`,
/// `bar.isra.0`) that DWARF names do not. Report the DWARF form everywhere
/// so artifacts read the same regardless of which path produced them.
pub(crate) fn canonical_function(func: &str) -> &str {
    const CLONE_SUFFIXES: &[&str] = &[
        ".constprop", ".isra", ".part", ".cold", ".lto_priv", ".llvm", ".sra",
    ];
    let mut end = func.len();
    for s in CLONE_SUFFIXES {
        if let Some(i) = func.find(s) {
            end = end.min(i);
        }
    }
    &func[..end]
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
        // "??" is unresolved; line 0 is the DWARF convention for code with
        // no source line (compiler-generated), which addr2line prints as
        // "?" and which has no excerpt to show.
        if file_path == "??" || lineno == 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_suffixes_are_stripped() {
        assert_eq!(canonical_function("foo.constprop.0"), "foo");
        assert_eq!(canonical_function("bar.isra.0.cold"), "bar");
        assert_eq!(canonical_function("baz"), "baz");
        assert_eq!(canonical_function("??"), "??");
        // Rust paths carry no clone suffix and must pass through intact.
        assert_eq!(
            canonical_function("<kernel::sync::Arc<T> as core::ops::Drop>::drop"),
            "<kernel::sync::Arc<T> as core::ops::Drop>::drop"
        );
    }

    #[test]
    fn classify_by_name() {
        assert!(matches!(
            classify(PathBuf::from("/usr/bin/llvm-addr2line-19")),
            Resolver::LlvmAddr2line(_)
        ));
        assert!(matches!(
            classify(PathBuf::from("llvm-symbolizer")),
            Resolver::LlvmSymbolizer(_)
        ));
        assert!(matches!(classify(PathBuf::from("addr2line")), Resolver::Gnu(_)));
    }
}
