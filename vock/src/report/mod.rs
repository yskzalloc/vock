//! Coverage report generator (in-process port of output.py + report/*.py).
//!
//! Reads a coverage log of kernel PCs and renders `coverage.html` (source
//! annotated via addr2line) plus a terminal summary. Also implements `--btf`
//! (resolve via /proc/kallsyms, no vmlinux) and `--ordered` execution traces.

mod btf;
mod dwarf;
pub(crate) mod timing;
pub(crate) mod symbolize;
mod html;
mod kaslr;
pub(crate) mod resolve;
mod terminal;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Report options, mirroring output.py's argparse surface. `None` fields fall
/// back to auto-detected defaults exactly as the Python did.
pub struct Options {
    pub kernel_src: Option<String>,
    pub vmlinux: Option<String>,
    pub log: String,
    pub filter: Option<String>,
    pub quiet: bool,
    pub ctx_after: i32,
    pub ctx_before: i32,
    pub output: String,
    pub btf: bool,
    pub ordered: bool,
    /// Raw logs to read instead of `log`, in order (the per-TID logs of a
    /// kcov run). With this set nothing is merged up front: the report
    /// streams straight from them and `log` receives only the processed
    /// excerpt report at the end.
    pub parts: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            kernel_src: None,
            vmlinux: None,
            log: "kerncov.log".to_string(),
            filter: None,
            quiet: false,
            ctx_after: 3,
            ctx_before: 3,
            output: "coverage.html".to_string(),
            btf: false,
            ordered: false,
            parts: Vec::new(),
        }
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// (default_kernel_src, default_vmlinux), matching output.py's auto-detect.
fn defaults() -> (String, String) {
    let h = home();
    let mut ks = h.join("stable");
    let mut vm = h.join("stable").join("vmlinux");
    for p in [h.join("linux"), h.join("stable"), h.join("net")] {
        if p.join("vmlinux").is_file() {
            ks = p.clone();
            vm = p.join("vmlinux");
            break;
        }
    }
    (ks.to_string_lossy().into(), vm.to_string_lossy().into())
}

/// Every PC in `data`, in order, duplicates kept. The first token of each
/// line is the address, so an annotated log ("0x<pc> file:line", the srccov
/// twin) stays valid input alongside a raw one; tokens that are not hex are
/// skipped.
fn parse_pcs(data: &[u8], out: &mut Vec<u64>) {
    for line in data.split(|&b| b == b'\n') {
        let mut tok = line;
        while let Some((&c, rest)) = tok.split_first() {
            if c == b' ' || c == b'\t' || c == b'\r' {
                tok = rest;
            } else {
                break;
            }
        }
        let end = tok
            .iter()
            .position(|&c| c == b' ' || c == b'\t' || c == b'\r')
            .unwrap_or(tok.len());
        let tok = &tok[..end];
        if tok.is_empty() {
            continue;
        }
        let hex = tok.strip_prefix(b"0x").or_else(|| tok.strip_prefix(b"0X")).unwrap_or(tok);
        if let Some(pc) = parse_hex_bytes(hex) {
            out.push(pc);
        }
    }
}

/// The logs a report reads: `parts` when given, else `log` itself.
fn input_parts(opts: &Options) -> Vec<PathBuf> {
    if opts.parts.is_empty() {
        vec![PathBuf::from(&opts.log)]
    } else {
        opts.parts.iter().map(PathBuf::from).collect()
    }
}

/// Every PC of every input, in file order, duplicates kept.
fn read_all_pcs(parts: &[PathBuf]) -> Vec<u64> {
    let mut v = Vec::new();
    for p in parts {
        if let Ok(data) = std::fs::read(p) {
            v.reserve(data.len() / 19 + 1);
            parse_pcs(&data, &mut v);
        }
    }
    v
}

/// Block size the reader thread hands to the parser: large enough that a
/// shared-filesystem read runs at full throughput, small enough that
/// symbolization and the srccov writer start long before the log is fully
/// read.
const READ_BLOCK: usize = 4 << 20;

/// Read the inputs on a thread, delivering line-aligned blocks in order.
fn spawn_reader(parts: Vec<PathBuf>) -> std::sync::mpsc::Receiver<Vec<u8>> {
    use std::io::Read;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2);
    std::thread::Builder::new()
        .name("vock-log-reader".into())
        .spawn(move || {
            let mut carry: Vec<u8> = Vec::new();
            for p in parts {
                let Ok(mut f) = std::fs::File::open(&p) else { continue };
                loop {
                    let mut block = Vec::with_capacity(READ_BLOCK + carry.len());
                    block.append(&mut carry);
                    let start = block.len();
                    block.resize(start + READ_BLOCK, 0);
                    let n = match f.read(&mut block[start..]) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    };
                    block.truncate(start + n);
                    // Hand over whole lines only; the tail waits for more.
                    match block.iter().rposition(|&b| b == b'\n') {
                        Some(nl) => {
                            carry.extend_from_slice(&block[nl + 1..]);
                            block.truncate(nl + 1);
                        }
                        None => {
                            carry.append(&mut block);
                            continue;
                        }
                    }
                    if tx.send(block).is_err() {
                        return;
                    }
                }
                // A log cut mid-line (a task killed inside its exit writer)
                // must not glue onto the next file's first PC.
                if !carry.is_empty() {
                    carry.push(b'\n');
                    let tail = std::mem::take(&mut carry);
                    if tx.send(tail).is_err() {
                        return;
                    }
                }
            }
        })
        .ok();
    rx
}

/// Write blocks to `path` on a thread, so the srccov twin (one line per
/// collected PC, 100+ MB for a million-PC run) streams out while the
/// report goes on parsing and symbolizing.
fn spawn_block_writer(
    path: PathBuf,
) -> (
    std::sync::mpsc::SyncSender<Vec<u8>>,
    std::thread::JoinHandle<()>,
) {
    use std::io::Write;
    // Deep enough (32 MB in flight) that a slow shared-filesystem write
    // drains behind the loop instead of throttling symbolization.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(32);
    let h = std::thread::Builder::new()
        .name("vock-srccov-writer".into())
        .spawn(move || {
            let Ok(f) = std::fs::File::create(&path) else {
                for _ in rx {}
                return;
            };
            let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
            for block in rx {
                if w.write_all(&block).is_err() {
                    break;
                }
            }
            let _ = w.flush();
            timing::mark("writer: srccov written");
        })
        .expect("spawn srccov writer");
    (tx, h)
}

fn parse_hex_bytes(hex: &[u8]) -> Option<u64> {
    if hex.is_empty() || hex.len() > 16 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in hex {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | d as u64;
    }
    Some(v)
}

/// Sorted, deduplicated copy of a PC sequence.
fn unique_sorted(seq: &[u64]) -> Vec<u64> {
    let mut u = seq.to_vec();
    u.sort_unstable();
    u.dedup();
    u
}

fn hex_strings(pcs: &[u64]) -> Vec<String> {
    pcs.iter().map(|pc| format!("0x{pc:x}")).collect()
}

/// Read every source file the report will show, once, from a few threads:
/// the HTML, the text artifact and the terminal view render the same hunks,
/// and each file is a round trip over a VM guest's shared filesystem.
pub(crate) fn load_sources(
    cov: &std::collections::BTreeMap<String, BTreeSet<usize>>,
    kernel_src: &str,
    filter_kw: Option<&str>,
) -> HashMap<String, String> {
    let root = Path::new(kernel_src);
    let files: Vec<&String> = cov
        .keys()
        .filter(|f| filter_kw.is_none_or(|kw| f.contains(kw)))
        .collect();
    let mut m = HashMap::with_capacity(files.len());
    if files.is_empty() {
        return m;
    }
    let n = 8usize.min(files.len());
    let per = files.len().div_ceil(n);
    std::thread::scope(|s| {
        let handles: Vec<_> = files
            .chunks(per)
            .map(|chunk| {
                s.spawn(move || {
                    let mut v = Vec::with_capacity(chunk.len());
                    for f in chunk {
                        if let Ok(c) = std::fs::read_to_string(root.join(f)) {
                            v.push(((*f).clone(), c));
                        }
                    }
                    v
                })
            })
            .collect();
        for h in handles {
            if let Ok(v) = h.join() {
                m.extend(v);
            }
        }
    });
    m
}

/// One line of progress per report phase, with its cost. The report used
/// to go silent for the whole symbolization, which on a slow path (GNU
/// addr2line, a 9p-mounted vmlinux) reads as a hang.
struct Progress {
    quiet: bool,
    t: Instant,
}

impl Progress {
    fn new(quiet: bool) -> Self {
        Progress { quiet, t: Instant::now() }
    }

    /// Report the phase that just finished and start timing the next one.
    fn done(&mut self, what: &str) {
        if !self.quiet {
            println!("  {what} ({:.1}s)", self.t.elapsed().as_secs_f64());
        }
        self.t = Instant::now();
    }
}

/// The vmlinux the report will use for (`kernel_src`, `vmlinux`) options,
/// with the same auto-detection as `run`; the collector uses it to pre-warm
/// the DWARF while the target runs.
pub fn vmlinux_path(kernel_src: Option<&str>, vmlinux: Option<&str>) -> String {
    let (def_ks, def_vm) = defaults();
    match (kernel_src, vmlinux) {
        (_, Some(v)) => v.to_string(),
        (Some(ks), None) => Path::new(ks).join("vmlinux").to_string_lossy().into_owned(),
        (None, None) => {
            let _ = def_ks;
            def_vm
        }
    }
}

/// Entry point: equivalent to `python3 output.py <opts>`.
pub fn run(opts: &Options) -> i32 {
    timing::mark("report: start");
    let (def_ks, _) = defaults();
    let kernel_src = opts.kernel_src.clone().unwrap_or_else(|| def_ks.clone());
    let vmlinux = vmlinux_path(opts.kernel_src.as_deref(), opts.vmlinux.as_deref());

    // DWARF paths are absolute; a relative --kernel-src ("." is the usual
    // spelling) cannot be stripped from them and every include/ path got
    // re-rooted at the wrong kernel directory ("include/net/9p/client.h"
    // became "net/9p/client.h").
    let kernel_src = std::fs::canonicalize(&kernel_src)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(kernel_src);

    if !opts.quiet {
        println!("{}", center(" VOCK Coverage Reporter ", 80, '='));
    }

    let log = Path::new(&opts.log);
    let parts = input_parts(opts);

    if opts.ordered {
        return run_ordered(opts, &parts, &kernel_src, &vmlinux);
    }
    if opts.btf {
        if let Some(rc) = run_btf(opts, &parts, &kernel_src, &vmlinux) {
            return rc;
        }
        // kallsyms unusable: fall through to the vmlinux pipeline.
    }
    if !Path::new(&vmlinux).is_file() {
        // No symbols to resolve against: keep the raw PCs as the artifact
        // (merged, when the input was per-TID parts) instead of nothing.
        let seq = read_all_pcs(&parts);
        if seq.is_empty() {
            if !opts.quiet {
                println!("\x1b[93mno coverage data found\x1b[0m");
            }
            return 0;
        }
        if !opts.parts.is_empty() {
            use std::io::Write;
            if let Ok(f) = std::fs::File::create(log) {
                let mut w = std::io::BufWriter::new(f);
                for pc in &seq {
                    let _ = writeln!(w, "0x{pc:x}");
                }
            }
        }
        if !opts.quiet {
            println!(
                "\x1b[93m{} PCs in {}; no vmlinux at {vmlinux}, no source report\x1b[0m",
                seq.len(),
                opts.log
            );
        }
        return 0;
    }
    run_streaming(opts, parts, &kernel_src, &vmlinux)
}

/// The report proper: PCs stream from the reader thread, each new unique
/// PC is symbolized as it first appears, and the srccov twin streams out
/// through the writer thread, all three overlapping. Only the excerpt
/// rendering needs the complete set and runs at the end.
fn run_streaming(opts: &Options, parts: Vec<PathBuf>, kernel_src: &str, vmlinux: &str) -> i32 {
    use std::io::Write;
    let log = Path::new(&opts.log);
    let mut p = Progress::new(opts.quiet);
    let rx = spawn_reader(parts);
    let (stx, srccov_writer) = spawn_block_writer(symbolize::srccov_path(log));

    let mut seen: HashMap<u64, u32> = HashMap::new();
    let mut uniq: Vec<u64> = Vec::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut locs: Vec<Option<String>> = Vec::new();
    let mut pcs: Vec<u64> = Vec::new();
    let mut fresh: Vec<u64> = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(1 << 20);
    let mut offset: Option<u64> = None;
    let mut total = 0usize;
    let mut announced = false;

    for block in rx {
        pcs.clear();
        parse_pcs(&block, &mut pcs);
        drop(block);
        if pcs.is_empty() {
            continue;
        }
        if total == 0 {
            timing::mark("report: first block parsed");
        }
        if !announced && !opts.quiet {
            announced = true;
            println!("\n\x1b[93m📊 [VOCK] Generating coverage report...\x1b[0m\n");
        }
        let off = *offset.get_or_insert_with(|| {
            // KASLR from the first PCs seen; the exact kallsyms method
            // does not depend on the sample, the heuristic only needs a
            // handful of code addresses.
            let mut sample: Vec<u64> = pcs.iter().copied().take(256).collect();
            sample.sort_unstable();
            sample.dedup();
            let o = kaslr::detect_offset(vmlinux, &sample);
            timing::mark("report: kaslr");
            if o != 0 && !opts.quiet {
                println!("  KASLR detected: offset 0x{o:x}");
            }
            o
        });

        fresh.clear();
        for &pc in &pcs {
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(pc) {
                e.insert(uniq.len() as u32);
                uniq.push(pc);
                fresh.push(pc);
            }
        }
        if !fresh.is_empty() {
            let dek: Vec<u64> = fresh.iter().map(|a| a.wrapping_sub(off)).collect();
            for (f, l) in resolve::symbolize(vmlinux, &dek) {
                locs.push(symbolize::location_string(&f, &l, kernel_src));
                pairs.push((f, l));
            }
            // A resolver that returned short (external tool died) must not
            // desynchronize the index; pad like resolve does.
            while pairs.len() < uniq.len() {
                pairs.push((String::from("??"), String::from("??:0")));
                locs.push(None);
            }
        }

        for &pc in &pcs {
            total += 1;
            match &locs[seen[&pc] as usize] {
                Some(l) => {
                    let _ = writeln!(out, "0x{pc:x} {l}");
                }
                None => {
                    let _ = writeln!(out, "0x{pc:x} ??");
                }
            }
            if out.len() >= 1 << 20 {
                let full = std::mem::replace(&mut out, Vec::with_capacity(1 << 20));
                if stx.send(full).is_err() {
                    break;
                }
            }
        }
    }
    if !out.is_empty() {
        let _ = stx.send(out);
    }
    drop(stx);
    timing::mark(&format!(
        "report: {} PCs streamed, {} unique symbolized",
        total,
        uniq.len()
    ));

    if total == 0 {
        let _ = srccov_writer.join();
        let _ = std::fs::remove_file(symbolize::srccov_path(log));
        if !opts.quiet {
            println!("\x1b[93mno coverage data found\x1b[0m");
        }
        return 0;
    }
    p.done(&format!(
        "{} PCs, {} unique symbolized, {}",
        total,
        uniq.len(),
        resolve::backend_name(vmlinux)
    ));

    // Aggregate in ascending PC order, not first-seen order, so the function
    // a hunk header names for a line hit through several PCs does not
    // depend on the trace's timing.
    let mut order: Vec<usize> = (0..uniq.len()).collect();
    order.sort_unstable_by_key(|&i| uniq[i]);
    // Split assembly-resolved PCs out of the C-source report: entry stubs
    // (entry_64.S, retpoline.S, ...) would drown it out. They are rendered
    // separately as asmcov.log with the same patch-style excerpts.
    let mut asm_pairs: Vec<(String, String)> = Vec::new();
    let mut src_pairs: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (func, l) in order.iter().map(|&i| &pairs[i]) {
        let file = l.rsplit_once(':').map(|(f, _)| f).unwrap_or(l.as_str());
        if file.ends_with(".S") || file.ends_with(".s") {
            asm_pairs.push((func.clone(), l.clone()));
        } else {
            src_pairs.push((func.clone(), l.clone()));
        }
    }
    let (cov, funcs) = resolve::aggregate(&src_pairs, kernel_src);
    let (asm_cov, asm_funcs) = resolve::aggregate(&asm_pairs, kernel_src);
    timing::mark(&format!("report: aggregated ({} files)", cov.len()));
    let sources = load_sources(&cov, kernel_src, opts.filter.as_deref());
    let asm_sources = load_sources(&asm_cov, kernel_src, opts.filter.as_deref());
    timing::mark(&format!("report: sources loaded ({} files)", sources.len()));
    p.done(&format!(
        "{} files, {} source lines",
        cov.len(),
        cov.values().map(|s| s.len()).sum::<usize>()
    ));

    if cov.is_empty() && asm_cov.is_empty() {
        let _ = srccov_writer.join();
        if !opts.quiet {
            println!("\x1b[93mno source lines resolved\x1b[0m");
        }
        return 0;
    }

    // The excerpt artifacts are written by a worker while the terminal
    // report streams, so neither waits for the other.
    let (before, after, filter) = (opts.ctx_before, opts.ctx_after, opts.filter.as_deref());
    std::thread::scope(|s| {
        let writer = s.spawn(|| {
            // asmcov.log: the processed assembly view, same excerpt format
            // and the same -A/-B/-C context as the C report. It exists for
            // every engine so the artifact set is uniform; with no assembly
            // PCs (KCOV: compiler instrumentation never reaches .S code) the
            // file says so.
            let asm_text = if asm_cov.is_empty() {
                String::from(
                    "# no assembly PCs in this log (KCOV instruments C code only; \
hardware engines observe entry stubs)\n",
                )
            } else {
                terminal::render_text(&asm_cov, &asm_funcs, before, after, filter, &asm_sources)
            };
            let _ = std::fs::write("asmcov.log", &asm_text);
            html::generate(&cov, &funcs, before, after, &opts.output, filter, &sources);
            timing::mark("writer: html written");
            // The log itself becomes the processed artifact: the same
            // patch-style text report, honoring -A/-B/-C. The raw data lives
            // untouched in the per-TID local-/remote- logs and in srccov.log,
            // whose first token per line is the original PC - srccov.log
            // therefore stays valid `vock report --log` input.
            let _ = std::fs::write(
                &opts.log,
                terminal::render_text(&cov, &funcs, before, after, filter, &sources),
            );
            timing::mark("writer: text report written");
        });
        if !opts.quiet && !cov.is_empty() {
            terminal::print_report(&cov, &funcs, before, after, filter, &sources);
            timing::mark("report: terminal printed");
        }
        let _ = writer.join();
    });
    let _ = srccov_writer.join();

    if !opts.quiet {
        if !asm_cov.is_empty() {
            println!(
                "  {} assembly source lines split out to asmcov.log",
                asm_cov.values().map(|s| s.len()).sum::<usize>()
            );
        }
        println!(
            "\n\x1b[92m✓ Written: {}, {}, asmcov.log, {} (excerpts)\x1b[0m",
            opts.output,
            symbolize::srccov_path(log).display(),
            opts.log
        );
        p.done("artifacts written");
    }
    timing::mark("report: done");
    0
}

/// `--ordered`: the execution sequence, every duplicate kept, as a trace.
fn run_ordered(opts: &Options, parts: &[PathBuf], kernel_src: &str, vmlinux: &str) -> i32 {
    let log = Path::new(&opts.log);
    let seq = read_all_pcs(parts);
    timing::mark(&format!("report: log parsed ({} PCs)", seq.len()));
    if seq.is_empty() {
        if !opts.quiet {
            println!("\x1b[93mno coverage data found\x1b[0m");
        }
        return 0;
    }
    let uniq = unique_sorted(&seq);
    if !opts.quiet {
        println!(
            "\n\x1b[93m📊 [VOCK] Ordered report ({} PCs, {} unique)\x1b[0m\n",
            seq.len(),
            uniq.len()
        );
    }
    let mut p = Progress::new(opts.quiet);
    let offset = kaslr::detect_offset(vmlinux, &seq[..seq.len().min(100)]);
    timing::mark("report: kaslr");
    // Resolve each *unique* address once and render the sequence via
    // lookup: an ordered log keeps every duplicate (that is the point),
    // and resolving 100K+ duplicates individually made the report take
    // longer than the selftest VM timeout.
    let uniq_dek: Vec<u64> = uniq.iter().map(|a| a.wrapping_sub(offset)).collect();
    let pairs_u = resolve::symbolize(vmlinux, &uniq_dek);
    p.done(&format!(
        "{} unique PCs symbolized, {}",
        uniq.len(),
        resolve::backend_name(vmlinux)
    ));
    let umap: HashMap<u64, &(String, String)> = uniq.iter().copied().zip(pairs_u.iter()).collect();
    let lines: Vec<String> = seq
        .iter()
        .map(|a| match umap.get(a) {
            Some((f, l)) => format!("{f} {l}"),
            None => String::from("?? ??"),
        })
        .collect();
    // Transform layer: the source-line twin shows code, not addresses.
    symbolize::write_srccov(log, &seq, &symbolize::location_map(&uniq, &pairs_u, kernel_src));
    timing::mark("report: srccov written");
    p.done(&format!(
        "source-line log \u{2192} {}",
        symbolize::srccov_path(log).display()
    ));
    let dek: Vec<String> = hex_strings(&seq.iter().map(|a| a.wrapping_sub(offset)).collect::<Vec<u64>>());
    html::generate_ordered(&dek, &lines, &opts.output);
    timing::mark("report: ordered html written");
    if !opts.quiet {
        println!(
            "\x1b[92m✓ Written: {} (ordered, {} entries)\x1b[0m",
            opts.output,
            seq.len()
        );
    }
    0
}

/// `--btf`: resolve via /proc/kallsyms. Returns `None` when kallsyms
/// resolved nothing and a vmlinux is at hand, so the caller falls back to
/// the DWARF pipeline.
fn run_btf(opts: &Options, parts: &[PathBuf], kernel_src: &str, vmlinux: &str) -> Option<i32> {
    let log = Path::new(&opts.log);
    let seq = read_all_pcs(parts);
    if seq.is_empty() {
        if !opts.quiet {
            println!("\x1b[93mno coverage data found\x1b[0m");
        }
        return Some(0);
    }
    let addrs = hex_strings(&unique_sorted(&seq));
    let resolved = btf::resolve_pcs(&addrs, "/proc/kallsyms");
    let ranked = btf::rank(&resolved);
    timing::mark("report: btf resolved");
    // kallsyms can be unusable for reasons that have nothing to do with
    // the coverage: no CONFIG_KALLSYMS, kptr_restrict hiding every
    // address, an architecture whose symbols do not cover the traced
    // range. Rather than emit an empty report (which reads as "nothing
    // ran"), fall back to the vmlinux pipeline when one is at hand,
    // which is the case whenever --kernel-src points at a built tree.
    // The fallback is strictly better output, file:line instead of bare
    // function names, so it also keeps the artifacts consistent.
    if ranked.is_empty() && Path::new(vmlinux).is_file() {
        eprintln!(
            "btf: kallsyms resolved 0 of {} PCs; falling back to \
             symbolization against {vmlinux}",
            addrs.len()
        );
        return None;
    }
    // Transform-layer twin, same as vmlinux mode: srccov.log carries the
    // best symbolization available. kallsyms gives function granularity
    // only, no file:line without a vmlinux.
    {
        use std::io::Write;
        let sc = symbolize::srccov_path(log);
        if let Ok(f) = std::fs::File::create(&sc) {
            let mut w = std::io::BufWriter::new(f);
            for (pc, name) in &resolved {
                let _ = writeln!(w, "{pc} {}", name.as_deref().unwrap_or("??"));
            }
        }
    }
    if !opts.quiet {
        println!(
            "\n\x1b[93m📊 [VOCK] BTF report ({} PCs → {} functions)\x1b[0m\n",
            addrs.len(),
            ranked.len()
        );
        println!("  {:<50} {:>6}", "Function", "Hits");
        println!("  {} {}", "─".repeat(50), "─".repeat(6));
        for (name, hits) in ranked.iter().take(50) {
            println!("  {name:<50} {hits:>6}");
        }
        if ranked.len() > 50 {
            println!("  ... and {} more functions", ranked.len() - 50);
        }
        println!("\n\x1b[92m✓ {} kernel functions covered\x1b[0m", ranked.len());
    }

    if opts.kernel_src.is_some() && Path::new(kernel_src).is_dir() {
        btf::generate_html(&ranked, kernel_src, &opts.output, 3);
        if !opts.quiet {
            println!("\x1b[92m✓ Written: {} (source-highlighted)\x1b[0m", opts.output);
        }
        return Some(0);
    }
    // Fallback: text-only report.
    let txt = opts.output.replace(".html", ".txt");
    if let Ok(mut f) = std::fs::File::create(&txt) {
        use std::io::Write;
        for (name, hits) in &ranked {
            let _ = writeln!(f, "{name}\t{hits}");
        }
    }
    if !opts.quiet {
        println!("\x1b[92m✓ Written: {txt}\x1b[0m");
    }
    Some(0)
}

fn center(s: &str, width: usize, fill: char) -> String {
    if s.len() >= width {
        return s.to_string();
    }
    let total = width - s.len();
    let left = total / 2;
    let right = total - left;
    format!(
        "{}{}{}",
        fill.to_string().repeat(left),
        s,
        fill.to_string().repeat(right)
    )
}
