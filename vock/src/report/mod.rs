//! Coverage report generator (in-process port of output.py + report/*.py).
//!
//! Reads a coverage log of kernel PCs and renders `coverage.html` (source
//! annotated via addr2line) plus a terminal summary. Also implements `--btf`
//! (resolve via /proc/kallsyms, no vmlinux) and `--ordered` execution traces.

mod btf;
pub(crate) mod symbolize;
mod html;
mod kaslr;
mod resolve;
mod terminal;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

fn read_addresses(log: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Ok(data) = std::fs::read_to_string(log) {
        for line in data.lines() {
            // First token only: an annotated log ("0x<pc> file:line") stays
            // valid input alongside a raw one.
            let Some(a) = line.split_whitespace().next() else { continue };
            set.insert(if a.starts_with("0x") {
                a.to_string()
            } else {
                format!("0x{a}")
            });
        }
    }
    set
}

fn read_addresses_ordered(log: &Path) -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(data) = std::fs::read_to_string(log) {
        for line in data.lines() {
            let Some(a) = line.split_whitespace().next() else { continue };
            v.push(if a.starts_with("0x") {
                a.to_string()
            } else {
                format!("0x{a}")
            });
        }
    }
    v
}

/// Entry point: equivalent to `python3 output.py <opts>`.
pub fn run(opts: &Options) -> i32 {
    let (def_ks, def_vm) = defaults();
    let kernel_src = opts.kernel_src.clone().unwrap_or_else(|| def_ks.clone());
    let mut vmlinux = opts.vmlinux.clone().unwrap_or_else(|| def_vm.clone());

    // If kernel-src was overridden but vmlinux wasn't, derive vmlinux from it.
    if opts.kernel_src.is_some() && opts.vmlinux.is_none() {
        vmlinux = Path::new(&kernel_src)
            .join("vmlinux")
            .to_string_lossy()
            .into();
    }

    if !opts.quiet {
        println!("{}", center(" VOCK Coverage Reporter ", 80, '='));
    }

    // ── Ordered mode ────────────────────────────────────────────────────────
    if opts.ordered {
        let addrs = read_addresses_ordered(Path::new(&opts.log));
        if addrs.is_empty() {
            if !opts.quiet {
                println!("\x1b[93mno coverage data found\x1b[0m");
            }
            return 0;
        }
        if !opts.quiet {
            println!(
                "\n\x1b[93m📊 [VOCK] Ordered report ({} PCs)\x1b[0m\n",
                addrs.len()
            );
        }
        let sample: Vec<String> = addrs.iter().take(100).cloned().collect();
        let offset = kaslr::detect_offset(&vmlinux, &sample);
        let orig = addrs.clone();
        let addrs = kaslr::dekaslr(&addrs, offset);
        // Resolve each *unique* address once and render the sequence via
        // lookup: an ordered log keeps every duplicate (that is the point),
        // and resolving 100K+ duplicates individually made the report take
        // longer than the selftest VM timeout.
        let uniq: Vec<String> = addrs
            .iter()
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        let pairs_u = resolve::run_addr2line(&vmlinux, &uniq);
        let umap: std::collections::HashMap<&str, &(String, String)> = uniq
            .iter()
            .map(String::as_str)
            .zip(pairs_u.iter())
            .collect();
        let lines: Vec<String> = addrs
            .iter()
            .map(|a| match umap.get(a.as_str()) {
                Some((f, l)) => format!("{f} {l}"),
                None => String::from("?? ??"),
            })
            .collect();
        // Transform layer: the source-line twin shows code, not addresses.
        let uniq_orig: Vec<String> = orig
            .iter()
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        symbolize::write_srccov(
            Path::new(&opts.log),
            &symbolize::location_map(&uniq_orig, &pairs_u, &kernel_src),
        );
        html::generate_ordered(&addrs, &lines, &opts.output);
        if !opts.quiet {
            println!(
                "\x1b[92m✓ Written: {} (ordered, {} entries)\x1b[0m",
                opts.output,
                addrs.len()
            );
        }
        return 0;
    }

    let addrs: Vec<String> = read_addresses(Path::new(&opts.log)).into_iter().collect();
    if addrs.is_empty() {
        if !opts.quiet {
            println!("\x1b[93mno coverage data found\x1b[0m");
        }
        return 0;
    }

    // ── BTF mode (resolve via kallsyms) ─────────────────────────────────────
    if opts.btf {
        let ranked = btf::generate_report(&addrs, "/proc/kallsyms");
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

        let ks = if opts.kernel_src.is_some() {
            Some(kernel_src.as_str())
        } else {
            None
        };
        if let Some(ks) = ks {
            if Path::new(ks).is_dir() {
                btf::generate_html(&ranked, ks, &opts.output, 3);
                if !opts.quiet {
                    println!("\x1b[92m✓ Written: {} (source-highlighted)\x1b[0m", opts.output);
                }
                return 0;
            }
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
        return 0;
    }

    // ── vmlinux / addr2line mode ────────────────────────────────────────────
    if !opts.quiet {
        println!("\n\x1b[93m📊 [VOCK] Generating coverage report...\x1b[0m\n");
    }

    let offset = kaslr::detect_offset(&vmlinux, &addrs);
    if offset != 0 && !opts.quiet {
        println!("  KASLR detected: offset 0x{offset:x}");
    }
    let orig = addrs.clone();
    let addrs = kaslr::dekaslr(&addrs, offset);

    let pairs = resolve::run_addr2line(&vmlinux, &addrs);

    // Transform layer: kerncov.log keeps the raw per-boot addresses (the
    // machine format other tools consume); its source-line twin srccov.log
    // carries "0x<pc> <function> <file>:<line>" for human checking.
    symbolize::write_srccov(
        Path::new(&opts.log),
        &symbolize::location_map(&orig, &pairs, &kernel_src),
    );
    if !opts.quiet {
        println!(
            "  source-line log \u{2192} {}",
            symbolize::srccov_path(Path::new(&opts.log)).display()
        );
    }

    // Split assembly-resolved PCs out of the C-source report: entry stubs
    // (entry_64.S, retpoline.S, ...) would drown it out. They are rendered
    // separately below as asmcov.log with the same patch-style excerpts.
    let mut asm_pairs: Vec<(String, String)> = Vec::new();
    let mut src_pairs: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (func, l) in pairs.iter() {
        let file = l.rsplit_once(':').map(|(f, _)| f).unwrap_or(l.as_str());
        if file.ends_with(".S") || file.ends_with(".s") {
            asm_pairs.push((func.clone(), l.clone()));
        } else {
            src_pairs.push((func.clone(), l.clone()));
        }
    }

    let (cov, funcs) = resolve::aggregate(&src_pairs, &kernel_src);

    // asmcov.log: the processed assembly view, same excerpt format and the
    // same -A/-B/-C context as the C report. It exists for every engine so
    // the artifact set is uniform; with no assembly PCs (KCOV: compiler
    // instrumentation never reaches .S code) the file says so.
    let (asm_cov, asm_funcs) = resolve::aggregate(&asm_pairs, &kernel_src);
    let asm_text = if asm_cov.is_empty() {
        String::from(
            "# no assembly PCs in this log (KCOV instruments C code only; \
hardware engines observe entry stubs)\n",
        )
    } else {
        terminal::render_text(
            &asm_cov,
            &asm_funcs,
            &kernel_src,
            opts.ctx_before,
            opts.ctx_after,
            opts.filter.as_deref(),
        )
    };
    let _ = std::fs::write("asmcov.log", &asm_text);
    if !asm_cov.is_empty() && !opts.quiet {
        println!(
            "  {} assembly source lines split out to asmcov.log",
            asm_cov.values().map(|s| s.len()).sum::<usize>()
        );
    }

    if cov.is_empty() {
        if !opts.quiet {
            println!("\x1b[93mno source lines resolved\x1b[0m");
        }
        return 0;
    }

    html::generate(
        &cov,
        &funcs,
        &kernel_src,
        opts.ctx_before,
        opts.ctx_after,
        &opts.output,
        opts.filter.as_deref(),
    );
    // The log itself becomes the processed artifact: the same patch-style
    // text report, honoring -A/-B/-C. The raw data lives untouched in the
    // per-TID local-/remote- logs and in srccov.log, whose first token per
    // line is the original PC - srccov.log therefore stays valid
    // `vock report --log` input for re-processing.
    let _ = std::fs::write(
        &opts.log,
        terminal::render_text(
            &cov,
            &funcs,
            &kernel_src,
            opts.ctx_before,
            opts.ctx_after,
            opts.filter.as_deref(),
        ),
    );

    if !opts.quiet {
        println!("\n\x1b[92m✓ Written: {}\x1b[0m", opts.output);
        terminal::print_report(
            &cov,
            &funcs,
            &kernel_src,
            opts.ctx_before,
            opts.ctx_after,
            opts.filter.as_deref(),
        );
    }
    0
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
