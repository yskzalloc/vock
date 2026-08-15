//! Coverage report generator (in-process port of output.py + report/*.py).
//!
//! Reads a coverage log of kernel PCs and renders `coverage.html` (source
//! annotated via addr2line) plus a terminal summary. Also implements `--btf`
//! (resolve via /proc/kallsyms, no vmlinux) and `--ordered` execution traces.

mod btf;
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
            ctx_after: 4,
            ctx_before: 4,
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
            let a = line.trim();
            if a.is_empty() {
                continue;
            }
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
            let a = line.trim();
            if a.is_empty() {
                continue;
            }
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
        let addrs = kaslr::dekaslr(&addrs, offset);
        let lines = resolve::run_addr2line(&vmlinux, &addrs);
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
    let addrs = kaslr::dekaslr(&addrs, offset);

    let lines = resolve::run_addr2line(&vmlinux, &addrs);

    // Split assembly-resolved PCs out of the source report: the annotated C
    // source is what the report is for, and entry stubs (entry_64.S,
    // retpoline.S, ...) drown it out. They are preserved, not dropped -
    // asmcov.log carries one "0x<pc> <file>:<line>" per assembly PC.
    let mut asm_out = String::new();
    let mut asm_count = 0usize;
    let mut src_lines: Vec<String> = Vec::with_capacity(lines.len());
    for (a, l) in addrs.iter().zip(lines.iter()) {
        let file = l.rsplit_once(':').map(|(f, _)| f).unwrap_or(l.as_str());
        if file.ends_with(".S") || file.ends_with(".s") {
            asm_out.push_str(&format!("{a} {l}
"));
            asm_count += 1;
        } else {
            src_lines.push(l.clone());
        }
    }
    if asm_count > 0 {
        let _ = std::fs::write("asmcov.log", &asm_out);
        if !opts.quiet {
            println!("  {asm_count} assembly PCs split out to asmcov.log");
        }
    }

    let cov = resolve::aggregate(&src_lines, &kernel_src);
    if cov.is_empty() {
        if !opts.quiet {
            println!("\x1b[93mno source lines resolved\x1b[0m");
        }
        return 0;
    }

    html::generate(
        &cov,
        &kernel_src,
        opts.ctx_before,
        opts.ctx_after,
        &opts.output,
        opts.filter.as_deref(),
    );
    if !opts.quiet {
        println!("\n\x1b[92m✓ Written: {}\x1b[0m", opts.output);
        terminal::print_report(
            &cov,
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
