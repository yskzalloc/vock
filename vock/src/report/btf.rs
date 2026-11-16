//! BTF/kallsyms-based PC resolver (port of report/btf.py).
//!
//! Resolves kernel PCs to function names via /proc/kallsyms, no vmlinux or
//! addr2line needed. Optionally renders highlighted source via grep.

use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Sorted (addr, name) symbol list.
fn load_kallsyms(path: &str) -> Vec<(u64, String)> {
    let mut syms = Vec::new();
    if let Ok(data) = std::fs::read_to_string(path) {
        for line in data.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let Ok(addr) = u64::from_str_radix(parts[0], 16) else {
                continue;
            };
            if addr == 0 {
                continue;
            }
            syms.push((addr, parts[2].to_string()));
        }
    }
    syms.sort_by_key(|s| s.0);
    syms
}

fn parse_pc(pc: &str) -> Option<u64> {
    let s = pc.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

/// KASLR offset between the log's PCs and the loaded kallsyms.
///
/// The common case, a log from the *running* kernel, needs no offset at all:
/// KCOV PCs and /proc/kallsyms describe the same live image, KASLR or not,
/// on every architecture. So when the majority of PCs already fall inside
/// the kallsyms text range the offset is 0, and a stray malformed PC (a
/// merge-glued line, a truncated write) cannot poison the whole report. The
/// old min-PC heuristic compared against the hardcoded x86 text base
/// 0xffffffff81000000, so one sub-text PC on arm64 shifted every address by
/// about -128 TiB and resolved 0 functions; on x86 the same poison happened
/// to compute the correct slide, which is why only arm64 CI caught it.
///
/// KCOV is the exception: with CONFIG_RANDOMIZE_BASE it reports *unslid*
/// PCs (`canonicalize_ip()` subtracts `kaslr_offset()`), i.e. link-time
/// addresses relative to the arch's link base, while /proc/kallsyms is
/// slid. The slide is then the kallsyms text anchor minus the link base;
/// see [`link_bases`] and [`slide_from`].
///
/// A foreign log (PCs from another boot of the kernel) keeps the legacy
/// heuristic, on x86_64 only, where its text-base constant is meaningful.
fn kaslr_offset(int_pcs: &[u64], syms: &[(u64, String)]) -> i64 {
    kaslr_offset_for(HOST_ARCH, int_pcs, syms)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Arch {
    X86_64,
    Aarch64,
    Other,
}

const HOST_ARCH: Arch = if cfg!(target_arch = "x86_64") {
    Arch::X86_64
} else if cfg!(target_arch = "aarch64") {
    Arch::Aarch64
} else {
    Arch::Other
};

/// Link-time (unslid) `_text` addresses the kernel can have on `arch`.
///
/// - x86_64: `__START_KERNEL` = `__START_KERNEL_map` + the default
///   `CONFIG_PHYSICAL_START` (16 MiB).
/// - arm64: `KIMAGE_VADDR` = `MODULES_END` = `_PAGE_END(VA_BITS_MIN)` +
///   `MODULES_VSIZE` (`arch/arm64/include/asm/memory.h`), where
///   `_PAGE_END(va)` = `-(1 << (va - 1))` and `VA_BITS_MIN` is `VA_BITS`
///   capped at 48 (52-bit configs use 48). `MODULES_VSIZE` is 2 GiB on
///   current kernels and was 128 MiB before v6.2.
///
/// The candidates sit hundreds of MiB to TiBs apart while kernel text is
/// tens of MiB, so at most one of them can put the majority of a log's PCs
/// inside the kallsyms text range: the choice is checked, not guessed.
fn link_bases(arch: Arch) -> Vec<u64> {
    match arch {
        Arch::X86_64 => vec![0xffff_ffff_8100_0000],
        Arch::Aarch64 => {
            let mut v = Vec::new();
            for va in [48u32, 47, 42, 39, 36] {
                let page_end = (1u64 << (va - 1)).wrapping_neg();
                for modules_vsize in [2u64 << 30, 128 << 20] {
                    v.push(page_end.wrapping_add(modules_vsize));
                }
            }
            v
        }
        Arch::Other => Vec::new(),
    }
}

/// KASLR slide granularity: `MIN_KIMG_ALIGN` on arm64, the default
/// `CONFIG_PHYSICAL_ALIGN` on x86_64. Both 2 MiB.
const KASLR_ALIGN: u64 = 2 << 20;

/// Slide for a kernel linked at `base`, from the slid kallsyms anchor.
///
/// `base` is the link address of `_text`. x86 lists `_text` in kallsyms, so
/// the difference is exact. arm64 does not: the only anchor is `_stext`,
/// which sits after `.head.text` (64 KiB on current kernels, not a fixed
/// constant), so `_stext - base` overshoots by that much. The slide itself
/// is `KASLR_ALIGN`-aligned and `.head.text` is far smaller, so rounding
/// down recovers it.
fn slide_from(anchor: u64, anchor_is_text: bool, base: u64) -> i64 {
    let d = anchor.wrapping_sub(base);
    (if anchor_is_text {
        d
    } else {
        d & !(KASLR_ALIGN - 1)
    }) as i64
}

fn kaslr_offset_for(arch: Arch, int_pcs: &[u64], syms: &[(u64, String)]) -> i64 {
    let Some(min_pc) = int_pcs.iter().copied().min() else {
        return 0;
    };
    let last = syms.last().unwrap().0;
    let mut text_addr: Option<u64> = None;
    let mut anchor_is_text = false;
    for (addr, name) in syms {
        if name == "_text" || name == "_stext" {
            text_addr = Some(*addr);
            anchor_is_text = name == "_text";
            break;
        }
    }
    let Some(text_addr) = text_addr else {
        eprintln!(
            "btf: no _text/_stext in kallsyms ({} symbols); assuming offset 0",
            syms.len()
        );
        return 0;
    };

    let in_text = int_pcs
        .iter()
        .filter(|&&pc| pc >= text_addr && pc <= last)
        .count();
    let max_pc = int_pcs.iter().copied().max().unwrap_or(0);
    let pct = |n: usize| {
        if int_pcs.is_empty() {
            0
        } else {
            n * 100 / int_pcs.len()
        }
    };

    // The decision made here cannot be validated after the fact: a wrong
    // offset still lands inside the symbol table and resolves to
    // plausible-looking but unrelated functions. So state the inputs and the
    // choice, always. Without this line a misattributed report is
    // indistinguishable from a report of genuinely odd coverage.
    let say = |decision: &str, n: usize| {
        eprintln!(
            "btf: kallsyms text {text_addr:#x}..{last:#x} ({} syms), PCs \
             {min_pc:#x}..{max_pc:#x}, {n}/{} in text ({}%) → {decision}",
            syms.len(),
            int_pcs.len(),
            pct(n),
        );
    };

    if in_text * 2 >= int_pcs.len() {
        say("same-kernel, offset 0", in_text);
        if in_text < int_pcs.len() {
            eprintln!(
                "btf: {} PC(s) fall outside the kallsyms text range and \
                 resolve to ?? ",
                int_pcs.len() - in_text
            );
        }
        return 0; // same-kernel log
    }

    // Unslid log (KCOV under KASLR): slide = kallsyms _text - link base.
    // Take the one link base that puts the majority of PCs in the kernel
    // image text. Bounded by _etext, not the last kallsyms entry: module
    // symbols can sit far above the image and would widen the window enough
    // for a wrong candidate to pass too. Ties keep the earlier (current
    // layout) candidate.
    let text_end = syms
        .iter()
        .find(|(_, n)| n == "_etext")
        .or_else(|| syms.iter().find(|(_, n)| n == "_end"))
        .map(|s| s.0)
        .unwrap_or(last);
    let mut best: Option<(u64, i64, usize)> = None;
    for base in link_bases(arch) {
        let off = slide_from(text_addr, anchor_is_text, base);
        let n = int_pcs
            .iter()
            .filter(|&&pc| {
                let adj = (pc as i64).wrapping_add(off) as u64;
                adj >= text_addr && adj <= text_end
            })
            .count();
        if best.is_none_or(|(_, _, b)| n > b) {
            best = Some((base, off, n));
        }
    }
    if let Some((base, off, n)) = best {
        if n * 2 >= int_pcs.len() {
            say(
                &format!("unslid log, link base {base:#x}, slide {:#x}", off as u64),
                n,
            );
            return off;
        }
    }

    if min_pc < text_addr {
        if arch == Arch::X86_64 {
            say("foreign log, legacy x86 slide", in_text);
            text_addr as i64 - 0xffff_ffff_8100_0000u64 as i64
        } else {
            say("foreign log, no slide on this arch", in_text);
            0
        }
    } else if min_pc > last {
        say("foreign log, negative slide", in_text);
        -((min_pc - text_addr) as i64)
    } else {
        say("offset 0", in_text);
        0
    }
}

/// Resolve each PC to its kallsyms function, parallel to the input; `None`
/// for unparseable tokens and addresses outside the symbol table. This is
/// the shared base of the ranked report and BTF-mode `srccov.log`.
pub fn resolve_pcs(pcs: &[String], kallsyms_path: &str) -> Vec<(String, Option<String>)> {
    let syms = load_kallsyms(kallsyms_path);
    if syms.is_empty() {
        // Say which of the two failure modes it is: no file at all versus a
        // file whose addresses are all zero. The second is the common one
        // and is a permission setting, not a missing kernel feature.
        let lines = std::fs::read_to_string(kallsyms_path)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        let restrict = std::fs::read_to_string("/proc/sys/kernel/kptr_restrict")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".into());
        if lines == 0 {
            eprintln!(
                "btf: {kallsyms_path} is empty or unreadable; the kernel needs \
                 CONFIG_KALLSYMS=y"
            );
        } else {
            eprintln!(
                "btf: all {lines} symbols in {kallsyms_path} read as address 0 \
                 (kptr_restrict={restrict}); run as root or set \
                 kernel.kptr_restrict=0 to symbolize via kallsyms"
            );
        }
        return pcs.iter().map(|p| (p.clone(), None)).collect();
    }
    let sym_addrs: Vec<u64> = syms.iter().map(|s| s.0).collect();
    let int_pcs: Vec<u64> = pcs.iter().filter_map(|p| parse_pc(p)).collect();
    let offset = kaslr_offset(&int_pcs, &syms);

    pcs.iter()
        .map(|p| {
            let name = parse_pc(p).and_then(|pc| {
                let adj = (pc as i64 + offset) as u64;
                let idx = sym_addrs.partition_point(|&a| a <= adj);
                if idx == 0 {
                    None
                } else {
                    Some(syms[idx - 1].1.clone())
                }
            });
            (p.clone(), name)
        })
        .collect()
}

/// Ranked (function, hits) list from a per-PC resolution.
pub fn rank(resolved: &[(String, Option<String>)]) -> Vec<(String, usize)> {
    use std::collections::HashMap;
    let mut hits: HashMap<&str, usize> = HashMap::new();
    for (_, name) in resolved {
        if let Some(name) = name {
            *hits.entry(name.as_str()).or_insert(0) += 1;
        }
    }
    let mut ranked: Vec<(String, usize)> =
        hits.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    // Sort by hit count descending; stable order for ties.
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    ranked
}

/// Locate the definitions of many functions in the kernel source in a SINGLE
/// `grep` pass over the tree (instead of one recursive grep per function, which
/// is O(N × tree-walk) and times out on a real kernel). Returns, per resolved
/// function, its `(relative-path, lineno)`. A hard `timeout` bounds the grep so
/// the report can never hang.
fn locate_functions(
    names: &[&str],
    kernel_src: &str,
) -> std::collections::HashMap<String, (String, usize)> {
    use std::collections::HashMap;
    let mut found: HashMap<String, (String, usize)> = HashMap::new();
    if names.is_empty() || kernel_src.is_empty() || !Path::new(kernel_src).is_dir() {
        return found;
    }
    // Function names are C identifiers, so no regex escaping is needed.
    let alt = names.join("|");
    let pattern = format!(r"^[a-zA-Z_].*\b({alt})[[:space:]]*\(");
    let nameset: std::collections::HashSet<&str> = names.iter().copied().collect();

    let out = Command::new("timeout")
        .args(["120", "grep", "-rnE", "--include=*.c", &pattern, kernel_src])
        .output();
    let Ok(out) = out else { return found };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // grep -rn output: path:lineno:content
        let mut it = line.splitn(3, ':');
        let (Some(path), Some(lno), Some(content)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let Ok(lineno) = lno.parse::<usize>() else { continue };
        let Some(func) = func_before_paren(content, &nameset) else { continue };
        found.entry(func.to_string()).or_insert_with(|| {
            let rel = Path::new(path)
                .strip_prefix(kernel_src)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.to_string());
            (rel, lineno)
        });
    }
    found
}

/// In a source line, find an identifier immediately preceding a `(` that is one
/// of the target function names (i.e. the definition's name), scanning every
/// `(` so we don't misattribute to an unrelated leading token.
fn func_before_paren<'a>(
    content: &'a str,
    names: &std::collections::HashSet<&str>,
) -> Option<&'a str> {
    let bytes = content.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c != b'(' {
            continue;
        }
        // Walk back over optional whitespace, then over the identifier.
        let mut end = i;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && {
            let b = bytes[start - 1];
            b == b'_' || b.is_ascii_alphanumeric()
        } {
            start -= 1;
        }
        if start < end {
            let ident = &content[start..end];
            if names.contains(ident) {
                return Some(ident);
            }
        }
    }
    None
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Source-highlighted HTML report (port of btf.py generate_btf_html).
pub fn generate_html(ranked: &[(String, usize)], kernel_src: &str, output_path: &str, ctx: usize) {
    let mut html: Vec<String> = vec![
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">".into(),
        "<title>vock BTF Coverage Report</title>".into(),
        "<style>".into(),
        "body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}".into(),
        "h1{color:#569cd6} h2{color:#4ec9b0;margin-top:2em}".into(),
        ".func{background:#264f78;padding:2px 6px;border-radius:3px}".into(),
        ".hit{color:#b5cea8} .file{color:#ce9178}".into(),
        "pre{background:#2d2d2d;padding:10px;border-radius:5px;overflow-x:auto}".into(),
        ".cov{background:#2ea04366;display:block}".into(),
        ".line-num{color:#858585;user-select:none;padding-right:1em}".into(),
        "</style></head><body>".into(),
        "<h1>vock BTF Coverage Report</h1>".into(),
        format!("<p>{} kernel functions covered</p>", ranked.len()),
    ];

    use std::collections::BTreeMap;
    let mut file_funcs: BTreeMap<String, Vec<(String, usize, usize)>> = BTreeMap::new();
    let mut unresolved: Vec<(String, usize)> = Vec::new();

    let top: Vec<(String, usize)> = ranked.iter().take(200).cloned().collect();
    let names: Vec<&str> = top.iter().map(|(f, _)| f.as_str()).collect();
    let located = locate_functions(&names, kernel_src);
    for (func, hits) in &top {
        match located.get(func) {
            Some((filepath, lineno)) => file_funcs
                .entry(filepath.clone())
                .or_default()
                .push((func.clone(), *hits, *lineno)),
            None => unresolved.push((func.clone(), *hits)),
        }
    }

    for (filepath, funcs) in &file_funcs {
        html.push(format!("<h2 class=\"file\">{filepath}</h2>"));
        let fullpath = Path::new(kernel_src).join(filepath);
        let content = match std::fs::read_to_string(&fullpath) {
            Ok(c) => c,
            Err(_) => {
                for (func, hits, lineno) in funcs {
                    html.push(format!(
                        "<p><span class=\"func\">{func}</span> <span class=\"hit\">({hits} hits)</span> line {lineno}</p>"
                    ));
                }
                continue;
            }
        };
        let lines: Vec<&str> = content.lines().collect();

        use std::collections::BTreeSet;
        let mut highlight: BTreeSet<usize> = BTreeSet::new();
        let mut show: BTreeSet<usize> = BTreeSet::new();
        for (_, _, lineno) in funcs {
            highlight.insert(*lineno);
            let lo = lineno.saturating_sub(ctx).max(1);
            let hi = (lineno + ctx).min(lines.len());
            for l in lo..=hi {
                show.insert(l);
            }
        }

        html.push("<pre>".into());
        let mut prev = 0usize;
        for &ln in &show {
            if prev != 0 && ln > prev + 1 {
                html.push("<span class=\"line-num\">...</span>".into());
            }
            prev = ln;
            let raw = if ln <= lines.len() {
                lines[ln - 1].trim_end()
            } else {
                ""
            };
            let content = esc(raw);
            let cls = if highlight.contains(&ln) {
                " class=\"cov\""
            } else {
                ""
            };
            let mut hit_info = String::new();
            for (func, hits, lineno) in funcs {
                if ln == *lineno {
                    hit_info = format!("  ← {func} ({hits} hits)");
                    break;
                }
            }
            html.push(format!(
                "<span class=\"line-num\">{ln:>5}</span><span{cls}>{content}{hit_info}</span>"
            ));
        }
        html.push("</pre>".into());
    }

    if !unresolved.is_empty() {
        html.push("<h2>Functions (source not found)</h2><pre>".into());
        for (func, hits) in unresolved.iter().take(50) {
            html.push(format!("  {func:<50} {hits:>6} hits"));
        }
        html.push("</pre>".into());
    }

    html.push("</body></html>".into());
    if let Ok(mut f) = std::fs::File::create(output_path) {
        let _ = f.write_all(html.join("\n").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_kallsyms(name: &str, lines: &str) -> String {
        let path = std::env::temp_dir()
            .join(format!("vock-btf-test-{}-{name}", std::process::id()));
        std::fs::write(&path, lines).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn sv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// arm64 CI regression: a same-kernel log with one malformed line must
    /// still resolve. The old min-PC heuristic saw the poison parse as a
    /// low value and shifted every PC by (_text - x86 text base), which on
    /// arm64 pushed the whole log below the symbol table: 0 functions.
    #[test]
    fn same_kernel_arm64_log_survives_poison_line() {
        let ks = fake_kallsyms(
            "arm64",
            "ffff800080000000 T _text\n\
             ffff800080010000 T alpha\n\
             ffff800080020000 T beta\n\
             ffff800082000000 B _end\n",
        );
        let pcs = sv(&[
            "0xffff800080010004",
            "0xffff800080010008",
            "0xffff800080020010",
            "0xffff800080010004\u{30}xffff800080020010", // merge-glued line
        ]);
        let resolved = resolve_pcs(&pcs, &ks);
        let ranked = rank(&resolved);
        std::fs::remove_file(&ks).unwrap();
        assert_eq!(resolved[0].1.as_deref(), Some("alpha"));
        assert_eq!(resolved[2].1.as_deref(), Some("beta"));
        assert_eq!(resolved[3].1, None, "poison line resolves to nothing");
        let alpha = ranked.iter().find(|(f, _)| f == "alpha").unwrap();
        assert_eq!(alpha.1, 2);
    }

    /// A numeric-but-bogus low PC (below _text) must not poison the offset
    /// either, the majority of in-range PCs decides.
    #[test]
    fn same_kernel_log_survives_low_pc() {
        let ks = fake_kallsyms(
            "lowpc",
            "ffff800080000000 T _text\n\
             ffff800080010000 T alpha\n\
             ffff800082000000 B _end\n",
        );
        let pcs = sv(&["0x10", "0xffff800080010004", "0xffff800080010008"]);
        let resolved = resolve_pcs(&pcs, &ks);
        std::fs::remove_file(&ks).unwrap();
        assert_eq!(resolved[0].1, None);
        assert_eq!(resolved[1].1.as_deref(), Some("alpha"));
    }

    /// x86 foreign-log case the legacy heuristic exists for: an unslid log
    /// resolved against a KASLR-slid kallsyms still maps via the text-base
    /// constant. x86_64-only, the constant is meaningless elsewhere.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn foreign_x86_log_uses_legacy_slide() {
        let slide = 0x4000000u64;
        let ks = fake_kallsyms(
            "x86",
            &format!(
                "{:x} T _text\n{:x} T alpha\n{:x} B _end\n",
                0xffffffff81000000u64 + slide,
                0xffffffff81010000u64 + slide,
                0xffffffff83000000u64 + slide,
            ),
        );
        let pcs = sv(&["0xffffffff81010004"]);
        let resolved = resolve_pcs(&pcs, &ks);
        std::fs::remove_file(&ks).unwrap();
        assert_eq!(resolved[0].1.as_deref(), Some("alpha"));
    }

    /// kallsyms of a KASLR-slid kernel whose image links at `base`: the
    /// text anchor, two functions, `_etext`, plus a module symbol far above
    /// the image (arm64 places modules within 2 GiB of the kernel). x86
    /// lists `_text`; arm64 lists only `_stext`, after the 64 KiB
    /// `.head.text`, as the real qemuarm64 kallsyms does.
    fn slid_syms(arch: Arch, base: u64, slide: u64) -> Vec<(u64, String)> {
        let s = |off: u64, n: &str| (base + slide + off, n.to_string());
        let anchor = if arch == Arch::X86_64 {
            s(0, "_text")
        } else {
            s(0x10000, "_stext")
        };
        vec![
            anchor,
            s(0x10000, "alpha"),
            s(0x20000, "beta"),
            s(0x0200_0000, "_etext"),
            s(0x0300_0000, "_end"),
            s(0xf000_0000, "mod_func"),
        ]
    }

    /// arm64 CI regression: KCOV reports unslid PCs (canonicalize_ip()
    /// subtracts kaslr_offset()), so a `--mode kcov --btf` log on a KASLR
    /// arm64 kernel sat entirely below kallsyms _text and every PC resolved
    /// to ??. The slide is the kallsyms anchor minus KIMAGE_VADDR, rounded
    /// to 2 MiB because arm64 kallsyms has only `_stext` (64 KiB in): an
    /// unrounded slide resolved every PC to a function 64 KiB away.
    #[test]
    fn unslid_arm64_kcov_log_va48() {
        let base = 0xffff_8000_8000_0000; // KIMAGE_VADDR, VA_BITS_MIN=48
        let slide = 0x3e_7a20_0000;
        let syms = slid_syms(Arch::Aarch64, base, slide);
        let pcs = [
            base + 0x10004,
            base + 0x10008,
            base + 0x20010,
            base + 0x59148,
        ];
        assert_eq!(kaslr_offset_for(Arch::Aarch64, &pcs, &syms), slide as i64);
    }

    #[test]
    fn unslid_arm64_kcov_log_va39() {
        let base = 0xffff_ffc0_8000_0000; // KIMAGE_VADDR, VA_BITS=39
        let slide = 0x1_2340_0000;
        let syms = slid_syms(Arch::Aarch64, base, slide);
        let pcs = [base + 0x10004, base + 0x20010];
        assert_eq!(kaslr_offset_for(Arch::Aarch64, &pcs, &syms), slide as i64);
    }

    /// Pre-v6.2 layout, MODULES_VSIZE = 128 MiB.
    #[test]
    fn unslid_arm64_kcov_log_old_modules_vsize() {
        let base = 0xffff_8000_0800_0000;
        let slide = 0x2_0000_0000;
        let syms = slid_syms(Arch::Aarch64, base, slide);
        let pcs = [base + 0x10004, base + 0x20010];
        assert_eq!(kaslr_offset_for(Arch::Aarch64, &pcs, &syms), slide as i64);
    }

    /// nokaslr arm64 kernel: the log is already in kallsyms space.
    #[test]
    fn arm64_kcov_log_without_kaslr_needs_no_slide() {
        let base = 0xffff_8000_8000_0000;
        let syms = slid_syms(Arch::Aarch64, base, 0);
        let pcs = [base + 0x10004, base + 0x20010];
        assert_eq!(kaslr_offset_for(Arch::Aarch64, &pcs, &syms), 0);
    }

    /// x86 KCOV under KASLR goes through the same link-base path.
    #[test]
    fn unslid_x86_kcov_log() {
        let base = 0xffff_ffff_8100_0000;
        let slide = 0xb20_0000;
        let syms = slid_syms(Arch::X86_64, base, slide);
        let pcs = [base + 0x10004, base + 0x20010];
        assert_eq!(kaslr_offset_for(Arch::X86_64, &pcs, &syms), slide as i64);
    }
}
