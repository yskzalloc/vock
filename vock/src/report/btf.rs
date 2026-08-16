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
/// A foreign log (PCs from another boot of the kernel) keeps the legacy
/// heuristic, on x86_64 only, where its text-base constant is meaningful.
fn kaslr_offset(int_pcs: &[u64], syms: &[(u64, String)]) -> i64 {
    let Some(min_pc) = int_pcs.iter().copied().min() else {
        return 0;
    };
    let last = syms.last().unwrap().0;
    let mut text_addr: Option<u64> = None;
    for (addr, name) in syms {
        if name == "_text" || name == "_stext" {
            text_addr = Some(*addr);
            break;
        }
    }
    let Some(text_addr) = text_addr else { return 0 };

    let in_text = int_pcs
        .iter()
        .filter(|&&pc| pc >= text_addr && pc <= last)
        .count();
    if in_text * 2 >= int_pcs.len() {
        return 0; // same-kernel log
    }
    if min_pc < text_addr {
        if cfg!(target_arch = "x86_64") {
            text_addr as i64 - 0xffff_ffff_8100_0000u64 as i64
        } else {
            0
        }
    } else if min_pc > last {
        -((min_pc - text_addr) as i64)
    } else {
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
}
