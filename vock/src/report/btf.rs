//! BTF/kallsyms-based PC resolver (port of report/btf.py).
//!
//! Resolves kernel PCs to function names via /proc/kallsyms — no vmlinux or
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

fn parse_pc(pc: &str) -> u64 {
    let s = pc.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Ranked (function, hits) list. Applies the same KASLR heuristic as btf.py.
pub fn generate_report(pcs: &[String], kallsyms_path: &str) -> Vec<(String, usize)> {
    let syms = load_kallsyms(kallsyms_path);
    if syms.is_empty() {
        return Vec::new();
    }
    let sym_addrs: Vec<u64> = syms.iter().map(|s| s.0).collect();
    let int_pcs: Vec<u64> = pcs.iter().map(|p| parse_pc(p)).collect();

    let mut text_addr: Option<u64> = None;
    for (addr, name) in &syms {
        if name == "_text" || name == "_stext" {
            text_addr = Some(*addr);
            break;
        }
    }

    let mut offset: i64 = 0;
    if let (Some(text_addr), false) = (text_addr, int_pcs.is_empty()) {
        let min_pc = *int_pcs.iter().min().unwrap();
        if min_pc < text_addr {
            offset = text_addr as i64 - 0xffff_ffff_8100_0000u64 as i64;
        } else if min_pc > syms.last().unwrap().0 {
            offset = -((min_pc - text_addr) as i64);
        }
    }

    use std::collections::HashMap;
    let mut hits: HashMap<&str, usize> = HashMap::new();
    for &pc in &int_pcs {
        let adj = (pc as i64 + offset) as u64;
        let idx = sym_addrs.partition_point(|&a| a <= adj);
        if idx == 0 {
            continue;
        }
        let name = syms[idx - 1].1.as_str();
        *hits.entry(name).or_insert(0) += 1;
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
