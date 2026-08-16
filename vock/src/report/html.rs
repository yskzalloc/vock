//! HTML coverage report generation (port of report/html.py + ordered HTML).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[allow(clippy::too_many_arguments)]
pub fn generate(
    cov: &BTreeMap<String, BTreeSet<usize>>,
    funcs: &BTreeMap<String, BTreeMap<usize, String>>,
    kernel_src: &str,
    before: i32,
    after: i32,
    output_path: &str,
    filter_kw: Option<&str>,
) {
    let src_root = Path::new(kernel_src);
    let before = before.max(0) as usize;
    let after = after.max(0) as usize;

    let mut body = String::new();
    let mut total_files = 0usize;
    let mut total_lines = 0usize;

    for (fpath, covered) in cov {
        if let Some(kw) = filter_kw {
            if !fpath.contains(kw) {
                continue;
            }
        }
        total_files += 1;
        total_lines += covered.len();
        body.push_str(&format!(
            "<h2>{} ({} lines)</h2>\n<pre>",
            esc(fpath),
            covered.len()
        ));

        let full = src_root.join(fpath);
        let content = match std::fs::read_to_string(&full) {
            Ok(c) => c,
            Err(_) => {
                body.push_str("  (file not found)\n</pre>");
                continue;
            }
        };
        let all_lines: Vec<&str> = content.split('\n').collect();

        let mut show: BTreeSet<usize> = BTreeSet::new();
        for &ln in covered {
            let lo = ln.saturating_sub(before).max(1);
            let hi = (ln + after).min(all_lines.len());
            for i in lo..=hi {
                show.insert(i);
            }
        }

        // Kernel-patch-style hunk headers, as in the terminal report.
        let ffuncs = funcs.get(fpath);
        let mut last: i64 = -1;
        for &ln in &show {
            if ln as i64 != last + 1 {
                let func = ffuncs.and_then(|m| {
                    covered
                        .range(ln..)
                        .next()
                        .and_then(|c| m.get(c))
                        .map(String::as_str)
                });
                match func {
                    Some(f) => body.push_str(&format!(
                        "<span class=\"sep\">   ... @@ {}</span>\n",
                        esc(f)
                    )),
                    None => body.push_str("<span class=\"sep\">   ...</span>\n"),
                }
            }
            let text = if ln <= all_lines.len() {
                esc(all_lines[ln - 1])
            } else {
                String::new()
            };
            let (cls, mark) = if covered.contains(&ln) {
                ("cov", "&gt;")
            } else {
                ("ctx", "|")
            };
            body.push_str(&format!(
                "<span class=\"{cls}\"><span class=\"ln\">{ln}</span> {mark} {text}</span>\n"
            ));
            last = ln as i64;
        }
        body.push_str("</pre>\n");
    }

    let header = "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>vock coverage</title>\n<style>\nbody { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }\nh1 { color: #569cd6; } h2 { color: #dcdcaa; margin-top: 2em; }\n.cov { background: #1e3a1e; color: #4ec9b0; }\n.ctx { color: #808080; } .sep { color: #569cd6; }\n.ln { color: #858585; display: inline-block; width: 5em; text-align: right; margin-right: 1em; }\npre { margin: 0; } .summary { color: #9cdcfe; margin-bottom: 2em; }\n</style></head><body>\n<h1>vock kernel coverage report</h1>\n";
    let summary = format!(
        "<p class=\"summary\">{total_files} files, {total_lines} covered lines</p>\n"
    );

    if let Ok(f) = std::fs::File::create(output_path) {
        let mut w = std::io::BufWriter::new(f);
        let _ = w.write_all(header.as_bytes());
        let _ = w.write_all(summary.as_bytes());
        let _ = w.write_all(body.as_bytes());
        let _ = w.write_all(b"</body></html>");
    }
}

/// Ordered execution-trace HTML (port of output.py's --ordered branch).
/// Rows the ordered trace table renders before it stops.
///
/// A traced program's own startup is hundreds of thousands of PCs, and one
/// row costs about 700 bytes of markup, so an uncapped table reaches 160 MB
/// for a single task: too large for a browser to open, and slow enough to
/// write that a VM guest sharing its filesystem over 9p spends minutes on
/// it. The complete sequence is never lost, it is the log this report was
/// made from plus its srccov twin; this file is the human-facing view of
/// the head of the trace. Override with VOCK_ORDERED_HTML_ROWS (0 = all).
const ORDERED_HTML_ROWS: usize = 20_000;

fn ordered_html_rows() -> usize {
    match std::env::var("VOCK_ORDERED_HTML_ROWS") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(0) => usize::MAX,
            Ok(n) => n,
            Err(_) => ORDERED_HTML_ROWS,
        },
        Err(_) => ORDERED_HTML_ROWS,
    }
}

pub fn generate_ordered(addrs: &[String], lines: &[String], output_path: &str) {
    let Ok(f) = std::fs::File::create(output_path) else {
        return;
    };
    let max = ordered_html_rows();
    let shown = lines.len().min(max);
    let mut w = std::io::BufWriter::new(f);
    let _ = w.write_all(b"<!DOCTYPE html><html><head><meta charset='utf-8'>\n");
    let _ = w.write_all(b"<title>vock ordered coverage</title>\n");
    let _ = w.write_all(b"<style>body{background:#1e1e1e;color:#d4d4d4;font-family:monospace;padding:20px}");
    let _ = w.write_all(b"table{border-collapse:collapse;width:100%}");
    let _ = w.write_all(b"td,th{padding:4px 8px;border-bottom:1px solid #333;text-align:left}");
    let _ = w.write_all(b"th{background:#264f78;color:#fff}");
    let _ = w.write_all(b".func{color:#dcdcaa}.file{color:#9cdcfe}.line{color:#b5cea8}");
    let _ = w.write_all(b"</style></head><body>\n");
    let _ = write!(w, "<h2>Ordered Kernel Execution Trace ({} PCs)</h2>\n", addrs.len());
    if shown < lines.len() {
        // Say it on the page and on stderr: a truncated view that looks
        // complete is worse than no view.
        let _ = write!(
            w,
            "<p>Showing the first {shown} of {} entries. The complete \
             sequence, in order and with every duplicate, is the log this \
             report was generated from and its srccov twin. Set \
             VOCK_ORDERED_HTML_ROWS=0 to render all of them.</p>\n",
            lines.len()
        );
        eprintln!(
            "[vock] {output_path}: rendering the first {shown} of {} trace \
             entries (VOCK_ORDERED_HTML_ROWS=0 for all)",
            lines.len()
        );
    }
    let _ = w.write_all(b"<table><tr><th>#</th><th>Address</th><th>Function</th><th>Source</th></tr>\n");
    for (i, loc) in lines.iter().take(shown).enumerate() {
        let (func, src) = match loc.split_once(' ') {
            Some((f, s)) => (f, s),
            None => (loc.as_str(), ""),
        };
        let addr = addrs.get(i).map(String::as_str).unwrap_or("");
        let _ = write!(w, "<tr><td>{}</td><td>{}</td>", i + 1, addr);
        let _ = write!(w, "<td class='func'>{func}</td>");
        let _ = write!(w, "<td class='file'>{src}</td></tr>\n");
    }
    let _ = w.write_all(b"</table></body></html>\n");
}
