//! Terminal colored coverage output (port of report/terminal.py).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const G: &str = "\x1b[92m";
const R: &str = "\x1b[0m";
const YB: &str = "\x1b[1;33m";
const CY: &str = "\x1b[96m";

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

pub fn print_report(
    cov: &BTreeMap<String, BTreeSet<usize>>,
    funcs: &BTreeMap<String, BTreeMap<usize, String>>,
    kernel_src: &str,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
) {
    print!("{}", render(cov, funcs, kernel_src, before, after, filter_kw, true));
}

/// Plain-text form of the same report, what kerncov.log and asmcov.log
/// carry after processing.
pub fn render_text(
    cov: &BTreeMap<String, BTreeSet<usize>>,
    funcs: &BTreeMap<String, BTreeMap<usize, String>>,
    kernel_src: &str,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
) -> String {
    render(cov, funcs, kernel_src, before, after, filter_kw, false)
}

#[allow(clippy::too_many_arguments)]
fn render(
    cov: &BTreeMap<String, BTreeSet<usize>>,
    funcs: &BTreeMap<String, BTreeMap<usize, String>>,
    kernel_src: &str,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
    color: bool,
) -> String {
    let (g, r, yb, cy) = if color { (G, R, YB, CY) } else { ("", "", "", "") };
    let mut out = String::new();
    let src_root = Path::new(kernel_src);
    let before = before.max(0) as usize;
    let after = after.max(0) as usize;
    out.push_str(&format!("\n{}\n", center(" Coverage Report ", 80, '-')));

    for (fpath, covered) in cov {
        if let Some(kw) = filter_kw {
            if !fpath.contains(kw) {
                continue;
            }
        }
        let full = src_root.join(fpath);
        out.push_str(&format!("\n📄 {yb}{fpath}{r} ({} lines)\n", covered.len()));

        let content = match std::fs::read_to_string(&full) {
            Ok(c) => c,
            Err(_) => {
                let nums: Vec<String> = covered.iter().map(|n| n.to_string()).collect();
                out.push_str(&format!("   {}\n", nums.join(" ")));
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

        // Kernel-patch-style hunk headers: each gap prints the function the
        // next covered line belongs to, like "@@ ... @@ func" in a diff.
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
                    Some(f) => out.push_str(&format!("{cy}   ... @@ {f}{r}\n")),
                    None => out.push_str(&format!("{cy}   ...{r}\n")),
                }
            }
            let text = if ln <= all_lines.len() {
                all_lines[ln - 1]
            } else {
                ""
            };
            if covered.contains(&ln) {
                out.push_str(&format!("{g}{ln:5} > {text}{r}\n"));
            } else {
                out.push_str(&format!("{ln:5} | {text}\n"));
            }
            last = ln as i64;
        }
        out.push_str(&format!("{cy}   ...{r}\n"));
    }
    out
}
