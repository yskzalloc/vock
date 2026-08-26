//! Terminal colored coverage output (port of report/terminal.py).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

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

pub type Cov = BTreeMap<String, BTreeSet<usize>>;
pub type Funcs = BTreeMap<String, BTreeMap<usize, String>>;

/// Print the colored report, one file at a time, flushing after each so the
/// terminal shows progress while the rest of the report (and, in parallel,
/// the artifact writer) is still working.
pub fn print_report(
    cov: &Cov,
    funcs: &Funcs,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
    sources: &HashMap<String, String>,
) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "\n{}", center(" Coverage Report ", 80, '-'));
    let mut buf = String::new();
    for (fpath, covered) in cov {
        if filter_kw.is_some_and(|kw| !fpath.contains(kw)) {
            continue;
        }
        buf.clear();
        render_file(&mut buf, fpath, covered, funcs.get(fpath), sources.get(fpath), before, after, true);
        if out.write_all(buf.as_bytes()).is_err() {
            return;
        }
        let _ = out.flush();
    }
}

/// Plain-text form of the same report, what kerncov.log and asmcov.log
/// carry after processing.
pub fn render_text(
    cov: &Cov,
    funcs: &Funcs,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
    sources: &HashMap<String, String>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n{}\n", center(" Coverage Report ", 80, '-')));
    for (fpath, covered) in cov {
        if filter_kw.is_some_and(|kw| !fpath.contains(kw)) {
            continue;
        }
        render_file(&mut out, fpath, covered, funcs.get(fpath), sources.get(fpath), before, after, false);
    }
    out
}

/// One file's hunks: covered lines with -B/-A context and kernel-patch-style
/// `@@ function` headers at each gap.
#[allow(clippy::too_many_arguments)]
fn render_file(
    out: &mut String,
    fpath: &str,
    covered: &BTreeSet<usize>,
    ffuncs: Option<&BTreeMap<usize, String>>,
    content: Option<&String>,
    before: i32,
    after: i32,
    color: bool,
) {
    let (g, r, yb, cy) = if color { (G, R, YB, CY) } else { ("", "", "", "") };
    let before = before.max(0) as usize;
    let after = after.max(0) as usize;
    out.push_str(&format!("\n📄 {yb}{fpath}{r} ({} lines)\n", covered.len()));

    let Some(content) = content else {
        let nums: Vec<String> = covered.iter().map(|n| n.to_string()).collect();
        out.push_str(&format!("   {}\n", nums.join(" ")));
        return;
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
