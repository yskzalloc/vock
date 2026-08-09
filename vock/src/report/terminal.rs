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
    kernel_src: &str,
    before: i32,
    after: i32,
    filter_kw: Option<&str>,
) {
    let src_root = Path::new(kernel_src);
    let before = before.max(0) as usize;
    let after = after.max(0) as usize;
    println!("\n{}", center(" Coverage Report ", 80, '-'));

    for (fpath, covered) in cov {
        if let Some(kw) = filter_kw {
            if !fpath.contains(kw) {
                continue;
            }
        }
        let full = src_root.join(fpath);
        println!("\n📄 {YB}{fpath}{R} ({} lines)", covered.len());

        let content = match std::fs::read_to_string(&full) {
            Ok(c) => c,
            Err(_) => {
                let nums: Vec<String> = covered.iter().map(|n| n.to_string()).collect();
                println!("   {}", nums.join(" "));
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

        let mut last: i64 = -1;
        for &ln in &show {
            if ln as i64 != last + 1 {
                println!("{CY}   ...{R}");
            }
            let text = if ln <= all_lines.len() {
                all_lines[ln - 1]
            } else {
                ""
            };
            if covered.contains(&ln) {
                println!("{G}{ln:5} > {text}{R}");
            } else {
                println!("{ln:5} | {text}");
            }
            last = ln as i64;
        }
        println!("{CY}   ...{R}");
    }
}
