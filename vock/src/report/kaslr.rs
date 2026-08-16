//! KASLR offset detection and de-randomization (port of report/kaslr.py).

use std::process::{Command, Stdio};

fn addr2line_probe(vmlinux: &str, input: &str) -> String {
    let mut child = match Command::new("addr2line")
        .arg("-e")
        .arg(vmlinux)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(input.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

fn parse_hex(a: &str) -> u64 {
    let s = a.strip_prefix("0x").unwrap_or(a);
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// `_stext` of the *running* kernel from /proc/kallsyms, when readable and
/// not hidden by kptr_restrict.
fn kallsyms_stext() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/kallsyms").ok()?;
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(addr), Some(t), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if name == "_stext" && t.eq_ignore_ascii_case("t") {
            return u64::from_str_radix(addr, 16).ok().filter(|&v| v != 0);
        }
    }
    None
}

/// A named text symbol out of the vmlinux symbol table.
fn vmlinux_sym(vmlinux: &str, want: &str) -> Option<u64> {
    let nm = Command::new("nm").arg(vmlinux).output().ok()?;
    let s = String::from_utf8_lossy(&nm.stdout);
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(addr), Some(t), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if name == want && t.eq_ignore_ascii_case("t") {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

pub fn detect_offset(vmlinux: &str, addrs: &[String]) -> u64 {
    if addrs.is_empty() {
        return 0;
    }
    let norm: Vec<String> = addrs
        .iter()
        .map(|a| {
            if a.starts_with("0x") {
                a.clone()
            } else {
                format!("0x{a}")
            }
        })
        .collect();

    // Try resolving raw addresses first, if they resolve, there's no KASLR.
    let probe_input = norm.iter().take(10).cloned().collect::<Vec<_>>().join("\n");
    let out = addr2line_probe(vmlinux, &probe_input);
    let resolved: Vec<&str> = out.lines().filter(|l| !l.is_empty() && !l.contains("??")).collect();
    if !resolved.is_empty() {
        return 0;
    }

    // Exact method: offset = running kernel _stext (kallsyms) minus the
    // vmlinux _stext. Valid whenever the log was collected on the running
    // kernel, which is vock's normal in-process report flow. The heuristic
    // below cannot be exact: it rounds the sample-to-vmlinux delta to an
    // alignment, and its addr2line probe cannot reject a wrong guess, any
    // address that still lands inside the text range resolves to *some*
    // plausible file, silently attributing coverage to unrelated code.
    if let (Some(run), Some(vml)) = (kallsyms_stext(), vmlinux_sym(vmlinux, "_stext")) {
        let off = run.wrapping_sub(vml);
        // x86 KASLR randomizes the virtual base with 2 MiB granularity; an
        // unaligned diff means the kallsyms/vmlinux pair do not belong
        // together (e.g. resolving a foreign log), so fall through.
        if off & 0x1f_ffff == 0 && (off >> 21) < (1 << 20) {
            return off;
        }
    }

    // Find vmlinux _text / _stext via nm.
    let nm = Command::new("nm").arg(vmlinux).output();
    let mut text_addr: Option<u64> = None;
    if let Ok(nm) = nm {
        let s = String::from_utf8_lossy(&nm.stdout);
        for l in s.lines() {
            if l.contains(" T _text") || l.contains(" T _stext") {
                if let Some(first) = l.split_whitespace().next() {
                    text_addr = u64::from_str_radix(first, 16).ok();
                }
                break;
            }
        }
    }
    let Some(text_addr) = text_addr else {
        return 0;
    };

    let mut code_addrs: Vec<u64> = norm
        .iter()
        .map(|a| parse_hex(a))
        .filter(|&v| v > text_addr)
        .collect();
    if code_addrs.is_empty() {
        return 0;
    }
    code_addrs.sort_unstable();
    let median = code_addrs[code_addrs.len() / 2];
    let diff = median.wrapping_sub(text_addr);

    for shift in [21u32, 24u32] {
        let offset = (diff >> shift) << shift;
        if offset > 0 {
            let test = format!("0x{:x}", median - offset);
            let out = addr2line_probe(vmlinux, &test);
            if !out.is_empty() && !out.contains("??") {
                return offset;
            }
        }
    }
    let offset = (diff >> 24) << 24;
    if offset > 0 {
        offset
    } else {
        0
    }
}

pub fn dekaslr(addrs: &[String], offset: u64) -> Vec<String> {
    if offset == 0 {
        return addrs.to_vec();
    }
    addrs
        .iter()
        .map(|a| format!("0x{:x}", parse_hex(a).wrapping_sub(offset)))
        .collect()
}
