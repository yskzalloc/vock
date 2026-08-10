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

    // Try resolving raw addresses first — if they resolve, there's no KASLR.
    let probe_input = norm.iter().take(10).cloned().collect::<Vec<_>>().join("\n");
    let out = addr2line_probe(vmlinux, &probe_input);
    let resolved: Vec<&str> = out.lines().filter(|l| !l.is_empty() && !l.contains("??")).collect();
    if !resolved.is_empty() {
        return 0;
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

    for shift in [24u32, 21u32] {
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
