//! KASLR offset detection and de-randomization (port of report/kaslr.py).

use super::resolve;

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

fn resolves(locs: &[String]) -> bool {
    locs.iter().any(|l| !l.is_empty() && !l.contains("??"))
}

pub fn detect_offset(vmlinux: &str, pcs: &[u64]) -> u64 {
    if pcs.is_empty() {
        return 0;
    }

    // Try resolving raw addresses first, if they resolve, there's no KASLR.
    let probe = &pcs[..pcs.len().min(10)];
    if resolves(&resolve::probe_locations(vmlinux, probe)) {
        return 0;
    }

    // Exact method: offset = running kernel _stext (kallsyms) minus the
    // vmlinux _stext. Valid whenever the log was collected on the running
    // kernel, which is vock's normal in-process report flow. The heuristic
    // below cannot be exact: it rounds the sample-to-vmlinux delta to an
    // alignment, and its probe cannot reject a wrong guess, any address that
    // still lands inside the text range resolves to *some* plausible file,
    // silently attributing coverage to unrelated code.
    if let (Some(run), Some(vml)) = (kallsyms_stext(), resolve::symbol_address(vmlinux, "_stext")) {
        let off = run.wrapping_sub(vml);
        // x86 KASLR randomizes the virtual base with 2 MiB granularity; an
        // unaligned diff means the kallsyms/vmlinux pair do not belong
        // together (e.g. resolving a foreign log), so fall through.
        if off & 0x1f_ffff == 0 && (off >> 21) < (1 << 20) {
            return off;
        }
    }

    // Heuristic: vmlinux _text / _stext versus the median sampled PC.
    let Some(text_addr) = resolve::symbol_address(vmlinux, "_text")
        .or_else(|| resolve::symbol_address(vmlinux, "_stext"))
    else {
        return 0;
    };
    let mut code_addrs: Vec<u64> = pcs.iter().copied().filter(|&v| v > text_addr).collect();
    if code_addrs.is_empty() {
        return 0;
    }
    code_addrs.sort_unstable();
    let median = code_addrs[code_addrs.len() / 2];
    let diff = median.wrapping_sub(text_addr);

    for shift in [21u32, 24u32] {
        let offset = (diff >> shift) << shift;
        if offset > 0 && resolves(&resolve::probe_locations(vmlinux, &[median - offset])) {
            return offset;
        }
    }
    (diff >> 24) << 24
}
