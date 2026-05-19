"""BTF/kallsyms-based kernel PC resolver.

Resolves kernel PCs to function names using /proc/kallsyms.
No vmlinux or addr2line needed — works on any running kernel.
"""

import bisect


def load_kallsyms(path="/proc/kallsyms"):
    """Parse kallsyms into sorted (addr, name) list."""
    syms = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr = int(parts[0], 16)
            if addr == 0:
                continue
            name = parts[2]
            syms.append((addr, name))
    syms.sort(key=lambda x: x[0])
    return syms


def resolve_pc(syms, pc):
    """Find function containing PC (largest addr <= pc)."""
    if isinstance(pc, str):
        pc = int(pc, 16)
    sym_addrs = [s[0] for s in syms]
    idx = bisect.bisect_right(sym_addrs, pc) - 1
    if idx < 0:
        return None
    return syms[idx][1]


def resolve_pcs(pcs, kallsyms_path="/proc/kallsyms"):
    """Resolve a list of PCs to (pc, function_name) pairs."""
    syms = load_kallsyms(kallsyms_path)
    results = []
    for pc in pcs:
        name = resolve_pc(syms, pc)
        results.append((pc, name or "??"))
    return results


def generate_btf_report(pcs, kallsyms_path="/proc/kallsyms"):
    """Generate a function-level coverage report from PCs + kallsyms."""
    syms = load_kallsyms(kallsyms_path)
    if not syms:
        return []

    # Convert PCs to ints
    int_pcs = []
    for pc in pcs:
        if isinstance(pc, str):
            pc = int(pc.replace("0x", "").replace("0X", ""), 16)
        int_pcs.append(pc)

    # Detect KASLR offset: find _text in kallsyms, compare with PC range
    text_addr = None
    for addr, name in syms:
        if name == "_text" or name == "_stext":
            text_addr = addr
            break

    offset = 0
    if text_addr and int_pcs:
        # PCs should be >= _text. If they're below, compute offset.
        min_pc = min(int_pcs)
        if min_pc < text_addr:
            # Assume default _text is 0xffffffff81000000
            offset = text_addr - 0xffffffff81000000
        elif min_pc > syms[-1][0]:
            offset = -(min_pc - text_addr)

    func_hits = {}
    for pc in int_pcs:
        name = resolve_pc(syms, pc + offset)
        if name:
            func_hits[name] = func_hits.get(name, 0) + 1

    # Sort by hit count descending
    ranked = sorted(func_hits.items(), key=lambda x: -x[1])
    return ranked
