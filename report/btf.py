"""BTF/kallsyms-based kernel PC resolver.

Resolves kernel PCs to function names using /proc/kallsyms.
No vmlinux or addr2line needed — works on any running kernel.
Generates HTML report with highlighted function definitions from kernel source.
"""

import bisect
import os
import re
import subprocess


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
        pc = int(pc.replace("0x", "").replace("0X", ""), 16)
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


def find_function_in_source(func_name, kernel_src):
    """Find function definition in kernel source using grep."""
    if not kernel_src or not os.path.isdir(kernel_src):
        return None, None
    try:
        r = subprocess.run(
            ["grep", "-rn", f"^[a-zA-Z_].*\\b{func_name}\\b(", kernel_src,
             "--include=*.c", "-l"],
            capture_output=True, timeout=5)
        if r.returncode == 0 and r.stdout:
            filepath = r.stdout.decode().strip().split('\n')[0]
            # Get line number
            r2 = subprocess.run(
                ["grep", "-n", f"\\b{func_name}\\b(", filepath],
                capture_output=True, timeout=5)
            if r2.returncode == 0 and r2.stdout:
                line = r2.stdout.decode().strip().split('\n')[0]
                lineno = int(line.split(':')[0])
                relpath = os.path.relpath(filepath, kernel_src)
                return relpath, lineno
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None, None


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


def generate_btf_html(ranked, kernel_src, output_path="coverage.html", ctx=3):
    """Generate HTML report with highlighted function lines from kernel source."""
    html = ['<!DOCTYPE html><html><head><meta charset="utf-8">',
            '<title>vock BTF Coverage Report</title>',
            '<style>',
            'body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}',
            'h1{color:#569cd6} h2{color:#4ec9b0;margin-top:2em}',
            '.func{background:#264f78;padding:2px 6px;border-radius:3px}',
            '.hit{color:#b5cea8} .file{color:#ce9178}',
            'pre{background:#2d2d2d;padding:10px;border-radius:5px;overflow-x:auto}',
            '.cov{background:#2ea04366;display:block}',
            '.line-num{color:#858585;user-select:none;padding-right:1em}',
            '</style></head><body>',
            f'<h1>vock BTF Coverage Report</h1>',
            f'<p>{len(ranked)} kernel functions covered</p>']

    # Group by source file
    file_funcs = {}  # {filepath: [(func, hits, lineno)]}
    unresolved = []

    for func, hits in ranked[:200]:  # top 200 functions
        filepath, lineno = find_function_in_source(func, kernel_src)
        if filepath and lineno:
            file_funcs.setdefault(filepath, []).append((func, hits, lineno))
        else:
            unresolved.append((func, hits))

    # Render each file with highlighted function lines
    for filepath in sorted(file_funcs.keys()):
        funcs = file_funcs[filepath]
        html.append(f'<h2 class="file">{filepath}</h2>')

        fullpath = os.path.join(kernel_src, filepath)
        if not os.path.isfile(fullpath):
            for func, hits, lineno in funcs:
                html.append(f'<p><span class="func">{func}</span> '
                            f'<span class="hit">({hits} hits)</span> line {lineno}</p>')
            continue

        try:
            lines = open(fullpath).readlines()
        except:
            continue

        # Collect line ranges to show (function line ± ctx)
        highlight_lines = set()
        show_lines = set()
        for func, hits, lineno in funcs:
            highlight_lines.add(lineno)
            for l in range(max(1, lineno - ctx), min(len(lines) + 1, lineno + ctx + 1)):
                show_lines.add(l)

        html.append('<pre>')
        sorted_show = sorted(show_lines)
        prev = 0
        for ln in sorted_show:
            if prev and ln > prev + 1:
                html.append('<span class="line-num">...</span>')
            prev = ln
            line_content = lines[ln - 1].rstrip() if ln <= len(lines) else ""
            line_content = line_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            cls = ' class="cov"' if ln in highlight_lines else ''
            # Find which function this highlights
            hit_info = ""
            for func, hits, lineno in funcs:
                if ln == lineno:
                    hit_info = f'  ← {func} ({hits} hits)'
                    break
            html.append(f'<span class="line-num">{ln:>5}</span>'
                        f'<span{cls}>{line_content}{hit_info}</span>')
        html.append('</pre>')

    # Unresolved functions (no source found)
    if unresolved:
        html.append('<h2>Functions (source not found)</h2><pre>')
        for func, hits in unresolved[:50]:
            html.append(f'  {func:<50} {hits:>6} hits')
        html.append('</pre>')

    html.append('</body></html>')

    with open(output_path, 'w') as f:
        f.write('\n'.join(html))
    return output_path
