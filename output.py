#!/usr/bin/env python3
"""vock output — coverage report generator.

Reads kerncov.log, resolves to source via addr2line, outputs coverage.html + terminal.
"""
import argparse
from pathlib import Path
from os import path

from report.kaslr import detect_kaslr_offset, dekaslr_addresses
from report.resolve import run_addr2line, aggregate
from report.html import generate as generate_html
from report.terminal import print_report

DEFAULT_KERNEL_SRC = str(Path.home() / "stable")
DEFAULT_VMLINUX = str(Path.home() / "stable" / "vmlinux")

# Auto-detect kernel source
for _p in [Path.home() / "linux", Path.home() / "stable", Path.home() / "net"]:
    if (_p / "vmlinux").is_file():
        DEFAULT_KERNEL_SRC = str(_p)
        DEFAULT_VMLINUX = str(_p / "vmlinux")
        break


def read_addresses(log_path: Path) -> set[str]:
    if not log_path.is_file():
        return set()
    with log_path.open() as f:
        addrs = set()
        for line in f:
            a = line.strip()
            if a:
                addrs.add(a if a.startswith("0x") else "0x" + a)
        return addrs


def read_addresses_ordered(log_path: Path) -> list[str]:
    """Read addresses preserving execution order (with duplicates)."""
    if not log_path.is_file():
        return []
    with log_path.open() as f:
        addrs = []
        for line in f:
            a = line.strip()
            if a:
                addrs.append(a if a.startswith("0x") else "0x" + a)
        return addrs


def parse_args():
    p = argparse.ArgumentParser(description="VOCK Coverage Reporter")
    p.add_argument("--kernel-src", default=DEFAULT_KERNEL_SRC)
    p.add_argument("--vmlinux", default=DEFAULT_VMLINUX)
    p.add_argument("--log", default="kerncov.log", help="coverage log file")
    p.add_argument("--filter", help="only show files containing keyword")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-A", type=int, default=4, help="context lines after")
    p.add_argument("-B", type=int, default=4, help="context lines before")
    p.add_argument("-o", "--output", default="coverage.html")
    p.add_argument("--btf", action="store_true",
                   help="resolve PCs via /proc/kallsyms (no vmlinux needed)")
    p.add_argument("--ordered", action="store_true",
                   help="preserve execution order in output (no dedup)")
    return p.parse_args()


def main():
    args = parse_args()

    if args.kernel_src != DEFAULT_KERNEL_SRC and args.vmlinux == DEFAULT_VMLINUX:
        args.vmlinux = str(Path(args.kernel_src) / "vmlinux")

    if not args.quiet:
        print(" VOCK Coverage Reporter ".center(80, "="))

    # Ordered mode: preserve execution sequence
    if args.ordered:
        addrs = read_addresses_ordered(Path(args.log))
        if not addrs:
            if not args.quiet:
                print("\033[93mno coverage data found\033[0m")
            return
        if not args.quiet:
            print(f"\n\033[93m📊 [VOCK] Ordered report ({len(addrs)} PCs)\033[0m\n")
        offset = detect_kaslr_offset(args.vmlinux, addrs[:100])
        addrs = dekaslr_addresses(addrs, offset)
        lines = run_addr2line(args.vmlinux, addrs)
        # Generate ordered HTML: list of source locations in execution order
        with open(args.output, "w") as f:
            f.write("<!DOCTYPE html><html><head><meta charset='utf-8'>\n")
            f.write("<title>vock ordered coverage</title>\n")
            f.write("<style>body{background:#1e1e1e;color:#d4d4d4;font-family:monospace;padding:20px}")
            f.write("table{border-collapse:collapse;width:100%}")
            f.write("td,th{padding:4px 8px;border-bottom:1px solid #333;text-align:left}")
            f.write("th{background:#264f78;color:#fff}")
            f.write(".func{color:#dcdcaa}.file{color:#9cdcfe}.line{color:#b5cea8}")
            f.write("</style></head><body>\n")
            f.write(f"<h2>Ordered Kernel Execution Trace ({len(addrs)} PCs)</h2>\n")
            f.write("<table><tr><th>#</th><th>Address</th><th>Function</th><th>Source</th></tr>\n")
            for i, loc in enumerate(lines):
                parts = loc.split(" ", 1) if " " in loc else [loc, ""]
                func = parts[0] if parts else "??"
                src = parts[1] if len(parts) > 1 else ""
                addr = addrs[i] if i < len(addrs) else ""
                f.write(f"<tr><td>{i+1}</td><td>{addr}</td>")
                f.write(f"<td class='func'>{func}</td>")
                f.write(f"<td class='file'>{src}</td></tr>\n")
            f.write("</table></body></html>\n")
        if not args.quiet:
            print(f"\033[92m✓ Written: {args.output} (ordered, {len(addrs)} entries)\033[0m")
        return

    addrs = sorted(read_addresses(Path(args.log)))
    if not addrs:
        if not args.quiet:
            print("\033[93mno coverage data found\033[0m")
        return

    # BTF mode: resolve via /proc/kallsyms, no vmlinux needed
    if args.btf:
        from report.btf import generate_btf_report, generate_btf_html
        ranked = generate_btf_report(addrs)
        if not args.quiet:
            print(f"\n\033[93m📊 [VOCK] BTF report ({len(addrs)} PCs → {len(ranked)} functions)\033[0m\n")
            print(f"  {'Function':<50} {'Hits':>6}")
            print(f"  {'─'*50} {'─'*6}")
            for name, hits in ranked[:50]:
                print(f"  {name:<50} {hits:>6}")
            if len(ranked) > 50:
                print(f"  ... and {len(ranked)-50} more functions")
            print(f"\n\033[92m✓ {len(ranked)} kernel functions covered\033[0m")

        # Generate HTML with highlighted source lines if kernel-src available
        kernel_src = args.kernel_src if args.kernel_src != DEFAULT_KERNEL_SRC else None
        if kernel_src and path.isdir(kernel_src):
            generate_btf_html(ranked, kernel_src, args.output)
            if not args.quiet:
                print(f"\033[92m✓ Written: {args.output} (source-highlighted)\033[0m")
        else:
            # Fallback: text-only report
            txt_path = args.output.replace(".html", ".txt")
            with open(txt_path, "w") as f:
                for name, hits in ranked:
                    f.write(f"{name}\t{hits}\n")
            if not args.quiet:
                print(f"\033[92m✓ Written: {txt_path}\033[0m")
        return

    # KASLR detection
    if not args.quiet:
        print(f"\n\033[93m📊 [VOCK] Generating coverage report...\033[0m\n")

    offset = detect_kaslr_offset(args.vmlinux, addrs)
    if offset and not args.quiet:
        print(f"  KASLR detected: offset 0x{offset:x}")
    addrs = dekaslr_addresses(addrs, offset)

    # Resolve addresses
    lines = run_addr2line(args.vmlinux, addrs)
    cov = aggregate(lines, args.kernel_src)
    if not cov:
        if not args.quiet:
            print("\033[93mno source lines resolved\033[0m")
        return

    # HTML output
    generate_html(cov, args.kernel_src, args.B, args.A, args.output, args.filter)
    if not args.quiet:
        print(f"\n\033[92m✓ Written: {args.output}\033[0m")

    # Terminal output
    if not args.quiet:
        print_report(cov, args.kernel_src, args.B, args.A, args.filter)


if __name__ == "__main__":
    main()
