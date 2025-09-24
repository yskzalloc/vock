#!/usr/bin/env python3
import argparse
import subprocess
import re
from os import path
from pathlib import Path
from collections import defaultdict

DEFAULT_KERNEL_SRC = str(Path.home() / "linux")
DEFAULT_VMLINUX = str(Path.home() / "linux" / "vmlinux")

DEFAULT_LOCAL_LOG = "local_coverage.log"
DEFAULT_REMOTE_LOG = "remote_coverage.log"
DEFAULT_MERGED_LOG = "coverage.log"

CONTEXT_LINES = 8

COLOR = {
    "GREEN": '\033[92m',
    "RESET": '\033[0m',
    "YELLOW_BOLD": '\033[1;33m',
    "CYAN": '\033[96m',
    "YELLOW": '\033[93m',
    "RED": '\033[91m'
}


def read_addresses(log_path: Path) -> set[str]:
    if not log_path.is_file():
        return set()
    with log_path.open() as f:
        return {line.strip() for line in f if line.strip()}


def write_addresses(addresses: set[str], out_path: Path):
    with out_path.open("w") as f:
        for addr in sorted(addresses):
            f.write(f"{addr}\n")


def run_addr2line(vmlinux: str, addrs: list[str]) -> list[str]:
    print("\n\033[93m📊 [VOCK] Generating final report...\033[0m\n")
    if not addrs:
        return []
    proc = subprocess.run(
        ["addr2line", "-e", vmlinux],
        input="\n".join(addrs),
        text=True,
        capture_output=True
    )
    if proc.returncode != 0:
        print(f"{COLOR['RED']}addr2line failed{COLOR['RESET']}")
        return []
    return proc.stdout.strip().splitlines()


def aggregate(lines: list[str], kernel_src: str) -> dict[str, set[int]]:
    cov = defaultdict(set)
    for line in lines:
        m = re.match(r"(.+):(\d+)", line)
        if not m:
            continue
        file_path, lineno = m.groups()
        if file_path == "??":
            continue
        try:
            rel = path.relpath(file_path, kernel_src)
        except ValueError:
            rel = file_path
        cov[rel].add(int(lineno))
    return cov


def print_code(file_path: Path, covered: set[int]):
    try:
        with file_path.open(errors="ignore") as f:
            all_lines = f.readlines()
    except FileNotFoundError:
        return False

    lines_to_show = set()
    for ln in covered:
        start = max(1, ln - CONTEXT_LINES)
        end = min(len(all_lines), ln + CONTEXT_LINES)
        for i in range(start, end + 1):
            lines_to_show.add(i)

    last = -1
    for ln in sorted(lines_to_show):
        if ln != last + 1:
            print(f"{COLOR['CYAN']}   ...{COLOR['RESET']}")
        content = all_lines[ln - 1].rstrip()
        if ln in covered:
            print(f"{COLOR['GREEN']}{ln:5d} > {content}{COLOR['RESET']}")
        else:
            print(f"{ln:5d} | {content}")
        last = ln
    print(f"{COLOR['CYAN']}   ...{COLOR['RESET']}")
    return True


def merge_logs(local: Path, remote: Path, out: Path) -> set[str]:
    la = read_addresses(local)
    ra = read_addresses(remote)
    merged = la.union(ra)
    if merged:
        write_addresses(merged, out)
    return merged


def parse_args():
    p = argparse.ArgumentParser(description="VOCK Coverage Reporter")
    p.add_argument("--mode", choices=["local", "remote", "merge"],
                   default="merge", help="coverage mode (default: merge)")
    p.add_argument("--kernel-src", default=DEFAULT_KERNEL_SRC,
                   help=f"kernel source path (default: {DEFAULT_KERNEL_SRC})")
    p.add_argument("--vmlinux", default=DEFAULT_VMLINUX,
                   help=f"vmlinux with debug symbols (default: {DEFAULT_VMLINUX})")
    p.add_argument("--local-log", default=DEFAULT_LOCAL_LOG,
                   help="local coverage log")
    p.add_argument("--remote-log", default=DEFAULT_REMOTE_LOG,
                   help="remote coverage log")
    p.add_argument("--out", default=DEFAULT_MERGED_LOG,
                   help="merged coverage log")
    p.add_argument("--filter", help="only show files containing keyword")
    return p.parse_args()


def main():
    args = parse_args()
    print(" VOCK Coverage Reporter ".center(80, "="))

    local = Path(args.local_log)
    remote = Path(args.remote_log)
    merged = Path(args.out)

    if args.mode == "local":
        addrs = read_addresses(local)
        label = local.name
    elif args.mode == "remote":
        addrs = read_addresses(remote)
        label = remote.name
    else:
        addrs = merge_logs(local, remote, merged)
        label = merged.name

    if not addrs:
        print(f"{COLOR['YELLOW']}no coverage data found{COLOR['RESET']}")
        return

    lines = run_addr2line(args.vmlinux, sorted(addrs))
    cov = aggregate(lines, args.kernel_src)

    print("\n" + " Coverage Report ".center(80, "-"))
    src_root = Path(args.kernel_src)
    for fpath, covered in sorted(cov.items()):
        if args.filter and args.filter not in fpath:
            continue
        full = src_root / fpath
        print(f"📄 {COLOR['YELLOW_BOLD']}{fpath}{COLOR['RESET']} "
              f"({len(covered)} lines)")
        if full.is_file():
            print_code(full, covered)
        else:
            print("   " + " ".join(map(str, sorted(covered))))


if __name__ == "__main__":
    main()

