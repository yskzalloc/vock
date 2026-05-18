"""Resolve kernel addresses to source file:line via addr2line."""
import re
import subprocess
from os import path
from collections import defaultdict


def run_addr2line(vmlinux: str, addrs: list[str]) -> list[str]:
    """Run addr2line and return file:line results."""
    if not addrs or not path.isfile(vmlinux):
        return []
    proc = subprocess.run(
        ["addr2line", "-e", vmlinux],
        input="\n".join(addrs), text=True, capture_output=True
    )
    return proc.stdout.strip().splitlines() if proc.stdout.strip() else []


def aggregate(lines: list[str], kernel_src: str) -> dict[str, set[int]]:
    """Group addr2line output by source file → set of line numbers."""
    cov = defaultdict(set)
    kernel_dirs = {"arch/", "fs/", "net/", "drivers/", "kernel/", "mm/",
                   "block/", "security/", "crypto/", "lib/", "ipc/", "init/",
                   "include/", "sound/", "virt/", "io_uring/"}

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

        if rel.startswith(".."):
            for kd in kernel_dirs:
                idx = file_path.find("/" + kd)
                if idx >= 0:
                    rel = file_path[idx + 1:]
                    break
            else:
                rel = file_path.split("/")[-1] if "/" in file_path else file_path

        cov[rel].add(int(lineno))
    return cov
