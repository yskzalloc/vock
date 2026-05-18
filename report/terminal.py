"""Terminal colored coverage output."""
from pathlib import Path

C = {"G": '\033[92m', "R": '\033[0m', "YB": '\033[1;33m', "CY": '\033[96m'}


def print_report(cov: dict[str, set[int]], kernel_src: str,
                 before: int, after: int, filter_kw: str = None):
    """Print coverage to terminal with colors."""
    src_root = Path(kernel_src)
    print("\n" + " Coverage Report ".center(80, "-"))

    for fpath, covered in sorted(cov.items()):
        if filter_kw and filter_kw not in fpath:
            continue
        full = src_root / fpath
        print(f"\n📄 {C['YB']}{fpath}{C['R']} ({len(covered)} lines)")

        if not full.is_file():
            print("   " + " ".join(map(str, sorted(covered))))
            continue

        all_lines = full.read_text(errors="ignore").splitlines()
        show = set()
        for ln in covered:
            for i in range(max(1, ln - before), min(len(all_lines), ln + after) + 1):
                show.add(i)

        last = -1
        for ln in sorted(show):
            if ln != last + 1:
                print(f"{C['CY']}   ...{C['R']}")
            content = all_lines[ln - 1] if ln <= len(all_lines) else ""
            if ln in covered:
                print(f"{C['G']}{ln:5d} > {content}{C['R']}")
            else:
                print(f"{ln:5d} | {content}")
            last = ln
        print(f"{C['CY']}   ...{C['R']}")
