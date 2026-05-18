"""KASLR offset detection and address de-randomization."""
import subprocess


def detect_kaslr_offset(vmlinux: str, addrs: list[str]) -> int:
    """Detect KASLR offset by comparing runtime addresses to vmlinux symbols."""
    if not addrs:
        return 0

    # Normalize: ensure 0x prefix
    norm = [a if a.startswith("0x") else "0x" + a for a in addrs]

    # Try resolving raw addresses first
    proc = subprocess.run(
        ["addr2line", "-e", vmlinux],
        input="\n".join(norm[:10]), text=True, capture_output=True
    )
    lines = [l for l in proc.stdout.strip().splitlines() if l and "??" not in l]
    if lines:
        return 0  # No KASLR — addresses resolve directly

    # Get vmlinux _text address
    nm = subprocess.run(["nm", vmlinux], capture_output=True, text=True)
    text_addr = None
    for l in nm.stdout.splitlines():
        if " T _text" in l or " T _stext" in l:
            text_addr = int(l.split()[0], 16)
            break

    if not text_addr:
        return 0

    # Filter to addresses likely in kernel text (above _text base)
    code_addrs = [int(a, 16) for a in norm if int(a, 16) > text_addr]
    if not code_addrs:
        return 0

    # Use median address (more robust than min which may be from fixed mappings)
    code_addrs.sort()
    median_addr = code_addrs[len(code_addrs) // 2]

    # Try common KASLR alignment granularities (16MB, 2MB)
    diff = median_addr - text_addr
    for shift in [24, 21]:  # 16MB, 2MB
        offset = (diff >> shift) << shift
        if offset > 0:
            # Verify: try resolving one address with this offset
            test_addr = f"0x{median_addr - offset:x}"
            proc = subprocess.run(
                ["addr2line", "-e", vmlinux],
                input=test_addr, text=True, capture_output=True
            )
            if proc.stdout.strip() and "??" not in proc.stdout:
                return offset
    # Fallback: 16MB aligned
    offset = (diff >> 24) << 24
    return offset if offset > 0 else 0


def dekaslr_addresses(addrs: list[str], offset: int) -> list[str]:
    """Remove KASLR offset from addresses."""
    if offset == 0:
        return addrs
    return [f"0x{int(a if a.startswith('0x') else '0x'+a, 16) - offset:x}" for a in addrs]
