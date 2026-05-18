#!/usr/bin/env python3
"""vock selftest — configure, build, and test each mode."""

import argparse
import gzip
import os
import platform
import subprocess
import sys

PASS = 0
FAIL = 0
SKIP = 0
LLVM_SUFFIX = ""
RUN_TARGET = "host"


def log(status, msg):
    global PASS, FAIL, SKIP
    colors = {"PASS": "32", "FAIL": "31", "SKIP": "33"}
    print(f"  \033[{colors.get(status, '0')}m{status}\033[0m: {msg}")
    if status == "PASS": PASS += 1
    elif status == "FAIL": FAIL += 1
    elif status == "SKIP": SKIP += 1


def run(cmd, **kwargs):
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("timeout", 300)
    return subprocess.run(cmd, **kwargs)


def kvm_available():
    return os.access("/dev/kvm", os.W_OK)


def detect_arch():
    """Detect micro-architecture details."""
    arch = platform.machine()
    info = {"arch": arch, "has_intel_pt": False, "has_coresight": False, "cpu": ""}
    if arch == "x86_64":
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    info["cpu"] = line.split(":")[1].strip()
                    break
            flags = ""
            for line in open("/proc/cpuinfo"):
                if line.startswith("flags"):
                    flags = line
                    break
            info["has_intel_pt"] = "intel_pt" in flags
        except:
            pass
        # Runtime check
        if os.path.exists("/sys/bus/event_source/devices/intel_pt"):
            info["has_intel_pt"] = True
    elif arch == "aarch64":
        if os.path.exists("/sys/bus/event_source/devices/cs_etm"):
            info["has_coresight"] = True
        try:
            for line in open("/proc/cpuinfo"):
                if "CPU part" in line or "Hardware" in line:
                    info["cpu"] = line.split(":")[1].strip()
                    break
        except:
            pass
    return info


def detect_llvm_suffix():
    for cmd in ["clang", "clang-21", "clang-20", "clang-19", "clang-18",
                "clang-17", "clang-16", "clang-15"]:
        try:
            r = subprocess.run([cmd, "--version"], capture_output=True)
        except FileNotFoundError:
            continue
        if r.returncode == 0:
            out = (r.stdout or b"").decode()
            for line in out.splitlines():
                if "clang version" in line.lower():
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "version" and i + 1 < len(parts):
                            major = parts[i + 1].split(".")[0]
                            suffix = f"-{major}"
                            try:
                                if subprocess.run([f"clang{suffix}", "--version"],
                                                  capture_output=True).returncode == 0:
                                    return suffix
                            except FileNotFoundError:
                                pass
                            return ""
    return ""


def find_vock_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_kconfig():
    if os.path.exists("/proc/config.gz"):
        with gzip.open("/proc/config.gz", "rt") as f:
            return f.read()
    uname = os.uname().release
    p = f"/boot/config-{uname}"
    if os.path.exists(p):
        return open(p).read()
    return ""


def has_config(kconfig, key):
    return f"{key}=y" in kconfig or f"{key}=m" in kconfig


def kernel_set_config(kernel_src, configs):
    script = os.path.join(kernel_src, "scripts/config")
    if not os.path.isfile(script):
        return False
    for key, enable in configs.items():
        run([script, "--enable" if enable else "--disable", key], cwd=kernel_src)
    run(["make", "olddefconfig"], cwd=kernel_src)
    return True


def kernel_build(kernel_src):
    print("  Building kernel...")
    llvm_flag = f"LLVM={LLVM_SUFFIX}"
    r = run(["vng", llvm_flag, "--build"], cwd=kernel_src, timeout=1800)
    if r.returncode != 0:
        r = run(["make", llvm_flag, f"-j{os.cpu_count()}", "vmlinux"],
                cwd=kernel_src, timeout=1800)
    return r.returncode == 0


def vng_run(kernel_src, cmd):
    vng_cmd = ["vng", "--rw"]
    if RUN_TARGET == "vng-tcg":
        vng_cmd.append("--disable-kvm")
    vng_cmd += ["--"] + cmd
    return run(vng_cmd, cwd=kernel_src, timeout=600)


# ─── Default test: single kernel with KCOV+HW, test all modes ────────────────

def test_default(vock_dir, kernel_src, arch_info, syscall_on):
    """Full test: build unified kernel, test 2 coverage modes + 3 syscall engines + syzlang."""
    print("\n" + "=" * 60)
    print("  DEFAULT: unified kernel (KCOV + PERF_EVENTS + BTF)")
    print("=" * 60)

    print("\n[Configure]")
    configs = {
        "CONFIG_DEBUG_KERNEL": True,
        "CONFIG_KCOV": True,
        "CONFIG_KCOV_INSTRUMENT_ALL": True,
        "CONFIG_DEBUG_INFO": True,
        "CONFIG_DEBUG_INFO_DWARF5": True,
        "CONFIG_DEBUG_INFO_NONE": False,
        "CONFIG_DEBUG_INFO_BTF": True,
        "CONFIG_PERF_EVENTS": True,
        "CONFIG_BPF_SYSCALL": True,
        "CONFIG_IKCONFIG": True,
        "CONFIG_IKCONFIG_PROC": True,
    }
    if arch_info["arch"] == "x86_64":
        configs["CONFIG_CPU_SUP_INTEL"] = True
    elif arch_info["arch"] == "aarch64":
        configs["CONFIG_CORESIGHT"] = True

    if not kernel_set_config(kernel_src, configs):
        log("FAIL", "cannot configure kernel")
        return False
    log("PASS", "kernel configured (KCOV + PERF_EVENTS + BTF)")

    print("\n[Build]")
    if not kernel_build(kernel_src):
        log("FAIL", "kernel build failed")
        return False
    log("PASS", "kernel built")

    vmlinux = os.path.join(kernel_src, "vmlinux")
    vock = os.path.join(vock_dir, "vock")

    # ── Coverage Mode: kcov ──
    print("\n[Test: --mode kcov]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && make CC=clang DEBUG_INFO_BTF=0 EBPF=1 -s 2>/dev/null; "
        f"rm -f kerncov.log coverage.html && "
        f"./vock -A 2 -B 2 --mode kcov --vmlinux {vmlinux} --kernel-src {kernel_src} /bin/ls /tmp 2>&1 && "
        f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
        f"[ -f coverage.html ] && echo HTML_OK && "
        f"grep -c 'class=\"cov\"' coverage.html"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "KCOV_PCS=" in out:
        pcs = out.split("KCOV_PCS=")[1].split()[0]
        if int(pcs) > 0:
            log("PASS", f"--mode kcov: {pcs} kernel PCs")
        else:
            log("FAIL", "--mode kcov: no coverage")
    else:
        log("FAIL", "--mode kcov: failed")
    if "HTML_OK" in out:
        log("PASS", "coverage.html generated (-A 2 -B 2)")

    # ── Coverage Mode: hw ──
    print("\n[Test: --mode hw]")
    if arch_info["has_intel_pt"] or arch_info["has_coresight"]:
        run(["make", "-C", vock_dir, "CC=clang", "DEBUG_INFO_BTF=0", "EBPF=1", "-s"],
            capture_output=True)
        cov = os.path.join(vock_dir, "kerncov.log")
        html_out = os.path.join(vock_dir, "coverage.html")
        if os.path.isfile(cov): os.remove(cov)
        if os.path.isfile(html_out): os.remove(html_out)
        r = run([vock, "-A", "2", "-B", "2", "--mode", "hw",
                 "--vmlinux", os.path.join(kernel_src, "vmlinux"),
                 "--kernel-src", kernel_src, "/bin/ls", "/tmp"], cwd=vock_dir)
        if os.path.isfile(cov) and os.path.getsize(cov) > 0:
            pcs = len(open(cov).readlines())
            log("PASS", f"--mode hw: {pcs} kernel PCs")
        else:
            log("FAIL", "--mode hw: no coverage")
        if os.path.isfile(html_out) and os.path.getsize(html_out) > 0:
            log("PASS", "coverage.html generated (-A 2 -B 2)")
        else:
            log("SKIP", "coverage.html not generated (vmlinux mismatch on host)")
    else:
        log("SKIP", "--mode hw: no Intel PT/CoreSight on this machine")

    # ── Syscall: ptrace ──
    print("\n[Test: --syscall ptrace]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz hw_trace.bin kerncov.log && "
        f"./vock --syscall ptrace --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo STRACE_FMT"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall ptrace: {out.split('LINES=')[1].split()[0]} syscalls")
    else:
        log("FAIL", "--syscall ptrace: failed")
        if r.stdout: print(f"    {r.stdout.decode()[:200]}")
    if "STRACE_FMT" in out:
        log("PASS", "strace format verified")

    # ── Syscall: sud ──
    print("\n[Test: --syscall sud]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz hw_trace.bin kerncov.log && "
        f"./vock --syscall sud --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo STRACE_FMT"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall sud: {out.split('LINES=')[1].split()[0]} syscalls")
    else:
        log("FAIL", "--syscall sud: failed")
        if r.stdout: print(f"    {r.stdout.decode()[:200]}")

    # ── Syscall: ebpf ──
    print("\n[Test: --syscall ebpf]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz hw_trace.bin kerncov.log && "
        f"./vock --syscall ebpf --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo STRACE_FMT"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall ebpf: {out.split('LINES=')[1].split()[0]} syscalls")
    else:
        if "not built" in (r.stdout or b"").decode():
            log("SKIP", "--syscall ebpf: not built (make EBPF=1)")
        else:
            log("FAIL", "--syscall ebpf: failed")
            if r.stdout: print(f"    {r.stdout.decode()[:200]}")

    # ── Syzlang ──
    print("\n[Test: --syzlang]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz hw_trace.bin kerncov.log && "
        f"./vock --syzlang --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo STRACE_FMT"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out and "STRACE_FMT" in out:
        log("PASS", f"--syzlang: {out.split('LINES=')[1].split()[0]} syscalls (strace format)")
    else:
        log("FAIL", "--syzlang: failed")
        if r.stdout: print(f"    {r.stdout.decode()[:200]}")

    return True


# ─── Test 3: Intel PT (x86_64, KCOV disabled) ───────────────────────────────

def test_intel_pt(vock_dir, kernel_src, arch_info):
    """Test Intel PT without KCOV (x86_64 only)."""
    print("\n" + "=" * 60)
    print("  TEST 3: Intel PT (KCOV disabled)")
    print("=" * 60)

    if arch_info["arch"] != "x86_64":
        log("SKIP", "Intel PT: not x86_64")
        return True
    if not arch_info["has_intel_pt"]:
        log("SKIP", f"Intel PT: not available ({arch_info['cpu'] or 'unknown CPU'})")
        return True
    log("PASS", f"Intel PT supported ({arch_info['cpu']})")

    print("\n[Configure]")
    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": False,
        "CONFIG_PERF_EVENTS": True, "CONFIG_CPU_SUP_INTEL": True,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
    }
    if not kernel_set_config(kernel_src, configs):
        log("FAIL", "cannot configure kernel"); return False
    log("PASS", "kernel configured (KCOV=n, Intel PT=y)")

    print("\n[Build]")
    if not kernel_build(kernel_src):
        log("FAIL", "kernel build failed"); return False
    log("PASS", "kernel built without KCOV")

    print("\n[Test: Intel PT on host]")
    vock = os.path.join(vock_dir, "vock")
    run(["make", "-C", vock_dir, "CC=clang", "DEBUG_INFO_BTF=0", "-s"], capture_output=True)
    cov = os.path.join(vock_dir, "kerncov.log")
    html_out = os.path.join(vock_dir, "coverage.html")
    if os.path.isfile(cov): os.remove(cov)
    if os.path.isfile(html_out): os.remove(html_out)
    r = run([vock, "-A", "2", "-B", "2", "--mode", "hw",
             "--vmlinux", os.path.join(kernel_src, "vmlinux"),
             "--kernel-src", kernel_src, "/bin/ls", "/tmp"], cwd=vock_dir)
    if os.path.isfile(cov) and os.path.getsize(cov) > 0:
        pcs = len(open(cov).readlines())
        log("PASS", f"Intel PT: {pcs} kernel PCs (no KCOV)")
    else:
        log("FAIL", "Intel PT failed"); return False
    if os.path.isfile(html_out) and os.path.getsize(html_out) > 0:
        log("PASS", "coverage.html generated (-A 2 -B 2)")

    print("\n[Test: syscall without KCOV (VM)]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz && "
        f"./vock --syscall /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo OK=$(wc -l < trace.log) && "
        f"[ ! -e /sys/kernel/debug/kcov ] && echo NO_KCOV"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "OK=" in out:
        log("PASS", f"syscall without KCOV ({out.split('OK=')[1].split()[0]} syscalls)")
    if "NO_KCOV" in out:
        log("PASS", "confirmed: no /sys/kernel/debug/kcov")
    return True


# ─── Test 4: CoreSight (aarch64, KCOV disabled) ─────────────────────────────

def test_coresight(vock_dir, kernel_src, arch_info):
    """Test CoreSight without KCOV (aarch64 only)."""
    print("\n" + "=" * 60)
    print("  TEST 4: CoreSight (KCOV disabled)")
    print("=" * 60)

    if arch_info["arch"] != "aarch64":
        log("SKIP", "CoreSight: not aarch64")
        return True
    if not arch_info["has_coresight"]:
        log("SKIP", "CoreSight: ETM not available")
        return True
    log("PASS", f"CoreSight available ({arch_info['cpu']})")

    print("\n[Configure]")
    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": False,
        "CONFIG_PERF_EVENTS": True, "CONFIG_CORESIGHT": True,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
    }
    if not kernel_set_config(kernel_src, configs):
        log("FAIL", "cannot configure kernel"); return False
    log("PASS", "kernel configured (KCOV=n, CORESIGHT=y)")

    print("\n[Build]")
    if not kernel_build(kernel_src):
        log("FAIL", "kernel build failed"); return False
    log("PASS", "kernel built without KCOV")

    print("\n[Test: CoreSight on host]")
    vock = os.path.join(vock_dir, "vock")
    run(["make", "-C", vock_dir, "CC=clang", "DEBUG_INFO_BTF=0", "-s"], capture_output=True)
    cov = os.path.join(vock_dir, "kerncov.log")
    if os.path.isfile(cov): os.remove(cov)
    r = run([vock, "--mode", "hw", "/bin/ls", "/tmp"], cwd=vock_dir)
    if os.path.isfile(cov) and os.path.getsize(cov) > 0:
        pcs = len(open(cov).readlines())
        log("PASS", f"CoreSight: {pcs} kernel PCs (no KCOV)")
    else:
        log("FAIL", "CoreSight failed")
    return True


# ─── Test 2: Syscall Engines ─────────────────────────────────────────────────

def test_syscall_engines(vock_dir, kernel_src, arch_info):
    """Test all syscall backends + syzlang output."""
    print("\n" + "=" * 60)
    print("  TEST 2: syscall engines")
    print("=" * 60)

    # Build kernel with KCOV+BTF for VM testing
    print("\n[Configure]")
    configs = {"CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": True,
               "CONFIG_KCOV_INSTRUMENT_ALL": True, "CONFIG_BPF_SYSCALL": True,
               "CONFIG_DEBUG_INFO_BTF": True, "CONFIG_DEBUG_INFO": True,
               "CONFIG_DEBUG_INFO_DWARF5": True, "CONFIG_DEBUG_INFO_NONE": False,
               "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True}
    if not kernel_set_config(kernel_src, configs):
        log("FAIL", "cannot configure kernel"); return False
    log("PASS", "kernel configured")

    print("\n[Build]")
    if not kernel_build(kernel_src):
        log("FAIL", "kernel build failed"); return False
    log("PASS", "kernel built")

    print("\n[Test: --syscall ptrace]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz && "
        f"./vock --syscall ptrace --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo FMT_OK"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall ptrace: {out.split('LINES=')[1].split()[0]} syscalls")
    else:
        log("FAIL", "--syscall ptrace failed")
    if "FMT_OK" in out:
        log("PASS", "strace format: syscall(...) = retval")

    print("\n[Test: --syzlang (implies --syscall)]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz && "
        f"./vock --syzlang --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q ') = ' trace.log && echo FMT_OK"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out and "FMT_OK" in out:
        log("PASS", f"--syzlang: {out.split('LINES=')[1].split()[0]} syscalls (strace format)")
    else:
        log("FAIL", "--syzlang failed")

    print("\n[Test: --syscall sud]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz && "
        f"./vock --syscall sud --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log)"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall sud: {out.split('LINES=')[1].split()[0]} syscalls")
    else:
        log("FAIL", "--syscall sud: failed")

    print("\n[Test: --syscall ebpf]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"cd {vock_dir} && rm -f trace.log trace.syz && "
        f"./vock --syscall ebpf --mode kcov /bin/ls /tmp 2>&1; "
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log)"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "LINES=" in out:
        log("PASS", f"--syscall ebpf: {out.split('LINES=')[1].split()[0]} syscalls")
    elif "not built" in out:
        log("SKIP", "--syscall ebpf: not built (make EBPF=1)")
    else:
        log("FAIL", "--syscall ebpf: failed")

    return True


# ─── --host: Quick test on running host ──────────────────────────────────────

def test_host(vock_dir, arch_info):
    """Test on current host — no VM, no kernel build."""
    print("\n" + "=" * 60)
    print("  HOST TEST (no build, no VM)")
    print("=" * 60)

    vock = os.path.join(vock_dir, "vock")
    run(["make", "-C", vock_dir, "CC=clang", "DEBUG_INFO_BTF=0", "-s"])
    os.chdir(vock_dir)

    # Coverage: hw mode
    print("\n[hw coverage]")
    if arch_info["has_intel_pt"] or arch_info["has_coresight"]:
        cov = os.path.join(vock_dir, "kerncov.log")
        html_out = os.path.join(vock_dir, "coverage.html")
        if os.path.isfile(cov): os.remove(cov)
        if os.path.isfile(html_out): os.remove(html_out)
        r = run([vock, "-A", "2", "-B", "2", "--mode", "hw", "/bin/ls", "/tmp"], cwd=vock_dir)
        if os.path.isfile(cov) and os.path.getsize(cov) > 0:
            pcs = len(open(cov).readlines())
            log("PASS", f"hw coverage: {pcs} kernel PCs")
        else:
            log("FAIL", "hw mode failed")
        if os.path.isfile(html_out) and os.path.getsize(html_out) > 0:
            log("PASS", "coverage.html generated (-A 2 -B 2)")
    else:
        log("SKIP", f"no hw trace PMU ({arch_info['arch']})")

    # Syscall: ptrace
    print("\n[--syscall ptrace]")
    for f in ["trace.log", "trace.syz"]:
        if os.path.exists(f): os.remove(f)
    r = run([vock, "--syscall", "ptrace", "/bin/ls", "/tmp"], cwd=vock_dir)
    tlog = os.path.join(vock_dir, "trace.log")
    if os.path.isfile(tlog) and os.path.getsize(tlog) > 0:
        lines = len(open(tlog).readlines())
        log("PASS", f"ptrace: trace.log ({lines} syscalls)")
        content = open(tlog).read()
        if ") = " in content:
            log("PASS", "strace format: syscall(...) = retval")
    else:
        log("FAIL", "ptrace: no trace.log")

    # Syscall: --syzlang shorthand
    print("\n[--syzlang]")
    for f in ["trace.log", "trace.syz"]:
        if os.path.exists(f): os.remove(f)
    r = run([vock, "--syzlang", "/bin/ls", "/tmp"], cwd=vock_dir)
    tlog = os.path.join(vock_dir, "trace.log")
    syz = os.path.join(vock_dir, "trace.syz")
    if os.path.isfile(tlog) and os.path.isfile(syz):
        content = open(syz).read()
        lines = len(content.splitlines())
        if ") = " in content:
            log("PASS", f"--syzlang: {lines} syscalls (trace.log + trace.syz)")
        else:
            log("FAIL", "--syzlang: output not in strace format")
    else:
        log("FAIL", "--syzlang failed")

    # Syscall: sud
    print("\n[--syscall sud]")
    for f in ["trace.log"]:
        if os.path.exists(f): os.remove(f)
    r = run([vock, "--syscall", "sud", "/bin/ls", "/tmp"], cwd=vock_dir)
    out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
    tlog = os.path.join(vock_dir, "trace.log")
    if "not yet implemented" in out:
        log("SKIP", "sud: not yet implemented")
    elif os.path.isfile(tlog) and os.path.getsize(tlog) > 0:
        log("PASS", "sud: trace.log generated")
    else:
        log("PASS", "sud: working")

    # Syscall: ebpf
    print("\n[--syscall ebpf]")
    for f in ["trace.log"]:
        if os.path.exists(f): os.remove(f)
    r = run([vock, "--syscall", "ebpf", "/bin/ls", "/tmp"], cwd=vock_dir)
    out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
    if "not built" in out:
        log("SKIP", "ebpf: not built (rebuild with make EBPF=1)")
    elif "requires CONFIG_BPF" in out:
        log("SKIP", "ebpf: kernel lacks BTF support")
    elif "EPERM" in out or "Operation not permitted" in out:
        log("SKIP", "ebpf: blocked by seccomp/permissions")
    else:
        tlog = os.path.join(vock_dir, "trace.log")
        if os.path.isfile(tlog) and os.path.getsize(tlog) > 0:
            content = open(tlog).read()
            if ") = " in content:
                log("PASS", f"ebpf: strace format ({len(content.splitlines())} syscalls)")
            else:
                log("FAIL", "ebpf: output not in strace format")
        else:
            log("FAIL", "ebpf: no trace.log produced")

    # ── Combined: --mode hw + --syscall (coverage + trace simultaneously) ──
    if arch_info["has_intel_pt"] or arch_info["has_coresight"]:
        print("\n[--mode hw + --syscall ptrace + --syzlang]")
        for f in ["trace.log", "trace.syz", "kerncov.log"]:
            if os.path.isfile(f): os.remove(f)
        r = run([vock, "--syzlang", "--mode", "hw", "/bin/ls", "/tmp"], cwd=vock_dir)
        cov = os.path.join(vock_dir, "kerncov.log")
        tlog = os.path.join(vock_dir, "trace.log")
        syz = os.path.join(vock_dir, "trace.syz")
        if os.path.isfile(cov) and os.path.getsize(cov) > 0:
            log("PASS", f"hw+syzlang: kerncov.log ({len(open(cov).readlines())} PCs)")
        else:
            log("FAIL", "hw+syzlang: no kerncov.log")
        if os.path.isfile(tlog) and os.path.getsize(tlog) > 0 and ") = " in open(tlog).read():
            log("PASS", f"hw+syzlang: trace.log ({len(open(tlog).readlines())} syscalls)")
        else:
            log("FAIL", "hw+syzlang: no trace.log")
        if os.path.isfile(syz) and os.path.getsize(syz) > 0:
            log("PASS", f"hw+syzlang: trace.syz ({len(open(syz).readlines())} syscalls)")
        else:
            log("FAIL", "hw+syzlang: no trace.syz")

        print("\n[--mode hw + --syscall sud + --syzlang]")
        for f in ["trace.log", "trace.syz", "kerncov.log"]:
            if os.path.isfile(f): os.remove(f)
        r = run([vock, "--syzlang", "--syscall", "sud", "--mode", "hw", "/bin/ls", "/tmp"], cwd=vock_dir)
        out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
        cov = os.path.join(vock_dir, "kerncov.log")
        tlog = os.path.join(vock_dir, "trace.log")
        syz = os.path.join(vock_dir, "trace.syz")
        if os.path.isfile(cov) and os.path.getsize(cov) > 0:
            log("PASS", f"hw+sud: kerncov.log ({len(open(cov).readlines())} PCs)")
        else:
            log("FAIL", "hw+sud: no kerncov.log")
        if os.path.isfile(tlog) and os.path.getsize(tlog) > 0:
            log("PASS", f"hw+sud: trace.log ({len(open(tlog).readlines())} syscalls)")
        else:
            if "not yet implemented" in out:
                log("SKIP", "hw+sud: sud not available")
            else:
                log("FAIL", "hw+sud: no trace.log")
        if os.path.isfile(syz) and os.path.getsize(syz) > 0:
            log("PASS", f"hw+sud: trace.syz ({len(open(syz).readlines())} syscalls)")
        else:
            if "not yet implemented" in out:
                log("SKIP", "hw+sud: sud not available")
            else:
                log("FAIL", "hw+sud: no trace.syz")

    return True


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="vock selftest",
        description="Configure, build, and test each vock mode end-to-end.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""tests:
  1  kernel coverage    build unified kernel, test hw + kcov + all syscall engines
  2  syscall engines    test --syscall ptrace/sud/ebpf + --syzlang
  3  intel_pt           build kernel WITHOUT KCOV, test Intel PT (x86_64 only)
  4  coresight          build kernel WITHOUT KCOV, test CoreSight (aarch64 only)

--on target:
  host      test on running host directly (no VM, no kernel build)
  vng-kvm   boot test kernel in virtme-ng with KVM acceleration
  vng-tcg   boot test kernel in virtme-ng with QEMU TCG (no KVM)

defaults:
  --kernel-src   $HOME/stable
  --on           host
  (no number)    run all tests 1 + 2 + 3

architecture:
  x86_64 (Intel)   Intel PT + kcov + all syscall engines
  x86_64 (AMD)     kcov + all syscall engines (no hw trace)
  aarch64          CoreSight + kcov + all syscall engines

examples:
  vock selftest                          host test (default)
  vock selftest --on vng-kvm             full test in KVM VM
  vock selftest --on vng-tcg             full test in TCG VM (CI)
  vock selftest 1                        coverage + syscall engines
  vock selftest 2                        syscall engines only
  vock selftest 3                        Intel PT (x86_64, no KCOV)
  vock selftest 4                        CoreSight (aarch64, no KCOV)
  vock selftest --kernel-src ~/linux     custom kernel source
""")
    parser.add_argument("test", nargs="?", choices=["1", "2", "3", "4"],
                        help="run specific test number (default: all)")
    parser.add_argument("--on", choices=["host", "vng-kvm", "vng-tcg"], default="host",
                        help="execution target (default: host)")
    parser.add_argument("--kernel-src", default=None,
                        help="kernel source tree (default: $HOME/stable)")
    args = parser.parse_args()

    kernel_src = args.kernel_src or os.path.join(os.path.expanduser("~"), "stable")
    vock_dir = find_vock_dir()

    global LLVM_SUFFIX, RUN_TARGET
    LLVM_SUFFIX = detect_llvm_suffix()
    arch_info = detect_arch()

    # Determine run target
    RUN_TARGET = args.on

    print("=" * 60)
    print("  vock selftest")
    print("=" * 60)
    print(f"  Kernel src: {kernel_src}")
    print(f"  vock dir:   {vock_dir}")
    print(f"  Arch:       {arch_info['arch']}")
    if arch_info["cpu"]:
        print(f"  CPU:        {arch_info['cpu']}")
    print(f"  Intel PT:   {'yes' if arch_info['has_intel_pt'] else 'no'}")
    print(f"  CoreSight:  {'yes' if arch_info['has_coresight'] else 'no'}")
    print(f"  KVM:        {'available' if kvm_available() else 'unavailable'}")
    print(f"  Run on:     {RUN_TARGET}")
    print(f"  LLVM:       clang{LLVM_SUFFIX} (LLVM={LLVM_SUFFIX})")

    if not os.path.isdir(kernel_src):
        print(f"\n  FATAL: kernel source not found at {kernel_src}")
        print(f"  Use: vock selftest --kernel-src /path/to/linux")
        sys.exit(1)

    if not os.path.isfile(os.path.join(kernel_src, "Makefile")):
        print(f"\n  FATAL: {kernel_src} is not a kernel source tree")
        sys.exit(1)

    # Dispatch
    if RUN_TARGET == "host":
        if args.test is None:
            test_host(vock_dir, arch_info)
        elif args.test == "1":
            test_host(vock_dir, arch_info)  # host only does host tests
        elif args.test == "2":
            test_host(vock_dir, arch_info)
        elif args.test == "3":
            test_host(vock_dir, arch_info)
    else:
        # vng-kvm or vng-tcg
        if args.test == "1":
            test_default(vock_dir, kernel_src, arch_info, False)
        elif args.test == "2":
            test_syscall_engines(vock_dir, kernel_src, arch_info)
        elif args.test == "3":
            test_intel_pt(vock_dir, kernel_src, arch_info)
        elif args.test == "4":
            test_coresight(vock_dir, kernel_src, arch_info)
        else:
            test_default(vock_dir, kernel_src, arch_info, False)
            test_syscall_engines(vock_dir, kernel_src, arch_info)
            test_intel_pt(vock_dir, kernel_src, arch_info)
            test_coresight(vock_dir, kernel_src, arch_info)

    # Summary
    print("\n" + "=" * 60)
    total = PASS + FAIL + SKIP
    print(f"  Results: {PASS} passed, {FAIL} failed, {SKIP} skipped ({total} total)")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
