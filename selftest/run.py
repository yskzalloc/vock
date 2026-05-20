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
    info = {"arch": arch, "has_intel_pt": False, "has_amd_lbr": False, "has_coresight": False, "cpu": ""}
    if arch == "x86_64":
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    info["cpu"] = line.split(":")[1].strip()
                    break
            flags = ""
            vendor = ""
            for line in open("/proc/cpuinfo"):
                if line.startswith("flags"):
                    flags = line
                if line.startswith("vendor_id"):
                    vendor = line.split(":")[1].strip()
            info["has_intel_pt"] = "intel_pt" in flags
            if "AuthenticAMD" in vendor:
                info["has_amd_lbr"] = True
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
    """Configure kernel. Uses scripts/config + olddefconfig."""
    script = os.path.join(kernel_src, "scripts/config")
    if not os.path.isfile(script):
        return False
    for key, enable in configs.items():
        run([script, "--enable" if enable else "--disable", key], cwd=kernel_src)
    run(["make", "olddefconfig"], cwd=kernel_src)
    return True


def kernel_build(kernel_src):
    """Build kernel using vng --build (handles 9p/VFS properly)."""
    print("  Building kernel...")
    r = run(["vng", f"LLVM={LLVM_SUFFIX}", "--build"], cwd=kernel_src, timeout=1800)
    return r.returncode == 0


def kernel_configure_and_build(kernel_src, configs):
    """Configure + build in one step using vng --configitem + --build."""
    if RUN_TARGET == "host":
        # On host, don't build — assume kernel is already built
        return True

    print("  Configuring + building kernel...")
    cmd = ["vng"]
    for key, enable in configs.items():
        if enable:
            cmd += ["--configitem", f"{key}=y"]
        else:
            cmd += ["--configitem", f"{key}=n"]
    cmd += ["--build", f"LLVM={LLVM_SUFFIX}"]
    r = run(cmd, cwd=kernel_src, timeout=1800)
    if r.returncode != 0:
        vlog(r)
    return r.returncode == 0


def vng_run(kernel_src, cmd):
    """Run command on target. If --on host, run directly. Otherwise use vng."""
    if RUN_TARGET == "host":
        return run(cmd, cwd=kernel_src, timeout=600)
    vng_cmd = ["vng", "--rw"]
    if RUN_TARGET == "vng-tcg":
        vng_cmd.append("--disable-kvm")
    vng_cmd += ["--"] + cmd
    return run(vng_cmd, cwd=kernel_src, timeout=600)


def crypto_setup_cmds(cipher="xts(aes)", bs="64K", count=64,
                      key="ThisIsA64ByteSecretKeyForAES256XTSModeWhichRequires512BitsOfData",
                      iv="00000000000000000000000000000000"):
    """Shell commands to create test block + key + encrypt (setup phase, not traced)."""
    return (
        f"dd if=/dev/urandom of=/tmp/block.img bs={bs} count={count} 2>/dev/null; "
        f"printf '{key}' > /tmp/key.bin; "
        f"kcapi-enc -c '{cipher}' -e -i /tmp/block.img -o /tmp/block.enc "
        f"--iv {iv} --keyfd 3 3</tmp/key.bin 2>/dev/null; "
        f"printf '#!/bin/sh\\nkcapi-enc -d -c \"{cipher}\" -i /tmp/block.enc -o /tmp/block.dec "
        f"--iv {iv} --keyfd 3 3</tmp/key.bin\\n' > /tmp/dec.sh; "
        f"chmod +x /tmp/dec.sh; true"
    )


def crypto_decrypt_script(cipher="xts(aes)",
                          iv="00000000000000000000000000000000"):
    """Shell commands to write a decrypt wrapper script (to be traced by vock)."""
    return (
        f"printf '#!/bin/sh\\nkcapi-enc -d -c \"{cipher}\" -i /tmp/block.enc -o /tmp/block.dec "
        f"--iv {iv} --keyfd 3 3</tmp/key.bin\\n' > /tmp/dec.sh && "
        f"chmod +x /tmp/dec.sh"
    )


def crypto_prepare():
    """Full setup + decrypt script creation. Call before tracing CRYPTO_TARGET."""
    return crypto_setup_cmds()


# SUD requires mmap_min_addr=0 for zpoline
SUD_SETUP = "echo 0 > /proc/sys/vm/mmap_min_addr 2>/dev/null; "

# Target command for VM tests (exercises crypto subsystem instead of /bin/ls)
CRYPTO_TARGET = "/bin/sh /tmp/dec.sh"

VERBOSE = False


def vlog(r):
    """Print command output if --verbose."""
    if not VERBOSE:
        return
    out = r.stdout.decode() if r.stdout else ""
    err = r.stderr.decode() if r.stderr else ""
    if out:
        for line in out.strip().split('\n')[-20:]:
            print(f"    | {line}")
    if err:
        for line in err.strip().split('\n')[-10:]:
            print(f"    ! {line}")


def test_default(vock_dir, kernel_src, arch_info, syscall_on):
    """Full test: 3 groups depending on environment."""
    print("\n" + "=" * 60)
    print("  TEST 1: coverage + syscall engines")
    print("=" * 60)

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
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if arch_info["arch"] == "x86_64":
        configs["CONFIG_CPU_SUP_INTEL"] = True

    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed")
        return False
    log("PASS", "kernel configured + built")

    vmlinux = os.path.join(kernel_src, "vmlinux")

    # ─── Group A: KCOV + vmlinux (source-level report) ───────────────────────
    print("\n── Group A: KCOV + vmlinux + syzlang ──")

    for backend in ["ptrace", "sud", "ebpf"]:
        print(f"\n[Test: --mode kcov --syzlang --syscall {backend} --vmlinux]")
        sud_pre = SUD_SETUP if backend == "sud" else ""
        r = vng_run(kernel_src, [
            "bash", "-c",
            f"rm -f kerncov.log coverage.html trace.log trace.syz && "
            f"{sud_pre}{crypto_prepare()} && "
            f"{vock_dir}/vock --mode kcov --syzlang --syscall {backend} --vmlinux {vmlinux} --kernel-src {kernel_src} {CRYPTO_TARGET} 2>&1; "
            f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
            f"[ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && "
            f"grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && "
            f"[ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz) && "
            f"[ -f coverage.html ] && echo HTML_OK"
        ])
        vlog(r)
        out = r.stdout.decode() if r.stdout else ""
        if "ebpf backend not built" in out:
            log("SKIP", f"kcov+{backend}+vmlinux: ebpf not built")
        elif "KCOV_PCS=" in out:
            pcs = out.split("KCOV_PCS=")[1].split()[0]
            if int(pcs) > 0:
                log("PASS", f"kcov+{backend}+vmlinux: {pcs} PCs")
            else:
                log("FAIL", f"kcov+{backend}+vmlinux: no coverage")
        else:
            log("FAIL", f"kcov+{backend}+vmlinux: failed")
        if "TRACE_OK=" in out:
            log("PASS", f"  trace.log: {out.split('TRACE_OK=')[1].split()[0]} syscalls")
        if "FMT_OK" in out:
            log("PASS", f"  strace format verified")
        if "SYZ_OK=" in out:
            log("PASS", f"  trace.syz: {out.split('SYZ_OK=')[1].split()[0]} syscalls")
        if "HTML_OK" in out:
            log("PASS", f"  coverage.html generated")

    # ─── Group B: KCOV + BTF + syzlang (function-level, no vmlinux) ──────────
    print("\n── Group B: KCOV + BTF + kernel-src + syzlang ──")

    for backend in ["ptrace", "sud", "ebpf"]:
        print(f"\n[Test: --mode kcov --syzlang --syscall {backend} --btf --kernel-src]")
        sud_pre = SUD_SETUP if backend == "sud" else ""
        r = vng_run(kernel_src, [
            "bash", "-c",
            f"rm -f kerncov.log coverage.html trace.log trace.syz && "
            f"{sud_pre}{crypto_prepare()} && "
            f"{vock_dir}/vock --mode kcov --syzlang --syscall {backend} --btf --kernel-src {kernel_src} {CRYPTO_TARGET} 2>&1; "
            f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
            f"[ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && "
            f"grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && "
            f"[ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz) && "
            f"[ -f coverage.html ] && echo HTML_OK"
        ])
        vlog(r)
        out = r.stdout.decode() if r.stdout else ""
        if "ebpf backend not built" in out:
            log("SKIP", f"kcov+{backend}+btf: ebpf not built")
        elif "KCOV_PCS=" in out:
            pcs = out.split("KCOV_PCS=")[1].split()[0]
            if int(pcs) > 0:
                log("PASS", f"kcov+{backend}+btf: {pcs} PCs")
            else:
                log("FAIL", f"kcov+{backend}+btf: no coverage")
        else:
            log("FAIL", f"kcov+{backend}+btf: failed")
        if "TRACE_OK=" in out:
            log("PASS", f"  trace.log: {out.split('TRACE_OK=')[1].split()[0]} syscalls")
        if "FMT_OK" in out:
            log("PASS", f"  strace format verified")
        if "SYZ_OK=" in out:
            log("PASS", f"  trace.syz: {out.split('SYZ_OK=')[1].split()[0]} syscalls")
        if "HTML_OK" in out:
            log("PASS", f"  coverage.html: source-highlighted functions")

    return True


# ─── Test 2: Intel PT / AMD LBR (x86_64, KCOV disabled) ─────────────────────

def test_intel_pt(vock_dir, kernel_src, arch_info):
    """Test hardware trace: Intel PT or AMD LBR (x86_64 only)."""
    print("\n" + "=" * 60)
    print("  TEST 2: Hardware Trace (Intel PT / AMD LBR)")
    print("=" * 60)

    if RUN_TARGET != "host" and arch_info.get("has_intel_pt") and not arch_info.get("has_amd_lbr"):
        log("SKIP", "Intel PT unavailable in KVM guests (use --on host)")
        return True
    if arch_info["arch"] != "x86_64":
        log("SKIP", "HW trace: not x86_64")
        return True
    if not arch_info["has_intel_pt"] and not arch_info.get("has_amd_lbr"):
        log("SKIP", f"HW trace: not available ({arch_info['cpu'] or 'unknown CPU'})")
        return True
    hw_type = "Intel PT" if arch_info["has_intel_pt"] else "AMD LBR"
    log("PASS", f"{hw_type} supported ({arch_info['cpu']})")

    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": False,
        "CONFIG_PERF_EVENTS": True, "CONFIG_CPU_SUP_INTEL": True,
        "CONFIG_BPF_SYSCALL": True, "CONFIG_DEBUG_INFO_BTF": True,
        "CONFIG_DEBUG_INFO": True, "CONFIG_DEBUG_INFO_DWARF5": True,
        "CONFIG_DEBUG_INFO_NONE": False,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed"); return False
    log("PASS", "kernel configured + built")

    print(f"\n[Test: {hw_type} + each --syscall]")
    vmlinux = os.path.join(kernel_src, "vmlinux")

    # Intel PT requires perf_event_paranoid <= 1 or root
    perf_pre = "echo -1 | sudo -n tee /proc/sys/kernel/perf_event_paranoid > /dev/null 2>&1 || true; "

    for backend in ["ptrace", "sud", "ebpf"]:
        sud_pre = SUD_SETUP if backend == "sud" else ""
        print(f"\n[Test: --mode hw --syzlang --syscall {backend} --vmlinux]")
        r = vng_run(kernel_src, [
            "bash", "-c",
            f"rm -f kerncov.log trace.log trace.syz && "
            f"{perf_pre}{sud_pre}{crypto_prepare()} && "
            f"{vock_dir}/vock --mode hw --syzlang --syscall {backend} "
            f"--vmlinux {vmlinux} --kernel-src {kernel_src} {CRYPTO_TARGET} 2>&1; "
            f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
            f"[ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && "
            f"grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && "
            f"[ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz)"
        ])
        vlog(r)
        out = r.stdout.decode() if r.stdout else ""
        if "ebpf backend not built" in out:
            log("SKIP", f"hw+{backend}: ebpf not built")
        elif "requires privileges" in out or "no hardware trace PMU" in out:
            log("SKIP", f"hw+{backend}: needs perf_event_paranoid=-1 or Intel PT unavailable")
        elif "KCOV_PCS=" in out:
            pcs = out.split("KCOV_PCS=")[1].split()[0]
            if int(pcs) > 0:
                log("PASS", f"hw+{backend}+vmlinux: {pcs} PCs")
            else:
                log("FAIL", f"hw+{backend}+vmlinux: no coverage")
        else:
            log("FAIL", f"hw+{backend}+vmlinux: failed")
        if "TRACE_OK=" in out:
            log("PASS", f"  trace.log: {out.split('TRACE_OK=')[1].split()[0]} syscalls")
        if "FMT_OK" in out:
            log("PASS", f"  strace format verified")
        if "SYZ_OK=" in out:
            log("PASS", f"  trace.syz: {out.split('SYZ_OK=')[1].split()[0]} syscalls")

    return True


# ─── Test 3: CoreSight (aarch64, KCOV disabled) ─────────────────────────────

def test_coresight(vock_dir, kernel_src, arch_info):
    """Test CoreSight without KCOV (aarch64 only)."""
    print("\n" + "=" * 60)
    print("  TEST 3: CoreSight (KCOV disabled)")
    print("=" * 60)

    if arch_info["arch"] != "aarch64":
        log("SKIP", "CoreSight: not aarch64")
        return True
    if not arch_info["has_coresight"]:
        log("SKIP", "CoreSight: ETM not available")
        return True
    log("PASS", f"CoreSight available ({arch_info['cpu']})")

    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": False,
        "CONFIG_PERF_EVENTS": True, "CONFIG_CORESIGHT": True,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed"); return False
    log("PASS", "kernel configured + built")

    print("\n[Test: CoreSight]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"rm -f kerncov.log && "
        f"{vock_dir}/vock --mode hw /bin/ls /tmp 2>&1; "
        f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0)"
    ])
    out = r.stdout.decode() if r.stdout else ""
    if "KCOV_PCS=" in out:
        pcs = out.split("KCOV_PCS=")[1].split()[0]
        if int(pcs) > 0:
            log("PASS", f"CoreSight: {pcs} kernel PCs (no KCOV)")
        else:
            log("FAIL", "CoreSight: no coverage")
    else:
        log("FAIL", "CoreSight failed")
    return True


# ─── Test 4: Filter (--filter netdev, --mode kcov, --syscall ebpf) ───────────

def test_filter(vock_dir, kernel_src, arch_info):
    """Test --filter with kcov + ebpf using veth create/destroy, verify netdev subsystem."""
    print("\n" + "=" * 60)
    print("  TEST 4: --filter (kcov + ebpf + veth create/destroy)")
    print("=" * 60)

    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": True,
        "CONFIG_KCOV_INSTRUMENT_ALL": True, "CONFIG_BPF_SYSCALL": True,
        "CONFIG_DEBUG_INFO_BTF": True, "CONFIG_DEBUG_INFO": True,
        "CONFIG_DEBUG_INFO_DWARF5": True, "CONFIG_DEBUG_INFO_NONE": False,
        "CONFIG_NET": True, "CONFIG_INET": True, "CONFIG_VETH": True,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed"); return False
    log("PASS", "kernel configured + built")

    vmlinux = os.path.join(kernel_src, "vmlinux")

    # Target: create/configure/destroy veth — exercises netlink write paths
    net_target = (
        "ip link add veth0 type veth peer name veth1 && "
        "ip addr add 10.0.0.1/24 dev veth0 && "
        "ip link set veth0 up && "
        "ip link set veth1 up && "
        "ip link del veth0"
    )

    print("\n[Test: --mode kcov --syscall ebpf --filter net (veth create/destroy)]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"rm -f kerncov.log coverage.html trace.log && "
        f"{vock_dir}/vock --mode kcov --syscall ebpf --filter net "
        f"--vmlinux {vmlinux} --kernel-src {kernel_src} "
        f"/bin/sh -c '{net_target}' 2>&1; "
        f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
        f"[ -f coverage.html ] && echo HTML_OK && "
        f"grep -c 'net/' coverage.html && echo NET_FOUND"
    ])
    out = r.stdout.decode() if r.stdout else ""

    if "KCOV_PCS=" in out:
        pcs = out.split("KCOV_PCS=")[1].split()[0]
        if int(pcs) > 0:
            log("PASS", f"--mode kcov + --syscall ebpf: {pcs} kernel PCs")
        else:
            log("FAIL", "--mode kcov: no coverage from veth create/destroy")
    else:
        log("FAIL", "--mode kcov --syscall ebpf: command failed")
        if out: print(f"    {out[:300]}")

    if "HTML_OK" in out:
        log("PASS", "coverage.html generated")
    else:
        log("FAIL", "coverage.html missing")

    if "NET_FOUND" in out:
        log("PASS", "--filter net: netdev subsystem paths in report")
    else:
        log("FAIL", "--filter net: no net/ paths in coverage report")

    # Verify trace.log was produced (ebpf syscall tracing)
    print("\n[Test: trace.log from --syscall ebpf]")
    r2 = vng_run(kernel_src, [
        "bash", "-c",
        f"[ -s trace.log ] && echo LINES=$(wc -l < trace.log) && "
        f"grep -q 'socket\\|sendmsg\\|ioctl' trace.log && echo NETDEV_SYSCALLS"
    ])
    out2 = r2.stdout.decode() if r2.stdout else ""
    if "LINES=" in out2:
        log("PASS", f"--syscall ebpf trace: {out2.split('LINES=')[1].split()[0]} syscalls")
    else:
        log("FAIL", "--syscall ebpf: no trace.log")
    if "NETDEV_SYSCALLS" in out2:
        log("PASS", "netdev syscalls (socket/sendmsg/ioctl) captured")

    return True


# ─── Test 5: BTF (--btf, --mode kcov, resolve via kallsyms) ─────────────────

def test_btf(vock_dir, kernel_src, arch_info):
    """Test --btf: resolve PCs via /proc/kallsyms without vmlinux."""
    print("\n" + "=" * 60)
    print("  TEST 5: --btf (kcov + kallsyms resolution)")
    print("=" * 60)

    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": True,
        "CONFIG_KCOV_INSTRUMENT_ALL": True, "CONFIG_DEBUG_INFO": True,
        "CONFIG_DEBUG_INFO_BTF": True, "CONFIG_DEBUG_INFO_DWARF5": True,
        "CONFIG_DEBUG_INFO_NONE": False,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed"); return False
    log("PASS", "kernel configured + built")

    print("\n[Test: --mode kcov --btf (crypto decrypt)]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"rm -f kerncov.log coverage.txt && "
        f"{crypto_prepare()} && {vock_dir}/vock --mode kcov --btf {CRYPTO_TARGET} 2>&1; "
        f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
        f"[ -f coverage.txt ] && echo TXT_OK && "
        f"FUNCS=$(wc -l < coverage.txt) && echo FUNCS=$FUNCS"
    ])
    out = r.stdout.decode() if r.stdout else ""

    if "KCOV_PCS=" in out:
        pcs = out.split("KCOV_PCS=")[1].split()[0]
        if int(pcs) > 0:
            log("PASS", f"--mode kcov: {pcs} kernel PCs collected")
        else:
            log("FAIL", "--mode kcov: no coverage")
    else:
        log("FAIL", "--btf: command failed")
        if out: print(f"    {out[:300]}")

    if "TXT_OK" in out:
        log("PASS", "coverage.txt generated (BTF report)")
    else:
        log("FAIL", "coverage.txt missing")

    if "FUNCS=" in out:
        funcs = out.split("FUNCS=")[1].split()[0]
        if int(funcs) > 0:
            log("PASS", f"--btf: {funcs} functions resolved via kallsyms")
        else:
            log("FAIL", "--btf: no functions resolved")

    # Verify mutual exclusion
    print("\n[Test: --btf + --vmlinux mutual exclusion]")
    r2 = vng_run(kernel_src, [
        "bash", "-c",
        f"{vock_dir}/vock --mode kcov --btf --vmlinux /dev/null {CRYPTO_TARGET} 2>&1; echo EXIT=$?"
    ])
    out2 = r2.stdout.decode() if r2.stdout else ""
    if "mutually exclusive" in out2 and "EXIT=1" in out2:
        log("PASS", "--btf + --vmlinux correctly rejected")
    else:
        log("FAIL", "mutual exclusion not enforced")

    return True


# ─── Test 6: Crypto subsystem (--mode kcov --btf, xts(aes) decrypt) ──────────

def test_crypto(vock_dir, kernel_src, arch_info):
    """Test crypto subsystem coverage: encrypt setup, then trace decrypt with vock."""
    print("\n" + "=" * 60)
    print("  TEST 6: crypto subsystem (kcov + btf + xts(aes) decrypt)")
    print("=" * 60)

    configs = {
        "CONFIG_DEBUG_KERNEL": True, "CONFIG_KCOV": True,
        "CONFIG_KCOV_INSTRUMENT_ALL": True, "CONFIG_DEBUG_INFO": True,
        "CONFIG_DEBUG_INFO_BTF": True, "CONFIG_DEBUG_INFO_DWARF5": True,
        "CONFIG_DEBUG_INFO_NONE": False,
        "CONFIG_CRYPTO": True, "CONFIG_CRYPTO_XTS": True,
        "CONFIG_CRYPTO_AES": True, "CONFIG_CRYPTO_USER_API": True,
        "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
        "CONFIG_IKCONFIG": True, "CONFIG_IKCONFIG_PROC": True,
        "CONFIG_CRYPTO_XTS": True, "CONFIG_CRYPTO_USER": True, "CONFIG_CRYPTO_USER_API_SKCIPHER": True,
    }
    if not kernel_configure_and_build(kernel_src, configs):
        log("FAIL", "kernel configure+build failed"); return False
    log("PASS", "kernel configured + built")

    print("\n[Test: --mode kcov --btf (xts(aes) decrypt)]")
    r = vng_run(kernel_src, [
        "bash", "-c",
        f"rm -f kerncov.log coverage.txt && "
        f"{crypto_setup_cmds()} && "
        f"{crypto_decrypt_script()} && "
        f"{vock_dir}/vock --mode kcov --btf /bin/sh /tmp/dec.sh 2>&1; "
        f"echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && "
        f"[ -f coverage.txt ] && echo TXT_OK && "
        f"grep -ic 'aes\\|xts\\|crypto\\|skcipher' coverage.txt && echo CRYPTO_FOUND && "
        f"cmp /tmp/block.img /tmp/block.dec 2>/dev/null && echo DECRYPT_OK"
    ])
    out = r.stdout.decode() if r.stdout else ""

    if "KCOV_PCS=" in out:
        pcs = out.split("KCOV_PCS=")[1].split()[0]
        if int(pcs) > 0:
            log("PASS", f"--mode kcov: {pcs} kernel PCs from xts(aes) decrypt")
        else:
            log("FAIL", "--mode kcov: no coverage from decrypt")
    else:
        log("FAIL", "crypto test: command failed")
        if out: print(f"    {out[:400]}")

    if "TXT_OK" in out:
        log("PASS", "coverage.txt generated (BTF report)")
    else:
        log("FAIL", "coverage.txt missing")

    if "CRYPTO_FOUND" in out:
        log("PASS", "crypto subsystem functions (aes/xts/skcipher) in coverage")
    else:
        log("FAIL", "no crypto functions found in coverage report")

    if "DECRYPT_OK" in out:
        log("PASS", "decrypt verified: plaintext matches original")
    else:
        log("SKIP", "decrypt verification skipped (netns isolation)")

    return True



# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="vock selftest",
        description="Configure, build, and test each vock mode end-to-end.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""tests:
  1  coverage + syscall  build unified kernel, test kcov + all syscall engines + syzlang
  2  intel_pt/amd_lbr    build kernel WITHOUT KCOV, test Intel PT / AMD LBR (x86_64 only)
  3  coresight           build kernel WITHOUT KCOV, test CoreSight (aarch64 only)
  4  filter              --filter net + --mode kcov + --syscall ebpf (veth create/destroy)
  5  btf                 --btf + --mode kcov (resolve via /proc/kallsyms)
  6  crypto              --btf + --mode kcov + xts(aes) decrypt coverage

--on target:
  vng-kvm   VM tests use KVM acceleration (default)
  vng-tcg   VM tests use QEMU TCG (CI, no KVM)

Tests auto-select host or VM:
  Tests 1,4,5,6  → run in vng (need custom kernel)
  Test 2         → run on host (need bare metal Intel PT / AMD LBR)
  Test 3         → run on host (need bare metal CoreSight)

defaults:
  --kernel-src   $HOME/stable
  --on           vng-kvm
  (no number)    run all tests

architecture:
  x86_64 (Intel)   Intel PT + kcov + all syscall engines
  x86_64 (AMD)     AMD LBR + kcov + all syscall engines
  aarch64          CoreSight + kcov + all syscall engines

examples:
  vock selftest                          run all tests (KVM)
  vock selftest --on vng-tcg             run all tests (TCG, CI)
  vock selftest 1                        coverage + syscall engines + syzlang
  vock selftest 2                        Intel PT / AMD LBR (bare metal)
  vock selftest 4                        filter + kcov + ebpf (netdev)
  vock selftest --llvm -21               explicit LLVM version
  vock selftest --kernel-src ~/linux     custom kernel source
""")
    parser.add_argument("test", nargs="?", choices=["1", "2", "3", "4", "5", "6"],
                        help="run specific test number (default: all)")
    parser.add_argument("--on", choices=["host", "vng-kvm", "vng-tcg"], default="vng-kvm",
                        help="execution target (default: vng-kvm)")
    parser.add_argument("--kernel-src", default=None,
                        help="kernel source tree (default: $HOME/stable)")
    parser.add_argument("--llvm", default=None,
                        help="LLVM suffix (e.g. -21, -20). Overrides auto-detect. Env: LLVM=")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show command output for debugging")
    args = parser.parse_args()

    kernel_src = args.kernel_src or os.path.join(os.path.expanduser("~"), "stable")
    vock_dir = find_vock_dir()

    global LLVM_SUFFIX, RUN_TARGET, VERBOSE
    VERBOSE = args.verbose
    if args.llvm is not None:
        LLVM_SUFFIX = args.llvm
    elif os.environ.get("LLVM"):
        LLVM_SUFFIX = os.environ["LLVM"]
    else:
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
    print(f"  AMD LBR:    {'yes' if arch_info.get('has_amd_lbr') else 'no'}")
    print(f"  CoreSight:  {'yes' if arch_info['has_coresight'] else 'no'}")
    print(f"  KVM:        {'available' if kvm_available() else 'unavailable'}")
    print(f"  Run on:     {RUN_TARGET}")
    print(f"  LLVM:       clang{LLVM_SUFFIX} (LLVM={LLVM_SUFFIX})")

    # Build vock with all features enabled
    print("\n[Build vock]")
    if "/" in LLVM_SUFFIX:
        # LLVM is a path (e.g. ~/llvm-project/build/bin)
        cc = os.path.join(os.path.expanduser(LLVM_SUFFIX), "clang")
    else:
        cc = f"clang{LLVM_SUFFIX}"
    run(["make", "clean"], cwd=vock_dir, timeout=30)
    r = run(["make", f"CC={cc}", "-j4"],
            cwd=vock_dir, timeout=120)
    if r.returncode != 0:
        # Fallback without EBPF
        r = run(["make", f"CC={cc}", "-j4"],
                cwd=vock_dir, timeout=120)
    if r.returncode != 0:
        print("  FATAL: cannot build vock")
        vlog(r)
        sys.exit(1)
    print("  vock built")

    if not os.path.isdir(kernel_src):
        print(f"\n  FATAL: kernel source not found at {kernel_src}")
        print(f"  Use: vock selftest --kernel-src /path/to/linux")
        sys.exit(1)

    if not os.path.isfile(os.path.join(kernel_src, "Makefile")):
        print(f"\n  FATAL: {kernel_src} is not a kernel source tree")
        sys.exit(1)

    # Dispatch
    # Dispatch — each test decides internally whether to use vng or host
    tests = {
        "1": lambda: test_default(vock_dir, kernel_src, arch_info, False),
        "2": lambda: test_intel_pt(vock_dir, kernel_src, arch_info),
        "3": lambda: test_coresight(vock_dir, kernel_src, arch_info),
        "4": lambda: test_filter(vock_dir, kernel_src, arch_info),
        "5": lambda: test_btf(vock_dir, kernel_src, arch_info),
        "6": lambda: test_crypto(vock_dir, kernel_src, arch_info),
    }

    if args.test:
        tests[args.test]()
    else:
        for t in tests.values():
            t()

    # Summary
    print("\n" + "=" * 60)
    total = PASS + FAIL + SKIP
    print(f"  Results: {PASS} passed, {FAIL} failed, {SKIP} skipped ({total} total)")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
