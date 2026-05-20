# vock selftest

Automated test framework. Configures kernels, builds, boots VMs, and verifies each feature.

## Quick Start

```bash
# VM tests (need kernel source + vng)
vock selftest 1 --on vng-kvm --kernel-src ~/net

# HW trace: Intel PT (bare metal only, needs root)
sudo vock selftest 2 --on host --kernel-src ~/net

# HW trace: AMD LBR (works in VM too)
vock selftest 2 --on vng-kvm --kernel-src ~/net

# CI (no KVM available)
vock selftest 1 --on vng-tcg --kernel-src ~/net
```

## Options

```
vock selftest [-h] [--on {host,vng-kvm,vng-tcg}] [--kernel-src PATH] [--llvm SUFFIX] [1-6]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--on` | `vng-kvm` | Execution target |
| `--kernel-src` | `$HOME/stable` | Kernel source tree |
| `--llvm` | auto-detect | LLVM suffix (e.g. `-21`) or path. Also reads `LLVM` env |
| `1`-`6` | all | Run specific test only |

## Test Numbers

| # | Name | Runs on | What |
|---|------|---------|------|
| 1 | Coverage + Syscall + Syzlang | vng | KCOV+vmlinux, KCOV+BTF × each --syscall + --syzlang |
| 2 | Intel PT / AMD LBR | **host** (Intel) or vng (AMD) | HW + vmlinux × each --syscall + --syzlang |
| 3 | CoreSight | **host** (bare metal) | aarch64 HW trace, KCOV disabled |
| 4 | Filter + netdev | vng | `--filter net` + veth create/configure/destroy |
| 5 | BTF | vng | `--btf --kernel-src` + HTML report |
| 6 | Crypto | vng | xts(aes) decrypt coverage + verification |

## Test 1: Coverage + Syscall + Syzlang (vng)

Builds one kernel, runs 2 groups:

### Group A: KCOV + vmlinux + syzlang + each `--syscall`

```
--mode kcov --syzlang --syscall ptrace --vmlinux  → kerncov.log + trace.log + trace.syz + coverage.html
--mode kcov --syzlang --syscall sud --vmlinux     → kerncov.log + trace.log + trace.syz + coverage.html
--mode kcov --syzlang --syscall ebpf --vmlinux    → kerncov.log + trace.log + trace.syz + coverage.html
```

### Group B: KCOV + BTF + kernel-src + syzlang + each `--syscall`

```
--mode kcov --syzlang --syscall ptrace --btf --kernel-src  → kerncov.log + trace.log + trace.syz + coverage.html
--mode kcov --syzlang --syscall sud --btf --kernel-src     → kerncov.log + trace.log + trace.syz + coverage.html
--mode kcov --syzlang --syscall ebpf --btf --kernel-src    → kerncov.log + trace.log + trace.syz + coverage.html
```

Verifies: strace format (`') = '`), trace.syz output, coverage PCs > 0.

## Test 2: Intel PT / AMD LBR (bare metal or VM)

Requirements vary by hardware:
- **Intel PT**: requires `--on host` (not available inside KVM guests) + root
- **AMD LBR**: works in both `--on host` and `--on vng-kvm`

```bash
# Intel PT (bare metal only):
sudo ./vock selftest 2 --on host --kernel-src ~/net

# AMD LBR (works in VM too):
./vock selftest 2 --on vng-kvm --kernel-src ~/net

# Or set paranoid first (Intel):
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
./vock selftest 2 --on host --kernel-src ~/net
```

Skips automatically if:
- Intel PT + `--on vng-kvm` (Intel PT unavailable in KVM guests)
- No Intel PT / AMD LBR hardware detected
- Insufficient privileges

```
--mode hw --syzlang --syscall ptrace --vmlinux  → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall sud --vmlinux     → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall ebpf --vmlinux    → kerncov.log + trace.log + trace.syz
```

## Target Programs

| Test | Target | Kernel subsystem |
|------|--------|-----------------|
| 1, 5, 6 | xts(aes) decrypt | crypto (skcipher, aes, xts) |
| 4 | veth create/up/mtu/destroy | netdev (rtnl_newlink, dev_change_flags) |

## Kernel Configuration

### Full config

```bash
cd ~/net
scripts/config \
    --enable CONFIG_DEBUG_KERNEL \
    --enable CONFIG_KCOV \
    --enable CONFIG_KCOV_INSTRUMENT_ALL \
    --enable CONFIG_DEBUG_INFO \
    --enable CONFIG_DEBUG_INFO_BTF \
    --enable CONFIG_PERF_EVENTS \
    --enable CONFIG_CPU_SUP_INTEL \
    --enable CONFIG_BPF_SYSCALL \
    --enable CONFIG_CRYPTO_XTS \
    --enable CONFIG_CRYPTO_USER \
    --enable CONFIG_CRYPTO_USER_API_SKCIPHER \
    --enable CONFIG_VETH \
    --enable CONFIG_IKCONFIG \
    --enable CONFIG_IKCONFIG_PROC \
    --disable CONFIG_DEBUG_INFO_NONE
make olddefconfig
vng LLVM=-21 --build
```

### Minimum per feature

| Feature | Required configs |
|---------|-----------------|
| `--mode hw` | `PERF_EVENTS`, `CPU_SUP_INTEL` |
| `--mode kcov` | `KCOV`, `KCOV_INSTRUMENT_ALL`, `DEBUG_INFO` |
| `--btf` | `DEBUG_INFO_BTF` |
| `--syscall ptrace` | (none) |
| `--syscall sud` | (none, kernel ≥ 5.11) |
| `--syscall ebpf` | `BPF_SYSCALL`, `DEBUG_INFO_BTF` |
| crypto target | `CRYPTO_XTS`, `CRYPTO_USER`, `CRYPTO_USER_API_SKCIPHER` |
| netdev target | `VETH`, `NET`, `INET` |

## LLVM Toolchain

Priority: `--llvm` flag > `LLVM` env > auto-detect.

```bash
# Suffix style (system-installed)
vock selftest 1 --llvm -21 --kernel-src ~/net

# Path style (custom build)
sudo vock selftest 2 --llvm /home/yunseong/llvm-project/build/bin/ --on host --kernel-src ~/net
```

## GitHub CI

```yaml
- name: Test
  run: |
    if [ -w /dev/kvm ]; then ON=vng-kvm; else ON=vng-tcg; fi
    ./vock selftest 1 --on $ON --kernel-src $PWD/staging
```
