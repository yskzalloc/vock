# vock selftest

Automated test framework. Configures kernels, builds, boots VMs, and verifies each feature.

## Quick Start

```bash
# VM tests (need kernel source)
vock selftest 1 --on vng-kvm --kernel-src ~/net
vock selftest 2 --on vng-kvm --kernel-src ~/net

# Bare metal tests (need Intel PT hardware)
vock selftest 3 --kernel-src ~/net

# CI (no KVM available)
vock selftest 1 --on vng-tcg --kernel-src ~/net
```

## Options

```
vock selftest [-h] [--on {vng-kvm,vng-tcg}] [--kernel-src PATH] [--llvm SUFFIX] [1-7]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--on` | `vng-kvm` | VM acceleration for tests that need vng |
| `--kernel-src` | `$HOME/stable` | Kernel source tree |
| `--llvm` | auto-detect | LLVM suffix (e.g. `-21`). Also reads `LLVM` env |
| `1`-`7` | all | Run specific test only |

## Test Numbers

| # | Name | Runs on | What |
|---|------|---------|------|
| 1 | Coverage + Syscall | vng | KCOV+vmlinux, KCOV+BTF × each --syscall |
| 2 | Syscall engines | vng | ptrace/sud/ebpf + syzlang format check |
| 3 | Intel PT | **host** | HW + vmlinux × each --syscall (ptrace/sud/ebpf) |
| 4 | CoreSight | **host** | aarch64 HW trace, KCOV disabled |
| 5 | Filter + netdev | vng | `--filter net` + veth create/configure/destroy |
| 6 | BTF | vng | `--btf --kernel-src` + HTML report |
| 7 | Crypto | vng | xts(aes) decrypt coverage + verification |

## Test 1: Coverage + Syscall (vng)

Builds one kernel, runs 2 groups:

### Group A: KCOV + vmlinux + each `--syscall`

```
--mode kcov --syscall ptrace --vmlinux  → kerncov.log + trace.log + coverage.html
--mode kcov --syscall sud --vmlinux     → kerncov.log + trace.log + coverage.html
--mode kcov --syscall ebpf --vmlinux    → kerncov.log + trace.log + coverage.html
```

### Group B: KCOV + BTF + kernel-src + each `--syscall`

```
--mode kcov --syscall ptrace --btf --kernel-src  → kerncov.log + trace.log + coverage.html
--mode kcov --syscall sud --btf --kernel-src     → kerncov.log + trace.log + coverage.html
--mode kcov --syscall ebpf --btf --kernel-src    → kerncov.log + trace.log + coverage.html
```

## Test 3: Intel PT (host, bare metal)

Requires Intel PT hardware. Skipped on AMD/KVM.

```
--mode hw --syscall ptrace --vmlinux  → kerncov.log + trace.log
--mode hw --syscall sud --vmlinux     → kerncov.log + trace.log
--mode hw --syscall ebpf --vmlinux    → kerncov.log + trace.log
```

## Target Programs

| Test | Target | Kernel subsystem |
|------|--------|-----------------|
| 1, 2, 6, 7 | xts(aes) decrypt | crypto (skcipher, aes, xts) |
| 5 | veth create/up/mtu/destroy | netdev (rtnl_newlink, dev_change_flags) |

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
| `--syscall ebpf` | `BPF_SYSCALL`, `DEBUG_INFO_BTF` |
| `--syscall ptrace` | (none) |
| `--syscall sud` | (none, kernel ≥ 5.11) |
| crypto target | `CRYPTO_XTS`, `CRYPTO_USER`, `CRYPTO_USER_API_SKCIPHER` |
| netdev target | `VETH`, `NET`, `INET` |

## LLVM Toolchain

Priority: `--llvm` flag > `LLVM` env > auto-detect.

```bash
vock selftest 1 --llvm -21 --kernel-src ~/net
LLVM=-21 vock selftest 1 --kernel-src ~/net
```

## GitHub CI

```yaml
- name: Test
  run: |
    if [ -w /dev/kvm ]; then ON=vng-kvm; else ON=vng-tcg; fi
    ./vock selftest 1 --on $ON --kernel-src $PWD/staging
    ./vock selftest 2 --on $ON --kernel-src $PWD/staging
```
