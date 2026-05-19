# vock selftest

Automated test framework. Configures kernels, builds, boots VMs, and verifies each feature.

## Quick Start

```bash
vock selftest                              # host-only (fast)
vock selftest --on vng-kvm                 # full VM test with KVM
vock selftest --on vng-tcg                 # full VM test without KVM (CI)
vock selftest --on host                    # explicit host test
```

## Options

```
vock selftest [-h] [--on {host,vng-kvm,vng-tcg}] [--kernel-src PATH] [1|2|3|4]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--on` | `host` | Where to run tests |
| `--kernel-src` | `$HOME/stable` | Kernel source tree for VM tests |
| `1`-`4` | all | Run specific test only |

## What Gets Tested

### Host tests (`--on host`)

| Test | What |
|------|------|
| hw coverage | Intel PT → kerncov.log + coverage.html |
| --syscall ptrace | trace.log in strace format |
| --syzlang | trace.log + trace.syz |
| --syscall sud | SUD/lazypoline trace |
| --syscall ebpf | eBPF tracepoints (if permissions allow) |
| hw + syzlang | Combined coverage + syscall |
| hw + sud + syzlang | Combined with SUD backend |

### VM tests (`--on vng-kvm` / `--on vng-tcg`)

| Test | What |
|------|------|
| kcov | CONFIG_KCOV coverage |
| kcov + ptrace | Combined |
| kcov + sud | Combined |
| kcov + ebpf | Combined (needs CONFIG_BPF + BTF) |
| syzlang format | Verify strace-compatible output |
| filter + kcov + ebpf | `--filter net` with `ip addr show`, verify netdev paths |

## Kernel Configuration

### Full config (all features)

```bash
cd ~/stable
scripts/config \
    --enable CONFIG_DEBUG_KERNEL \
    --enable CONFIG_KCOV \
    --enable CONFIG_KCOV_INSTRUMENT_ALL \
    --enable CONFIG_DEBUG_INFO \
    --enable CONFIG_DEBUG_INFO_BTF \
    --enable CONFIG_PERF_EVENTS \
    --enable CONFIG_CPU_SUP_INTEL \
    --enable CONFIG_BPF_SYSCALL \
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
| `--syscall ebpf` | `BPF_SYSCALL`, `DEBUG_INFO_BTF` |
| `--syscall ptrace` | (none) |
| `--syscall sud` | (none, kernel ≥ 5.11) |

### SUD requirement

```bash
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
```

## Execution Targets

| Target | Speed | Use when |
|--------|-------|----------|
| `host` | Fast | Quick validation, Intel PT on baremetal |
| `vng-kvm` | Medium | Full pipeline with KVM |
| `vng-tcg` | Slow | CI without KVM |

## Test Numbers

| # | Name | What |
|---|------|------|
| 1 | Coverage + Syscall | All modes in one kernel |
| 2 | Syscall only | All backends, format verification |
| 3 | Intel PT (no KCOV) | Proves hw mode works independently |
| 4 | CoreSight (aarch64) | ARM64 hardware trace |
| 5 | Filter | `--filter net` + `--mode kcov` + `--syscall ebpf` with `ip addr show` |

## GitHub CI

```yaml
- name: Test
  run: |
    if [ -w /dev/kvm ]; then TARGET=vng-kvm; else TARGET=vng-tcg; fi
    ./vock selftest --on $TARGET --kernel-src $HOME/stable
```

## Architecture Detection

The selftest auto-detects:
- CPU (Intel PT / CoreSight / AMD)
- KVM availability
- Installed clang version
- Kernel config via `/proc/config.gz`

Skips tests that can't run on the current hardware.
