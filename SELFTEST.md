# vock selftest

Automated test framework. Configures kernels, builds them, boots VMs, and
verifies each feature. Written in Rust (part of the `vock` binary); it shells
out to `make` (which builds the Rust workspace), `vng` (virtme-ng) and the
kernel toolchain.

## Quick Start

```bash
# Test 1 — KCOV + syscall engines + reporting (VM)
vock selftest 1 --on vng-kvm --kernel-src ~/stable

# Test 2 — HW trace, auto-selected for the host CPU (bare metal, needs root)
sudo vock selftest 2 --on host --kernel-src ~/stable

# Test 3 — --filter + xts(aes) crypto coverage (VM)
vock selftest 3 --on vng-kvm --kernel-src ~/stable

# All four
vock selftest --on vng-kvm --kernel-src ~/stable

# CI (no KVM available)
vock selftest 1 --on vng-tcg --kernel-src ~/stable
```

## Options

```
vock selftest [-h] [--on {host,vng-kvm,vng-tcg}] [--kernel-src PATH]
              [--vmlinux PATH] [--llvm SUFFIX] [--no-build] [-v] [1-4]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--on` | `vng-kvm` | Execution target (`host`, `vng-kvm`, `vng-tcg`) |
| `--kernel-src` | `$HOME/stable` | Kernel source tree |
| `--vmlinux` | `<kernel-src>/vmlinux` | vmlinux with debug info |
| `--llvm` | auto-detect | LLVM suffix (e.g. `-21`) or path. Also reads `LLVM` env |
| `--no-build` | off | Skip the `make` step and use the existing `./vock.bin` |
| `-v` | off | Verbose: show command output for debugging |
| `1`-`4` | all | Run a specific test only |

## Test Numbers

| # | Name | Runs on | What |
|---|------|---------|------|
| 1 | Coverage + Syscall + Syzlang | vng | Every KCOV collection & reporting feature: KCOV+vmlinux, KCOV+BTF × each `--syscall` + `--syzlang`, plus `--ordered` and `--filter` |
| 2 | Intel PT / AMD LBR / Arm64 CoreSight | **host** | Detects the host CPU and runs the matching HW engine: HW + vmlinux × each `--syscall` + `--syzlang` |
| 3 | Filter + xts Crypto | vng | `--filter` narrowed xts(aes) decrypt coverage + plaintext verification |
| 4 | KASAN bug hunt | vng | build a KASAN+KCOV kernel; loop a sample reproducer (MIDI UAF) for ≤30 min, watching for a KASAN report |

## Test 1: Coverage + Syscall + Syzlang (vng)

Builds one KCOV kernel, then exercises **all** KCOV collection and reporting
features across three groups.

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

### Group C: remaining reporting features

```
--mode kcov --ordered --vmlinux    → coverage-<TID>.html (per-TID execution trace)
--mode kcov --filter fs --vmlinux  → coverage.html narrowed to fs/ paths
```

Verifies: strace format (`') = '`), trace.syz output, coverage PCs > 0, HTML
report, per-TID ordered report, and keyword filtering. `sud` traces up to the
target's `execve`, so its `trace.log` is short by design; KCOV coverage is
collected regardless of syscall backend.

## Test 2: Intel PT / AMD LBR / CoreSight (host)

Detects the host CPU and builds a kernel **without KCOV**, then runs the engine
that matches the hardware:

| Host | Engine | Extra config |
|------|--------|--------------|
| x86_64 Intel | Intel PT (full branch) | `CONFIG_CPU_SUP_INTEL` |
| x86_64 AMD | AMD LBR (function-entry) | — |
| aarch64 | CoreSight | `CONFIG_CORESIGHT` |

```bash
# Intel PT / CoreSight: bare metal only, needs root or perf_event_paranoid <= 1
sudo vock selftest 2 --on host --kernel-src ~/stable
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid    # alternative to root

# AMD LBR also works inside a KVM guest
vock selftest 2 --on vng-kvm --kernel-src ~/stable
```

For each backend it runs:

```
--mode hw --syzlang --syscall ptrace --vmlinux  → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall sud --vmlinux     → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall ebpf --vmlinux    → kerncov.log + trace.log + trace.syz
```

Skips automatically when:
- Intel PT + `--on vng-kvm` (Intel PT is unavailable in KVM guests)
- No Intel PT / AMD LBR / CoreSight hardware is detected
- perf is unavailable (`perf_event_paranoid >= 2` without root, or a nested VM)

## Test 3: Filter + xts(aes) Crypto (vng)

Builds a KCOV kernel with the crypto subsystem enabled, encrypts a block with
`kcapi-enc`, then traces the **decrypt** with a keyword-filtered report:

```
--mode kcov --filter crypto --vmlinux  /bin/sh /tmp/dec.sh
    → kerncov.log + coverage.html (narrowed to crypto/ paths)
```

Verifies: coverage PCs > 0, `coverage.html` generated, the filtered report
contains `aes`/`xts`/`crypto`/`skcipher` paths, and the decrypted plaintext
matches the original (`cmp /tmp/block.img /tmp/block.dec`).

> Note: `xts(aes)` via AF_ALG completes asynchronously (cryptd / io-wq worker),
> off the traced task's syscall path, so per-task KCOV may not capture the
> `crypto/*` source. The crypto-path and decrypt-verify checks are therefore
> SKIP-not-FAIL; coverage collection, report generation and `--filter` are
> asserted.

## Test 4: KASAN bug hunt (vng)

Builds a **KASAN + KCOV** kernel (with the sound / USB-MIDI surface) and loops
a sample reproducer for up to **30 minutes**, scraping `dmesg` for a KASAN
report:

```
vock execprog -repeat=0 -procs=4 selftest/samples/midi_uaf.syz   # in the VM
→ PASS if a KASAN/use-after-free/BUG report appears
→ SKIP if none within 30 min (bug not reproduced this run)
```

The bundled sample targets the syzbot bug
[`KASAN: slab-use-after-free Write in snd_usb_midi_v2_free`](https://syzkaller.appspot.com/bug?extid=565b1138cfbe549d4422),
and the test **passes** — the reproducer triggers a real KASAN report.

Both reproducer forms run: `execprog` drives syzkaller **pseudo-syscalls**
(`syz_usb_*`) through the raw-gadget interpreter, and a reproducer written in
syzkaller's `&(0x7f…)` memory layout goes through the arena deserialiser. A
program needing a pseudo-syscall vock has not implemented does not fail
silently — those return `ENOSYS` and are named on startup. See
[FUZZ.md](FUZZ.md) → *Limitations*.

## Target Programs

| Test | Target | Kernel subsystem |
|------|--------|-----------------|
| 1 | `/bin/ls /tmp` | vfs / general syscall paths |
| 3 | `kcapi-enc -d xts(aes)` decrypt | crypto (skcipher, aes, xts) |

## Kernel Configuration

### Test 1 / Test 3 (KCOV)

```
CONFIG_DEBUG_KERNEL, CONFIG_KCOV, CONFIG_KCOV_INSTRUMENT_ALL, CONFIG_DEBUG_FS,
CONFIG_DEBUG_INFO, CONFIG_DEBUG_INFO_DWARF5, CONFIG_DEBUG_INFO_BTF,
CONFIG_PERF_EVENTS, CONFIG_BPF_SYSCALL, CONFIG_IKCONFIG, CONFIG_IKCONFIG_PROC,
CONFIG_CRYPTO_XTS, CONFIG_CRYPTO_USER, CONFIG_CRYPTO_USER_API_SKCIPHER
```

### Test 2 (HW trace, no KCOV)

```
CONFIG_KCOV=n, CONFIG_PERF_EVENTS=y, CONFIG_DEBUG_INFO=y, CONFIG_DEBUG_INFO_BTF=y
+ CONFIG_CPU_SUP_INTEL (Intel)  |  CONFIG_CORESIGHT (arm64)
```

### Minimum per feature

| Feature | Required configs |
|---------|-----------------|
| `--mode hw` | `PERF_EVENTS` (+ `CPU_SUP_INTEL` on Intel, `CORESIGHT` on arm64) |
| `--mode kcov` | `KCOV`, `KCOV_INSTRUMENT_ALL`, `DEBUG_INFO` |
| `--btf` | `DEBUG_INFO_BTF` |
| `--syscall ptrace` | (none) |
| `--syscall sud` | (none, kernel ≥ 5.11) |
| `--syscall ebpf` | `BPF_SYSCALL`, `DEBUG_INFO_BTF` |
| crypto target | `CRYPTO_XTS`, `CRYPTO_USER`, `CRYPTO_USER_API_SKCIPHER` |

## LLVM Toolchain

Priority: `--llvm` flag > `LLVM` env > auto-detect.

```bash
# Suffix style (system-installed)
vock selftest 1 --llvm -21 --kernel-src ~/stable

# Path style (custom build)
sudo vock selftest 2 --llvm /home/you/llvm-project/build/bin/ --on host --kernel-src ~/stable
```

Note: `--llvm` / `CC=...` selects the toolchain for the **kernel** build. vock
itself is built with `cargo` (any `CC=` passed to `make` is ignored).

## GitHub CI

The workflow lives in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
and runs tests 1, 2 and 3 on x86_64 and arm64 runners. Two things it has to
work around, worth knowing if you script selftest yourself:

* **`sudo` breaks the rebuild.** selftest re-runs `make` on startup, `make`
  needs `cargo`, and sudoers' `secure_path` drops `~/.cargo/bin`. Either pass
  `--no-build` (the binary is already built) or preserve PATH explicitly:

  ```bash
  sudo env "PATH=$PATH" ./vock.bin selftest 2 --on host --no-build
  ```

* **Exit codes must be collected.** selftest returns non-zero if any check
  failed, so a CI script that swallows the status reports success regardless.

Test 4 is not run in CI: each test reconfigures and rebuilds the kernel, so
adding a 30-minute bug hunt on top of three builds per architecture risks the
job time limit.
