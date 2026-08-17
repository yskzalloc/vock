# vock selftest

Automated test framework. Configures kernels, builds them, boots VMs, and
verifies each feature. Written in Rust (part of the `vock` binary); it shells
out to `make` (which builds the Rust workspace), `vng` (virtme-ng) and the
kernel toolchain.

## Quick Start

```bash
# Test 1: KCOV + syscall engines + reporting (VM)
vock selftest 1 --on vng-kvm --kernel-src ~/stable

# Test 2: HW trace, auto-selected for the host CPU (bare metal, needs root;
# on AMD LBR CPUs it also runs fully inside a KVM guest, no root needed)
sudo vock selftest 2 --on host --kernel-src ~/stable
vock selftest 2 --on vng-kvm --kernel-src ~/stable   # AMD LBR

# Test 3: --filter + xts(aes) crypto coverage (VM)
vock selftest 3 --on vng-kvm --kernel-src ~/stable

# Test 5: Rust-for-Linux module coverage (VM; skips without a kernel Rust toolchain)
vock selftest 5 --on vng-kvm --kernel-src ~/stable

# All four
vock selftest --on vng-kvm --kernel-src ~/stable

# CI (no KVM available)
vock selftest 1 --on vng-tcg --kernel-src ~/stable
```

## Options

```
vock selftest [-h] [--on {host,vng-kvm,vng-tcg}] [--kernel-src PATH]
              [--vmlinux PATH] [--llvm SUFFIX] [--no-build] [-v] [1-5]
```

`vock selftest --help` also prints, for every test, the equivalent raw
command (the exact `vng --rw -- vock ...` invocation and any setup it needs),
so each test can be replayed by hand. The target programs and their setup
live in [`vock/src/selftest/target.rs`](vock/src/selftest/target.rs),
separate from the harness.

| Option | Default | Description |
|--------|---------|-------------|
| `--on` | `vng-kvm` | Execution target (`host`, `vng-kvm`, `vng-tcg`) |
| `--kernel-src` | `$HOME/stable` | Kernel source tree |
| `--vmlinux` | `<kernel-src>/vmlinux` | vmlinux with debug info |
| `--llvm` | auto-detect | LLVM suffix (e.g. `-21`) or path. Also reads `LLVM` env |
| `--no-build` | off | Skip the `make` step and use the existing `./vock.bin` |
| `--record` | off | Record each selected test with asciinema into `selftest<N>.cast` |
| `-v` | off | Verbose: show command output for debugging |
| `1`-`4` | all | Run a specific test only |

## Recording (asciinema)

`--record` re-runs each selected test under `asciinema rec` and writes one
`selftest<N>.cast` (asciicast v3) per test into the current directory:

```bash
vock selftest 1 --record --kernel-src ~/stable    # selftest1.cast
vock selftest --record --kernel-src ~/stable      # selftest1.cast ... selftest5.cast
asciinema play selftest1.cast                     # replay
```

Each cast is a self-contained demo: it opens with the reproducible raw
command for the test (the same text `vock selftest --help` and
`vock selftest raw <n>` print), then records the full test run, and closes
with a `head`/`tail` tour of the artifacts the run produced (`kerncov.log`,
`srccov.log`, `asmcov.log`, `trace.log`, `trace.syz`, `coverage.html`), so
the files are visible in the cast even where no verdict sampled them.
Recording needs `asciinema` on PATH (`cargo install asciinema`,
`pipx install asciinema`, or the distro package) and works headless, so it
runs in CI too; vock is built once by the wrapper and the recorded child
runs with `--no-build`. The child's exit code is propagated
(`asciinema rec --return`), so `--record` still fails when a test fails.

## Test Numbers

| # | Name | Runs on | What |
|---|------|---------|------|
| 1 | Coverage + Syscall + Syzlang | vng | Every KCOV collection & reporting feature: KCOV+vmlinux, KCOV+BTF × each `--syscall` + `--syzlang`, plus `--ordered` and `--filter` |
| 2 | Intel PT / AMD LBR / Arm64 CoreSight | **host** (AMD LBR: vng too) | Detects the host CPU and runs the matching HW engine: HW + vmlinux × each `--syscall` + `--syzlang` |
| 3 | Filter + xts Crypto | vng | `--filter` narrowed xts(aes) decrypt coverage + plaintext verification |
| 4 | KASAN bug hunt | vng | build a KASAN+KCOV kernel; loop a sample reproducer (MIDI UAF) for ≤30 min, watching for a KASAN report |
| 5 | Rust module coverage | vng | build a KCOV kernel with `CONFIG_RUST` + the built-in `rust_misc_device` sample; write()/read()/ioctl() into it from userspace and assert `.rs` source lines (incl. `write_iter`) appear in the coverage; SKIPs without a kernel Rust toolchain |

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

BTF mode resolves PCs against the running kernel's `/proc/kallsyms` (no
vmlinux, no addr2line) and also writes `srccov.log` at kallsyms
granularity, `0x<pc> <function>` per unique PC, so the inode/write-path
assertion works in this group too. When kallsyms cannot resolve anything
(no `CONFIG_KALLSYMS`, `kptr_restrict` hiding every address, or symbols
that do not cover the traced range) vock says which of those it is and
falls back to symbolizing against the vmlinux implied by `--kernel-src`,
so the group reports real code instead of an empty table. Resolution applies no KASLR offset
when the PCs already fall inside the kallsyms range, which is always the
case for a same-kernel log on any architecture; the x86 text-base
heuristic is reserved for foreign x86 logs.

### Group C: remaining reporting features

```
--mode kcov --ordered --vmlinux  vock selftest target vfs-fork  → coverage-<TID>.html per task
--mode kcov --filter fs --vmlinux                     → coverage.html narrowed to fs/ paths
```

The `--ordered` run uses a **forking target** (`vfs-fork`, a fixed 2
children plus the parent) and asserts the sequence semantics, not just file
existence: one per-TID report per task (the fan-out is real and its size is
known, not whatever a shell decided to fork), duplicate PCs preserved (no
dedup), the log in
chronological KCOV-buffer order (not sorted), and the per-TID HTML being
the ordered execution-trace table.

**Skipped on emulated guests (`--on vng-tcg`).** Sequence mode is the one
check whose cost tracks coverage volume rather than the workload: every
task's whole execution is kept, duplicates and all, so `vfs-fork`'s three
tasks produce about 2M PCs and the report symbolizes each one. Measured on a
fast host that is 582s under TCG against about 60s under KVM, and CI runners
are slower still, so on an emulated guest the check only produces timeouts
that say nothing about sequence semantics. The skip is by emulation, not by
architecture: a bare-metal arm64 machine with KVM still runs it, and so does
`--on host`. Capping the report did not help, the symbolization is the cost,
not the rendering.

Verifies: strace format (`') = '`), trace.syz output, coverage PCs > 0, HTML
report, per-TID ordered report, and keyword filtering. `sud` traces up to the
target's `execve`, so its `trace.log` is short by design; KCOV coverage is
collected regardless of syscall backend. On kernels without
syscall user dispatch the `sud` runs SKIP rather than fail. On arm64 that
skip is permanent and no kernel config changes it: SUD is built by
`CONFIG_GENERIC_SYSCALL` (`kernel/entry/Makefile`), only `CONFIG_GENERIC_ENTRY`
selects that symbol (`arch/Kconfig`), and neither has a prompt, so they cannot
be set by hand. arm64 selects `GENERIC_IRQ_ENTRY` alone, leaving
`set_syscall_user_dispatch()` as the `-EINVAL` stub in
`include/linux/syscall_user_dispatch.h`. Enabling `sud` on arm64 needs the
architecture converted to generic syscall entry upstream; x86_64, s390,
riscv, loongarch and powerpc are converted today.

## Test 2: Intel PT / AMD LBR / CoreSight (host)

Detects the host CPU and builds a kernel **without KCOV**, then runs the engine
that matches the hardware. On an AMD LBR CPU with `--on vng-kvm` (the
default), one invocation runs **both** passes:

* **2.1 host**, traces the running host kernel directly (skips cleanly
  when perf privileges are missing, i.e. `perf_event_paranoid >= 2`
  without root)
* **2.2 guest**, boots the freshly built kernel in the KVM guest and
  traces there

For the host pass to run the **ebpf** backend as a normal user, `bpf(2)`
and the tracepoint program load must both be permitted:

```bash
sudo sysctl kernel.unprivileged_bpf_disabled=0         # 1 is locked until reboot
sudo setcap cap_bpf,cap_perfmon+ep ~/.local/bin/vock   # or ./vock.bin
sudo mount -o remount,mode=755,gid=$(id -g) /sys/kernel/tracing  # tracepoint ids (gid=: the id files are 0440)
```

Each missing step SKIPs naming the exact command; with all three granted
the host pass runs every backend and the whole test passes, verified
26 passed / 0 failed / 0 skipped on an AMD Ryzen 7 250 as a normal user.
Re-apply `setcap` after every `make` / `make install` (they rewrite the
binary and Linux drops file capabilities on write). Root needs none of
this. The guest passes are unaffected (you are root inside the VM).

| Host | Engine | Extra config |
|------|--------|--------------|
| x86_64 Intel | Intel PT (full branch) | `CONFIG_CPU_SUP_INTEL` |
| x86_64 AMD | AMD LBR (function-entry) | - |
| aarch64 | CoreSight | `CONFIG_CORESIGHT` |

```bash
# Intel PT / CoreSight: bare metal only, needs root or perf_event_paranoid <= 1
sudo vock selftest 2 --on host --kernel-src ~/stable
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid    # alternative to root

# AMD LBR virtualizes on Zen, so a KVM guest works too (no root needed;
# this is what CI runs on AMD runners). Intel PT and CoreSight stay
# host-only, KVM does not expose them to guests.
vock selftest 2 --on vng-kvm --kernel-src ~/stable
```

For each backend it runs:

```
--mode hw --syzlang --syscall ptrace --vmlinux  → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall sud --vmlinux     → kerncov.log + trace.log + trace.syz
--mode hw --syzlang --syscall ebpf --vmlinux    → kerncov.log + trace.log + trace.syz
```

Each side then runs an `--mode hw --ordered` sequence check: the AMD
decoder merges the LBR and IBS sample streams by `PERF_SAMPLE_TIME` and
reverses each LBR snapshot to oldest-first, so `kerncov.log` is a true
execution sequence. The check asserts duplicates preserved, chronological
(unsorted) order, and that `coverage.html` is the ordered trace table.

Skips automatically when:
- Intel PT + `--on vng-kvm` (Intel PT is unavailable in KVM guests)
- No Intel PT / AMD LBR / CoreSight hardware is detected
- perf is unavailable (`perf_event_paranoid >= 2` without root, or a nested VM)

On arm64 the CoreSight skip distinguishes the cause: inside any VM guest
the message says so directly, hypervisors never describe the ETM/ETE
trace unit in the guest's ACPI tables, so a `cs_etm` PMU cannot exist
there. This is why GitHub's arm64 hosted runners (Azure Cobalt VMs on
Neoverse N2, whose silicon does implement ETE + TRBE) always SKIP test 2:
it is a platform limit, not a missing package. CoreSight validation needs
bare-metal arm64 with `CONFIG_CORESIGHT=y` (plus `CONFIG_CORESIGHT_TRBE`
for ARMv9 ETE) and firmware that describes the trace unit.

References:

* [Linux arm64 hosted runners now available for free in public
  repositories](https://github.blog/changelog/2025-01-16-linux-arm64-hosted-runners-now-available-for-free-in-public-repositories-public-preview/)
  (GitHub changelog): the arm64 runners are Azure Cobalt 100 VMs
* [Arm-hosted Runners public beta
  feedback](https://github.com/orgs/community/discussions/127102)
  (GitHub community): runner hardware details, Neoverse N2 with SVE2
* [arm64: coresight: Add support for ETE and
  TRBE](https://lwn.net/Articles/847445/) (LWN): ETE is the ARMv9
  successor of ETM, driven by the same `cs_etm` perf PMU; TRBE is its
  per-CPU trace buffer
* [kvm/coresight: Support exclude guest and exclude
  host](https://lkml.iu.edu/hypermail/linux/kernel/2501.0/05073.html)
  (LKML): the current KVM/CoreSight work filters host-side trace across
  guest entry/exit; it does not expose the trace unit to guests

## Test 3: Filter + xts(aes) Crypto (vng)

Builds a KCOV kernel with the crypto subsystem enabled, stages an xts(aes)
workload **in Rust over AF_ALG** (no kcapi-tools, no shell): the harness
encrypts a random block on the host (`vock selftest target crypto-setup`),
then traces the in-VM **decrypt** with a keyword-filtered report:

```
--mode kcov --filter crypto --vmlinux  vock selftest target crypto-decrypt
    → kerncov.log + coverage.html (narrowed to crypto/ paths)
```

The staged files (`vock-block.img/.enc/.dec`, `vock-key.bin`) live in the
kernel tree, which vng shares with the host, so every check runs host-side on
the files themselves, no stdout markers. Verifies: coverage PCs > 0,
`coverage.html` generated, the filtered report contains
`aes`/`xts`/`crypto`/`skcipher` paths, and the decrypted plaintext matches
the original.

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
and the test **passes**, the reproducer triggers a real KASAN report.

Both reproducer forms run: `execprog` drives syzkaller **pseudo-syscalls**
(`syz_usb_*`) through the raw-gadget interpreter, and a reproducer written in
syzkaller's `&(0x7f…)` memory layout goes through the arena deserialiser. A
program needing a pseudo-syscall vock has not implemented does not fail
silently, those return `ENOSYS` and are named on startup. See
[FUZZ.md](FUZZ.md) → *Limitations*.

## Test 5: Rust-for-Linux module coverage (vng)

Builds a KCOV kernel with `CONFIG_RUST` and the **built-in**
`rust_misc_device` sample, then traces `vock selftest target rust-touch`:
a userspace program that `write()`s into `/dev/rust-misc-device` (landing in
the sample's Rust `write_iter`), reads back, and drives its three ioctls.

Asserts, host-side on the artifacts:

* `.rs` source lines appear in `srccov.log`, KCOV instruments Rust kernel
  code end to end
* the **write path** is covered (`write_iter` in the resolved coverage; the
  traced fops are generic wrappers from `rust/kernel/miscdevice.rs`
  instantiated for the sample)
* `coverage.html` shows the sample via the instantiated generic names
* Rust symbols are reported in **both forms**: the original v0-mangled name
  (as in kallsyms/nm) and the demangled one

A second pass runs the hw engine against the same device as a bonus
(SKIP-not-FAIL: statistical sampling, IP fallback in guests). The whole test
SKIPs cleanly when `make rustavailable` fails, the kernel Rust toolchain
needs `rustc`, `bindgen-cli` (`cargo install bindgen-cli`) and the rustup
`rust-src` component. Coverage buffers are sized for Rust kernels (2M
entries): a Rust-enabled kernel emits dense coverage and small buffers
saturate during process startup, silently losing the device ops.

## Target Programs

Every traced workload is an explicit syscall sequence implemented in vock
itself ([`vock/src/selftest/target.rs`](vock/src/selftest/target.rs)), not a
borrowed coreutils program. A target is the experiment, so it must not vary
with the guest: which syscalls `touch` issues depends on its build
(utimensat vs utimes, statx vs fstat), busybox applets take different paths
again, and a shell had to expand a command substitution just to make the
file name unique. Each call below is present for the kernel path it must
reach, and every target runs standalone:

```bash
vock selftest target vfs-write     # any of the three, no harness needed
```

| Test | Target | Syscalls | Kernel subsystem |
|------|--------|----------|------------------|
| 1 | `vock selftest target vfs-write` | openat(O_CREAT/O_WRONLY/O_TRUNC), write x4, fsync, futimens, fchmod, ftruncate, fstat, openat(O_RDONLY), read, unlink | vfs write path: path walk and `vfs_create`, inode allocation, `vfs_write`, writeback, inode timestamps, `notify_change` / `do_truncate`, `vfs_getattr`, `vfs_unlink`. The harness asserts inode/write functions appear in `srccov.log` |
| 1 (`--ordered`) | `vock selftest target vfs-fork` | fork x2, each child the vfs-write sequence then `_exit`, then the parent's own | per-task fan-out: a fixed 3 tasks (2 children + parent), so "at least N per-TID reports" is a property of the target. Children ending via `_exit()` still produce their logs, the shim interposes it |
| 2 | `vock selftest target vfs-read` | openat(O_DIRECTORY), getdents64 loop, openat(O_RDONLY), read loop, unlink | vfs read path: `iterate_dir` and the filldir path, `vfs_read` |
| 3 | `vock selftest target crypto-decrypt` (AF_ALG xts(aes)) | socket(AF_ALG), bind, setsockopt, accept, sendmsg, read | crypto (skcipher, aes, xts) |
| 5 | `vock selftest target rust-touch` | openat, write, read, ioctl x3 | Rust misc device (`write_iter`, `read_iter`, ioctl handler) |

## Kernel Configuration

### Test 1 / Test 3 (KCOV)

```
CONFIG_DEBUG_KERNEL, CONFIG_KCOV, CONFIG_KCOV_INSTRUMENT_ALL, CONFIG_DEBUG_FS,
CONFIG_DEBUG_INFO, CONFIG_DEBUG_INFO_DWARF5, CONFIG_DEBUG_INFO_BTF,
CONFIG_PERF_EVENTS, CONFIG_BPF_SYSCALL, CONFIG_IKCONFIG, CONFIG_IKCONFIG_PROC,
CONFIG_CRYPTO_XTS, CONFIG_CRYPTO_AES, CONFIG_CRYPTO_USER_API_SKCIPHER
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
| `--syscall sud` | kernel ≥ 5.11 with `CONFIG_GENERIC_SYSCALL`, which only `CONFIG_GENERIC_ENTRY` selects (x86_64, s390, riscv, loongarch, powerpc). arm64 selects `GENERIC_IRQ_ENTRY` alone and always SKIPs; no config can change that |
| `--syscall ebpf` | `BPF_SYSCALL`, `DEBUG_INFO_BTF` |
| crypto target | `CRYPTO_XTS`, `CRYPTO_AES`, `CRYPTO_USER_API_SKCIPHER` (AF_ALG) |

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
and runs tests 1, 2, 3 and 5 on x86_64 and arm64 runners (the CI installs
`bindgen-cli` and `rust-src`, so test 5 runs rather than skipping). Each job writes a
**summary table** (test, verdict, pass/fail/skip counts) to the Actions
run's Summary tab, uploads every test's full log as its **own artifact**
linked from that table, and appends the reproducible raw command for each
test, the same text `vock selftest --help` prints, via
`vock selftest raw <n>`, so the two cannot drift. The summary layout is a
static template, [`template/ACTION.md`](template/ACTION.md): the last CI
step substitutes `{{ARCH}}` and replaces the `{{RESULT_ROWS}}` /
`{{RAW_COMMANDS}}` placeholder lines, so the page can be restyled without
touching the workflow. Two things the workflow
has to work around, worth knowing if you script selftest yourself:

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
