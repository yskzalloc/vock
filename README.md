# vock

![vock](https://github.com/user-attachments/assets/69531851-8776-42ed-82f9-dac937f089de)

Map any userspace program to the exact kernel code it exercises.

```bash
sudo ./vock.bin --vmlinux vmlinux /bin/ip addr show
# → kerncov.log + coverage.html
```

vock is written in Rust — a full port of the original C/Python, with no C
remaining and `libc` as the only crate dependency. `make` produces `./vock.bin`
and the `mode/kcov.so` LD_PRELOAD coverage shim.

**Status.** All four selftests pass on x86_64. `selftest 1` (KCOV) covers
KCOV+vmlinux and KCOV+BTF across all three syscall backends (`ptrace`, `sud`,
`ebpf`), with `--syzlang`, `--ordered` and `--filter` reporting. `selftest 3`
(crypto) passes; `selftest 4` reproduces a real KASAN use-after-free from the
bundled sample. `selftest 2` (HW trace) traces with Intel PT on bare metal
(`--on host`, root or `perf_event_paranoid ≤ 1`) and is fully validated on
AMD: one run covers a host pass and a KVM-guest pass across all three
backends — 26/26 checks pass as a normal user with the privileges described
under [eBPF Syscall Backend](#ebpf-syscall-backend---syscall-ebpf). The `sud`
backend traces up to and including the target's `execve` (the LD_PRELOAD
re-injection that keeps tracing past exec is not yet ported). CoreSight
(arm64) is ported and builds; it is validated in follow-up work.

`vock execprog` is a **syz-execprog-style executor**: it replays a program
with `-repeat`/`-procs` and can attribute KCOV coverage to each call. An
unmodified syzbot reproducer works, including the `&(0x7f…)` memory layout,
resource wiring and 13 of the `syz_*` pseudo-syscalls; the rest return `ENOSYS`
and are named on startup. `execprog -stress` mutates the program and loops it,
mirroring `syz-execprog -stress`.

`vock fuzz` is **not implemented** and prints a notice explaining why:
coverage-guided mutation needs an edge signal that is not wired in yet. See
[FUZZ.md](FUZZ.md).

## Install

Toolchain (Rust, via [rustup](https://rustup.rs)):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Optional runtime helpers:
```bash
sudo apt install binutils   # addr2line, nm — source-annotated reports
sudo apt install clang      # only to build test kernels in `vock selftest`
```

Or build a package (see [Build](#build)):
```bash
./debian/get-vendor.sh && dpkg-buildpackage -us -uc -b
sudo apt install ../vock_0.1.0-1_*.deb
```

Build:
```bash
git clone https://github.com/yskzalloc/vock && cd vock
make            # wraps `cargo build --release`; places ./vock.bin and mode/kcov.so
```

## Usage

### 1. Hardware Mode (Intel PT / AMD LBR)

Works on **any kernel** — no CONFIG_KCOV needed:

```bash
# Full branch coverage (needs vmlinux for TNT decoding)
sudo ./vock.bin --vmlinux /boot/vmlinux-$(uname -r) /bin/ip addr show
# → kerncov.log + coverage.html

# Function-entry only (no vmlinux)
sudo ./vock.bin /bin/ip addr show
# → kerncov.log
```

If not running as root — the kernel only forbids kernel profiling at
`perf_event_paranoid >= 2`, so 1 is enough:
```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
./vock.bin --vmlinux vmlinux /bin/ip addr show
```

### 2. KCOV Mode

Per-task kernel coverage including remote (softirqs, workqueues):

```bash
sudo ./vock.bin --mode kcov /bin/ip addr show
# → kerncov.log (local + remote) + coverage.html
```

Tracks coverage across `fork()` and `pthread_create()` — each child gets its own KCOV instance (`local-<TID>.log`).

### 3. Syscall Tracking

```bash
sudo ./vock.bin --syscall /bin/ls /tmp
# → kerncov.log + trace.log

sudo ./vock.bin --syzlang /bin/ip addr show
# → kerncov.log + trace.log + trace.syz (for syz-trace2syz)
```

### 4. Program execution (syz-execprog style)

Replay a program, or use it as a seed and loop mutated variants (`-stress`):

```bash
sudo ./vock.bin --syzlang /bin/ip addr show           # capture a program
./vock.bin execprog -stress -procs=8 trace.syz       # mutate + execute in a loop
sudo ./vock.bin execprog trace.syz                    # replay a saved program
```

See [FUZZ.md](FUZZ.md) for details and current limitations.

## Using with virtme-ng

vock integrates with [virtme-ng](https://github.com/arighi/virtme-ng) for testing custom kernels in lightweight VMs. This is useful for running vock against kernels with specific configs (KCOV, debug info) without rebooting your host.

Install virtme-ng:
```bash
python3 -m venv venv-virtme
source venv-virtme/bin/activate
pip3 install git+https://github.com/arighi/virtme-ng.git
```

### KCOV mode in VM

Build a kernel with KCOV and run vock inside it:
```bash
cd /path/to/linux
vng --configitem CONFIG_KCOV=y --configitem CONFIG_KCOV_INSTRUMENT_ALL=y --build LLVM=-21
vng --rw -- /path/to/vock --mode kcov --vmlinux vmlinux /bin/ip addr show
```

### Hardware mode in VM (AMD LBR)

AMD LBR works inside KVM guests. Build a kernel without KCOV to verify HW-only coverage:
```bash
cd /path/to/linux
vng --configitem CONFIG_KCOV=n --configitem CONFIG_PERF_EVENTS=y --build LLVM=-21
vng --rw -- /path/to/vock --mode hw --vmlinux vmlinux /bin/ip addr show
```

Note: Intel PT requires host passthrough and is typically unavailable in guests. Use `--on host` for Intel PT testing.

## Kernel Configuration

Each feature requires specific kernel configs:

### HW Mode (Intel PT / AMD LBR / CoreSight)

Works on stock distro kernels — only needs:
```
CONFIG_PERF_EVENTS=y
```

### KCOV Mode

```
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
```

### eBPF Syscall Backend (`--syscall ebpf`)

```
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
```

Privileges: the backend calls `bpf(2)` and attaches a tracepoint program.
Most distributions ship `kernel.unprivileged_bpf_disabled=1` or `2`, so as a
normal user the very first `bpf()` call fails with `EPERM` and vock skips the
backend (the message names the sysctl). To use it without root:

```bash
sudo sysctl kernel.unprivileged_bpf_disabled=0   # value 1 is locked until reboot
```

Loading the tracepoint program additionally needs `CAP_BPF` + `CAP_PERFMON`,
so grant them as file capabilities (or simply run vock as root):

```bash
sudo setcap cap_bpf,cap_perfmon+ep ./vock.bin        # build tree
sudo setcap cap_bpf,cap_perfmon+ep ~/.local/bin/vock # installed
```

The backend also reads tracepoint ids from tracefs, which most systems mount
`700 root:root` — and file capabilities do not bypass path permissions. Note
that `mode=` only opens the directories; the `id` files themselves stay
`0440 root:root`, so the group must be handed over too with `gid=`:

```bash
sudo mount -o remount,mode=755,gid=$(id -g) /sys/kernel/tracing
```

So the full normal-user recipe is: the sysctl, the setcap, and the tracefs
remount — vock names the missing step in its skip message at each stage.
Two caveats: `make` / `make install` rewrite the binary, which drops the
capabilities, so re-apply setcap after every rebuild; and the kernel ignores
`LD_PRELOAD` for a capability-bearing binary (secure execution), which does
not matter here — vock sets `LD_PRELOAD` for its *children*, never for
itself. Inside a vng/virtme VM you are root, so none of this applies.

### Coverage Report with Source Annotation (`--vmlinux`, `--kernel-src`)

```
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF5=y
```

### BTF Function Resolution (`--btf`)

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
```

### Crypto Subsystem Coverage (selftest 3)

```
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
```

## Coverage Modes

| Mode | Flag | Coverage Level | Kernel Requirement |
|------|------|---------------|-------------------|
| Intel PT | `--mode hw` (default) | Branch (with vmlinux) or function-entry | `CONFIG_PERF_EVENTS=y` |
| AMD LBR | `--mode hw` (auto) | Function-entry, works in VMs | `CONFIG_PERF_EVENTS=y` |
| CoreSight | `--mode hw` (auto) | Function-entry | `CONFIG_PERF_EVENTS=y`, `CONFIG_CORESIGHT=y` |
| KCOV | `--mode kcov` | Branch (per-task + remote) | `CONFIG_KCOV=y`, `CONFIG_KCOV_INSTRUMENT_ALL=y` |

## Syscall Backends

| Backend | Flag | Requirement |
|---------|------|-------------|
| ptrace | `--syscall ptrace` (default) | Any kernel |
| SUD | `--syscall sud` | Kernel ≥ 5.11 with `SYSCALL_USER_DISPATCH`, x86_64, `mmap_min_addr=0` |
| eBPF | `--syscall ebpf` | `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`, root or `unprivileged_bpf_disabled=0` + `CAP_BPF`/`CAP_PERFMON` |

SUD setup:
```bash
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
```

## Architecture Support

| Feature | Intel x86_64 | ARM64 | AMD x86_64 |
|---------|:---:|:---:|:---:|
| Intel PT (full branch) | ✓ | — | — |
| AMD LBR (function-entry) | — | — | ✓ |
| CoreSight | — | ✓ | — |
| KCOV | ✓ | ✓ | ✓ |
| Syscall tracking | ✓ | ✓ | ✓ |

## Workflow: Coverage to Syzkaller

```bash
# 1. What kernel code does the target reach?
sudo ./vock.bin --vmlinux vmlinux /bin/ip addr show
# → kerncov.log (5000+ kernel PCs)

# 2. Get syscall trace for syzkaller
sudo ./vock.bin --syzlang /bin/ip addr show
# → trace.syz

# 3. Feed to syzkaller
syz-trace2syz -file trace.syz
# → syzkaller corpus
```

## Selftest

Four tests (see [SELFTEST.md](SELFTEST.md) for details):

```bash
./vock.bin selftest 1 --on vng-kvm       # KCOV + all syscall engines + reporting (VM)
sudo ./vock.bin selftest 2 --on host     # HW trace, auto-selected for the host CPU
./vock.bin selftest 3 --on vng-kvm       # --filter + xts(aes) crypto coverage (VM)
./vock.bin selftest 4 --on vng-kvm       # KASAN bug hunt: loop a sample repro ≤30 min
./vock.bin selftest      --on vng-kvm    # all four
./vock.bin selftest --help               # all options
```

Test 2 detects the host CPU and runs the matching engine — Intel PT or AMD LBR
on x86_64, CoreSight on arm64. Intel PT and CoreSight need `--on host` (and
either root or `perf_event_paranoid ≤ 1`); on AMD LBR CPUs one `--on vng-kvm`
run covers both a host pass and a KVM-guest pass. The host pass's ebpf
backend needs root, or as a normal user all three of:

```bash
sudo sysctl kernel.unprivileged_bpf_disabled=0                    # allow bpf(2)
sudo setcap cap_bpf,cap_perfmon+ep ~/.local/bin/vock              # program load
sudo mount -o remount,mode=755,gid=$(id -g) /sys/kernel/tracing   # tracepoint ids
```

Each missing step SKIPs with the exact command to run; with all three
granted the full test passes (verified 26/26 on an AMD Ryzen, host ebpf
included). Re-apply `setcap` after every rebuild — writing the binary drops
file capabilities.

## Output Files

| File | Description |
|------|-------------|
| `kerncov.log` | Merged kernel coverage (all per-TID logs combined) |
| `local-<TID>.log` | Per-task KCOV coverage (direct syscall paths) |
| `remote-<TID>.log` | Per-task remote coverage (softirqs, workqueues) |
| `remote_coverage.log` | Remote coverage collected by the parent |
| `kerncov_prog1.<N>` | Per-call coverage from `execprog -cover` |
| `kerncov_prog1.extra` | Background coverage belonging to no single call |
| `coverage.html` | Source-annotated coverage report |
| `coverage-<TID>.html` | Per-thread report from `--ordered` |
| `trace.log` | Strace-format syscall log |
| `trace.syz` | Syzlang format (for syz-trace2syz) |

All coverage logs carry `PreviousInstructionPC`-shifted PCs, syzkaller's
convention — see [FUZZ.md](FUZZ.md) → *PC convention*.

## Build

```bash
make                 # or: cargo build --release
```

vock is a Cargo workspace with two members at the repo root:

| Directory | Produces | What it is |
|---|---|---|
| `vock/` | `target/release/vock` → `./vock.bin` | The `vock` binary |
| `kcov-preload/` | `target/release/libkcov_preload.so` → `mode/kcov.so` | The `LD_PRELOAD` coverage shim |

`make` builds both and copies the artifacts into place. The binary is
`./vock.bin`, not `./vock`, because the crate directory at the repo root is
already named `vock/` — a file of the same name cannot coexist with it.

The only build dependency is a Rust toolchain; the sole crate dependency is
`libc`. There is no `build.rs`, no bindgen, and no C to compile — a `CC=...`
argument is accepted and ignored for backwards compatibility.

At runtime `vock` finds its shim by checking `$VOCK_KCOV_SO`, then
`<dir of the binary>/mode/kcov.so` (the build tree), then the packaged
locations such as `/usr/lib/vock/kcov.so`. So the same binary works from a
build tree and from an installed package.

### Debian package

```bash
./debian/get-vendor.sh          # vendor deps so the build works offline
dpkg-buildpackage -us -uc -b    # → ../vock_0.1.0-1_<arch>.deb
```

Installs `/usr/bin/vock`, `/usr/lib/vock/kcov.so` and `vock(1)`. See
`debian/README.Debian` for the privileges each mode needs.

## License

See [LICENSE](LICENSE).

