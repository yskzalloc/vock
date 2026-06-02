# vock

![vock](https://github.com/user-attachments/assets/69531851-8776-42ed-82f9-dac937f089de)

Map any userspace program to the exact kernel code it exercises.

```bash
sudo ./vock --vmlinux vmlinux /bin/ip addr show
# → kerncov.log + coverage.html
```

## Install

Debian/Ubuntu:
```bash
sudo apt install clang libelf-dev linux-headers-$(uname -r)
```

Build:
```bash
git clone https://github.com/yskzalloc/vock && cd vock
make CC=clang
```

## Usage

### 1. Hardware Mode (Intel PT / AMD LBR)

Works on **any kernel** — no CONFIG_KCOV needed:

```bash
# Full branch coverage (needs vmlinux for TNT decoding)
sudo ./vock --vmlinux /boot/vmlinux-$(uname -r) /bin/ip addr show
# → kerncov.log + coverage.html

# Function-entry only (no vmlinux)
sudo ./vock /bin/ip addr show
# → kerncov.log
```

If not running as root:
```bash
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
./vock --vmlinux vmlinux /bin/ip addr show
```

### 2. KCOV Mode

Per-task kernel coverage including remote (softirqs, workqueues):

```bash
sudo ./vock --mode kcov /bin/ip addr show
# → kerncov.log (local + remote) + coverage.html
```

Tracks coverage across `fork()` and `pthread_create()` — each child gets its own KCOV instance (`local-<TID>.log`).

### 3. Syscall Tracking

```bash
sudo ./vock --syscall /bin/ls /tmp
# → kerncov.log + trace.log

sudo ./vock --syzlang /bin/ip addr show
# → kerncov.log + trace.log + trace.syz (for syz-trace2syz)
```

### 4. Fuzzing (experimental)

```bash
sudo ./vock fuzz /bin/ip addr show
sudo ./vock fuzz -repeat=100 -procs=8 /bin/ip addr show
```

See [FUZZ.md](FUZZ.md) for details.

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

### Crypto Subsystem Coverage (selftest 6)

```
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_USER=y
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
| SUD | `--syscall sud` | Kernel ≥ 5.11, x86_64, `mmap_min_addr=0` |
| eBPF | `--syscall ebpf` | `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y` |

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
sudo ./vock --vmlinux vmlinux /bin/ip addr show
# → kerncov.log (5000+ kernel PCs)

# 2. Get syscall trace for syzkaller
sudo ./vock --syzlang /bin/ip addr show
# → trace.syz

# 3. Feed to syzkaller
syz-trace2syz -file trace.syz
# → syzkaller corpus
```

## Selftest

```bash
./vock selftest 1 --on vng-kvm       # KCOV + syscall engines (VM)
./vock selftest 2 --on vng-kvm       # AMD LBR (VM)
sudo ./vock selftest 2 --on host     # Intel PT (bare metal)
./vock selftest --help                # all options
```

See [SELFTEST.md](SELFTEST.md) for details.

## Output Files

| File | Description |
|------|-------------|
| `kerncov.log` | Merged kernel coverage (all per-TID logs combined) |
| `local-<TID>.log` | Per-task KCOV coverage (direct syscall paths) |
| `remote-<TID>.log` | Per-task remote coverage (softirqs, workqueues) |
| `coverage.html` | Source-annotated coverage report |
| `trace.log` | Strace-format syscall log |
| `trace.syz` | Syzlang format (for syz-trace2syz) |

## Build

```bash
make CC=clang           # recommended
make CC=gcc             # alternative
```

## License

See [LICENSE](LICENSE).

