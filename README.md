# vock

Kernel code coverage + syscall tracer + coverage-guided fuzzer — in one tool.

Map any userspace program to the exact kernel code it exercises, then fuzz those paths.

```bash
make && ./vock /bin/ip addr show
```

No dependencies beyond a C compiler. Just `make` and run.

## What It Does

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Your App   │────▶│  vock trace  │────▶│  Kernel PCs  │
│  /bin/ip    │     │  (coverage)  │     │  kerncov.log │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                           ▼
                    ┌──────────────┐     ┌──────────────┐
                    │  vock fuzz   │────▶│  New paths   │
                    │  (mutate)    │     │  fuzz.log    │
                    └──────────────┘     └──────────────┘
```

## Install

```bash
git clone https://github.com/yskzalloc/vock && cd vock
make
```

## Usage

### 1. Kernel Coverage

See which kernel code your program touches:

```bash
# Intel PT (works on any kernel, needs Intel CPU)
./vock /bin/ip addr show
# → kerncov.log + coverage.html

# KCOV (needs CONFIG_KCOV)
./vock --mode kcov /bin/ip addr show
# → kerncov.log + coverage.html
```

### 2. Syscall Tracing

Record all syscalls in strace format:

```bash
./vock --syscall /bin/ls /tmp
# → trace.log (human-readable strace format)

./vock --syzlang /bin/ls /tmp
# → trace.log + trace.syz (for syzkaller's syz-trace2syz)
```

### 3. Fuzzing

Mutate the program's syscalls to explore nearby kernel paths:

```bash
./vock fuzz /bin/ip addr show
# Runs until Ctrl+C
# → trace.syz (baseline) + fuzz_N.log (rankings)

./vock fuzz -repeat=100 /bin/ip addr show
# 100 iterations then stop

./vock fuzz -procs=8 /bin/ip addr show
# 8 parallel workers, until Ctrl+C
```

Each iteration: mutate baseline syscalls → fork child → child executes
mutated syscalls directly via `syscall()` → parent traces with Intel PT →
rank by coverage novelty. No compilation in the loop.

See [FUZZ.md](FUZZ.md) for algorithm details.

### 4. Combined

Coverage + syscall trace in one shot:

```bash
./vock --syscall /bin/ip addr show
# → kerncov.log + trace.log + coverage.html
```

## Syscall Backends

| Backend | Flag | Speed | Requirements |
|---------|------|-------|-------------|
| ptrace | `--syscall ptrace` | Moderate | Any kernel |
| SUD | `--syscall sud` | Fast | Kernel ≥ 5.11, x86_64, `mmap_min_addr=0` |
| eBPF | `--syscall ebpf` | Fastest | `make EBPF=1` + libbpf-dev |

SUD setup:
```bash
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
```

## Architecture

| Feature | Intel x86_64 | ARM64 | AMD x86_64 |
|---------|:---:|:---:|:---:|
| Intel PT coverage | ✓ | — | — |
| CoreSight coverage | — | ✓ | — |
| KCOV coverage | ✓ | ✓ | ✓ |
| Syscall trace | ✓ | ✓ | ✓ |
| Fuzzing | ✓ | ✓ | ✓ |

## Workflow: From Trace to Fuzzer Corpus

```bash
# 1. What kernel code does the target reach?
./vock /bin/ip addr show
# → kerncov.log (5000+ kernel PCs)

# 2. Get syscall trace for syzkaller
./vock --syzlang /bin/ip addr show
# → trace.syz

# 3. Feed to syzkaller
syz-trace2syz -file trace.syz
# → syzkaller corpus

# 4. Or fuzz directly with vock
./vock fuzz /bin/ip addr show
# → finds new kernel paths near the original execution
```

## Selftest

```bash
./vock selftest              # quick host test
./vock selftest --on vng-kvm # full VM test
./vock selftest --help       # all options
```

See [SELFTEST.md](SELFTEST.md) for kernel configuration and VM testing details.

## Files

| Output | Description |
|--------|-------------|
| `kerncov.log` | Merged kernel coverage (local + remote) |
| `local.log` | KCOV local coverage (direct syscall paths) |
| `remote.log` | KCOV remote coverage (softirqs, workqueues) |
| `coverage.html` | Source-annotated coverage report |
| `trace.log` | Strace-format decoded syscall log |
| `trace.syz` | Syzlang format (for syz-trace2syz) |
| `fuzz.log` | Fuzzer rankings (similarity, coverage, novelty) |

## Build Options

```bash
make                    # default (no eBPF)
make EBPF=1             # with eBPF backend (needs libbpf-dev)
make CC=clang           # use clang
```

## License

See [LICENSE](LICENSE).

![vock](https://github.com/user-attachments/assets/69531851-8776-42ed-82f9-dac937f089de)
