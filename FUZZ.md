# vock fuzz: Coverage-Guided Syscall Fuzzer

## Concept

`vock fuzz` traces a real program, captures its syscall sequence, then
**mutates and directly re-executes** the syscalls in a forked child process
while collecting kernel coverage via Intel PT. No compilation step during
fuzzing — just `fork() → syscall() × N → _exit()`.

## Usage

```bash
sudo vock fuzz /bin/ip addr show                  # until Ctrl+C
sudo vock fuzz -repeat=100 /bin/ip route          # 100 iterations
sudo vock fuzz -procs=8 /bin/ip addr show         # 8 parallel workers
sudo vock fuzz --help                             # show help
```

## How It Works

```
1. TRACE baseline: run target → capture syscall sequence + kernel coverage
2. LOOP (per worker, until Ctrl+C):
   a. MUTATE baseline syscalls (syzkaller-style: splice, bit-flip, delta, ...)
   b. FORK child in isolated namespace
   c. CHILD executes mutated syscalls directly via syscall()
   d. PARENT traces child with Intel PT → real kernel coverage
   e. RANK: score = novelty×2 + signal×1 + similarity×0.5
   f. If novel: minimize + add to corpus
3. OUTPUT: trace.syz (baseline), trace_N.log (corpus), fuzz_N.log (rankings)
```

No compilation. No file I/O in the hot loop. Each iteration is just
fork + syscall + waitpid + coverage read.

## Example: KASAN Bug Hunting

```bash
# Build KASAN kernel (or use ./fuzz.sh which does this automatically)
cd ~/net
vng --configitem CONFIG_KASAN=y --configitem CONFIG_KASAN_GENERIC=y \
    --configitem CONFIG_KCOV=y --configitem CONFIG_VETH=y \
    --configitem CONFIG_DUMMY=y --configitem CONFIG_FRAME_WARN=4096 \
    --build LLVM=-21

# Fuzz network namespace operations
vng --rw -- sudo ./vock fuzz -procs=8 \
  /usr/bin/unshare --user --map-root-user --net --pid --fork \
  sh -c "ip link add veth0 type veth peer name veth1 && ip link set veth0 up"

# Or just run the script:
./fuzz.sh
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-repeat=N` | 0 | Iterations per worker (0 = until Ctrl+C) |
| `-procs=N` | 1 | Parallel fuzzing workers |

## Modules

| File | Syzkaller equivalent | Purpose |
|------|---------------------|---------|
| `fuzz/fuzz.c` | `syz-execprog` | Orchestrator: fork workers, collect results |
| `fuzz/mutate.c` | `prog/mutation.go` | Mutation engine (weighted strategies) |
| `fuzz/covset.c` | `pkg/cover` | Coverage set: intersect, novel, load |
| `fuzz/signal.c` | `prog/analysis.go` | Fallback signal: (nr, errno) pairs |
| `fuzz/state.c` | `prog/analysis.go` | Live FD tracking |
| `prog2c/prog2c.c` | `syz-prog2c` | Generate C reproducer from trace |

## Scoring (fuzz_N.log)

| Column | Description |
|--------|-------------|
| sim | `|C ∩ B| / |B|` — coverage overlap with baseline |
| cov | `|C|` — total unique kernel PCs hit |
| novel | `|C \ B|` — new addresses not in baseline |
| sig | New (syscall_nr, errno) pairs |
| score | `novel×2 + sig×1 + sim×0.5` |

## Mutation Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| Splice from corpus | 200 | Take suffix from another interesting trace |
| Mutate one arg | 100 | FD-aware, biased toward later calls |
| Mutate multiple | 100 | 1-3 args per iteration |
| Reorder | 100 | Reverse a suffix |
| Squash | 50 | Randomize all args of one call |
| Remove | 10 | Drop one syscall |

Argument values: syzkaller's `randInt` distribution (55% small, 27% boundary, shrink/expand for kernel casts).

## vock prog2c

Generate a standalone C reproducer from any trace (for bug reporting):

```bash
vock prog2c trace.syz -o repro.c
cc -static -o repro repro.c
./repro  # replays the exact syscall sequence
```

## Key Differences from Syzkaller

| | syzkaller | vock fuzz |
|---|-----------|-----------|
| Seed | Grammar-generated | Real program trace |
| Execution | syz-executor via IPC | Direct fork+syscall() |
| Coverage | KCOV | Intel PT or KCOV |
| Compilation | None (executor interprets) | None (direct syscall) |
| Parallelism | Multi-VM | Multi-process (fork) |
| Scope | All kernel | Paths near target program |
