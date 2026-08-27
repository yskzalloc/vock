# vock dataflow mode

`vock --mode dataflow` records, for the traced task, **what values** flow
through the kernel, not only which lines run. Every instrumented function
reports its arguments at entry and its return value at exit, in execution
order; struct-pointer arguments are expanded field by field. KCOV tells you
`vfs_write` ran; dataflow tells you it ran as
`ksys_write(fd=0x3, buf=0x…, count=0x1000)` and returned `0x1000`.

```bash
sudo ./vock.bin --mode dataflow --vmlinux vmlinux --kernel-src . /bin/ls /tmp
# → dataflow.txt (call tree), dataflow.log, dataflow.html,
#   + kerncov.log / srccov.log / coverage.html (the usual line coverage)
```

## What it needs

The kernel must be built with the **kcov-dataflow** feature, which is the
clang `-fsanitize-coverage=trace-args` / `trace-ret` SanitizerCoverage passes
(a custom LLVM; not upstream today) plus `kernel/kcov_dataflow.c`:

```
CONFIG_KCOV=y
CONFIG_KCOV_DATAFLOW_ARGS=y        # capture arguments at function entry
CONFIG_KCOV_DATAFLOW_RET=y         # capture return values
CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y   # instrument the whole kernel
CONFIG_DEBUG_INFO=y                # struct field layout comes from DWARF
CONFIG_DEBUG_INFO_DWARF5=y
```

Those options `depend on CC_IS_CLANG` and on
`$(cc-option,-fsanitize-coverage=trace-args)`, so a stock clang silently
drops them (`.config` shows them unset). Build with the kcov-dataflow LLVM:

```bash
vng --build \
  --configitem CONFIG_KCOV=y \
  --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
  --configitem CONFIG_KCOV_DATAFLOW_RET=y \
  --configitem CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y \
  --configitem CONFIG_DEBUG_INFO_DWARF5=y \
  LLVM=/path/to/llvm-project/build/bin/ CC=clang
```

Collection needs **root** (it opens `/sys/kernel/debug/kcov_dataflow`);
symbolization needs a matching `vmlinux` (`--vmlinux`) or `--btf` for
kallsyms-only function names.

## How vock drives it

A dataflow session is a property of the **task**, not the process image, and
it survives `execve`. So there is no LD_PRELOAD shim (unlike `--mode kcov`):

1. The parent opens `/sys/kernel/debug/kcov_dataflow` and sizes the buffer
   (`KCOV_DF_INIT_TRACK`), then `fork()`s.
2. The child enables the session on the inherited fd (`KCOV_DF_ENABLE`) and
   `execvp()`s the target; recording covers everything from the dynamic
   loader onward.
3. When the target exits, the kernel tears the session down; the parent maps
   the buffer, decodes the records and symbolizes the function PCs.

The fd is close-on-exec, and the kernel keeps the buffer alive as long as the
parent's fd is open, so the parent reads it *after* the target has exited.

### Remote (softirq / workqueue) coverage

Kernel code that runs on the target's behalf in a kworker can bracket its
work with `kcov_df_remote_start(handle)` / `kcov_df_remote_stop()`. Publish a
second buffer for that handle with `--remote-handle`:

```bash
sudo ./vock.bin --mode dataflow --remote-handle 0x1 --vmlinux vmlinux ./workload
# → dataflow-remote.log holds the kworker's records
```

`H` is a `kcov_remote_handle()` value (see `include/linux/kcov.h`); the kernel
selftest module `rust_kworker_remote` uses handle 1.

## Buffer sizing

The kernel buffer is **linear, not a ring**: once `area[0]` reaches the
capacity the kernel stops recording, so a buffer that fills during process
startup drops the workload that follows. vock defaults to **64 MiB**
(8M u64 words); a full `vfs-write` under `INSTRUMENT_ALL` over a 9p share
uses ~5.2M words. Override with `VOCK_DATAFLOW_WORDS` (u64 words; kernel cap
128 MiB = 16M words):

```bash
sudo VOCK_DATAFLOW_WORDS=16777216 ./vock.bin --mode dataflow ... ./big-target
```

If a run prints `buffer full, later records were dropped`, raise it or trace
a smaller target. A record costs 3 words plus one per value word, so a
struct-heavy call is more expensive than a scalar one.

## Artifacts

| File | Contents |
|------|----------|
| `dataflow.txt` | The call tree: `<file:line>   [<ret> = ]<func>(<arg0>, <arg1>, …)`. `{a, b, …}` is an expanded struct pointer; `FAULT` a field the kernel could not read (a NULL/ERR_PTR the callee received). One line per call, indented by depth, in execution order. |
| `dataflow.log` | One record per line, machine format: `0x<pc> ENTRY seq=… arg=… size=… ptr=0x… vals=…` / `RET …` / `CMP …`. The PC is the per-boot (KASLR) address, so this is also valid `vock report --log` input. |
| `dataflow.html` | `dataflow.txt` as a self-contained page. |
| `dataflow-remote.log` | The remote (kworker) records, when `--remote-handle` was given. |
| `kerncov.log` | The function PCs in sequence — fed to the normal report, so `coverage.html`, `srccov.log` and the terminal source excerpts come out exactly as for `--mode kcov` / `--mode hw`. |

### Reading the call tree

```
fs/read_write.c:729   ksys_write(0x3, 0x0, 0x1000)
fs/read_write.c:668     vfs_write({0x0, 0x45d801e, …}, 0x0, 0x1000, 0x0)
fs/read_write.c:668   0x1000 = vfs_write()
fs/read_write.c:729   0x1000 = ksys_write()
```

The two ENTRY lines are `ksys_write` with its three scalar arguments and
`vfs_write` with its `struct file *` expanded plus the scalars; the two
matching lines with `0x1000 =` are the return records. Arguments are ordered
by source index (the pass emits any dead-argument traces last). A call that
returns without a return record — a `void` function, or one whose exit was
not instrumented — is printed when the enclosing call closes.

## Record format

The uapi is `include/uapi/linux/kcov_dataflow.h`. The buffer is u64 words:
`area[0]` counts the record words that follow, then records packed back to
back. Each record is a header word, the function PC (KASLR offset removed,
like mainline KCOV), a pointer/type word, then `nvals` value words:

| Header bits | Meaning |
|-------------|---------|
| 0–23 | per-task sequence number |
| 28–31 | type: `0xE` ENTRY, `0xF` RET, `0xC` CMP |
| 32–47 | `nvals` — value words after the pointer word |
| 48–55 | size in bytes of the argument / return value |
| 56–63 | ENTRY: argument index; RET: 0 |

Word 1 is the PC; word 2 is the traced pointer for ENTRY/RET (or the
comparison type for CMP); words 3.. are the scalar, the expanded struct
fields, or the two CMP operands. vock decodes this in
[`vock/src/mode/dataflow.rs`](vock/src/mode/dataflow.rs); the kernel-side
producer and its own consumer live in the kernel tree under
`kernel/kcov_dataflow.c` and
`tools/testing/selftests/kcov_dataflow/`.

## Symbolization

PCs are the KASLR-canonical (link-time) addresses the kernel records, so
DWARF symbolization against `vmlinux` uses them directly — vock's in-process
DWARF reader, the same one every other mode uses. For the per-boot
`dataflow.log` and for `--btf` (kallsyms), vock adds the running kernel's
KASLR offset back: runtime `_text` (`/proc/kallsyms`, needs root or
`kptr_restrict=0`) minus the vmlinux/link-time `_text`. A `vmlinux` from a
different build than the running kernel triggers a "KASLR offset not 2 MiB
aligned" warning.

## Selftest

`vock selftest 6` builds a `CONFIG_KCOV_DATAFLOW` kernel (SKIPs cleanly when
the clang has no `-fsanitize-coverage=trace-args`, i.e. without the
kcov-dataflow LLVM — pass `--llvm /path/to/llvm-project/build/bin/`), runs
the `vfs-write` target under `--mode dataflow`, and asserts its syscall
arguments and return values were captured: `ksys_write(…, 0x1000)` and its
`0x1000` return, `ftruncate(…, 0x800, …)`, at least one expanded struct
argument, DWARF file:line resolution, and the ordinary coverage report over
the function PCs — then repeats with `--btf`.

```bash
vock selftest 6 --on vng-kvm --kernel-src ~/linux \
     --llvm /path/to/llvm-project/build/bin/
```

## Limitations

- **x86_64 only, so far.** The KASLR defaults and the selftest cover x86_64;
  arm64 is untested (the offset math is arch-generic, the `_text` default is
  provided, but nothing exercises it yet).
- **No per-task fan-out.** Unlike `--mode kcov`, the session follows the one
  task through `execve` but is not re-established across `fork()` /
  `pthread_create()`; a multi-process target records only the line it enabled
  on. (The kernel supports a session per task; wiring a shim like the KCOV one
  is future work.)
- **Buffer, not ring** — see *Buffer sizing*; a long-running target can push
  its own interesting work out of a full buffer.
- The feature depends on an out-of-tree LLVM; there is no distribution kernel
  with `CONFIG_KCOV_DATAFLOW_*`.
