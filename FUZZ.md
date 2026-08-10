# vock execprog: replay and stress

> **Where fuzzing stands.** `vock execprog` replays programs, and
> `execprog -stress` mutates and loops them. `vock fuzz` is **not
> implemented** and prints a notice explaining why — see
> [Why not `vock fuzz` yet](#why-not-vock-fuzz-yet).

## Concept

`vock execprog` executes a syzkaller program — an unmodified syzbot
reproducer, vock's own inline-hex USB form, or a plain syscall trace — and can
attribute kernel coverage to each individual call. With `-stress` it treats
the program as a corpus seed and loops mutating and executing variants of it,
watching for a kernel report.

This mirrors syzkaller's own split
(see [`tools/syz-execprog/execprog.go`](https://github.com/google/syzkaller/blob/master/tools/syz-execprog/execprog.go)):

| syzkaller | vock | Purpose |
|---|---|---|
| `syz-execprog` (default) | `vock execprog` | Replay a program **verbatim** — mutation would stop a reproducer reproducing |
| `syz-execprog -stress` | `vock execprog -stress` | Local fuzzer for when `syz-manager` cannot be used |
| `pkg/fuzzer` + `syz-manager` | — | Out of scope |

## Usage

```bash
sudo vock --syzlang /bin/ip addr show     # capture a program → trace.syz
vock execprog trace.syz                   # replay it exactly
vock execprog -cover trace.syz            # replay once, per-call coverage
vock execprog -stress -procs=8 trace.syz  # mutate + execute in a loop
vock execprog --help
```

## Why not `vock fuzz` yet

vock's job is to map a program to the kernel code it reaches. Mutation is only
worth anything once that mapping feeds back into the choice of what to run
next. Today the execution signal is `(syscall, errno)`, which cannot
distinguish "reached new code" from "failed the same way again", so a mutator
driven by it is a random syscall generator.

Two things are needed before a real fuzzer earns its place:

1. **Edge signal.** `fuzz/signal_edge.rs` implements syzkaller's
   `pc ^ hash(prev_pc)` but sits off the execution path. Now that
   `prog_exec.rs` collects per-call KCOV, wiring it in is tractable.
2. **A choice table.** `prog.Mutate` is driven by syscall-selection priors
   derived from the descriptions, which vock does not carry — the same gap
   that limits argument-width inference below.

The ported building blocks (`fuzz/mutate.rs`, `signal.rs`, `signal_edge.rs`,
`covset.rs`, `btf.rs`) remain in the tree for that work.

## Stress mode

`execprog -stress` mutates the decoded argument tree directly
(`fuzz/prog_mutate.rs`). syzkaller alternates between generating a fresh random
program from the descriptions and mutating a corpus one; vock has no
descriptions, so only the mutation half applies and the input program is the
corpus.

Mutations are deliberately **structure-preserving** — pointers keep pointing at
their objects and `rN` wiring is untouched — so a variant stays a runnable
relative of the original rather than noise. What changes: integer leaves
(interesting values, bit flips, small deltas), buffer contents (bit flips,
grow, shrink), and the call sequence (drop or duplicate a call, which is how
double-free and use-after-free paths get exercised). Call count and buffer
sizes are bounded so a long run cannot grow without limit.

```bash
vock execprog -stress prog.syz              # until interrupted
vock execprog -stress -repeat=1000 prog.syz # bounded
vock execprog -stress -procs=8 prog.syz     # 8 workers, distinct RNG streams
```

A kernel bug surfaces as a KASAN/BUG splat in the console, the same shape as a
syzbot crash report. `vock selftest 4` wires this into the test framework.

## Example: reproducing a syzbot bug

Given a syzbot bug and its reproducer, run it against an instrumented kernel:

```bash
# Build a kernel with KASAN + KCOV
cd ~/stable
vng --configitem CONFIG_KASAN=y --configitem CONFIG_KASAN_GENERIC=y \
    --configitem CONFIG_KCOV=y --build LLVM=-21

# Replay the reproducer in the VM; a bug prints a KASAN/BUG splat
vng --rw -- vock execprog -repeat=0 -procs=8 repro.syz

# Or hunt for variants of it
vng --rw -- vock execprog -stress -procs=8 repro.syz
```

An unmodified syzbot reproducer works as-is. `vock selftest 4` automates
exactly this against a bundled sample
([`snd_usb_midi_v2_free` UAF](https://syzkaller.appspot.com/bug?extid=565b1138cfbe549d4422))
and reproduces the bug.

Turn a program into a standalone C reproducer for a bug report with
[`vock prog2c`](#vock-prog2c).

## Program forms

`vock execprog` auto-detects three input forms:

| Form | Detected by | Executed by |
|------|-------------|-------------|
| syzkaller memory-layout (an unmodified syzbot reproducer) | contains `&(0x7f…)` | `prog_decode.rs` (deserialise + arena) → `prog_exec.rs` |
| vock inline-hex USB | contains `syz_usb_*` with hex blobs | `pseudo_syscalls.rs` (raw-gadget) |
| plain syscall trace | neither | fork + `syscall(nr, …)` |

### The `&(0x7f…)` arena

Reproducers serialise pointer arguments against a textual base of
`0x7f0000000000` (`encodingAddrBase`). The parser subtracts it to get an
arena-relative offset and the runtime adds the target's `DataOffset` back:

```
offset       = textual_addr - 0x7f0000000000
runtime_addr = 0x200000000000 + offset          # amd64
```

vock maps the 16 MiB arena at `DataOffset` rather than at the textual base,
because `0x7f…` is exactly where Linux places shared libraries — a `MAP_FIXED`
there would unmap libc. Objects are laid out immediately before their owning
call runs (copyin), fixed addresses are reserved first (a 64-byte-granule
bitmap, as in `prog/alloc.go`) so `AUTO` objects cannot overlap them, and a
call's return value fills its `rN` slot for later calls (copyout). Resource
references support the full `rN/div+add` form, applied divide-then-add.

Supported argument syntax: integers (hex/octal/decimal/negative), `nil`,
`AUTO` (both values and `&AUTO` pointers, which get real slots from the
allocator), pointers (including VMA `&(addr/size)=nil` and squashed `ANY=`),
hex `"…"` and ASCII `'…'` literals with escapes, structs `{…}`, arrays `[…]`,
unions `@opt=…`, resources `rN[/div][+add]`, `csum` fields, compressed image
blobs `"$<base64>"` (zlib, inflated at parse time), and the
`(fail_nth: N)` / `(async)` call properties. A call may carry up to 9
arguments (`kMaxArgs`), since pseudo-syscalls such as `syz_mount_image` take
more than the six a real syscall can.

Resources are produced two ways, both supported. A call's return value fills
`rN` via the `rN = call(…)` prefix; a call that writes its handles into memory
marks them inline, `pipe(&(0x7f…)={<r0=>0x…, <r1=>0x…})`, and those are read
back out of the arena after the call returns. Without the second form every
`pipe`/`socketpair` reproducer would run the rest of its program on `-1` fds.

## Limitations

| Limitation | Effect | Status |
|---|---|---|
| No syscall description database (`sys/linux/*.txt`) | The textual form records field *values* but not field *widths*. Integers inside a struct/array default to 8 bytes (`VOCK_PROG_INT_WIDTH` overrides); resource fields use their natural 4 bytes. A write is clipped at the next object's address so an over-wide guess cannot corrupt its neighbour. Byte-exact targets — string literals, which is what most reproducers point at — are unaffected. | Inherent without the DB |
| Flag/const *names* have no numeric value | An argument written as a symbolic flag decodes to 0 | Inherent without the DB |
| Bitfield/csum field placement | The `csum_inet` and bitfield-packing primitives are implemented and unit-tested, but which field is a bitfield comes from the descriptions, so only explicit `csum` tokens are honoured | Partial |
| Pseudo-syscall coverage | 11 in `pseudo_ext.rs` plus the USB raw-gadget set (see below); the rest return **ENOSYS and are listed on startup** rather than silently succeeding | Partial |

Implemented in `pseudo_ext.rs`: `syz_open_dev`, `syz_open_procfs`,
`syz_open_pts`, `syz_init_net_socket`, `syz_create_resource`,
`syz_memcpy_off`, `syz_genetlink_get_family_id`, `syz_io_uring_setup`,
`syz_emit_ethernet`, `syz_mount_image`, `syz_read_part_table` — plus the USB
raw-gadget set (`syz_usb_connect`, `syz_usb_control_io`, `syz_usb_disconnect`)
in `pseudo_syscalls.rs`.

`syz_mount_image` and `syz_read_part_table` are implemented against upstream's
current ABI: the filesystem image arrives inline as `"$<base64>"` of a zlib
stream (`pkg/image/compression.go`), which `inflate.rs` decodes — a
from-scratch RFC 1950/1951 decoder following puff, so vock keeps its
libc-only dependency. The image is written to a temporary file, attached to a
free loop device, mounted, and the device is detached afterwards so a
`-repeat` run does not exhaust `/dev/loopN`.

Still missing: `syz_kvm_setup_cpu`, `syz_fuse_handle_req`, `syz_80211_*`,
`syz_ublk_*`. These return ENOSYS and are named on startup.

## Coverage attribution

With `-cover`, KCOV is opened **per thread**, reset immediately before each
call and drained immediately after, so PCs are attributed to individual calls.
A second, *remote* KCOV handle captures background work done on the process's
behalf by other tasks (workqueues, softirqs, USB/net completion) — coverage
that belongs to no single call.

Output matches `syz-execprog`'s layout (`pkg/instance/execprog.go:388`): one
`kerncov_prog1.<call>` per call, plus `kerncov_prog1.extra` for the background
stream, plus a merged, deduplicated `kerncov.log`.

### PC convention

All vock coverage logs follow syzkaller's convention: PCs are shifted with
`PreviousInstructionPC` (`pc-1` on x86_64, `pc-4` on arm64) before being
written. KCOV records the address *after* the call instruction, so the shift is
what makes a PC symbolize to the call site rather than to the following source
line. `pc-1` lands inside the call instruction, which is all `addr2line` needs.

This is applied by every producer — `prog_exec.rs`, `mode/kcov.rs`, and the
`mode/kcov.so` preload shim — so `kerncov.log`, `local-*.log`,
`remote_coverage.log` and the per-call `kerncov_prog1.*` files are all in the
same units, and the per-call files are drop-in compatible with syzkaller
tooling (which undoes the shift with `NextInstructionPC` before symbolizing,
execprog.go:413-424).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-repeat=N` | 1 (0 = until Ctrl+C) | Executions per worker; `-stress` defaults to 0 |
| `-procs=N`  | 1 | Parallel workers |
| `-cover` | off | Per-call KCOV → `kerncov.log` + `kerncov_prog1.<call>` |
| `-threaded` | off | Run `async` calls on their own thread |
| `-collide` | off | Overlap adjacent calls to shake out races (implies `-threaded`) |
| `-slowdown=N` | 1 | Scale the timeout tiers |
| `-stress` | off | Mutate the program and loop (local fuzzer) |

Timeout tiers follow syzkaller: syscall `50ms × slowdown`, program
`5s × min(slowdown,3)`, and an unfinished-call grace period of
`max(2 × syscall, program/6, prog_extra)`.

## Output

| File | Description |
|------|-------------|
| `trace.syz` | The captured program, in syzlang |
| `kerncov.log` | Kernel PCs from the KCOV execution (merged, deduplicated) |
| `kerncov_prog1.<N>` | Per-call kernel PCs when `-cover` is used |

Symbolize coverage into an annotated report:

```bash
vock report --vmlinux vmlinux --kernel-src ~/stable   # coverage.html
vock report --btf --kernel-src ~/stable               # kallsyms-based
```

## vock prog2c

Generate a standalone C reproducer from a program (for bug reporting):

```bash
vock prog2c trace.syz -o repro.c
cc -static -o repro repro.c
./repro   # replays the exact syscall sequence
```

## Roadmap

| Step | Why it comes first |
|---|---|
| Wire `signal_edge.rs` into the execution loop | Without edge coverage, `-stress` cannot tell progress from noise, and no corpus can grow |
| Track a corpus keyed by new edges | Turns `-stress` from blind mutation into feedback-driven search |
| Field widths from BTF | The largest remaining fidelity gap (see Limitations); vock already parses BTF |
| Choice table | Needed before `prog.Mutate`-style syscall selection is meaningful |

