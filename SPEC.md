# vock Type-Aware Fuzzing — Architecture Specification

## Overview

Automated, zero-dependency type-aware kernel fuzzing. No manual syscall descriptions needed.

```
trace.syz (from --syzlang)  +  /sys/kernel/btf/vmlinux
         │                              │
         ▼                              ▼
┌─────────────────┐          ┌─────────────────────┐
│ Trace Analysis  │          │ Native BTF Parser   │
│ Extract syscall │          │ Struct layouts,     │
│ nr + cmd + args │          │ enums, field types  │
└────────┬────────┘          └──────────┬──────────┘
         │                              │
         └──────────┬───────────────────┘
                    ▼
         ┌─────────────────────┐
         │ Type Binding        │
         │ ioctl cmd → struct  │
         │ setsockopt → struct │
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │ Priority Mutation   │
         │ Field-aware + signal│
         │ weighted selection  │
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │ Coverage Feedback   │
         │ KCOV signal edges   │
         │ Field weight update │
         └─────────────────────┘
```

## Why This Works (Lessons from Syzkaller)

Syzkaller's effectiveness comes from:

1. **Signal, not coverage** — tracks `PC ^ prev_PC` edge transitions, not raw PCs.
   A tiny program hitting one unique edge beats a large program hitting 1000 seen edges.

2. **Corpus minimization** — keeps only programs contributing unique signal.
   Result: small corpus, maximum coverage.

3. **Structured mutation** — knows field types, mutates integers with boundary
   values, pointers with NULL/misaligned, flags with valid enum values.

4. **Resource flow** — knows that `open()` returns an fd used by `ioctl()`.

Syzkaller requires **manual** `.txt` descriptions per subsystem (months of work).
vock automates this via BTF + trace inference.

## Implementation Phases

### Phase 1: Native BTF Parser (`btf/btf.c`) ← CURRENT

Parse `/sys/kernel/btf/vmlinux` directly. No libbpf, no external deps.

```c
struct vock_btf *vock_btf_open(const char *path);
void vock_btf_close(struct vock_btf *btf);
const struct vock_btf_type *vock_btf_type_by_id(struct vock_btf *btf, uint32_t id);
const struct vock_btf_type *vock_btf_find_struct(struct vock_btf *btf, const char *name);
int vock_btf_dump_struct(struct vock_btf *btf, const struct vock_btf_type *t);
```

BTF binary format:
```
┌──────────────┐
│ btf_header   │  magic=0xEB9F, version=1
├──────────────┤
│ type section │  array of btf_type records (variable-length)
├──────────────┤
│ str section  │  null-terminated strings
└──────────────┘
```

Each `btf_type`:
- `name_off` → index into string section
- `info` → kind (bits 24-28), vlen (bits 0-15)
- `size` or `type` depending on kind

Kinds we care about:
- `BTF_KIND_INT` (1) — integer with encoding (signed, bool, char)
- `BTF_KIND_PTR` (2) — pointer to another type
- `BTF_KIND_ARRAY` (3) — fixed-size array
- `BTF_KIND_STRUCT` (4) — struct with members
- `BTF_KIND_UNION` (5) — union
- `BTF_KIND_ENUM` (6) — enumeration with named constants
- `BTF_KIND_TYPEDEF` (8) — alias
- `BTF_KIND_CONST` (10), `BTF_KIND_VOLATILE` (9) — qualifiers

### Phase 2: Type Binding (`syzlang/types.c`) ← CURRENT

Given `trace.syz` + BTF, auto-resolve syscall args to kernel structs:

```c
int vock_types_resolve(struct vock_btf *btf, const char *trace_path,
                       struct vock_type_map *out);
```

Resolution strategies (in priority order):
1. **ioctl cmd → BTF enum lookup** — search all BTF enums for the cmd value
2. **ioctl cmd → _IOC_SIZE** — extract encoded struct size, find matching BTF struct
3. **setsockopt optlen** — match optval size against BTF structs
4. **sendmsg/write** — (future) protocol-specific struct matching

Example output:
```
line  60: ioctl(cmd=0x802c542a) arg[2] → struct acpi_genl_event (44 bytes)
           struct acpi_genl_event { /* 44 bytes */
             +  0.0  device_class  array[20]
             + 20.0  bus_id        array[15]
             + 36.0  type          u32
             + 40.0  data          u32
           }
```

The binding tells the mutator: "arg[2] of this ioctl points to a 44-byte struct
with these fields at these offsets with these types."

### Phase 3: Priority Mutation (`fuzz/mutate.c` upgrade)

Replace random byte-flip with:

1. **Field selection** — pick struct field weighted by past signal contribution
2. **Type-aware values**:
   - `BTF_KIND_INT`: 0, 1, -1, MAX, MIN, powers of 2, bit-flips
   - `BTF_KIND_PTR`: NULL, 0xdead, page-aligned, kernel-range
   - `BTF_KIND_ENUM`: pick from known valid values
   - `BTF_KIND_STRUCT` (nested): recurse
3. **Signal feedback** — track which field mutations produce new edges,
   increase weight for productive fields

### Phase 4: Signal-Based Corpus (`fuzz/signal.c` upgrade)

Replace raw PC counting with edge signal:
```c
signal = hash(current_PC ^ previous_PC)
```

Corpus keeps only programs with unique signal contribution.
Minimize periodically (drop programs whose signal is subset of others).

## File Layout

```
btf/
  btf.h          — public API
  btf.c          — parser implementation
  btf_test.c     — standalone test binary
syzlang/
  types.h        — type binding API
  types.c        — trace + BTF → type map
fuzz/
  mutate.c       — upgraded with type-aware mutation
  signal.c       — edge-based signal tracking
```

## Status

- [x] Phase 1: BTF parser — 140K types parsed, struct layouts verified
- [x] Phase 2: Type binding — ioctl/setsockopt → BTF struct resolution
- [ ] Phase 3: Priority mutation (field-aware + signal-weighted)
- [ ] Phase 4: Signal corpus (edge-based minimization)
