#ifndef VOCK_TYPES_H
#define VOCK_TYPES_H

#include "../btf/btf.h"
#include <stdint.h>

/* A resolved type binding: syscall arg → BTF struct */
struct vock_type_binding {
	int line;              /* line number in trace.syz */
	long syscall_nr;       /* __NR_ioctl, __NR_setsockopt, etc */
	const char *syscall_name;
	unsigned long cmd;     /* ioctl cmd / sockopt name */
	int arg_index;         /* which arg is the struct pointer (0-based) */
	uint32_t btf_type_id;  /* resolved BTF struct type */
	uint32_t arg_size;     /* struct size in bytes */
	const char *struct_name;
};

struct vock_type_map {
	struct vock_type_binding *bindings;
	int count;
	int capacity;
};

/*
 * Resolve type bindings from a trace file + BTF.
 * Strategy:
 *   1. Parse each line of trace.syz for ioctl(fd, CMD, arg) patterns
 *   2. Search BTF enums for CMD value → find associated struct
 *   3. For known syscalls (setsockopt, etc), use arg size heuristic
 *
 * Returns number of bindings found, or -1 on error.
 */
int vock_types_resolve(struct vock_btf *btf, const char *trace_path,
                       struct vock_type_map *out);

void vock_types_free(struct vock_type_map *map);
void vock_types_dump(struct vock_type_map *map, struct vock_btf *btf);

#endif
