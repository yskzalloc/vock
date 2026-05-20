/*
 * vock type binding — auto-resolve syscall args to BTF structs.
 *
 * Strategy:
 *   1. Parse trace.syz lines: "syscall(arg0, arg1, ...)"
 *   2. For ioctl: cmd (arg1) → search BTF enums for matching value
 *      → enum name often encodes the struct (e.g., VIDIOC_S_FMT → v4l2_format)
 *   3. For setsockopt/getsockopt: use (level, optname) → known struct mappings
 *   4. Fallback: match arg size against BTF struct sizes
 */
#include "types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ioctl cmd encoding (from asm-generic/ioctl.h) */
#define _IOC_NRBITS   8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS  2

#define _IOC_NRSHIFT   0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT  (_IOC_SIZESHIFT + _IOC_SIZEBITS)

#define _IOC_SIZE(nr)  (((nr) >> _IOC_SIZESHIFT) & ((1 << _IOC_SIZEBITS) - 1))
#define _IOC_DIR(nr)   (((nr) >> _IOC_DIRSHIFT) & ((1 << _IOC_DIRBITS) - 1))
#define _IOC_TYPE(nr)  (((nr) >> _IOC_TYPESHIFT) & ((1 << _IOC_TYPEBITS) - 1))

#define _IOC_WRITE 1
#define _IOC_READ  2

static void map_add(struct vock_type_map *map, struct vock_type_binding *b)
{
	if (map->count >= map->capacity) {
		map->capacity = map->capacity ? map->capacity * 2 : 64;
		map->bindings = realloc(map->bindings, map->capacity * sizeof(*map->bindings));
	}
	map->bindings[map->count++] = *b;
}

/* Search BTF for a struct matching the ioctl-encoded size */
static const struct vock_btf_type *find_struct_by_size(struct vock_btf *btf, uint32_t size)
{
	if (size == 0) return NULL;
	uint32_t n = vock_btf_type_count(btf);
	for (uint32_t i = 1; i < n; i++) {
		const struct vock_btf_type *t = vock_btf_type_by_id(btf, i);
		if ((t->kind == BTF_KIND_STRUCT || t->kind == BTF_KIND_UNION) &&
		    t->size == size && t->name && t->name[0])
			return t;
	}
	return NULL;
}

/* Search BTF enums for a value matching cmd, return the enum entry name */
static const char *find_enum_name_for_val(struct vock_btf *btf, unsigned long val)
{
	uint32_t n = vock_btf_type_count(btf);
	for (uint32_t i = 1; i < n; i++) {
		const struct vock_btf_type *t = vock_btf_type_by_id(btf, i);
		if (t->kind != BTF_KIND_ENUM) continue;
		for (int j = 0; j < t->nenums; j++) {
			if ((unsigned long)t->enums[j].val == val)
				return t->enums[j].name;
		}
	}
	return NULL;
}

/* Try to find struct by ioctl cmd name heuristic:
 * e.g., BTRFS_IOC_SNAP_CREATE → btrfs_ioctl_vol_args
 * This is a best-effort heuristic. */
static const struct vock_btf_type *find_struct_by_cmd_name(struct vock_btf *btf,
                                                           const char *enum_name)
{
	if (!enum_name) return NULL;

	/* Common pattern: FOO_IOC_BAR → try "foo_bar", "foo_ioctl_bar" */
	/* For now, just use the ioctl size encoding which is more reliable */
	(void)btf;
	(void)enum_name;
	return NULL;
}

/* Parse one trace line: "syscall_name(arg0, arg1, ...) = ret" */
static int parse_trace_line(const char *line, char *name, int name_sz,
                            unsigned long *args, int max_args)
{
	/* Skip leading whitespace */
	while (*line && isspace(*line)) line++;
	/* Extract syscall name */
	const char *p = line;
	int i = 0;
	while (*p && *p != '(' && i < name_sz - 1) name[i++] = *p++;
	name[i] = 0;
	if (*p != '(') return -1;
	p++; /* skip '(' */

	/* Parse args */
	int nargs = 0;
	while (*p && *p != ')' && nargs < max_args) {
		while (*p && isspace(*p)) p++;
		if (*p == ')') break;
		/* Parse hex or decimal */
		char *end;
		unsigned long val = strtoul(p, &end, 0);
		if (end == p) {
			/* Skip non-numeric (e.g., AT_FDCWD) */
			if (strncmp(p, "AT_FDCWD", 8) == 0) { val = (unsigned long)-100; end = (char*)p + 8; }
			else { while (*end && *end != ',' && *end != ')') end++; val = 0; }
		}
		args[nargs++] = val;
		p = end;
		while (*p && isspace(*p)) p++;
		if (*p == ',') p++;
	}
	return nargs;
}

int vock_types_resolve(struct vock_btf *btf, const char *trace_path,
                       struct vock_type_map *out)
{
	FILE *f = fopen(trace_path, "r");
	if (!f) return -1;

	memset(out, 0, sizeof(*out));
	char line[4096];
	int lineno = 0;

	while (fgets(line, sizeof(line), f)) {
		lineno++;
		char name[128];
		unsigned long args[6];
		int nargs = parse_trace_line(line, name, sizeof(name), args, 6);
		if (nargs < 0) continue;

		/* ioctl: arg0=fd, arg1=cmd, arg2=arg_ptr */
		if (strcmp(name, "ioctl") == 0 && nargs >= 3) {
			unsigned long cmd = args[1];
			uint32_t ioc_size = _IOC_SIZE(cmd);
			uint32_t ioc_dir = _IOC_DIR(cmd);

			if (ioc_size > 0 && (ioc_dir & (_IOC_WRITE | _IOC_READ))) {
				/* Try enum lookup first */
				const char *enum_name = find_enum_name_for_val(btf, cmd);
				const struct vock_btf_type *st = find_struct_by_cmd_name(btf, enum_name);

				/* Fallback: match by encoded size */
				if (!st) st = find_struct_by_size(btf, ioc_size);

				if (st) {
					struct vock_type_binding b = {
						.line = lineno,
						.syscall_nr = 16, /* __NR_ioctl */
						.syscall_name = "ioctl",
						.cmd = cmd,
						.arg_index = 2,
						.btf_type_id = st->id,
						.arg_size = st->size,
						.struct_name = st->name,
					};
					map_add(out, &b);
				}
			}
		}

		/* setsockopt: arg0=fd, arg1=level, arg2=optname, arg3=optval, arg4=optlen */
		if (strcmp(name, "setsockopt") == 0 && nargs >= 5) {
			uint32_t optlen = (uint32_t)args[4];
			if (optlen > 0 && optlen <= 4096) {
				const struct vock_btf_type *st = find_struct_by_size(btf, optlen);
				if (st) {
					struct vock_type_binding b = {
						.line = lineno,
						.syscall_nr = 54, /* __NR_setsockopt */
						.syscall_name = "setsockopt",
						.cmd = (args[1] << 16) | args[2],
						.arg_index = 3,
						.btf_type_id = st->id,
						.arg_size = st->size,
						.struct_name = st->name,
					};
					map_add(out, &b);
				}
			}
		}

		/* sendmsg/write with known sizes could also be matched */
	}

	fclose(f);
	return out->count;
}

void vock_types_free(struct vock_type_map *map)
{
	free(map->bindings);
	memset(map, 0, sizeof(*map));
}

void vock_types_dump(struct vock_type_map *map, struct vock_btf *btf)
{
	printf("Type bindings: %d resolved\n\n", map->count);
	for (int i = 0; i < map->count; i++) {
		struct vock_type_binding *b = &map->bindings[i];
		printf("  line %3d: %s(cmd=0x%lx) arg[%d] → struct %s (%u bytes, btf_id=%u)\n",
		       b->line, b->syscall_name, b->cmd, b->arg_index,
		       b->struct_name ? b->struct_name : "?", b->arg_size, b->btf_type_id);

		/* Dump the struct layout */
		const struct vock_btf_type *t = vock_btf_type_by_id(btf, b->btf_type_id);
		if (t) {
			printf("           ");
			vock_btf_dump_struct(btf, t, 0);
			printf("\n");
		}
	}
}
