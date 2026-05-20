#ifndef VOCK_BTF_H
#define VOCK_BTF_H

#include <stdint.h>

/* BTF type kinds */
#define BTF_KIND_INT       1
#define BTF_KIND_PTR       2
#define BTF_KIND_ARRAY     3
#define BTF_KIND_STRUCT    4
#define BTF_KIND_UNION     5
#define BTF_KIND_ENUM      6
#define BTF_KIND_FWD       7
#define BTF_KIND_TYPEDEF   8
#define BTF_KIND_VOLATILE  9
#define BTF_KIND_CONST    10
#define BTF_KIND_RESTRICT 11
#define BTF_KIND_FUNC     12
#define BTF_KIND_FUNC_PROTO 13
#define BTF_KIND_VAR      14
#define BTF_KIND_DATASEC  15
#define BTF_KIND_FLOAT    16
#define BTF_KIND_ENUM64   19

struct vock_btf_member {
	const char *name;
	uint32_t type_id;
	uint32_t offset_bits; /* bit offset from struct start */
};

struct vock_btf_enum_val {
	const char *name;
	int64_t val;
};

struct vock_btf_type {
	uint32_t id;
	uint16_t kind;
	const char *name;
	uint32_t size;         /* byte size for INT/STRUCT/UNION/ENUM */
	uint32_t ref_type_id;  /* for PTR/TYPEDEF/CONST/VOLATILE/RESTRICT */
	/* struct/union members */
	struct vock_btf_member *members;
	int nmembers;
	/* enum values */
	struct vock_btf_enum_val *enums;
	int nenums;
	/* int encoding */
	uint8_t int_bits;
	uint8_t int_signed;
	/* array */
	uint32_t array_type_id;
	uint32_t array_nelems;
};

struct vock_btf;

struct vock_btf *vock_btf_open(const char *path);
void vock_btf_close(struct vock_btf *btf);

uint32_t vock_btf_type_count(struct vock_btf *btf);
const struct vock_btf_type *vock_btf_type_by_id(struct vock_btf *btf, uint32_t id);
const struct vock_btf_type *vock_btf_find_struct(struct vock_btf *btf, const char *name);
void vock_btf_dump_struct(struct vock_btf *btf, const struct vock_btf_type *t, int depth);

#endif
