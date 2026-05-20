/*
 * btf/mutate.c — Type-aware struct mutation using BTF field layouts.
 *
 * Mutates raw buffers field-by-field using type-appropriate strategies.
 * Field selection is weighted by past signal contribution.
 */
#include "mutate.h"
#include "btf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Integer boundary values ─────────────────────────────────────────────── */

static const uint64_t int_boundaries[] = {
	0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
	0x10000, 0x7fffffff, 0x80000000, 0xffffffff,
	0x100000000ULL, 0x7fffffffffffffffULL, 0x8000000000000000ULL, 0xffffffffffffffffULL,
};
#define N_BOUNDARIES (sizeof(int_boundaries)/sizeof(int_boundaries[0]))

static const uint64_t ptr_values[] = {
	0,                      /* NULL */
	0xdead,                 /* sentinel */
	0x1000,                 /* page-aligned */
	0xffff,                 /* misaligned */
	0xffffffff,             /* 32-bit overflow */
	0x7fffffffe000ULL,      /* near stack */
	0xffff888000000000ULL,  /* kernel direct map */
};
#define N_PTR_VALUES (sizeof(ptr_values)/sizeof(ptr_values[0]))

/* ─── Weighted field selection ────────────────────────────────────────────── */

static int select_field(struct vock_btf_mutator *m)
{
	if (m->nmembers <= 0) return 0;

	/* Compute total weight (hits + 1 baseline per field) */
	uint32_t total = 0;
	for (int i = 0; i < m->nmembers; i++)
		total += m->weights[i].hits + 1;

	/* Weighted random selection */
	uint32_t r = rand() % total;
	uint32_t acc = 0;
	for (int i = 0; i < m->nmembers; i++) {
		acc += m->weights[i].hits + 1;
		if (r < acc) return i;
	}
	return m->nmembers - 1;
}

/* ─── Type-specific mutation ──────────────────────────────────────────────── */

static void mutate_int_field(void *field_ptr, int bits, int is_signed)
{
	int strategy = rand() % 100;

	if (strategy < 40) {
		/* Boundary value */
		uint64_t val = int_boundaries[rand() % N_BOUNDARIES];
		/* Mask to field width */
		if (bits < 64) val &= (1ULL << bits) - 1;
		if (is_signed && (rand() % 3) == 0)
			val = (uint64_t)(-(int64_t)val) & ((bits < 64) ? (1ULL << bits) - 1 : ~0ULL);
		memcpy(field_ptr, &val, (bits + 7) / 8);
	} else if (strategy < 60) {
		/* Bit-flip */
		int byte_idx = rand() % ((bits + 7) / 8);
		((uint8_t *)field_ptr)[byte_idx] ^= 1 << (rand() % 8);
	} else if (strategy < 80) {
		/* Delta (+/- small value) */
		uint64_t val = 0;
		memcpy(&val, field_ptr, (bits + 7) / 8);
		int delta = (rand() % 35) + 1;
		val = (rand() & 1) ? val + delta : val - delta;
		if (bits < 64) val &= (1ULL << bits) - 1;
		memcpy(field_ptr, &val, (bits + 7) / 8);
	} else {
		/* Random value */
		uint64_t val = (uint64_t)rand() << 32 | rand();
		if (bits < 64) val &= (1ULL << bits) - 1;
		memcpy(field_ptr, &val, (bits + 7) / 8);
	}
}

static void mutate_ptr_field(void *field_ptr)
{
	int strategy = rand() % 100;
	uint64_t val;

	if (strategy < 60)
		val = ptr_values[rand() % N_PTR_VALUES];
	else if (strategy < 80)
		val = ((uint64_t)rand() << 32 | rand()) & ~0xfffULL; /* page-aligned random */
	else
		val = (uint64_t)rand() << 32 | rand();

	memcpy(field_ptr, &val, 8);
}

static void mutate_enum_field(void *field_ptr, int size,
                              const struct vock_btf_type *enum_type)
{
	int strategy = rand() % 100;

	if (strategy < 70 && enum_type->nenums > 0) {
		/* Pick a valid enum value */
		int64_t val = enum_type->enums[rand() % enum_type->nenums].val;
		memcpy(field_ptr, &val, size);
	} else if (strategy < 90 && enum_type->nenums > 0) {
		/* Adjacent to valid value (+/- 1) */
		int64_t val = enum_type->enums[rand() % enum_type->nenums].val;
		val += (rand() & 1) ? 1 : -1;
		memcpy(field_ptr, &val, size);
	} else {
		/* Random */
		uint64_t val = (uint64_t)rand() << 32 | rand();
		if (size < 8) val &= (1ULL << (size * 8)) - 1;
		memcpy(field_ptr, &val, size);
	}
}

static void mutate_array_field(void *field_ptr, int elem_size, int nelems)
{
	if (nelems <= 0 || elem_size <= 0) return;
	int strategy = rand() % 100;

	if (strategy < 40) {
		/* Mutate one random element */
		int idx = rand() % nelems;
		uint8_t *elem = (uint8_t *)field_ptr + idx * elem_size;
		for (int i = 0; i < elem_size; i++)
			elem[i] ^= rand() & 0xff;
	} else if (strategy < 70) {
		/* Zero the array */
		memset(field_ptr, 0, elem_size * nelems);
	} else if (strategy < 85) {
		/* Fill with 0xff */
		memset(field_ptr, 0xff, elem_size * nelems);
	} else {
		/* Random fill */
		uint8_t *p = (uint8_t *)field_ptr;
		for (int i = 0; i < elem_size * nelems; i++)
			p[i] = rand() & 0xff;
	}
}

/* ─── Resolve type through qualifiers ─────────────────────────────────────── */

static const struct vock_btf_type *resolve_type(struct vock_btf *btf, uint32_t type_id)
{
	const struct vock_btf_type *t = vock_btf_type_by_id(btf, type_id);
	while (t && (t->kind == BTF_KIND_CONST || t->kind == BTF_KIND_VOLATILE ||
	             t->kind == BTF_KIND_TYPEDEF || t->kind == BTF_KIND_RESTRICT))
		t = vock_btf_type_by_id(btf, t->ref_type_id);
	return t;
}

/* ─── Public API ──────────────────────────────────────────────────────────── */

void vock_btf_mutator_init(struct vock_btf_mutator *m, struct vock_btf *btf,
                           const struct vock_btf_type *struct_type)
{
	m->btf = btf;
	m->root_type = struct_type;
	m->nmembers = struct_type->nmembers;
	m->weights = calloc(m->nmembers, sizeof(struct vock_field_weight));
}

void vock_btf_mutator_free(struct vock_btf_mutator *m)
{
	free(m->weights);
	memset(m, 0, sizeof(*m));
}

int vock_btf_mutate(struct vock_btf_mutator *m, void *buf, size_t buf_size)
{
	if (m->nmembers <= 0) return -1;
	if (buf_size < m->root_type->size) return -1;

	int field_idx = select_field(m);
	struct vock_btf_member *member = &m->root_type->members[field_idx];
	uint32_t byte_off = member->offset_bits / 8;

	if (byte_off >= buf_size) return -1;

	void *field_ptr = (uint8_t *)buf + byte_off;
	const struct vock_btf_type *ft = resolve_type(m->btf, member->type_id);
	if (!ft) return field_idx;

	m->weights[field_idx].tries++;

	switch (ft->kind) {
	case BTF_KIND_INT:
		mutate_int_field(field_ptr, ft->int_bits, ft->int_signed);
		break;
	case BTF_KIND_PTR:
		mutate_ptr_field(field_ptr);
		break;
	case BTF_KIND_ENUM:
		mutate_enum_field(field_ptr, ft->size, ft);
		break;
	case BTF_KIND_ARRAY:
		mutate_array_field(field_ptr, 1, ft->array_nelems); /* assume byte array */
		break;
	case BTF_KIND_STRUCT: case BTF_KIND_UNION:
		/* Recurse: mutate a random byte in the nested struct */
		if (ft->size > 0) {
			int off = rand() % ft->size;
			((uint8_t *)field_ptr)[off] ^= 1 << (rand() % 8);
		}
		break;
	default:
		/* Unknown type: random byte flip */
		if (byte_off < buf_size)
			((uint8_t *)buf)[byte_off] ^= 1 << (rand() % 8);
		break;
	}

	return field_idx;
}

void vock_btf_mutator_reward(struct vock_btf_mutator *m, int field_idx)
{
	if (field_idx >= 0 && field_idx < m->nmembers)
		m->weights[field_idx].hits++;
}

void vock_btf_mutator_dump(struct vock_btf_mutator *m)
{
	printf("Mutator: struct %s (%u bytes, %d fields)\n",
	       m->root_type->name ? m->root_type->name : "(anon)",
	       m->root_type->size, m->nmembers);
	printf("  %-20s  %6s  %6s  %6s\n", "field", "tries", "hits", "weight");
	for (int i = 0; i < m->nmembers; i++) {
		const char *name = m->root_type->members[i].name;
		uint32_t tries = m->weights[i].tries;
		uint32_t hits = m->weights[i].hits;
		float w = (float)(hits + 1) / (tries + 1);
		printf("  %-20s  %6u  %6u  %6.3f\n",
		       name[0] ? name : "(anon)", tries, hits, w);
	}
}
