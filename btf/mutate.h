#ifndef VOCK_BTF_MUTATE_H
#define VOCK_BTF_MUTATE_H

#include "btf.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Type-aware struct mutation engine.
 *
 * Given a raw buffer and its BTF struct type, mutate individual fields
 * using type-appropriate strategies:
 *   - INT: boundary values, bit-flips, delta, special constants
 *   - PTR: NULL, misaligned, page-boundary, sentinel values
 *   - ENUM: pick from known valid values, or invalid neighbor
 *   - ARRAY: mutate random element or length-adjacent bytes
 *   - STRUCT (nested): recurse into sub-struct
 *
 * Field selection is weighted: fields that previously produced new
 * coverage signal get higher priority.
 */

/* Per-field weight for priority selection */
struct vock_field_weight {
	uint32_t hits;    /* times this field produced new signal */
	uint32_t tries;   /* times this field was mutated */
};

/* Mutation context for one struct type */
struct vock_btf_mutator {
	struct vock_btf *btf;
	const struct vock_btf_type *root_type;
	struct vock_field_weight *weights; /* [nmembers] */
	int nmembers;
};

/* Initialize mutator for a given BTF struct type */
void vock_btf_mutator_init(struct vock_btf_mutator *m, struct vock_btf *btf,
                           const struct vock_btf_type *struct_type);
void vock_btf_mutator_free(struct vock_btf_mutator *m);

/*
 * Mutate buffer in-place. Returns index of mutated field (for signal feedback).
 * buf must be at least root_type->size bytes.
 */
int vock_btf_mutate(struct vock_btf_mutator *m, void *buf, size_t buf_size);

/* Signal feedback: call after execution if new coverage was found */
void vock_btf_mutator_reward(struct vock_btf_mutator *m, int field_idx);

/* Dump mutator state (weights) */
void vock_btf_mutator_dump(struct vock_btf_mutator *m);

#endif
