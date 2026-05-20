/*
 * fuzz/signal_edge.c — Edge-based signal tracking + corpus minimization.
 *
 * Signal = hash(PC ^ prev_PC) for each consecutive PC pair in KCOV trace.
 * Corpus keeps only programs that contribute at least one unique edge.
 * Minimization removes programs whose edges are all covered by others.
 */
#include "signal_edge.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ─── Hash function (fast, good distribution) ─────────────────────────────── */

static inline uint32_t edge_hash(unsigned long pc, unsigned long prev_pc)
{
	uint64_t h = (uint64_t)(pc ^ prev_pc);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return (uint32_t)(h & (SIGNAL_MAP_SIZE - 1));
}

/* ─── Edge signal from KCOV PCs ───────────────────────────────────────────── */

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
	return (x > y) - (x < y);
}

void edge_signal_from_pcs(const unsigned long *pcs, int npc,
                          struct prog_signal *out)
{
	out->count = 0;
	out->capacity = npc > 0 ? npc : 16;
	out->edges = malloc(out->capacity * sizeof(uint32_t));

	/* Temporary bitmap to dedup within this program */
	uint8_t *seen = calloc(SIGNAL_MAP_SIZE / 8 + 1, 1);

	unsigned long prev = 0;
	for (int i = 0; i < npc; i++) {
		uint32_t edge = edge_hash(pcs[i], prev);
		prev = pcs[i];

		/* Dedup: only add each edge once per program */
		if (seen[edge / 8] & (1 << (edge % 8))) continue;
		seen[edge / 8] |= (1 << (edge % 8));

		if (out->count >= out->capacity) {
			out->capacity *= 2;
			out->edges = realloc(out->edges, out->capacity * sizeof(uint32_t));
		}
		out->edges[out->count++] = edge;
	}
	free(seen);

	qsort(out->edges, out->count, sizeof(uint32_t), cmp_u32);
}

void prog_signal_free(struct prog_signal *s)
{
	free(s->edges);
	s->edges = NULL;
	s->count = 0;
}

/* ─── Corpus ──────────────────────────────────────────────────────────────── */

void signal_corpus_init(struct signal_corpus *c)
{
	memset(c, 0, sizeof(*c));
	c->capacity = 256;
	c->entries = calloc(c->capacity, sizeof(struct signal_corpus_entry));
}

void signal_corpus_free(struct signal_corpus *c)
{
	for (int i = 0; i < c->count; i++)
		prog_signal_free(&c->entries[i].sig);
	free(c->entries);
	memset(c, 0, sizeof(*c));
}

int edge_signal_new_count(struct signal_corpus *corpus, struct prog_signal *sig)
{
	int new = 0;
	for (int i = 0; i < sig->count; i++) {
		uint32_t e = sig->edges[i];
		if (corpus->max_signal.map[e] == 0)
			new++;
	}
	return new;
}

int signal_corpus_add(struct signal_corpus *c, int prog_id,
                      struct prog_signal *sig)
{
	/* Count new edges */
	int new_edges = edge_signal_new_count(c, sig);
	if (new_edges == 0) {
		prog_signal_free(sig);
		return 0; /* no new signal, reject */
	}

	/* Update global max signal */
	for (int i = 0; i < sig->count; i++) {
		uint32_t e = sig->edges[i];
		if (c->max_signal.map[e] < 255)
			c->max_signal.map[e]++;
		if (c->max_signal.map[e] == 1)
			c->max_signal.total_edges++;
	}

	/* Add to corpus */
	if (c->count >= c->capacity) {
		c->capacity *= 2;
		c->entries = realloc(c->entries, c->capacity * sizeof(struct signal_corpus_entry));
	}
	struct signal_corpus_entry *e = &c->entries[c->count++];
	e->prog_id = prog_id;
	e->sig = *sig; /* transfer ownership */
	e->unique_edges = new_edges;

	return 1;
}

int signal_corpus_minimize(struct signal_corpus *c)
{
	if (c->count <= 1) return 0;

	/* Rebuild: which edges are covered by how many programs */
	uint16_t *edge_refcount = calloc(SIGNAL_MAP_SIZE, sizeof(uint16_t));
	for (int i = 0; i < c->count; i++)
		for (int j = 0; j < c->entries[i].sig.count; j++) {
			uint32_t e = c->entries[i].sig.edges[j];
			if (edge_refcount[e] < 65535) edge_refcount[e]++;
		}

	/* Mark programs for removal: those with 0 unique edges */
	int removed = 0;
	for (int i = 0; i < c->count; i++) {
		int has_unique = 0;
		for (int j = 0; j < c->entries[i].sig.count; j++) {
			if (edge_refcount[c->entries[i].sig.edges[j]] == 1) {
				has_unique = 1;
				break;
			}
		}
		if (!has_unique) {
			/* Remove: decrement refcounts and compact */
			for (int j = 0; j < c->entries[i].sig.count; j++)
				edge_refcount[c->entries[i].sig.edges[j]]--;
			prog_signal_free(&c->entries[i].sig);
			c->entries[i] = c->entries[--c->count];
			i--; /* re-check swapped entry */
			removed++;
		}
	}

	/* Update unique_edges counts */
	for (int i = 0; i < c->count; i++) {
		int unique = 0;
		for (int j = 0; j < c->entries[i].sig.count; j++)
			if (edge_refcount[c->entries[i].sig.edges[j]] == 1) unique++;
		c->entries[i].unique_edges = unique;
	}

	free(edge_refcount);
	return removed;
}

int signal_corpus_total_edges(struct signal_corpus *c)
{
	return c->max_signal.total_edges;
}

int signal_corpus_size(struct signal_corpus *c)
{
	return c->count;
}
