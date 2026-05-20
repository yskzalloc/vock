#ifndef VOCK_FUZZ_SIGNAL_EDGE_H
#define VOCK_FUZZ_SIGNAL_EDGE_H

#include <stdint.h>

/*
 * Edge-based signal: hash(PC ^ prev_PC) — like syzkaller/AFL.
 * A program's "signal" is the set of unique edges it triggers.
 * Corpus keeps only programs contributing at least one unique edge.
 */

#define SIGNAL_MAP_BITS 16
#define SIGNAL_MAP_SIZE (1 << SIGNAL_MAP_BITS)

/* Global max signal — union of all edges ever seen */
struct edge_signal {
	uint8_t map[SIGNAL_MAP_SIZE]; /* hit count per edge bucket */
	uint32_t total_edges;         /* number of non-zero buckets */
};

/* Per-program signal — which edges this program contributes */
struct prog_signal {
	uint32_t *edges;    /* sorted array of edge hashes */
	int count;
	int capacity;
};

/* Corpus entry with signal */
struct signal_corpus_entry {
	int prog_id;              /* index into program storage */
	struct prog_signal sig;   /* edges this program covers */
	int unique_edges;         /* edges ONLY this program covers */
};

/* Signal corpus — maintains minimized set */
struct signal_corpus {
	struct signal_corpus_entry *entries;
	int count;
	int capacity;
	struct edge_signal max_signal; /* global edge map */
};

/* ─── Edge signal computation ─────────────────────────────────────────────── */

/* Compute edge signal from raw KCOV PC array */
void edge_signal_from_pcs(const unsigned long *pcs, int npc,
                          struct prog_signal *out);

/* Check how many new edges this signal contributes vs global max */
int edge_signal_new_count(struct signal_corpus *corpus, struct prog_signal *sig);

/* ─── Corpus management ───────────────────────────────────────────────────── */

void signal_corpus_init(struct signal_corpus *c);
void signal_corpus_free(struct signal_corpus *c);

/* Add program to corpus if it contributes new signal. Returns 1 if added. */
int signal_corpus_add(struct signal_corpus *c, int prog_id,
                      struct prog_signal *sig);

/* Minimize corpus: remove programs whose signal is subset of others */
int signal_corpus_minimize(struct signal_corpus *c);

/* Get corpus stats */
int signal_corpus_total_edges(struct signal_corpus *c);
int signal_corpus_size(struct signal_corpus *c);

/* Free a prog_signal */
void prog_signal_free(struct prog_signal *s);

#endif
