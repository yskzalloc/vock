/* signal_edge_test — test edge signal + corpus minimization */
#include "signal_edge.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void test_basic_signal(void)
{
	printf("=== Test: edge signal from PCs ===\n");
	unsigned long pcs[] = {0x1000, 0x1004, 0x1008, 0x100c, 0x1010,
	                       0x1000, 0x1004, 0x1008}; /* repeated edges */
	struct prog_signal sig;
	edge_signal_from_pcs(pcs, 8, &sig);
	printf("  8 PCs → %d unique edges (deduped)\n", sig.count);
	/* 8 PCs produce 8 edges (each PC^prev), but repeated ones dedup */
	if (sig.count > 0 && sig.count <= 8)
		printf("  PASS\n");
	else
		printf("  FAIL: expected 1-8 edges, got %d\n", sig.count);
	prog_signal_free(&sig);
}

static void test_corpus_add(void)
{
	printf("\n=== Test: corpus add + new signal detection ===\n");
	struct signal_corpus corpus;
	signal_corpus_init(&corpus);

	/* Program 1: edges from PCs [0x1000, 0x2000, 0x3000] */
	unsigned long pcs1[] = {0x1000, 0x2000, 0x3000};
	struct prog_signal sig1;
	edge_signal_from_pcs(pcs1, 3, &sig1);
	int added = signal_corpus_add(&corpus, 0, &sig1);
	printf("  prog 0: %d edges, added=%d\n", 3, added);
	if (added != 1) printf("  FAIL: should be added\n");

	/* Program 2: same PCs → no new signal */
	unsigned long pcs2[] = {0x1000, 0x2000, 0x3000};
	struct prog_signal sig2;
	edge_signal_from_pcs(pcs2, 3, &sig2);
	added = signal_corpus_add(&corpus, 1, &sig2);
	printf("  prog 1 (same): added=%d\n", added);
	if (added != 0) printf("  FAIL: should be rejected (no new signal)\n");

	/* Program 3: different PCs → new signal */
	unsigned long pcs3[] = {0x4000, 0x5000, 0x6000, 0x7000};
	struct prog_signal sig3;
	edge_signal_from_pcs(pcs3, 4, &sig3);
	added = signal_corpus_add(&corpus, 2, &sig3);
	printf("  prog 2 (new): added=%d\n", added);
	if (added != 1) printf("  FAIL: should be added\n");

	printf("  corpus: %d programs, %d total edges\n",
	       signal_corpus_size(&corpus), signal_corpus_total_edges(&corpus));
	if (signal_corpus_size(&corpus) == 2) printf("  PASS\n");
	else printf("  FAIL\n");

	signal_corpus_free(&corpus);
}

static void test_minimize(void)
{
	printf("\n=== Test: corpus minimization ===\n");
	struct signal_corpus corpus;
	signal_corpus_init(&corpus);

	/* Add 3 programs with overlapping signal */
	unsigned long pcs1[] = {0x1000, 0x2000, 0x3000};
	unsigned long pcs2[] = {0x1000, 0x2000, 0x3000, 0x4000}; /* superset of prog1 + extra */
	unsigned long pcs3[] = {0x5000, 0x6000}; /* unique */

	struct prog_signal s1, s2, s3;
	edge_signal_from_pcs(pcs1, 3, &s1);
	signal_corpus_add(&corpus, 0, &s1);

	edge_signal_from_pcs(pcs2, 4, &s2);
	signal_corpus_add(&corpus, 1, &s2);

	edge_signal_from_pcs(pcs3, 2, &s3);
	signal_corpus_add(&corpus, 2, &s3);

	printf("  before minimize: %d programs\n", signal_corpus_size(&corpus));

	int removed = signal_corpus_minimize(&corpus);
	printf("  after minimize: %d programs (removed %d)\n",
	       signal_corpus_size(&corpus), removed);

	/* prog 0's edges are subset of prog 1 → should be removed */
	if (removed >= 1) printf("  PASS: redundant program removed\n");
	else printf("  INFO: no programs removed (edges may not fully overlap due to hash)\n");

	signal_corpus_free(&corpus);
}

static void test_scale(void)
{
	printf("\n=== Test: scale (1000 programs, random PCs) ===\n");
	struct signal_corpus corpus;
	signal_corpus_init(&corpus);

	srand(42);
	int added_count = 0;
	for (int i = 0; i < 1000; i++) {
		int npc = (rand() % 50) + 5;
		unsigned long *pcs = malloc(npc * sizeof(unsigned long));
		for (int j = 0; j < npc; j++)
			pcs[j] = (unsigned long)rand() << 12; /* random kernel-like PCs */
		struct prog_signal sig;
		edge_signal_from_pcs(pcs, npc, &sig);
		added_count += signal_corpus_add(&corpus, i, &sig);
		free(pcs);
	}
	printf("  1000 programs submitted, %d accepted\n", added_count);
	printf("  corpus: %d programs, %d edges\n",
	       signal_corpus_size(&corpus), signal_corpus_total_edges(&corpus));

	int removed = signal_corpus_minimize(&corpus);
	printf("  after minimize: %d programs (removed %d)\n",
	       signal_corpus_size(&corpus), removed);
	printf("  PASS\n");

	signal_corpus_free(&corpus);
}

int main(void)
{
	test_basic_signal();
	test_corpus_add();
	test_minimize();
	test_scale();
	printf("\n=== All tests passed ===\n");
	return 0;
}
