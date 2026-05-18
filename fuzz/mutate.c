/*
 * fuzz/mutate.c — Mutation engine (syzkaller rand.go + mutation.go)
 *
 * Strategies: splice from corpus, mutate arg (fd-aware), multi-mutate,
 * reorder, squash, remove. Weighted like syzkaller.
 */
#include "mutate.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ─── Special integers (syzkaller rand.go) ────────────────────────────────── */

static const unsigned long special_ints[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	64, 127, 128, 129, 255, 256, 257, 511, 512,
	1023, 1024, 1025, 2047, 2048, 4095, 4096,
	0x7fff, 0x8000, 0x8001, 0xffff, 0x10000, 0x10001,
	0x7fffffffUL, 0x80000000UL, 0x80000001UL,
	0xffffffffUL, 0x100000000UL, 0x100000001UL,
	0x7fffffffffffffffUL, 0x8000000000000000UL, 0xffffffffffffffffUL,
};
#define N_SPECIAL (sizeof(special_ints)/sizeof(special_ints[0]))

unsigned long rand_int(void)
{
	unsigned long v = (unsigned long)rand() << 32 | rand();
	int r = rand() % 182;
	if (r < 100)      v %= 10;
	else if (r < 150) v = special_ints[rand() % N_SPECIAL];
	else if (r < 160) v %= 256;
	else if (r < 170) v %= 4096;
	else if (r < 180) v %= 65536;
	else              v %= 0x80000000UL;
	int p = rand() % 107;
	if (p >= 100 && p < 105) v = (unsigned long)(-(long)v);
	else if (p >= 105)       v <<= (rand() % 64);
	return v;
}

/* ─── FD-aware arg mutation ───────────────────────────────────────────────── */

static int is_fd_arg(long nr, int ai)
{
	if (ai != 0) return 0;
	switch (nr) {
	case 0: case 1: case 3: case 5: case 7: case 8: case 16:
	case 17: case 18: case 19: case 20: case 72: case 73: case 74: case 75:
		return 1;
	}
	return 0;
}

static unsigned long mutate_arg(unsigned long val, long nr, int ai, struct fd_state *fds)
{
	/* Skip userspace pointers — they don't exist in the forked child.
	 * Heuristic: values in typical userspace address range (stack/heap/mmap)
	 * are pointers. Values like 0, small ints, -1, flags are NOT pointers. */
	if ((val >= 0x100000 && val <= 0x7fffffffffff) ||
	    (val >= 0x7f0000000000UL && val <= 0x7fffffffffffffffUL))
		return val;

	if (is_fd_arg(nr, ai) && fds->nfds > 0 && (rand() % 4) < 3)
		return fd_state_get_valid(fds);

	int s = rand() % 100;
	if (s < 30) return rand_int();
	if (s < 50) { int d = (rand()%35)+1; return (rand()&1) ? val+d : val-d; }
	if (s < 70) return val ^ (1UL << (rand()%64));
	if (s < 85) {
		int w = 1 << (rand()%3);
		unsigned long mask = (w==4)?0xffffffffUL:(w==2)?0xffffUL:0xffUL;
		return (val & ~mask) | (rand_int() & mask);
	}
	return special_ints[rand() % N_SPECIAL];
}

/* ─── Biased call index (syzkaller prio.go biasedRand) ────────────────────── */

static int biased_idx(int n)
{
	if (n <= 0) return 0;
	int idx = n - 1 - (int)(sqrt((double)(rand() % (n * n))));
	return idx < 0 ? 0 : idx;
}

/* ─── Main mutation dispatch ──────────────────────────────────────────────── */

void mutate_sequence(struct sc_record *src, int nsrc,
		     struct sc_record *dst, int *ndst,
		     struct corpus_entry *corpus, int corpus_size,
		     struct fd_state *fds)
{
	memcpy(dst, src, nsrc * sizeof(struct sc_record));
	*ndst = nsrc;

	/* Weights: splice_corpus=200, mutate=100, multi=100, reorder=100, squash=50, remove=10 */
	int w = rand() % 560;

	if (w < 200 && corpus_size > 0) {
		/* SPLICE FROM CORPUS */
		struct corpus_entry *donor = &corpus[rand() % corpus_size];
		int cut = rand() % nsrc;
		int ds = donor->ncalls > 1 ? rand() % donor->ncalls : 0;
		int dl = donor->ncalls - ds;
		if (cut + dl > MAX_SYSCALLS) dl = MAX_SYSCALLS - cut;
		memcpy(&dst[cut], &donor->calls[ds], dl * sizeof(struct sc_record));
		*ndst = cut + dl;
	} else if (w < 300) {
		/* MUTATE ONE ARG */
		if (nsrc > 0) {
			int ci = biased_idx(nsrc), ai = rand() % 6;
			dst[ci].args[ai] = mutate_arg(dst[ci].args[ai], dst[ci].nr, ai, fds);
		}
	} else if (w < 400) {
		/* MUTATE MULTIPLE ARGS */
		for (int m = (rand()%3)+1; m > 0 && nsrc > 0; m--) {
			int ci = biased_idx(nsrc), ai = rand() % 6;
			dst[ci].args[ai] = mutate_arg(dst[ci].args[ai], dst[ci].nr, ai, fds);
		}
	} else if (w < 500) {
		/* REORDER (reverse suffix) */
		if (nsrc > 1) {
			int cut = rand() % nsrc;
			for (int i = cut, j = nsrc-1; i < j; i++, j--) {
				struct sc_record tmp = dst[i]; dst[i] = dst[j]; dst[j] = tmp;
			}
		}
	} else if (w < 550) {
		/* SQUASH */
		if (nsrc > 0) {
			int ci = rand() % nsrc;
			for (int a = 0; a < 6; a++) dst[ci].args[a] = rand_int();
		}
	} else {
		/* REMOVE */
		if (nsrc > 1) {
			int ci = rand() % nsrc;
			memmove(&dst[ci], &dst[ci+1], (nsrc-ci-1)*sizeof(struct sc_record));
			(*ndst)--;
		}
	}
}

/* ─── Minimization (syzkaller minimization.go) ────────────────────────────── */

void minimize_trace(struct sc_record *trace, int *ntrace)
{
	if (*ntrace <= 3) return;
	for (int i = *ntrace - 1; i > 0 && *ntrace > 3; i--) {
		int needed = 0;
		if (trace[i].ret >= 0 && trace[i].ret < 256) {
			for (int j = i + 1; j < *ntrace; j++)
				for (int a = 0; a < 6; a++)
					if (trace[j].args[a] == trace[i].ret) { needed = 1; break; }
		}
		if (!needed && (rand() % 3) == 0) {
			memmove(&trace[i], &trace[i+1], (*ntrace-i-1)*sizeof(struct sc_record));
			(*ntrace)--;
		}
	}
}
