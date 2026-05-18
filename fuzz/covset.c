#include "covset.h"
#include <stdlib.h>
#include <stdio.h>

void covset_init(struct covset *c, int cap)
{ c->pcs = calloc(cap, sizeof(unsigned long)); c->count = 0; c->cap = cap; }

void covset_add(struct covset *c, unsigned long pc)
{ if (c->count < c->cap) c->pcs[c->count++] = pc; }

void covset_free(struct covset *c)
{ free(c->pcs); c->pcs = NULL; c->count = 0; }

static int cmp_ulong(const void *a, const void *b)
{ unsigned long x = *(const unsigned long*)a, y = *(const unsigned long*)b; return (x>y)-(x<y); }

void covset_sort_dedup(struct covset *c)
{
	if (c->count <= 1) return;
	qsort(c->pcs, c->count, sizeof(unsigned long), cmp_ulong);
	int w = 1;
	for (int r = 1; r < c->count; r++)
		if (c->pcs[r] != c->pcs[r-1]) c->pcs[w++] = c->pcs[r];
	c->count = w;
}

int covset_intersect(struct covset *a, struct covset *b)
{
	int i = 0, j = 0, n = 0;
	while (i < a->count && j < b->count) {
		if (a->pcs[i] == b->pcs[j]) { n++; i++; j++; }
		else if (a->pcs[i] < b->pcs[j]) i++; else j++;
	}
	return n;
}

int covset_novel(struct covset *a, struct covset *b)
{
	int i = 0, j = 0, n = 0;
	while (i < a->count && j < b->count) {
		if (a->pcs[i] == b->pcs[j]) { i++; j++; }
		else if (a->pcs[i] < b->pcs[j]) { n++; i++; } else j++;
	}
	return n + (a->count - i);
}

int covset_load_file(struct covset *c, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[64];
	while (fgets(line, sizeof(line), f)) {
		unsigned long pc = strtoul(line, NULL, 16);
		if (pc) covset_add(c, pc);
	}
	fclose(f);
	covset_sort_dedup(c);
	return 0;
}
