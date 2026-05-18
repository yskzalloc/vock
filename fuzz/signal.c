#include "signal.h"
#include <stdlib.h>

static int cmp_ulong(const void *a, const void *b)
{ unsigned long x = *(const unsigned long*)a, y = *(const unsigned long*)b; return (x>y)-(x<y); }

void signal_init(struct signal_set *s, int cap)
{ s->sigs = calloc(cap, sizeof(unsigned long)); s->count = 0; s->cap = cap; }

void signal_add(struct signal_set *s, long nr, long ret)
{
	unsigned long sig = ((unsigned long)(nr & 0xffff) << 32) |
			    ((unsigned long)(ret < 0 ? -ret : 0) & 0xffffffff);
	if (s->count < s->cap) s->sigs[s->count++] = sig;
}

void signal_sort_dedup(struct signal_set *s)
{
	if (s->count <= 1) return;
	qsort(s->sigs, s->count, sizeof(unsigned long), cmp_ulong);
	int w = 1;
	for (int r = 1; r < s->count; r++)
		if (s->sigs[r] != s->sigs[r-1]) s->sigs[w++] = s->sigs[r];
	s->count = w;
}

int signal_novel(struct signal_set *a, struct signal_set *b)
{
	int i = 0, j = 0, n = 0;
	while (i < a->count && j < b->count) {
		if (a->sigs[i] == b->sigs[j]) { i++; j++; }
		else if (a->sigs[i] < b->sigs[j]) { n++; i++; } else j++;
	}
	return n + (a->count - i);
}

void signal_free(struct signal_set *s)
{ free(s->sigs); s->sigs = NULL; s->count = 0; }
