#ifndef VOCK_FUZZ_COVSET_H
#define VOCK_FUZZ_COVSET_H

#define MAX_COVERAGE 65536

struct covset {
	unsigned long *pcs;
	int count, cap;
};

void covset_init(struct covset *c, int cap);
void covset_add(struct covset *c, unsigned long pc);
void covset_free(struct covset *c);
void covset_sort_dedup(struct covset *c);
int  covset_intersect(struct covset *a, struct covset *b);
int  covset_novel(struct covset *a, struct covset *b);
int  covset_load_file(struct covset *c, const char *path);

#endif
