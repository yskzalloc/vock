#ifndef VOCK_FUZZ_SIGNAL_H
#define VOCK_FUZZ_SIGNAL_H

#define MAX_SIGNAL 8192

/* Fallback signal: (syscall_nr, errno) pairs — syzkaller analysis.go */
struct signal_set {
	unsigned long *sigs;
	int count, cap;
};

void signal_init(struct signal_set *s, int cap);
void signal_add(struct signal_set *s, long nr, long ret);
void signal_sort_dedup(struct signal_set *s);
int  signal_novel(struct signal_set *a, struct signal_set *b);
void signal_free(struct signal_set *s);

#endif
