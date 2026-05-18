#ifndef VOCK_FUZZ_MUTATE_H
#define VOCK_FUZZ_MUTATE_H

#include "state.h"

#define MAX_SYSCALLS 4096

struct sc_record {
	long nr;
	long args[6];
	long ret;
};

struct corpus_entry {
	struct sc_record *calls;
	int ncalls;
	double score;
	int coverage;
	int novelty;
	int signal_novelty;
};

/* syzkaller-style random integer (weighted distribution) */
unsigned long rand_int(void);

/* Mutate a syscall sequence. Uses corpus for splice, fd state for valid args. */
void mutate_sequence(struct sc_record *src, int nsrc,
		     struct sc_record *dst, int *ndst,
		     struct corpus_entry *corpus, int corpus_size,
		     struct fd_state *fds);

/* Minimize a trace by removing unneeded calls (syzkaller minimization.go) */
void minimize_trace(struct sc_record *trace, int *ntrace);

#endif
