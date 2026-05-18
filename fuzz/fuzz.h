#ifndef VOCK_FUZZ_H
#define VOCK_FUZZ_H

#include <stddef.h>

struct vock_fuzz_opts {
	int iterations;       /* number of fuzzing rounds (0 = infinite, Ctrl+C) */
	int procs;            /* parallel fuzzing processes */
	int kcov;             /* use KCOV mode (compile+exec with LD_PRELOAD) */
	const char *target;   /* target program path */
	char **target_argv;   /* target argv */
	int target_argc;
	const char *kernel_src;
	const char *vmlinux;
};

/*
 * Run the coverage-guided fuzzer.
 * 1. Traces target, collects baseline coverage + syscall sequence
 * 2. Mutates syscall args, re-executes, collects new coverage
 * 3. Ranks by similarity to baseline + novelty
 * Outputs: trace.log, trace.syz, kerncov.log, fuzz.log
 */
int vock_fuzz_run(struct vock_fuzz_opts *opts);

#endif
