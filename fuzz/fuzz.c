/*
 * fuzz/fuzz.c — Coverage-guided syscall fuzzer (orchestrator).
 *
 * Modules:
 *   covset.c  — coverage set operations
 *   signal.c  — fallback signal (syscall_nr, errno)
 *   mutate.c  — mutation engine (syzkaller-style)
 *   state.c   — live FD tracking
 */
#define _GNU_SOURCE
#include "fuzz.h"
#include "covset.h"
#include "signal.h"
#include "mutate.h"
#include "state.h"
#include "../syscall/ptrace/ptrace.h"
#include "../syscall/decode.h"
#include "../prog2c/prog2c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <signal.h>

#define MAX_CORPUS 1024

static volatile int fuzz_running = 1;
static void fuzz_sigint(int sig) { (void)sig; fuzz_running = 0; }

/* ─── Execute target: ptrace + hw trace → real coverage ───────────────────── */

static int run_iteration(struct vock_fuzz_opts *opts,
			 struct sc_record *trace, int *ntrace,
			 struct covset *cov, struct signal_set *sig,
			 struct fd_state *fds)
{
	struct vock_trace_ctx tctx;
	struct vock_syscall sc;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		execvp(opts->target, opts->target_argv);
		_exit(127);
	}
	if (pid < 0) return -1;

	if (vock_trace_start(&tctx, pid) < 0) {
		waitpid(pid, &status, 0);
		return -1;
	}

	*ntrace = 0;
	fd_state_init(fds);
	signal_init(sig, MAX_SIGNAL);

	while (vock_trace_next_syscall(&tctx, &sc) == 0 && *ntrace < MAX_SYSCALLS) {
		trace[*ntrace].nr = sc.nr;
		memcpy(trace[*ntrace].args, sc.args, sizeof(sc.args));
		trace[*ntrace].ret = sc.ret;
		fd_state_track(fds, sc.nr, sc.args, sc.ret);
		signal_add(sig, sc.nr, sc.ret);
		(*ntrace)++;
	}

	waitpid(pid, &status, 0);

	/* Build coverage from (nr, args_hash) — same as worker uses */
	covset_init(cov, MAX_COVERAGE);
	for (int i = 0; i < *ntrace; i++) {
		unsigned long h = trace[i].nr * 0x9e3779b97f4a7c15UL;
		for (int a = 0; a < 6; a++)
			if (trace[i].args[a] < 0x100000)
				h ^= trace[i].args[a] << (a * 8);
		covset_add(cov, h);
	}
	covset_sort_dedup(cov);
	signal_sort_dedup(sig);
	return 0;
}

/* ─── Write trace ─────────────────────────────────────────────────────────── */

static void write_trace(const char *path, struct sc_record *trace, int n)
{
	FILE *f = fopen(path, "w");
	if (!f) return;
	for (int i = 0; i < n; i++) {
		const char *name = vock_syscall_name(trace[i].nr);
		if (name) fprintf(f, "%s(", name); else fprintf(f, "syscall_%ld(", trace[i].nr);
		for (int a = 0; a < 6; a++) { if (a) fprintf(f, ", "); fprintf(f, "0x%lx", (unsigned long)trace[i].args[a]); }
		fprintf(f, ") = %ld\n", trace[i].ret);
	}
	fclose(f);
}

/* ─── Main loop ───────────────────────────────────────────────────────────── */

static int fuzz_worker(struct vock_fuzz_opts *opts, int worker_id,
		       struct sc_record *baseline, int ntrace,
		       struct covset *bcov, struct signal_set *bsig)
{
	struct sc_record *mutated = calloc(MAX_SYSCALLS, sizeof(struct sc_record));
	struct corpus_entry *corpus = calloc(MAX_CORPUS, sizeof(struct corpus_entry));
	struct covset icov, gcov;
	struct signal_set isig;
	struct fd_state fds;
	int csz = 0, iters = opts->iterations, total_novel = 0;
	char logname[64];
	FILE *flog;

	srand(time(NULL) ^ getpid() ^ worker_id);

	covset_init(&gcov, MAX_COVERAGE);
	for (int i = 0; i < bcov->count; i++) covset_add(&gcov, bcov->pcs[i]);

	snprintf(logname, sizeof(logname), "fuzz_%d.log", worker_id);
	flog = fopen(logname, "w");
	if (flog) fprintf(flog, "# iter\tsim\tcov\tnovel\tsig\tcalls\tscore\n");

	for (int it = 0; fuzz_running && (iters == 0 || it < iters); it++) {
		int nm = 0;
		mutate_sequence(baseline, ntrace, mutated, &nm, corpus, csz, &fds);

		/* Generate + compile + execute mutated program */
		if (opts->kcov)
			prog2c_exec_kcov(mutated, nm);
		else
			prog2c_exec(mutated, nm);

		/* Load real kernel coverage from kcov.so output */
		covset_init(&icov, MAX_COVERAGE);
		covset_load_file(&icov, "kerncov.log");

		/* Fallback: if no KCOV, use hash-based synthetic coverage */
		signal_init(&isig, MAX_SIGNAL);
		if (icov.count == 0) {
			for (int i = 0; i < nm; i++) {
				unsigned long h = mutated[i].nr * 0x9e3779b97f4a7c15UL;
				for (int a = 0; a < 6; a++)
					if (mutated[i].args[a] < 0x100000)
						h ^= mutated[i].args[a] << (a * 8);
				covset_add(&icov, h);
			}
			covset_sort_dedup(&icov);
		}
		for (int i = 0; i < nm; i++)
			signal_add(&isig, mutated[i].nr, 0);
		signal_sort_dedup(&isig);
		int sig_n = signal_novel(&isig, bsig);

		int isect = covset_intersect(&icov, bcov);
		int novel = covset_novel(&icov, bcov);
		double sim = bcov->count > 0 ? (double)isect / bcov->count : 0;
		double score = novel * 2.0 + sig_n * 1.0 + sim * 0.5;

		if (flog) fprintf(flog, "%d\t%.3f\t%d\t%d\t%d\t%d\t%.1f\n", it, sim, icov.count, novel, sig_n, nm, score);

		if ((novel > 0 || sig_n > 0) && csz < MAX_CORPUS) {
			minimize_trace(mutated, &nm);
			struct corpus_entry *e = &corpus[csz++];
			e->calls = malloc(nm * sizeof(struct sc_record));
			memcpy(e->calls, mutated, nm * sizeof(struct sc_record));
			e->ncalls = nm; e->score = score; e->coverage = icov.count;
			e->novelty = novel; e->signal_novelty = sig_n;
			total_novel += novel;
			for (int i = 0; i < icov.count && gcov.count < gcov.cap; i++)
				covset_add(&gcov, icov.pcs[i]);
			covset_sort_dedup(&gcov);
		}

		covset_free(&icov); signal_free(&isig);
		if ((it+1) % 10 == 0)
			fprintf(stderr, "[fuzz:%d] iter %d: corpus=%d, cov=%d, novel=%d\n",
				worker_id, it+1, csz, gcov.count, total_novel);
	}
	if (flog) fclose(flog);

	/* Write worker corpus */
	char tracename[64];
	snprintf(tracename, sizeof(tracename), "trace_%d.log", worker_id);
	FILE *tl = fopen(tracename, "w");
	if (tl) {
		for (int c = 0; c < csz; c++) {
			fprintf(tl, "# [%d] score=%.1f cov=%d novel=%d sig=%d\n",
				c, corpus[c].score, corpus[c].coverage, corpus[c].novelty, corpus[c].signal_novelty);
			for (int i = 0; i < corpus[c].ncalls; i++) {
				const char *name = vock_syscall_name(corpus[c].calls[i].nr);
				if (name) fprintf(tl, "%s(", name); else fprintf(tl, "syscall_%ld(", corpus[c].calls[i].nr);
				for (int a = 0; a < 6; a++) { if (a) fprintf(tl, ", "); fprintf(tl, "0x%lx", (unsigned long)corpus[c].calls[i].args[a]); }
				fprintf(tl, ") = %ld\n", corpus[c].calls[i].ret);
			}
		}
		fclose(tl);
	}

	for (int c = 0; c < csz; c++) free(corpus[c].calls);
	covset_free(&gcov);
	free(mutated); free(corpus);
	return 0;
}

int vock_fuzz_run(struct vock_fuzz_opts *opts)
{
	struct sc_record *baseline = calloc(MAX_SYSCALLS, sizeof(struct sc_record));
	struct covset bcov;
	struct signal_set bsig;
	struct fd_state fds;
	int ntrace = 0;

	srand(time(NULL) ^ getpid());
	signal(SIGINT, fuzz_sigint);

	/* Phase 1: Baseline */
	fprintf(stderr, "[fuzz] Collecting baseline...\n");
	unlink("kerncov.log"); /* remove stale coverage from previous runs */
	if (run_iteration(opts, baseline, &ntrace, &bcov, &bsig, &fds) < 0) {
		fprintf(stderr, "[fuzz] Baseline failed\n");
		free(baseline); return 1;
	}
	fprintf(stderr, "[fuzz] Baseline: %d calls, %d coverage, %d signals\n", ntrace, bcov.count, bsig.count);
	write_trace("trace.syz", baseline, ntrace);

	/* Phase 2: Fork workers */
	int nprocs = opts->procs > 0 ? opts->procs : 1;
	fprintf(stderr, "[fuzz] Starting %d worker(s)...\n", nprocs);

	if (nprocs == 1) {
		fuzz_worker(opts, 0, baseline, ntrace, &bcov, &bsig);
	} else {
		pid_t *pids = calloc(nprocs, sizeof(pid_t));
		for (int i = 0; i < nprocs; i++) {
			pids[i] = fork();
			if (pids[i] == 0) {
				/* Child worker */
				fuzz_worker(opts, i, baseline, ntrace, &bcov, &bsig);
				_exit(0);
			}
		}
		/* Parent: wait for all workers */
		for (int i = 0; i < nprocs; i++) {
			if (pids[i] > 0)
				waitpid(pids[i], NULL, 0);
		}
		free(pids);
	}

	fprintf(stderr, "[fuzz] Done.\n");
	covset_free(&bcov); signal_free(&bsig);
	free(baseline);
	return 0;
}
