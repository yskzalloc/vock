/*
 * execprog/execprog.c — Execute a syscall trace file.
 *
 * Parses trace.syz (strace format), replays syscalls via fork+syscall().
 * Supports -repeat=N and -procs=N like syzkaller's syz-execprog.
 */
#define _GNU_SOURCE
#include "execprog.h"
#include "../syscall/decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define MAX_CALLS 4096

struct call {
	long nr;
	long args[6];
};

static int parse_trace(const char *path, struct call *calls, int max)
{
	FILE *f = fopen(path, "r");
	if (!f) { perror(path); return -1; }

	char line[1024];
	int n = 0;
	while (fgets(line, sizeof(line), f) && n < max) {
		if (line[0] == '#' || line[0] == '\n') continue;
		char *paren = strchr(line, '(');
		if (!paren) continue;
		*paren = '\0';

		/* Find syscall number by name */
		long nr = -1;
		for (int i = 0; i < 500; i++) {
			const char *name = vock_syscall_name(i);
			if (name && !strcmp(name, line)) { nr = i; break; }
		}
		if (nr < 0) continue;

		/* Parse args */
		long args[6] = {0};
		char *p = paren + 1;
		for (int a = 0; a < 6 && *p; a++) {
			args[a] = strtol(p, &p, 0);
			while (*p == ',' || *p == ' ') p++;
		}

		calls[n].nr = nr;
		memcpy(calls[n].args, args, sizeof(args));
		n++;
	}
	fclose(f);
	return n;
}

static int exec_once(struct call *calls, int ncalls)
{
	pid_t pid = fork();
	if (pid == 0) {
		unshare(CLONE_NEWUSER | CLONE_NEWNET);
		for (int i = 0; i < ncalls; i++)
			syscall(calls[i].nr,
				calls[i].args[0], calls[i].args[1],
				calls[i].args[2], calls[i].args[3],
				calls[i].args[4], calls[i].args[5]);
		_exit(0);
	}
	if (pid < 0) return -1;
	int status;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void worker(struct call *calls, int ncalls, int repeat, int id)
{
	for (int i = 0; repeat == 0 || i < repeat; i++) {
		exec_once(calls, ncalls);
		if ((i + 1) % 100 == 0)
			fprintf(stderr, "[execprog:%d] executed %d programs\n", id, i + 1);
	}
}

int vock_execprog(const char *trace_file, int repeat, int procs)
{
	struct call *calls = calloc(MAX_CALLS, sizeof(struct call));
	int ncalls = parse_trace(trace_file, calls, MAX_CALLS);
	if (ncalls <= 0) {
		fprintf(stderr, "[execprog] Failed to parse %s\n", trace_file);
		free(calls);
		return 1;
	}
	fprintf(stderr, "[execprog] Loaded %d syscalls from %s\n", ncalls, trace_file);
	fprintf(stderr, "[execprog] repeat=%d, procs=%d\n", repeat, procs);

	if (procs <= 1) {
		worker(calls, ncalls, repeat, 0);
	} else {
		pid_t *pids = calloc(procs, sizeof(pid_t));
		for (int i = 0; i < procs; i++) {
			pids[i] = fork();
			if (pids[i] == 0) {
				worker(calls, ncalls, repeat, i);
				_exit(0);
			}
		}
		for (int i = 0; i < procs; i++)
			if (pids[i] > 0) waitpid(pids[i], NULL, 0);
		free(pids);
	}

	free(calls);
	return 0;
}
