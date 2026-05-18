/*
 * vock SUD (Syscall User Dispatch) syscall tracer.
 *
 * Uses lazypoline's hybrid SUD + zpoline binary rewriting technique.
 * Launches target with LD_PRELOAD=libbootstrap.so + LIBLAZYPOLINE=liblazypoline.so
 * The lazypoline library intercepts all syscalls and writes syzlang to
 * the file specified by VOCK_SUD_OUTPUT env var.
 *
 * Requires: kernel >= 5.11, x86_64, mmap_min_addr=0.
 */
#define _GNU_SOURCE
#include "sud_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <libgen.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON  1
#endif

int vock_sud_available(void)
{
	int ret = prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);
	return (ret == 0 || errno != EINVAL);
}

int vock_sud_run(int argc, char *argv[], int cmd_idx,
                 const char *output_path)
{
	char exe_path[1024], sud_dir[2048];
	char bootstrap_path[2048], lazypoline_path[2048];
	char abs_output[2048];
	ssize_t n;
	pid_t pid;
	int status;

	/* Find our library paths relative to vock binary */
	n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (n == -1) {
		perror("sud: readlink");
		return -1;
	}
	exe_path[n] = '\0';
	char *dir = dirname(exe_path);
	snprintf(sud_dir, sizeof(sud_dir), "%s/syscall/sud", dir);
	snprintf(bootstrap_path, sizeof(bootstrap_path), "%s/libbootstrap.so", sud_dir);
	snprintf(lazypoline_path, sizeof(lazypoline_path), "%s/liblazypoline.so", sud_dir);

	/* Check libraries exist */
	if (access(bootstrap_path, F_OK) != 0 || access(lazypoline_path, F_OK) != 0) {
		fprintf(stderr, "error: SUD libraries not built\n");
		fprintf(stderr, "  run: make -C %s\n", sud_dir);
		return -1;
	}

	/* Resolve output path to absolute */
	if (output_path[0] == '/')
		snprintf(abs_output, sizeof(abs_output), "%s", output_path);
	else {
		char cwd[1024];
		getcwd(cwd, sizeof(cwd));
		snprintf(abs_output, sizeof(abs_output), "%s/%s", cwd, output_path);
	}

	pid = fork();
	if (pid < 0) {
		perror("sud: fork");
		return -1;
	}

	if (pid == 0) {
		/* Set up environment for lazypoline */
		setenv("LD_PRELOAD", bootstrap_path, 1);
		setenv("LIBLAZYPOLINE", lazypoline_path, 1);
		setenv("VOCK_SUD_OUTPUT", abs_output, 1);

		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("sud: execvp");
		_exit(127);
	}

	waitpid(pid, &status, 0);
	fprintf(stderr, "[vock] sud trace written to %s\n", output_path);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
