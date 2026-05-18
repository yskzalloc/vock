/*
 * vock eBPF syscall tracer.
 *
 * Uses raw_syscalls:sys_enter/sys_exit tracepoints via CO-RE.
 * Filters by target PID, emits strace-compatible format.
 * Requires: libbpf-dev, kernel with CONFIG_BPF + BTF, root.
 */
#define _GNU_SOURCE
#include "ebpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>

int vock_ebpf_available(void)
{
	return access("/sys/kernel/btf/vmlinux", F_OK) == 0;
}

#ifdef VOCK_EBPF_ENABLED

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.skel.h"

struct event {
	int is_exit;
	long nr;
	unsigned long args[6];
	long ret;
};

static FILE *g_output;
static long g_pending_nr;
static unsigned long g_pending_args[6];
static int g_has_pending;

static const char *nr_to_name(long nr)
{
	switch (nr) {
	case 0: return "read"; case 1: return "write"; case 2: return "open";
	case 3: return "close"; case 5: return "fstat"; case 9: return "mmap";
	case 10: return "mprotect"; case 11: return "munmap"; case 12: return "brk";
	case 13: return "rt_sigaction"; case 14: return "rt_sigprocmask";
	case 16: return "ioctl"; case 17: return "pread64"; case 20: return "writev";
	case 21: return "access"; case 28: return "madvise";
	case 39: return "getpid"; case 41: return "socket"; case 42: return "connect";
	case 43: return "accept"; case 44: return "sendto"; case 45: return "recvfrom";
	case 49: return "bind"; case 50: return "listen";
	case 56: return "clone"; case 57: return "fork"; case 59: return "execve";
	case 60: return "exit"; case 62: return "kill";
	case 72: return "fcntl"; case 78: return "getdents64"; case 79: return "getcwd";
	case 89: return "readlink"; case 102: return "getuid"; case 104: return "getgid";
	case 158: return "arch_prctl"; case 186: return "gettid";
	case 202: return "futex"; case 218: return "set_tid_address";
	case 228: return "clock_gettime"; case 230: return "clock_nanosleep";
	case 231: return "exit_group"; case 257: return "openat";
	case 262: return "newfstatat"; case 273: return "set_robust_list";
	case 302: return "prlimit64"; case 318: return "getrandom"; case 334: return "rseq";
	default: return NULL;
	}
}

static void emit_strace(long nr, unsigned long *args, long ret)
{
	const char *name = nr_to_name(nr);
	if (name)
		fprintf(g_output, "%s(", name);
	else
		fprintf(g_output, "syscall_%ld(", nr);

	for (int i = 0; i < 6; i++) {
		if (i) fprintf(g_output, ", ");
		if (args[i] == 0)
			fprintf(g_output, "0");
		else if ((long)args[i] == -100)
			fprintf(g_output, "AT_FDCWD");
		else if ((long)args[i] == -1)
			fprintf(g_output, "-1");
		else
			fprintf(g_output, "0x%lx", args[i]);
	}

	if (ret < 0)
		fprintf(g_output, ") = -1\n");
	else if ((unsigned long)ret > 0xfffff)
		fprintf(g_output, ") = 0x%lx\n", (unsigned long)ret);
	else
		fprintf(g_output, ") = %ld\n", ret);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx; (void)len;
	struct event *e = data;

	if (!e->is_exit) {
		g_pending_nr = e->nr;
		memcpy(g_pending_args, e->args, sizeof(g_pending_args));
		g_has_pending = 1;
	} else {
		if (g_has_pending && g_pending_nr == e->nr) {
			emit_strace(g_pending_nr, g_pending_args, e->ret);
			g_has_pending = 0;
		}
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level > LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, fmt, args);
}

int vock_ebpf_run(int argc, char *argv[], int cmd_idx,
                  const char *output_path)
{
	struct trace_bpf *skel;
	struct ring_buffer *rb;
	pid_t pid;
	int status;

	libbpf_set_print(libbpf_print_fn);

	skel = trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "ebpf: failed to load BPF program\n");
		return -1;
	}

	/* Fork target */
	pid = fork();
	if (pid == 0) {
		raise(SIGSTOP);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("ebpf: execvp");
		_exit(127);
	} else if (pid < 0) {
		perror("ebpf: fork");
		trace_bpf__destroy(skel);
		return -1;
	}
	waitpid(pid, &status, WUNTRACED);

	/* Set target PID */
	uint32_t key = 0, val = pid;
	bpf_map__update_elem(skel->maps.target_pid, &key, sizeof(key),
			     &val, sizeof(val), BPF_ANY);

	if (trace_bpf__attach(skel)) {
		fprintf(stderr, "ebpf: attach failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		trace_bpf__destroy(skel);
		return -1;
	}

	g_output = fopen(output_path, "w");
	if (!g_output) {
		perror("ebpf: fopen");
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		trace_bpf__destroy(skel);
		return -1;
	}
	g_has_pending = 0;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ebpf: ring_buffer__new failed\n");
		fclose(g_output);
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		trace_bpf__destroy(skel);
		return -1;
	}

	/* Resume child */
	kill(pid, SIGCONT);

	/* Poll until child exits */
	while (waitpid(pid, &status, WNOHANG) == 0)
		ring_buffer__poll(rb, 100);
	ring_buffer__poll(rb, 0);

	fclose(g_output);
	ring_buffer__free(rb);
	trace_bpf__destroy(skel);

	fprintf(stderr, "[vock] ebpf trace written to %s\n", output_path);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 0;
}

#else /* !VOCK_EBPF_ENABLED */

int vock_ebpf_run(int argc, char *argv[], int cmd_idx,
                  const char *output_path)
{
	(void)argc; (void)argv; (void)cmd_idx; (void)output_path;
	fprintf(stderr, "[vock] ebpf backend not built\n");
	fprintf(stderr, "  install: sudo apt install libbpf-dev bpftool\n");
	fprintf(stderr, "  rebuild: make EBPF=1\n");
	return -1;
}

#endif
