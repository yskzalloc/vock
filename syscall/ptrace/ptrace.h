#ifndef PTRACE_TRACE_H
#define PTRACE_TRACE_H

#include <sys/types.h>

struct vock_syscall {
	long nr;
	long args[6];
	long ret;
};

struct vock_trace_ctx {
	pid_t pid;
	int in_syscall; /* 0 = waiting for entry, 1 = waiting for exit */
};

int vock_trace_start(struct vock_trace_ctx *ctx, pid_t pid);
int vock_trace_next_syscall(struct vock_trace_ctx *ctx, struct vock_syscall *sc);
void vock_trace_stop(struct vock_trace_ctx *ctx);

#endif
