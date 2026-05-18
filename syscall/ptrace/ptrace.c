#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include "ptrace.h"

#if defined(__x86_64__)
#define SC_NR(regs)  ((regs).orig_rax)
#define SC_ARG0(regs) ((regs).rdi)
#define SC_ARG1(regs) ((regs).rsi)
#define SC_ARG2(regs) ((regs).rdx)
#define SC_ARG3(regs) ((regs).r10)
#define SC_ARG4(regs) ((regs).r8)
#define SC_ARG5(regs) ((regs).r9)
#define SC_RET(regs)  ((regs).rax)
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#define SC_NR(regs)  ((regs).regs[8])
#define SC_ARG0(regs) ((regs).regs[0])
#define SC_ARG1(regs) ((regs).regs[1])
#define SC_ARG2(regs) ((regs).regs[2])
#define SC_ARG3(regs) ((regs).regs[3])
#define SC_ARG4(regs) ((regs).regs[4])
#define SC_ARG5(regs) ((regs).regs[5])
#define SC_RET(regs)  ((regs).regs[0])
#else
#error "Unsupported architecture"
#endif

int vock_trace_start(struct vock_trace_ctx *ctx, pid_t pid)
{
	int status;

	ctx->pid = pid;
	ctx->in_syscall = 0;

	if (waitpid(pid, &status, 0) < 0) {
		perror("ptrace: initial waitpid");
		return -1;
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, 0,
		   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {
		perror("ptrace: setoptions");
		return -1;
	}

	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
		perror("ptrace: initial syscall");
		return -1;
	}

	return 0;
}

int vock_trace_next_syscall(struct vock_trace_ctx *ctx, struct vock_syscall *sc)
{
	int status;
#if defined(__x86_64__)
	struct user_regs_struct regs;
#elif defined(__aarch64__)
	struct user_pt_regs regs;
#endif

	for (;;) {
		if (waitpid(ctx->pid, &status, 0) < 0)
			return -1;

		if (WIFEXITED(status) || WIFSIGNALED(status))
			return -1;

		if (!WIFSTOPPED(status) || !(WSTOPSIG(status) & 0x80)) {
			ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0);
			continue;
		}

#if defined(__x86_64__)
		if (ptrace(PTRACE_GETREGS, ctx->pid, 0, &regs) < 0)
			return -1;
#elif defined(__aarch64__)
		struct iovec iov = { &regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, ctx->pid, NT_PRSTATUS, &iov) < 0)
			return -1;
#endif

		if (!ctx->in_syscall) {
			/* syscall entry */
			sc->nr = SC_NR(regs);
			sc->args[0] = SC_ARG0(regs);
			sc->args[1] = SC_ARG1(regs);
			sc->args[2] = SC_ARG2(regs);
			sc->args[3] = SC_ARG3(regs);
			sc->args[4] = SC_ARG4(regs);
			sc->args[5] = SC_ARG5(regs);
			ctx->in_syscall = 1;
		} else {
			/* syscall exit */
			sc->ret = SC_RET(regs);
			ctx->in_syscall = 0;
			ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0);
			return 0;
		}

		ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0);
	}
}

void vock_trace_stop(struct vock_trace_ctx *ctx)
{
	ptrace(PTRACE_DETACH, ctx->pid, 0, 0);
}
