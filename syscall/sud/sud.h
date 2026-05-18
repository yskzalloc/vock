#ifndef VOCK_SUD_H
#define VOCK_SUD_H

#include "../ptrace/ptrace.h" /* struct vock_syscall, vock_trace_ctx */

/*
 * SUD (Syscall User Dispatch) based syscall tracer.
 * Uses prctl(PR_SET_SYSCALL_USER_DISPATCH) to intercept syscalls via SIGSYS.
 * Requires kernel >= 5.11.
 *
 * Advantages over ptrace:
 *   - No context switch per syscall (in-process interception)
 *   - Catches all syscalls including from JIT code
 *   - Lower overhead
 *
 * The traced program runs in the same process with LD_PRELOAD.
 */

int vock_sud_available(void);
int vock_sud_run(int argc, char *argv[], int cmd_idx,
                 const char *output_path);

#endif
