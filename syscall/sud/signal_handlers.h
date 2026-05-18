#pragma once

#include "config.h"
#include <sysdeps/kernel_sigaction.h>
#include "rigtorp_spinlock.h"

#include <signal.h>

typedef struct {
    struct kernel_sigaction dfl_handler;
    struct kernel_sigaction app_handlers[NSIG];
} SignalHandlersMembers;

typedef struct {
    SignalHandlersMembers members;
    spinlock mut;
} SignalHandlers;

void signal_handlers_init(SignalHandlers *sh);
void signal_handlers_copy(SignalHandlers *dst, const SignalHandlers *src);
long long signal_handlers_handle_app_sigaction(SignalHandlers *sh, int signo, const struct kernel_sigaction *newact, struct kernel_sigaction *oldact);
void signal_handlers_invoke_app_specific_handler(SignalHandlers *sh, int sig, siginfo_t *info, void *ucontextv);
