#pragma once

#include "config.h"
#include "util.h"
#include <sysdeps/kernel_sigaction.h>
#include "rigtorp_spinlock.h"
#include "signal_handlers.h"

#include <assert.h>
#include <syscall.h>

typedef struct {
    sigset_t ourmask;
    sigset_t newmask;
} SetRtSigProcMaskScope;

static inline void set_rt_sigprocmask_scope_init(SetRtSigProcMaskScope *s, const sigset_t *newmask) {
    memset(&s->ourmask, 0, sizeof(s->ourmask));
    s->newmask = *newmask;
    long long result = non_libc_rt_sigprocmask(SIG_SETMASK, newmask, &s->ourmask);
    if (result < 0) {
        errno = -result;
        perror("rt_sigprocmask");
    }
    assert(result == 0);
}

static inline void set_rt_sigprocmask_scope_cleanup(SetRtSigProcMaskScope *s) {
    sigset_t dbg_newmask = {};
    long long result = non_libc_rt_sigprocmask(SIG_SETMASK, &s->ourmask, &dbg_newmask);
    assert(result == 0);
    for (int i = 0; i < NSIG; i++)
        assert(sigismember(&dbg_newmask, i) == sigismember(&s->newmask, i));
}

static inline void block_all_signals_scope_init(SetRtSigProcMaskScope *s) {
    sigset_t all_sigs;
    ASSERT_ELSE_PERROR(sigfillset(&all_sigs) == 0);
    ASSERT_ELSE_PERROR(sigdelset(&all_sigs, SIGKILL) == 0);
    ASSERT_ELSE_PERROR(sigdelset(&all_sigs, SIGSTOP) == 0);
    set_rt_sigprocmask_scope_init(s, &all_sigs);
}
