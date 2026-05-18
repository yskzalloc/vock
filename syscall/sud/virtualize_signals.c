#include "signals.h"

#include "util.h"
#include "sud_core.h"
#include "lazypoline.h"
#include "gsreldata.h"

#include <syscall.h>
#include <sys/signal.h>
#include <immintrin.h>
#include <assert.h>
#include <string.h>

#ifndef SA_UNSUPPORTED
#define SA_UNSUPPORTED	0x00000400
#endif

#ifndef SA_EXPOSE_TAGBITS
#define SA_EXPOSE_TAGBITS 0x00000800
#endif

void restore_selector_trampoline(void);

static void wrap_signal_handler(int signo, siginfo_t *info, void *ucontextv) {
    char selector_on_signal_entry = get_privilege_level();

    gsreldata->sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;

    ucontext_t *uctxt = (ucontext_t *) ucontextv;
    greg_t *gregs = uctxt->uc_mcontext.gregs;
    long long rsp = gregs[REG_RSP];
    signal_handlers_invoke_app_specific_handler(gsreldata->signal_handlers, signo, info, ucontextv);

    assert(rsp == gregs[REG_RSP]);

    gsreldata->sigreturn_stack.current[0] = selector_on_signal_entry;
    gsreldata->sigreturn_stack.current++;
    set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
}

void signal_handlers_init(SignalHandlers *sh) {
    memset(sh, 0, sizeof(*sh));
    sh->mut = (spinlock)SPINLOCK_INIT;

    for (int i = 0; i < _NSIG; i++) {
        if (i == SIGKILL)
            continue;

        struct kernel_sigaction dfl_act;
        long long result = non_libc_rt_sigaction(i, NULL, &dfl_act);
        if (result)
            continue;
        sh->members.app_handlers[i] = dfl_act;
        if (dfl_act.k_sa_handler == SIG_DFL)
            sh->members.dfl_handler = dfl_act;
    }
}

void signal_handlers_copy(SignalHandlers *dst, const SignalHandlers *src) {
    spinlock_lock((spinlock *)&src->mut);
    dst->members = src->members;
    dst->mut = (spinlock)SPINLOCK_INIT;
    spinlock_unlock((spinlock *)&src->mut);
}

void signal_handlers_invoke_app_specific_handler(SignalHandlers *sh, int sig, siginfo_t *info, void *ucontextv) {
    spinlock_lock(&sh->mut);
    struct kernel_sigaction app_handler = sh->members.app_handlers[sig];
    assert(app_handler.k_sa_handler != SIG_DFL);
    assert(app_handler.k_sa_handler != SIG_IGN);
    assert(!(app_handler.sa_flags & SA_ONSTACK));

    if (app_handler.sa_flags & SA_RESETHAND)
        sh->members.app_handlers[sig] = sh->members.dfl_handler;
    spinlock_unlock(&sh->mut);

    /* block SUD for app handler */
    SudScope guard;
    sud_block_scope_init(&guard);

    /* k_sa_handler is typed as 1-arg __sighandler_t, but with SA_SIGINFO the
     * kernel calls it with the 3-arg signature. Route the cast through a
     * generic function pointer to satisfy -Wcast-function-type-mismatch. */
    void (*generic)(void) = (void (*)(void)) app_handler.k_sa_handler;
    ((void (*)(int, siginfo_t *, void *)) generic)(sig, info, ucontextv);

    sud_block_scope_cleanup(&guard);
}

long long signal_handlers_handle_app_sigaction(SignalHandlers *sh, int signo, const struct kernel_sigaction *newact, struct kernel_sigaction *oldact) {
    spinlock_lock(&sh->mut);

    if (signo == SIGSYS) {
        if (newact) {
            assert(!(newact->sa_flags & SA_UNSUPPORTED));
        }
        if (oldact)
            *oldact = sh->members.app_handlers[SIGSYS];
        spinlock_unlock(&sh->mut);
        return 0;
    }

    if (!newact || newact->k_sa_handler == SIG_IGN) {
        long long result = non_libc_rt_sigaction(signo, newact, oldact);
        if (result) {
            spinlock_unlock(&sh->mut);
            return result;
        }
        if (oldact)
            *oldact = sh->members.app_handlers[signo];
        if (newact)
            sh->members.app_handlers[signo] = *newact;
        spinlock_unlock(&sh->mut);
        return result;
    }

    if (newact->k_sa_handler == SIG_DFL) {
        long long result = non_libc_rt_sigaction(signo, newact, oldact);
        if (result == 0) {
            struct kernel_sigaction old = sh->members.app_handlers[signo];
            sh->members.app_handlers[signo] = *newact;
            if (oldact)
                *oldact = old;
        }
        spinlock_unlock(&sh->mut);
        return result;
    }

    struct kernel_sigaction newact_cpy = *newact;
    newact_cpy.sa_flags |= SA_SIGINFO;
    /* Stash the 3-arg wrapper into the 1-arg typed field; the kernel treats
     * it as 3-arg because SA_SIGINFO is set. Cast via a generic function
     * pointer to satisfy -Wcast-function-type-mismatch. */
    newact_cpy.k_sa_handler = (__sighandler_t) (void (*)(void)) wrap_signal_handler;
    long long result = non_libc_rt_sigaction(signo, &newact_cpy, oldact);
    if (result) {
        spinlock_unlock(&sh->mut);
        return result;
    }

    struct kernel_sigaction old = sh->members.app_handlers[signo];
    sh->members.app_handlers[signo] = *newact;
    if (oldact)
        *oldact = old;

    spinlock_unlock(&sh->mut);
    return result;
}
