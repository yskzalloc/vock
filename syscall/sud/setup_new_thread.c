#include "gsreldata.h"
#include "nolibc_util.h"
#include "signal_handlers.h"

#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/unistd.h>
#include <linux/mman.h>

#include <asm/prctl.h>

#include <immintrin.h>

#define PR_SET_SYSCALL_USER_DISPATCH	59
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF             0
#endif
/* Upstream <linux/prctl.h> (>= 6.11) may define PR_SYS_DISPATCH_ON as
 * PR_SYS_DISPATCH_INCLUSIVE_ON (2). lazypoline needs EXCLUSIVE_ON (1). */
#undef PR_SYS_DISPATCH_ON
#ifdef PR_SYS_DISPATCH_EXCLUSIVE_ON
#define PR_SYS_DISPATCH_ON              PR_SYS_DISPATCH_EXCLUSIVE_ON
#else
#define PR_SYS_DISPATCH_ON              1
#endif
#define SYSCALL_DISPATCH_FILTER_ALLOW	0
#define SYSCALL_DISPATCH_FILTER_BLOCK	1

void restore_selector_trampoline(void);

#ifndef assert
#define assert(cond)        \
    do {                    \
        if (!(cond))          \
            asm ("int3");   \
    } while (0);
#endif

char get_privilege_level(void) {
    return gsreldata->sud_selector;
}

void set_privilege_level(char sud_status) {
    if (sud_status == SYSCALL_DISPATCH_FILTER_ALLOW) {
        gsreldata->sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    } else {
        assert(sud_status == SYSCALL_DISPATCH_FILTER_BLOCK);
        gsreldata->sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
    }
}

struct GSRelativeData *map_gsrel_region(void) {
    void *mem = (void *) inline_syscall6(__NR_mmap, 0x0, sizeof(struct GSRelativeData), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(mem != (void *) -1 && mem != 0);
    struct GSRelativeData *g = (struct GSRelativeData *)mem;
    gsreldata_init(g);
#ifdef __FSGSBASE__
    _writegsbase_u64((unsigned long long) mem);
#else
    long result = inline_syscall6(__NR_arch_prctl, ARCH_SET_GS, mem, 0, 0, 0, 0);
    assert(result == 0);
#endif
    return g;
}

static inline unsigned long long rdgsbase(void) {
#ifdef __FSGSBASE__
    return _readgsbase_u64();
#else
    unsigned long long gsbase = 0;
    long result = inline_syscall6(__NR_arch_prctl, ARCH_GET_GS, &gsbase, 0, 0, 0, 0);
    assert(result == 0);
    return gsbase;
#endif
}

void teardown_thread_metadata(void) {
    long result = inline_syscall6(__NR_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0x0, 0, 0, 0);
    assert(result == 0);
    result = inline_syscall6(__NR_munmap, (void *)rdgsbase(), __builtin_align_up(sizeof(struct GSRelativeData), 0x1000), 0, 0, 0, 0);
    assert(result == 0);
}

void enable_sud(void) {
    volatile char *selector_addr = ((char *) rdgsbase()) + SUD_SELECTOR_OFFSET;
    long result = inline_syscall6(__NR_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0x0, 0, selector_addr, 0);
    assert(result == 0);
}

SignalHandlers *map_signal_handlers(void) {
    long result = inline_syscall6(__NR_mmap, 0x0, sizeof(SignalHandlers), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    assert(result != -1 && result != 0);
    return (SignalHandlers *) result;
}

void setup_new_thread(unsigned long long clone_flags) {
    struct GSRelativeData *cloner_gsrel = (struct GSRelativeData *) rdgsbase();
    map_gsrel_region();
    set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);

    if (clone_flags & CLONE_SIGHAND) {
        gsreldata->signal_handlers = cloner_gsrel->signal_handlers;
    } else {
        gsreldata->signal_handlers = map_signal_handlers();
        signal_handlers_copy(gsreldata->signal_handlers, cloner_gsrel->signal_handlers);
    }

    enable_sud();
}

void setup_vforked_child(void) {
    setup_new_thread(CLONE_VM|CLONE_VFORK|SIGCHLD);
}

void setup_restore_selector_trampoline(void *ucontextv) {
    const ucontext_t *uctxt = (ucontext_t *) ucontextv;
    const greg_t *gregs = uctxt->uc_mcontext.gregs;

    gsreldata->sigreturn_stack.current[0] = gregs[REG_RIP];
    gsreldata->sigreturn_stack.current++;
    /* cast away const — the kernel will use the modified gregs on sigreturn */
    ((greg_t *)gregs)[REG_RIP] = (uint64_t) restore_selector_trampoline;
}
