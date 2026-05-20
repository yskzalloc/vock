#include "sud_core.h"

#include "compat_align.h"
#include "lazypoline.h"
#include "zpoline.h"
#include "gsreldata.h"
#include "signal_handlers.h"

#include <immintrin.h>
#include <stddef.h>
#include <sys/auxv.h>
#include <assert.h>
#include <string.h>
#include <elf.h>

void sud_unblock_scope_init(SudScope *s) {
    s->oldselector = get_privilege_level();
    set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);
}

void sud_unblock_scope_cleanup(SudScope *s) {
    assert(get_privilege_level() == SYSCALL_DISPATCH_FILTER_ALLOW);
    set_privilege_level(s->oldselector);
}

void sud_block_scope_init(SudScope *s) {
    s->oldselector = get_privilege_level();
    set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
}

void sud_block_scope_cleanup(SudScope *s) {
    assert(get_privilege_level() == SYSCALL_DISPATCH_FILTER_BLOCK);
    set_privilege_level(s->oldselector);
}

typedef struct {
    const uint8_t *start;
    size_t len;
} vdso_location;

static vdso_location vdso;
static int vdso_inited = 0;

static vdso_location *get_vdso(void) {
    if (!vdso_inited) {
        vdso.start = (const uint8_t *) getauxval(AT_SYSINFO_EHDR);
        ASSERT_ELSE_PERROR(vdso.start);
        assert(__builtin_is_aligned(vdso.start, 0x1000));
        /* Compute real vDSO size from ELF header (kernel vDSO can exceed 1 page). */
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *) vdso.start;
        size_t end = (size_t) eh->e_shoff + (size_t) eh->e_shentsize * (size_t) eh->e_shnum;
        size_t phend = (size_t) eh->e_phoff + (size_t) eh->e_phentsize * (size_t) eh->e_phnum;
        if (phend > end) end = phend;
        vdso.len = (end + 0xfff) & ~(size_t)0xfff;
        if (vdso.len < 0x2000) vdso.len = 0x2000;
        vdso_inited = 1;
    }
    return &vdso;
}

static int vdso_contains(vdso_location *v, const uint8_t *addr) {
    return addr >= v->start && addr < v->start + v->len;
}

static void handle_sigsys(int sig, siginfo_t *info, void *ucontextv) {
    set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);

    assert(info->si_code == SYS_USER_DISPATCH && "SUD does not support safely running non-SUD SIGSYS handlers!");
    assert(sig == SIGSYS);
    assert(info->si_signo == SIGSYS);
    assert(info->si_errno == 0);

#if REWRITE_TO_ZPOLINE
    vdso_location *v = get_vdso();
    uint16_t *syscall_addr = &((uint16_t *)info->si_call_addr)[-1];
    if (!vdso_contains(v, (const uint8_t *) syscall_addr))
        rewrite_syscall_inst(syscall_addr);
#endif

    ucontext_t *uctxt = (ucontext_t *) ucontextv;
    greg_t *gregs = uctxt->uc_mcontext.gregs;
    assert(gregs[REG_RAX] == info->si_syscall);
    gregs[REG_RSP] -= 2 * sizeof(uint64_t);
    long long *stack_bottom = (long long *)gregs[REG_RSP];
    stack_bottom[1] = gregs[REG_RIP];
    stack_bottom[0] = gregs[REG_RAX];
    gregs[REG_RIP] = (long long) asm_syscall_hook;

    assert(gregs[REG_RAX] == info->si_syscall);
}

void init_sud(void) {
    map_gsrel_region();
    assert(gsreldata == 0);
    _Static_assert(offsetof(struct GSRelativeData, sud_selector) == 0, "asm code depends on this");
    set_privilege_level(SYSCALL_DISPATCH_FILTER_ALLOW);

    gsreldata->signal_handlers = map_signal_handlers();
    signal_handlers_init(gsreldata->signal_handlers);

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handle_sigsys;
    act.sa_flags = SA_SIGINFO;
    ASSERT_ELSE_PERROR(sigemptyset(&act.sa_mask) == 0);
    ASSERT_ELSE_PERROR(sigaction(SIGSYS, &act, NULL) == 0);
}
