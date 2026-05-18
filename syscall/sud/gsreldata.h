#pragma once

#include "config.h"

#define SUD_SELECTOR_OFFSET                 0
#define SIGRETURN_STACK_SP_OFFSET           16
#define RIP_AFTER_SYSCALL_STACK_SP_OFFSET   32792
#define XSAVE_AREA_STACK_SP_OFFSET          36928
#define XSAVE_EAX                           0b111
#define XSAVE_SIZE                          768

#ifndef __ASSEMBLER__

#include "signal_handlers.h"
#include <stddef.h>

struct GSRelativeData {
    volatile char sud_selector;
    char _pad[7];
    SignalHandlers *signal_handlers;
    struct {
        volatile long long *current;
        volatile long long base[0x1000];
    } sigreturn_stack;
    struct {
        volatile char *current;
        volatile char base[0x1000];
    } rip_after_syscall_stack;
    struct {
        volatile char *current;
        volatile char __attribute__((aligned(64))) base[XSAVE_SIZE * 6];
    } xsave_area_stack;
} __attribute__((aligned(0x1000)));

static inline void gsreldata_init(struct GSRelativeData *g) {
    g->sud_selector = (char)0xFF;
    g->signal_handlers = NULL;
    g->sigreturn_stack.current = g->sigreturn_stack.base;
    g->rip_after_syscall_stack.current = g->rip_after_syscall_stack.base;
    g->xsave_area_stack.current = g->xsave_area_stack.base;
}

/* GS-relative accessor — Clang __seg_gs extension works in C too */
#define gsreldata ((__seg_gs struct GSRelativeData *)0x0)

_Static_assert(offsetof(struct GSRelativeData, sud_selector) == SUD_SELECTOR_OFFSET, "");
_Static_assert(offsetof(struct GSRelativeData, sigreturn_stack.current) == SIGRETURN_STACK_SP_OFFSET, "");
_Static_assert(offsetof(struct GSRelativeData, rip_after_syscall_stack.current) == RIP_AFTER_SYSCALL_STACK_SP_OFFSET, "");
_Static_assert(offsetof(struct GSRelativeData, xsave_area_stack.current) == XSAVE_AREA_STACK_SP_OFFSET, "");

struct GSRelativeData *map_gsrel_region(void);
SignalHandlers *map_signal_handlers(void);
void enable_sud(void);
void setup_new_thread(unsigned long long clone_flags);
void teardown_thread_metadata(void);
void setup_restore_selector_trampoline(void *ucontextv);

#endif
