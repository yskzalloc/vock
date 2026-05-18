#include "gsreldata.h"

/* This is the landingpad for sigreturns from user-supplied signal handlers */
/* We just have to restore the selector value, and then jump back to where 
    the sigreturn should have actually went to (the "old RIP")
    We have to do so transparantly, without clobbering any registers */
/* `setup_restore_selector_trampoline` will have pushed the old RIP to the sigreturn stack*/
.globl restore_selector_trampoline
restore_selector_trampoline:
    /* we've intercepted all signal-handler syscalls */
    /* restore the selector to the value it had during the delivery of the signal */

    /*due to potention a potential redzone on the stack we cannot push anything on it including the rip after sigreturn*/
    /*so we push everything 128 bytes down to avoid this potential redzone*/
    subq $128, %rsp
    pushq %rax

    /*set SUD permissions to blocking*/
    movb $1, %gs:SUD_SELECTOR_OFFSET

    /*restore rip after sigreturn*/
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    subq $8, %rax
    movq %rax, %gs:SIGRETURN_STACK_SP_OFFSET
    movq (%rax), %rax
    movq %rax, -0x8(%rsp) /*put rip after sigreturn on the bottom of the stack this way we can jump to it without using a register later*/
    popq %rax
    addq $128, %rsp
    jmp *-0x90(%rsp) /* old RIP sits at top of stack */

.section .note.GNU-stack