#include "zpoline.h"

#include "compat_align.h"
#include "lazypoline.h"
#include "sud_core.h"
#include "rigtorp_spinlock.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init_zpoline(void) {
    volatile uint8_t *zeropage = (volatile uint8_t *) mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    if (zeropage == MAP_FAILED) {
        perror("mmap(NULL)");
        fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set to 0\n");
        exit(1);
    }

    const int num_syscalls = 512;
    for (int i = 0; i < num_syscalls; i++) {
        assert(num_syscalls == 512);
        if (i >= 0x19b) {
            if (i % 2 == 0)
                zeropage[i] = 0x66;
            else
                zeropage[i] = 0x90;
        } else {
            int x = i % 3;
            switch (x) {
            case 0: zeropage[i] = 0xeb; break;
            case 1: zeropage[i] = 0x66; break;
            case 2: zeropage[i] = 0x90; break;
            }
        }
    }

    zeropage[num_syscalls + 0x0] = 0x50;
    zeropage[num_syscalls + 0x1] = 0x48;
    zeropage[num_syscalls + 0x2] = 0xb8;
    zeropage[num_syscalls + 0x3] = ((uint64_t) asm_syscall_hook >> (8 * 0)) & 0xff;
    zeropage[num_syscalls + 0x4] = ((uint64_t) asm_syscall_hook >> (8 * 1)) & 0xff;
    zeropage[num_syscalls + 0x5] = ((uint64_t) asm_syscall_hook >> (8 * 2)) & 0xff;
    zeropage[num_syscalls + 0x6] = ((uint64_t) asm_syscall_hook >> (8 * 3)) & 0xff;
    zeropage[num_syscalls + 0x7] = ((uint64_t) asm_syscall_hook >> (8 * 4)) & 0xff;
    zeropage[num_syscalls + 0x8] = ((uint64_t) asm_syscall_hook >> (8 * 5)) & 0xff;
    zeropage[num_syscalls + 0x9] = ((uint64_t) asm_syscall_hook >> (8 * 6)) & 0xff;
    zeropage[num_syscalls + 0xa] = ((uint64_t) asm_syscall_hook >> (8 * 7)) & 0xff;
    zeropage[num_syscalls + 0xb] = 0xff;
    zeropage[num_syscalls + 0xc] = 0xe0;

    ASSERT_ELSE_PERROR(mprotect((void *)zeropage, 0x1000, PROT_READ|PROT_EXEC) == 0);
}

long zpoline_syscall_handler(int64_t rdi, int64_t rsi,
    int64_t rdx, int64_t r10,
    int64_t r8, int64_t r9,
    const int64_t rax,
    int64_t rip_after_syscall __attribute__((unused)),
    uint64_t *const should_emulate
) {
    return syscall_emulate(rax, rdi, rsi, rdx, r10, r8, r9, should_emulate);
}

static spinlock rewrite_lock = SPINLOCK_INIT;

void rewrite_syscall_inst(uint16_t *syscall_addr) {
    void *syscall_page = __builtin_align_down(syscall_addr, 0x1000);

    spinlock_lock(&rewrite_lock);
    if (*syscall_addr == 0xD0FF) {
        spinlock_unlock(&rewrite_lock);
        return;
    }
    int perms = PROT_WRITE|PROT_EXEC;
#if COMPAT_NONDEP_APP
    perms |= PROT_READ;
#endif
    if (mprotect(syscall_page, 0x1000, perms) != 0) {
        /* Address is in a non-rewritable mapping (e.g. [vvar], [vvar_vclock],
         * or another special kernel mapping). Leave the SIGSYS trap in place. */
        spinlock_unlock(&rewrite_lock);
        return;
    }
    *syscall_addr = 0xD0FF;
#if !COMPAT_NONDEP_APP
    perms = PROT_READ|PROT_EXEC;
    ASSERT_ELSE_PERROR(mprotect(syscall_page, 0x1000, perms) == 0);
#endif
    spinlock_unlock(&rewrite_lock);
}
