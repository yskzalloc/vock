#pragma once

#include "config.h"
#include "util.h"
#include <sys/mman.h>
#include <stdint.h>

void init_zpoline(void);

void asm_syscall_hook(void);

void rewrite_syscall_inst(uint16_t *syscall_addr);
