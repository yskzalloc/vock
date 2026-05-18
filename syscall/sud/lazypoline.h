#pragma once

#include <stdint.h>

void init_lazypoline(void);

long syscall_emulate(int64_t syscall_no, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6, uint64_t *const should_emulate);
