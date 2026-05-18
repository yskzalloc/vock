#ifndef VOCK_PROG2C_H
#define VOCK_PROG2C_H

#include "../fuzz/mutate.h"

/*
 * Generate a standalone C program from a syscall trace.
 * The C program replays the syscalls directly (no ptrace needed).
 * Returns 0 on success.
 */
int prog2c_generate(struct sc_record *trace, int ntrace, const char *output_path);

/*
 * Compile a generated C program.
 * Returns 0 on success.
 */
int prog2c_compile(const char *src_path, const char *bin_path);

/*
 * Execute directly via fork+syscall (fast, no coverage).
 */
int prog2c_exec(struct sc_record *trace, int ntrace);

/*
 * Compile to C, then exec with LD_PRELOAD=mode/kcov.so for real coverage.
 * Writes kerncov.log. Slower but gives real kernel coverage in VMs.
 */
int prog2c_exec_kcov(struct sc_record *trace, int ntrace);

#endif
