#ifndef VOCK_EXECPROG_H
#define VOCK_EXECPROG_H

/*
 * Execute a syscall trace file directly (fork + syscall).
 * Like syzkaller's syz-execprog.
 *
 * Returns child exit status.
 */
int vock_execprog(const char *trace_file, int repeat, int procs);

#endif
