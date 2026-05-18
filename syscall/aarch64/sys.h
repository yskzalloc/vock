#ifndef VOCK_SYSCALL_AARCH64_SYS_H
#define VOCK_SYSCALL_AARCH64_SYS_H

/* Architecture-specific syscall name table for aarch64 */
const char *vock_syscall_name(long nr);
int vock_max_syscall_nr(void);

#endif
