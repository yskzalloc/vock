#ifndef VOCK_DECODING_H
#define VOCK_DECODING_H

#include <sys/types.h>
#include <stdio.h>

/*
 * Decode a syscall into human-readable strace format.
 * Reads strings/structs from target process memory via process_vm_readv.
 *
 * Output: "openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"
 */
void vock_decode_syscall(FILE *out, pid_t pid, long nr,
			 long args[6], long ret);

/* Arch-specific syscall name lookup (provided by x86_64/sys.c or aarch64/sys.c) */
const char *vock_syscall_name(long nr);

/* ─── Common helpers (implemented in decode.c, used by arch decode files) ── */

int  vock_read_str(pid_t pid, unsigned long addr, char *buf, size_t size);
void vock_print_str(FILE *out, pid_t pid, unsigned long addr);
void vock_print_open_flags(FILE *out, long flags);
void vock_print_mmap_prot(FILE *out, long prot);
void vock_print_mmap_flags(FILE *out, long flags);
void vock_print_socket_domain(FILE *out, long domain);
void vock_print_socket_type(FILE *out, long type);

/* Common per-syscall formatters */
void vock_fmt_openat(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_open(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_read(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_write(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_close(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_mmap(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_mprotect(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_socket(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_connect(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_execve(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_access(FILE *out, pid_t pid, long *a, long ret);
void vock_fmt_brk(FILE *out, pid_t pid, long *a, long ret);

/* Generic fallback (name + hex args) */
void vock_fmt_generic(FILE *out, long nr, long *args, long ret);

#endif
