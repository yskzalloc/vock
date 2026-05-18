/*
 * syscall/x86_64/decode.c — x86_64 syscall dispatch.
 * Maps x86_64 syscall numbers to common formatters.
 * x86_64 has legacy syscalls (open, stat, access, pipe, fork, etc.)
 * that don't exist on aarch64.
 */
#include "../decode.h"

/* x86_64 syscall numbers */
#define NR_read             0
#define NR_write            1
#define NR_open             2
#define NR_close            3
#define NR_mmap             9
#define NR_mprotect        10
#define NR_brk             12
#define NR_access          21
#define NR_socket          41
#define NR_connect         42
#define NR_execve          59
#define NR_openat         257

void vock_decode_syscall(FILE *out, pid_t pid, long nr,
			 long args[6], long ret)
{
	switch (nr) {
	case NR_read:      vock_fmt_read(out, pid, args, ret); return;
	case NR_write:     vock_fmt_write(out, pid, args, ret); return;
	case NR_open:      vock_fmt_open(out, pid, args, ret); return;
	case NR_close:     vock_fmt_close(out, pid, args, ret); return;
	case NR_mmap:      vock_fmt_mmap(out, pid, args, ret); return;
	case NR_mprotect:  vock_fmt_mprotect(out, pid, args, ret); return;
	case NR_brk:       vock_fmt_brk(out, pid, args, ret); return;
	case NR_access:    vock_fmt_access(out, pid, args, ret); return;
	case NR_socket:    vock_fmt_socket(out, pid, args, ret); return;
	case NR_connect:   vock_fmt_connect(out, pid, args, ret); return;
	case NR_execve:    vock_fmt_execve(out, pid, args, ret); return;
	case NR_openat:    vock_fmt_openat(out, pid, args, ret); return;
	}
	vock_fmt_generic(out, nr, args, ret);
}
