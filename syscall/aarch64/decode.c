/*
 * syscall/aarch64/decode.c — aarch64 syscall dispatch.
 * Maps generic 64-bit syscall numbers to common formatters.
 * aarch64 has NO legacy syscalls (no open, stat, access, pipe, fork).
 * Uses *at variants exclusively (openat, faccessat, fstatat, etc.)
 */
#include "../decode.h"

/* aarch64 (generic 64-bit) syscall numbers */
#define NR_openat          56
#define NR_close           57
#define NR_read            63
#define NR_write           64
#define NR_brk             214
#define NR_mmap            222
#define NR_mprotect        226
#define NR_execve          221
#define NR_socket          198
#define NR_connect         203

void vock_decode_syscall(FILE *out, pid_t pid, long nr,
			 long args[6], long ret)
{
	switch (nr) {
	case NR_read:      vock_fmt_read(out, pid, args, ret); return;
	case NR_write:     vock_fmt_write(out, pid, args, ret); return;
	case NR_openat:    vock_fmt_openat(out, pid, args, ret); return;
	case NR_close:     vock_fmt_close(out, pid, args, ret); return;
	case NR_mmap:      vock_fmt_mmap(out, pid, args, ret); return;
	case NR_mprotect:  vock_fmt_mprotect(out, pid, args, ret); return;
	case NR_brk:       vock_fmt_brk(out, pid, args, ret); return;
	case NR_socket:    vock_fmt_socket(out, pid, args, ret); return;
	case NR_connect:   vock_fmt_connect(out, pid, args, ret); return;
	case NR_execve:    vock_fmt_execve(out, pid, args, ret); return;
	}
	vock_fmt_generic(out, nr, args, ret);
}
