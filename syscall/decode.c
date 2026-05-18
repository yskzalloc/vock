/*
 * syscall/decode.c — Common syscall argument decoding helpers.
 * Arch-independent formatters for strings, flags, and per-syscall output.
 */
#define _GNU_SOURCE
#include "decode.h"
#include <string.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>

/* ─── String reader ───────────────────────────────────────────────────────── */

int vock_read_str(pid_t pid, unsigned long addr, char *buf, size_t size)
{
	if (!addr || addr > 0x0000ffffffffffff) {
		buf[0] = '\0';
		return -1;
	}
	struct iovec local = { .iov_base = buf, .iov_len = size };
	struct iovec remote = { .iov_base = (void *)addr, .iov_len = size };
	ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (n <= 0) { buf[0] = '\0'; return -1; }
	buf[size - 1] = '\0';
	return 0;
}

void vock_print_str(FILE *out, pid_t pid, unsigned long addr)
{
	char buf[256];
	if (vock_read_str(pid, addr, buf, sizeof(buf)) == 0 && buf[0]) {
		fputc('"', out);
		for (int i = 0; buf[i] && i < 64; i++) {
			if (buf[i] >= 32 && buf[i] < 127)
				fputc(buf[i], out);
			else
				fprintf(out, "\\x%02x", (unsigned char)buf[i]);
		}
		fputc('"', out);
	} else {
		if (addr == 0) fprintf(out, "NULL");
		else fprintf(out, "0x%lx", addr);
	}
}

/* ─── Flag printers ───────────────────────────────────────────────────────── */

void vock_print_open_flags(FILE *out, long flags)
{
	int mode = flags & 3;
	const char *m[] = {"O_RDONLY", "O_WRONLY", "O_RDWR", "O_RDWR"};
	fprintf(out, "%s", m[mode]);
	flags &= ~3;
	if (flags & O_CREAT)    { fprintf(out, "|O_CREAT"); flags &= ~O_CREAT; }
	if (flags & O_EXCL)     { fprintf(out, "|O_EXCL"); flags &= ~O_EXCL; }
	if (flags & O_TRUNC)    { fprintf(out, "|O_TRUNC"); flags &= ~O_TRUNC; }
	if (flags & O_APPEND)   { fprintf(out, "|O_APPEND"); flags &= ~O_APPEND; }
	if (flags & O_NONBLOCK) { fprintf(out, "|O_NONBLOCK"); flags &= ~O_NONBLOCK; }
	if (flags & O_CLOEXEC)  { fprintf(out, "|O_CLOEXEC"); flags &= ~O_CLOEXEC; }
	if (flags & O_DIRECTORY){ fprintf(out, "|O_DIRECTORY"); flags &= ~O_DIRECTORY; }
#ifdef O_LARGEFILE
	if (flags & O_LARGEFILE){ fprintf(out, "|O_LARGEFILE"); flags &= ~O_LARGEFILE; }
#endif
	if (flags) fprintf(out, "|0x%lx", flags);
}

void vock_print_mmap_prot(FILE *out, long prot)
{
	if (prot == 0) { fprintf(out, "PROT_NONE"); return; }
	int f = 1;
	if (prot & 1) { fprintf(out, "PROT_READ"); f = 0; prot &= ~1; }
	if (prot & 2) { fprintf(out, "%sPROT_WRITE", f ? "" : "|"); f = 0; prot &= ~2; }
	if (prot & 4) { fprintf(out, "%sPROT_EXEC", f ? "" : "|"); prot &= ~4; }
	if (prot) fprintf(out, "|0x%lx", prot);
}

void vock_print_mmap_flags(FILE *out, long flags)
{
	if (flags & MAP_PRIVATE) fprintf(out, "MAP_PRIVATE");
	else if (flags & MAP_SHARED) fprintf(out, "MAP_SHARED");
	else fprintf(out, "0x%lx", flags & 0xf);
	flags &= ~0xf;
	if (flags & MAP_ANONYMOUS) { fprintf(out, "|MAP_ANONYMOUS"); flags &= ~MAP_ANONYMOUS; }
	if (flags & MAP_FIXED)     { fprintf(out, "|MAP_FIXED"); flags &= ~MAP_FIXED; }
#ifdef MAP_POPULATE
	if (flags & MAP_POPULATE)  { fprintf(out, "|MAP_POPULATE"); flags &= ~MAP_POPULATE; }
#endif
	if (flags) fprintf(out, "|0x%lx", flags);
}

void vock_print_socket_domain(FILE *out, long d)
{
	switch (d) {
	case AF_UNIX: fprintf(out, "AF_UNIX"); break;
	case AF_INET: fprintf(out, "AF_INET"); break;
	case AF_INET6: fprintf(out, "AF_INET6"); break;
	case AF_NETLINK: fprintf(out, "AF_NETLINK"); break;
	case AF_PACKET: fprintf(out, "AF_PACKET"); break;
	default: fprintf(out, "%ld", d);
	}
}

void vock_print_socket_type(FILE *out, long type)
{
	long base = type & 0xf;
	switch (base) {
	case SOCK_STREAM: fprintf(out, "SOCK_STREAM"); break;
	case SOCK_DGRAM: fprintf(out, "SOCK_DGRAM"); break;
	case SOCK_RAW: fprintf(out, "SOCK_RAW"); break;
	case SOCK_SEQPACKET: fprintf(out, "SOCK_SEQPACKET"); break;
	default: fprintf(out, "%ld", base);
	}
	if (type & SOCK_NONBLOCK) fprintf(out, "|SOCK_NONBLOCK");
	if (type & SOCK_CLOEXEC) fprintf(out, "|SOCK_CLOEXEC");
}

/* ─── Per-syscall formatters ──────────────────────────────────────────────── */

void vock_fmt_openat(FILE *out, pid_t pid, long *a, long ret)
{
	if (a[0] == -100 || (unsigned long)a[0] == 0xffffff9c ||
	    (unsigned long)a[0] == 0xffffffffffffff9c)
		fprintf(out, "openat(AT_FDCWD, ");
	else
		fprintf(out, "openat(%ld, ", a[0]);
	vock_print_str(out, pid, a[1]);
	fprintf(out, ", ");
	vock_print_open_flags(out, a[2]);
	if (a[2] & O_CREAT) fprintf(out, ", %04lo", a[3]);
	fprintf(out, ") = %ld\n", ret);
}

void vock_fmt_open(FILE *out, pid_t pid, long *a, long ret)
{
	fprintf(out, "open(");
	vock_print_str(out, pid, a[0]);
	fprintf(out, ", ");
	vock_print_open_flags(out, a[1]);
	if (a[1] & O_CREAT) fprintf(out, ", %04lo", a[2]);
	fprintf(out, ") = %ld\n", ret);
}

void vock_fmt_read(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "read(%ld, 0x%lx, %lu) = %ld\n", a[0], a[1], a[2], ret);
}

void vock_fmt_write(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "write(%ld, 0x%lx, %lu) = %ld\n", a[0], a[1], a[2], ret);
}

void vock_fmt_close(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "close(%ld) = %ld\n", a[0], ret);
}

void vock_fmt_mmap(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "mmap(");
	if (a[0] == 0) fprintf(out, "NULL"); else fprintf(out, "0x%lx", a[0]);
	fprintf(out, ", %lu, ", a[1]);
	vock_print_mmap_prot(out, a[2]);
	fprintf(out, ", ");
	vock_print_mmap_flags(out, a[3]);
	fprintf(out, ", %ld, %ld) = 0x%lx\n", a[4], a[5], (unsigned long)ret);
}

void vock_fmt_mprotect(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "mprotect(0x%lx, %lu, ", a[0], a[1]);
	vock_print_mmap_prot(out, a[2]);
	fprintf(out, ") = %ld\n", ret);
}

void vock_fmt_socket(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "socket(");
	vock_print_socket_domain(out, a[0]);
	fprintf(out, ", ");
	vock_print_socket_type(out, a[1]);
	fprintf(out, ", %ld) = %ld\n", a[2], ret);
}

void vock_fmt_connect(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	fprintf(out, "connect(%ld, 0x%lx, %lu) = %ld\n", a[0], a[1], a[2], ret);
}

void vock_fmt_execve(FILE *out, pid_t pid, long *a, long ret)
{
	fprintf(out, "execve(");
	vock_print_str(out, pid, a[0]);
	fprintf(out, ", 0x%lx, 0x%lx) = %ld\n", a[1], a[2], ret);
}

void vock_fmt_access(FILE *out, pid_t pid, long *a, long ret)
{
	fprintf(out, "access(");
	vock_print_str(out, pid, a[0]);
	fprintf(out, ", ");
	long m = a[1];
	if (m == 0) fprintf(out, "F_OK");
	else {
		int f = 1;
		if (m & 4) { fprintf(out, "R_OK"); f = 0; m &= ~4; }
		if (m & 2) { fprintf(out, "%sW_OK", f ? "" : "|"); f = 0; m &= ~2; }
		if (m & 1) { fprintf(out, "%sX_OK", f ? "" : "|"); m &= ~1; }
	}
	fprintf(out, ") = %ld\n", ret);
}

void vock_fmt_brk(FILE *out, pid_t pid, long *a, long ret)
{
	(void)pid;
	if (a[0] == 0) fprintf(out, "brk(NULL) = 0x%lx\n", (unsigned long)ret);
	else fprintf(out, "brk(0x%lx) = 0x%lx\n", a[0], (unsigned long)ret);
}

void vock_fmt_generic(FILE *out, long nr, long *args, long ret)
{
	const char *name = vock_syscall_name(nr);
	if (name) fprintf(out, "%s(", name);
	else fprintf(out, "syscall_%ld(", nr);
	for (int i = 0; i < 6; i++) {
		if (i) fprintf(out, ", ");
		if (args[i] == 0) fprintf(out, "0");
		else fprintf(out, "0x%lx", (unsigned long)args[i]);
	}
	fprintf(out, ") = %ld\n", ret);
}
