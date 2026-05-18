#ifndef SYZLANG_H
#define SYZLANG_H

#include <stdio.h>
#include "../syscall/ptrace/ptrace.h"

struct vock_syz_ctx {
	FILE *output;
	pid_t pid;
	int next_res;
	int fd_map[1024];
};

int vock_syz_init(struct vock_syz_ctx *ctx, const char *output_path);
int vock_syz_emit(struct vock_syz_ctx *ctx, const struct vock_syscall *sc);
void vock_syz_fini(struct vock_syz_ctx *ctx);

#endif
