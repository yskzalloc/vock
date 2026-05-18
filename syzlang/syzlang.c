#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include "syzlang.h"
#include "../syscall/decode.h"

int vock_syz_init(struct vock_syz_ctx *ctx, const char *output_path)
{
	ctx->output = fopen(output_path, "w");
	if (!ctx->output) {
		perror("syz: fopen");
		return -1;
	}
	ctx->next_res = 0;
	memset(ctx->fd_map, -1, sizeof(ctx->fd_map));
	return 0;
}

int vock_syz_emit(struct vock_syz_ctx *ctx, const struct vock_syscall *sc)
{
	vock_decode_syscall(ctx->output, ctx->pid, sc->nr, (long *)sc->args, sc->ret);
	return 0;
}

void vock_syz_fini(struct vock_syz_ctx *ctx)
{
	if (ctx->output) {
		fclose(ctx->output);
		ctx->output = NULL;
	}
}
