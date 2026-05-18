#ifndef MODE_HW_H
#define MODE_HW_H

#include <sys/types.h>

struct vock_hw_ctx {
	int perf_fd;
	pid_t pid;
	void *base;
	size_t mmap_size;
	void *aux_buf;
	size_t aux_size;
};

int vock_hw_trace_init(struct vock_hw_ctx *ctx);
int vock_hw_trace_start(struct vock_hw_ctx *ctx, pid_t pid);
int vock_hw_trace_stop(struct vock_hw_ctx *ctx);
int vock_hw_trace_decode(struct vock_hw_ctx *ctx, const char *vmlinux);
void vock_hw_trace_fini(struct vock_hw_ctx *ctx);
int vock_hw_trace_available(void);

#endif
