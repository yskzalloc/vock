/* Hardware trace dispatcher (aviator).
 * Auto-selects backend: Intel PT, CoreSight, or AMD LBR.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include "hw.h"
#include "intel_pt.h"
#include "amd_lbr.h"

int vock_hw_trace_available(void)
{
	if (intel_pt_available())
		return 1;
	if (amd_lbr_available())
		return 1;
	return 0;
}

int vock_hw_trace_init(struct vock_hw_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->perf_fd = -1;
	ctx->base = MAP_FAILED;
	ctx->aux_buf = MAP_FAILED;
	return 0;
}

int vock_hw_trace_start(struct vock_hw_ctx *ctx, pid_t pid)
{
	if (intel_pt_available())
		return intel_pt_start(ctx, pid);
	if (amd_lbr_available())
		return amd_lbr_start(ctx, pid);
	fprintf(stderr, "hw_trace: no hardware trace PMU found\n");
	return -1;
}

int vock_hw_trace_stop(struct vock_hw_ctx *ctx)
{
	if (ctx->perf_fd >= 0)
		ioctl(ctx->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
	return 0;
}

int vock_hw_trace_decode(struct vock_hw_ctx *ctx, const char *vmlinux)
{
	if (ctx->base == MAP_FAILED)
		return -1;
	if (ctx->amd_lbr)
		return amd_lbr_decode(ctx);
	return intel_pt_decode(ctx, vmlinux);
}

void vock_hw_trace_fini(struct vock_hw_ctx *ctx)
{
	if (ctx->aux_buf != MAP_FAILED)
		munmap(ctx->aux_buf, ctx->aux_size);
	if (ctx->base != MAP_FAILED)
		munmap(ctx->base, ctx->mmap_size);
	if (ctx->perf_fd >= 0)
		close(ctx->perf_fd);
}
