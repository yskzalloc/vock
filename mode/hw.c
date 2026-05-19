/* Hardware trace dispatcher.
 * Auto-selects: Intel PT → full trace, AMD → LBR sampling, ARM → CoreSight.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "hw.h"
#include "pt_decode.h"
#include "amd_lbr.h"

#define AUX_SIZE (4 * 1024 * 1024)
#define MMAP_PAGES 1

int vock_hw_trace_available(void)
{
	if (access("/sys/bus/event_source/devices/intel_pt", F_OK) == 0)
		return 1;
	if (access("/sys/bus/event_source/devices/cs_etm", F_OK) == 0)
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
	ctx->aux_size = AUX_SIZE;
	return 0;
}

int vock_hw_trace_start(struct vock_hw_ctx *ctx, pid_t pid)
{
	struct perf_event_attr attr;
	int type = -1;
	FILE *f;
	char buf[64];
	size_t mmap_size;

	/* Try Intel PT / CoreSight first */
	f = fopen("/sys/bus/event_source/devices/intel_pt/type", "r");
	if (!f)
		f = fopen("/sys/bus/event_source/devices/cs_etm/type", "r");
	if (f) {
		if (fgets(buf, sizeof(buf), f))
			type = atoi(buf);
		fclose(f);
	}

	/* AMD fallback: use LBR sampling */
	if (type < 0)
		return amd_lbr_start(ctx, pid);

	/* Intel PT / CoreSight setup */
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = type;
	attr.disabled = 1;
	attr.exclude_kernel = 0;
	attr.exclude_user = 1;

	ctx->pid = pid;
	ctx->amd_lbr = 0;
	ctx->perf_fd = syscall(__NR_perf_event_open, &attr, pid, -1, -1, 0);
	if (ctx->perf_fd < 0) {
		perror("hw_trace: perf_event_open");
		return -1;
	}

	mmap_size = (MMAP_PAGES + 1) * 4096;
	ctx->base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->perf_fd, 0);
	if (ctx->base == MAP_FAILED) {
		perror("hw_trace: mmap ring");
		close(ctx->perf_fd);
		ctx->perf_fd = -1;
		return -1;
	}
	ctx->mmap_size = mmap_size;

	/* Aux area for PT/CoreSight trace data */
	struct perf_event_mmap_page *header = ctx->base;
	header->aux_offset = mmap_size;
	header->aux_size = ctx->aux_size;

	ctx->aux_buf = mmap(NULL, ctx->aux_size, PROT_READ,
			    MAP_SHARED, ctx->perf_fd, header->aux_offset);
	if (ctx->aux_buf == MAP_FAILED) {
		perror("hw_trace: aux mmap");
		munmap(ctx->base, mmap_size);
		ctx->base = MAP_FAILED;
		close(ctx->perf_fd);
		ctx->perf_fd = -1;
		return -1;
	}

	ioctl(ctx->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
	return 0;
}

int vock_hw_trace_stop(struct vock_hw_ctx *ctx)
{
	if (ctx->perf_fd >= 0)
		ioctl(ctx->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
	return 0;
}

int vock_hw_trace_decode(struct vock_hw_ctx *ctx, const char *vmlinux)
{
	FILE *f;
	size_t len;
	struct perf_event_mmap_page *header;
	unsigned char *data;
	int pc_count = 0;

	if (ctx->base == MAP_FAILED)
		return -1;

	/* AMD LBR: dispatch to dedicated decoder */
	if (ctx->amd_lbr)
		return amd_lbr_decode(ctx);

	/* Intel PT / CoreSight: decode from aux buffer */
	if (ctx->aux_buf == MAP_FAILED)
		return -1;

	header = (struct perf_event_mmap_page *)ctx->base;
	len = header->aux_head;
	if (len > ctx->aux_size)
		len = ctx->aux_size;
	if (len == 0) {
		fprintf(stderr, "[vock] hw_trace: no data captured\n");
		return -1;
	}

	data = (unsigned char *)ctx->aux_buf;

	/* Save raw trace */
	f = fopen("hw_trace.bin", "wb");
	if (f) { fwrite(data, 1, len, f); fclose(f); }

	/* Decode PT → kernel PCs */
	f = fopen("kerncov.log", "w");
	if (!f) {
		perror("hw_trace: fopen kerncov.log");
		return -1;
	}

	if (vmlinux) {
		/* Full decode with TNT walking */
		struct pt_decoder dec;
		if (pt_decoder_init(&dec, vmlinux, data, len, f) == 0) {
			pc_count = pt_decoder_run(&dec);
			pt_decoder_fini(&dec);
		} else {
			fprintf(stderr, "[vock] hw_trace: vmlinux load failed, TIP-only mode\n");
			goto tip_only;
		}
	} else {
tip_only:;
		/* TIP-only fallback (no vmlinux) */
		uint64_t last_ip = 0;
		size_t pos = 0;
		while (pos < len) {
			unsigned char b = data[pos];
			unsigned char opcode = b & 0x1f;
			int ip_bytes = 0;

			if (opcode == 0x0d || opcode == 0x1d ||
			    opcode == 0x11 || opcode == 0x01) {
				int enc = (b >> 5) & 0x7;
				switch (enc) {
				case 1: ip_bytes = 2; break;
				case 2: ip_bytes = 4; break;
				case 3: case 4: ip_bytes = 6; break;
				case 6: ip_bytes = 8; break;
				}
				if (ip_bytes > 0 && pos + 1 + ip_bytes <= len) {
					uint64_t ip = 0;
					for (int i = 0; i < ip_bytes; i++)
						ip |= (uint64_t)data[pos + 1 + i] << (8 * i);
					if (enc == 1) last_ip = (last_ip & ~0xFFFFULL) | ip;
					else if (enc == 2) last_ip = (last_ip & ~0xFFFFFFFFULL) | ip;
					else if (enc == 3) { last_ip = ip; if (ip & (1ULL<<47)) last_ip |= 0xFFFF000000000000ULL; }
					else if (enc == 4) last_ip = (last_ip & ~0xFFFFFFFFFFFFULL) | ip;
					else if (enc == 6) last_ip = ip;
					if (last_ip >= 0xffff000000000000ULL) {
						fprintf(f, "0x%lx\n", (unsigned long)last_ip);
						pc_count++;
					}
					pos += 1 + ip_bytes;
					continue;
				}
			}
			if (b == 0x99 && pos + 1 < len && data[pos + 1] == 0x01)
				pos += 16;
			else
				pos++;
		}
	}

	fclose(f);
	fprintf(stderr, "[vock] hw_trace: %d kernel PCs → kerncov.log\n", pc_count);
	(void)vmlinux;
	return 0;
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
