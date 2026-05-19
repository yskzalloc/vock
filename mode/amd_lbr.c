/* AMD LBR (Last Branch Record) sampling for kernel coverage.
 * Uses PERF_SAMPLE_BRANCH_STACK to collect kernel branch targets.
 * Sampled coverage (not complete like Intel PT). Works on Zen 3+.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "hw.h"

#define MMAP_PAGES 128  /* larger ring for sampling */

int amd_lbr_available(void)
{
	FILE *f = fopen("/proc/cpuinfo", "r");
	if (!f) return 0;
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "AuthenticAMD")) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

int amd_lbr_start(struct vock_hw_ctx *ctx, pid_t pid)
{
	struct perf_event_attr attr;
	size_t mmap_size;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
	attr.disabled = 1;
	attr.exclude_kernel = 0;
	attr.exclude_user = 1;
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_BRANCH_STACK;
	attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL |
				  PERF_SAMPLE_BRANCH_ANY;
	attr.wakeup_events = 1;

	ctx->pid = pid;
	ctx->amd_lbr = 1;
	ctx->perf_fd = syscall(__NR_perf_event_open, &attr, pid, -1, -1, 0);
	if (ctx->perf_fd < 0) {
		perror("amd_lbr: perf_event_open");
		return -1;
	}

	mmap_size = (MMAP_PAGES + 1) * 4096;
	ctx->base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->perf_fd, 0);
	if (ctx->base == MAP_FAILED) {
		perror("amd_lbr: mmap");
		close(ctx->perf_fd);
		ctx->perf_fd = -1;
		return -1;
	}
	ctx->mmap_size = mmap_size;

	ioctl(ctx->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
	return 0;
}

int amd_lbr_decode(struct vock_hw_ctx *ctx)
{
	struct perf_event_mmap_page *header = ctx->base;
	uint64_t head = header->data_head;
	uint64_t tail = header->data_tail;
	size_t data_size = ctx->mmap_size - 4096;
	unsigned char *ring = (unsigned char *)ctx->base + 4096;
	int pc_count = 0;

	FILE *f = fopen("kerncov.log", "w");
	if (!f) return -1;

	while (tail < head) {
		struct perf_event_header *ev =
			(struct perf_event_header *)(ring + (tail % data_size));
		if (ev->type == PERF_RECORD_SAMPLE && ev->size > sizeof(*ev)) {
			unsigned char *p = (unsigned char *)ev + sizeof(*ev);
			uint64_t ip = *(uint64_t *)p;
			p += 8;
			uint64_t nr = *(uint64_t *)p;
			p += 8;
			if (ip >= 0xffff800000000000ULL) {
				fprintf(f, "0x%lx\n", ip);
				pc_count++;
			}
			for (uint64_t i = 0; i < nr && i < 32; i++) {
				uint64_t from = *(uint64_t *)p;
				uint64_t to = *(uint64_t *)(p + 8);
				p += 24; /* from, to, flags */
				if (from >= 0xffff800000000000ULL) {
					fprintf(f, "0x%lx\n", from);
					pc_count++;
				}
				if (to >= 0xffff800000000000ULL) {
					fprintf(f, "0x%lx\n", to);
					pc_count++;
				}
			}
		}
		tail += ev->size;
	}
	header->data_tail = head;
	fclose(f);
	fprintf(stderr, "[vock] AMD LBR: %d kernel PCs sampled\n", pc_count);
	return pc_count > 0 ? 0 : -1;
}
