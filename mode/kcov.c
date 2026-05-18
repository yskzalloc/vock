#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kcov.h>

#define COVER_SZ		(64 << 10)

#ifndef KCOV_REMOTE_ENABLE
struct kcov_remote_arg {
	__u32 trace_mode;
	__u32 area_size;
	__u32 num_handles;
	__aligned_u64 common_handle;
	__aligned_u64 handles[0];
};
#define KCOV_REMOTE_ENABLE	_IOW('c', 102, struct kcov_remote_arg)
#endif

#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffULL)

static inline uint64_t vock_kcov_handle(uint64_t subsys, uint64_t inst)
{
	return subsys | (inst & KCOV_INSTANCE_MASK);
}

/* Local coverage (per-task: direct syscall paths) */
static int local_fd = -1;
static unsigned long *local_area = (unsigned long *)MAP_FAILED;

/* Remote coverage (background tasks: softirqs, workqueues) */
static int remote_fd = -1;
static unsigned long *remote_area = (unsigned long *)MAP_FAILED;

static void kcov_enable(void)
{
	int ret;

	/* ─── Local coverage ──────────────────────────────────────────── */
	local_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (local_fd < 0) {
		perror("kcov: open failed (local)");
		return;
	}

	ret = ioctl(local_fd, KCOV_INIT_TRACE, COVER_SZ);
	if (ret) { perror("kcov: init local"); goto err_local; }

	local_area = mmap(NULL, COVER_SZ * sizeof(unsigned long),
			  PROT_READ | PROT_WRITE, MAP_SHARED, local_fd, 0);
	if (local_area == MAP_FAILED) { perror("kcov: mmap local"); goto err_local; }

	ret = ioctl(local_fd, KCOV_ENABLE, KCOV_TRACE_PC);
	if (ret) { perror("kcov: enable local"); goto err_local_unmap; }

	__atomic_store_n(&local_area[0], 0, __ATOMIC_RELAXED);

	/* ─── Remote coverage ─────────────────────────────────────────── */
	remote_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (remote_fd < 0) {
		/* Remote not available — local-only mode */
		fprintf(stderr, "kcov: local coverage enabled (remote unavailable)\n");
		return;
	}

	ret = ioctl(remote_fd, KCOV_INIT_TRACE, COVER_SZ);
	if (ret) { close(remote_fd); remote_fd = -1; goto local_only; }

	remote_area = mmap(NULL, COVER_SZ * sizeof(unsigned long),
			   PROT_READ | PROT_WRITE, MAP_SHARED, remote_fd, 0);
	if (remote_area == MAP_FAILED) { close(remote_fd); remote_fd = -1; goto local_only; }

	/* Enable remote with common handle (captures softirqs/workqueues for this process) */
	struct kcov_remote_arg *arg = calloc(1, sizeof(*arg));
	if (!arg) { goto local_only; }
	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = COVER_SZ;
	arg->num_handles = 0;
	arg->common_handle = vock_kcov_handle(KCOV_SUBSYSTEM_COMMON, getpid());

	ret = ioctl(remote_fd, KCOV_REMOTE_ENABLE, arg);
	free(arg);
	if (ret) {
		munmap(remote_area, COVER_SZ * sizeof(unsigned long));
		remote_area = (unsigned long *)MAP_FAILED;
		close(remote_fd);
		remote_fd = -1;
		goto local_only;
	}

	__atomic_store_n(&remote_area[0], 0, __ATOMIC_RELAXED);
	fprintf(stderr, "kcov: local + remote coverage enabled\n");
	return;

local_only:
	fprintf(stderr, "kcov: local coverage enabled\n");
	return;

err_local_unmap:
	munmap(local_area, COVER_SZ * sizeof(unsigned long));
	local_area = (unsigned long *)MAP_FAILED;
err_local:
	close(local_fd);
	local_fd = -1;
}

static void write_coverage(const char *path, unsigned long *area, int fd)
{
	unsigned long n, i;
	FILE *f;

	if (fd < 0 || area == MAP_FAILED)
		return;

	ioctl(fd, KCOV_DISABLE, 0);
	n = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	f = fopen(path, "w");
	if (f) {
		for (i = 0; i < n; i++)
			fprintf(f, "0x%lx\n", area[i + 1]);
		fclose(f);
		if (n > 0)
			fprintf(stderr, "kcov: %lu PCs → %s\n", n, path);
	}

	munmap(area, COVER_SZ * sizeof(unsigned long));
	close(fd);
}

static void kcov_disable(void)
{
	write_coverage("local.log", local_area, local_fd);
	local_area = (unsigned long *)MAP_FAILED;
	local_fd = -1;

	write_coverage("remote.log", remote_area, remote_fd);
	remote_area = (unsigned long *)MAP_FAILED;
	remote_fd = -1;

	/* Merge into kerncov.log for compatibility */
	FILE *merged = fopen("kerncov.log", "w");
	if (merged) {
		FILE *f;
		char line[64];
		f = fopen("local.log", "r");
		if (f) { while (fgets(line, sizeof(line), f)) fputs(line, merged); fclose(f); }
		f = fopen("remote.log", "r");
		if (f) { while (fgets(line, sizeof(line), f)) fputs(line, merged); fclose(f); }
		fclose(merged);
	}
}

__attribute__((constructor))
static void kcov_ctor(void)
{
	kcov_enable();
}

__attribute__((destructor))
static void kcov_dtor(void)
{
	kcov_disable();
}
