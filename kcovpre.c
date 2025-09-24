#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kcov.h>

#define COVER_SZ		(64 << 10)

static int kcov_fd = -1;
static unsigned long *kcov_area = (unsigned long *)MAP_FAILED;

static void kcov_enable(void)
{
	int ret;

	kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov_fd < 0) {
		perror("kcov: open failed");
		return;
	}

	ret = ioctl(kcov_fd, KCOV_INIT_TRACE, COVER_SZ);
	if (ret) {
		perror("kcov: init failed");
		goto err_close;
	}

	kcov_area = mmap(NULL, COVER_SZ * sizeof(unsigned long),
			 PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
	if (kcov_area == (unsigned long *)MAP_FAILED) {
		perror("kcov: mmap failed");
		goto err_close;
	}

	ret = ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC);
	if (ret) {
		perror("kcov: enable failed");
		goto err_unmap;
	}

	__atomic_store_n(&kcov_area[0], 0, __ATOMIC_RELAXED);
	fprintf(stderr, "kcov: local coverage enabled\n");
	return;

err_unmap:
	munmap(kcov_area, COVER_SZ * sizeof(unsigned long));
	kcov_area = (unsigned long *)MAP_FAILED;
err_close:
	close(kcov_fd);
	kcov_fd = -1;
}

static void kcov_disable(void)
{
	FILE *f;
	unsigned long n;
	unsigned long i;

	if (kcov_fd < 0 || kcov_area == (unsigned long *)MAP_FAILED)
		return;

	f = fopen("local_coverage.log", "w");
	if (!f)
		perror("kcov: fopen local_coverage.log failed");

	ioctl(kcov_fd, KCOV_DISABLE, 0);

	n = __atomic_load_n(&kcov_area[0], __ATOMIC_RELAXED);
	if (f) {
		for (i = 0; i < n; i++)
			fprintf(f, "0x%lx\n", kcov_area[i + 1]);
		fclose(f);
	}

	munmap(kcov_area, COVER_SZ * sizeof(unsigned long));
	kcov_area = (unsigned long *)MAP_FAILED;
	close(kcov_fd);
	kcov_fd = -1;
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

