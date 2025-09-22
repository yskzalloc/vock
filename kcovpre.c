// File: kcov_preload.c (English Version, Simplified)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kcov.h>

#define COVER_SIZE (64 << 10)

static int fd = -1;
static unsigned long *cover = MAP_FAILED;

__attribute__((constructor))
static void kcov_init_local(void) {
    fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (fd == -1) {
        // Don't exit, just fail gracefully if kcov isn't available
        perror("[kcov_preload] Warning: Could not open kcov");
        return;
    }

    if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE)) {
        perror("[kcov_preload] Warning: Could not init local trace");
        close(fd);
        fd = -1;
        return;
    }

    cover = (unsigned long *)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
                                  PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cover == MAP_FAILED) {
        perror("[kcov_preload] Warning: Could not mmap local buffer");
        close(fd);
        fd = -1;
        return;
    }
    
    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)) {
        perror("[kcov_preload] Warning: Could not enable local coverage");
        munmap(cover, COVER_SIZE * sizeof(unsigned long));
        close(fd);
        fd = -1;
        cover = MAP_FAILED;
        return;
    }

    fprintf(stderr, "[VOCK Tracee] Local coverage enabled.\n");
    __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
}

__attribute__((destructor))
static void kcov_exit_local(void) {
    if (fd == -1 || cover == MAP_FAILED) return;

    // Save to a specific file to avoid race conditions with the tracer
    FILE *f = fopen("local_coverage.log", "w");
    if (f == NULL) return;

    ioctl(fd, KCOV_DISABLE, 0);
    unsigned long n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
    for (unsigned long i = 0; i < n; i++) {
        fprintf(f, "0x%lx\n", cover[i + 1]);
    }

    fclose(f);
    munmap(cover, COVER_SIZE * sizeof(unsigned long));
    close(fd);
}

