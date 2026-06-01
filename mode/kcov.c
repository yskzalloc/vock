#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <linux/kcov.h>
#include <linux/sched.h>

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

#ifndef KCOV_SUBSYSTEM_COMMON
#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)
#endif
#ifndef KCOV_INSTANCE_MASK
#define KCOV_INSTANCE_MASK	(0xffffffffULL)
#endif

static inline uint64_t vock_kcov_handle(uint64_t subsys, uint64_t inst)
{
	return subsys | (inst & KCOV_INSTANCE_MASK);
}

/* Per-thread KCOV state (threads share address space, need TLS) */
static __thread int local_fd = -1;
static __thread unsigned long *local_area = (unsigned long *)MAP_FAILED;
static __thread int remote_fd = -1;
static __thread unsigned long *remote_area = (unsigned long *)MAP_FAILED;
static __thread pid_t kcov_tid;

static pid_t initial_pid;

static void kcov_enable(void)
{
	int ret;

	kcov_tid = syscall(__NR_gettid);

	local_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (local_fd < 0)
		return;

	ret = ioctl(local_fd, KCOV_INIT_TRACE, COVER_SZ);
	if (ret) goto err_local;

	local_area = mmap(NULL, COVER_SZ * sizeof(unsigned long),
			  PROT_READ | PROT_WRITE, MAP_SHARED, local_fd, 0);
	if (local_area == MAP_FAILED) goto err_local;

	ret = ioctl(local_fd, KCOV_ENABLE, KCOV_TRACE_PC);
	if (ret) goto err_local_unmap;

	__atomic_store_n(&local_area[0], 0, __ATOMIC_RELAXED);

	/* Remote coverage */
	remote_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (remote_fd < 0)
		goto done;

	ret = ioctl(remote_fd, KCOV_INIT_TRACE, COVER_SZ);
	if (ret) { close(remote_fd); remote_fd = -1; goto done; }

	remote_area = mmap(NULL, COVER_SZ * sizeof(unsigned long),
			   PROT_READ | PROT_WRITE, MAP_SHARED, remote_fd, 0);
	if (remote_area == MAP_FAILED) { close(remote_fd); remote_fd = -1; goto done; }

	struct kcov_remote_arg *arg = calloc(1, sizeof(*arg));
	if (!arg) goto done;
	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = COVER_SZ;
	arg->num_handles = 0;
	arg->common_handle = vock_kcov_handle(KCOV_SUBSYSTEM_COMMON, kcov_tid);

	ret = ioctl(remote_fd, KCOV_REMOTE_ENABLE, arg);
	free(arg);
	if (ret) {
		munmap(remote_area, COVER_SZ * sizeof(unsigned long));
		remote_area = (unsigned long *)MAP_FAILED;
		close(remote_fd);
		remote_fd = -1;
		goto done;
	}
	__atomic_store_n(&remote_area[0], 0, __ATOMIC_RELAXED);

done:
	fprintf(stderr, "kcov[%d]: coverage enabled\n", kcov_tid);
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
			fprintf(stderr, "kcov[%d]: %lu PCs → %s\n", kcov_tid, n, path);
	}

	munmap(area, COVER_SZ * sizeof(unsigned long));
	close(fd);
}

static void kcov_disable(void)
{
	char path[64];

	snprintf(path, sizeof(path), "local-%d.log", kcov_tid);
	write_coverage(path, local_area, local_fd);
	local_area = (unsigned long *)MAP_FAILED;
	local_fd = -1;

	snprintf(path, sizeof(path), "remote-%d.log", kcov_tid);
	write_coverage(path, remote_area, remote_fd);
	remote_area = (unsigned long *)MAP_FAILED;
	remote_fd = -1;
}

/* ─── fork interception ───────────────────────────────────────────────────── */

static void kcov_child_reinit(void)
{
	if (local_fd >= 0) { close(local_fd); local_fd = -1; }
	if (remote_fd >= 0) { close(remote_fd); remote_fd = -1; }
	local_area = (unsigned long *)MAP_FAILED;
	remote_area = (unsigned long *)MAP_FAILED;
	kcov_enable();
}

pid_t fork(void)
{
	pid_t (*real_fork)(void) = dlsym(RTLD_NEXT, "fork");
	pid_t pid = real_fork();
	if (pid == 0)
		kcov_child_reinit();
	return pid;
}

pid_t vfork(void)
{
	return fork();
}

/* ─── pthread_create interception ─────────────────────────────────────────── */

struct thread_wrap {
	void *(*fn)(void *);
	void *arg;
};

static void *kcov_thread_entry(void *p)
{
	struct thread_wrap w = *(struct thread_wrap *)p;
	free(p);
	kcov_enable();
	void *ret = w.fn(w.arg);
	kcov_disable();
	return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		   void *(*start_routine)(void *), void *arg)
{
	int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
				   void *(*)(void *), void *) =
		dlsym(RTLD_NEXT, "pthread_create");

	struct thread_wrap *w = malloc(sizeof(*w));
	if (!w)
		return real_pthread_create(thread, attr, start_routine, arg);

	w->fn = start_routine;
	w->arg = arg;
	return real_pthread_create(thread, attr, kcov_thread_entry, w);
}

/* ─── constructor / destructor ────────────────────────────────────────────── */

__attribute__((constructor))
static void kcov_ctor(void)
{
	initial_pid = getpid();
	kcov_enable();
}

__attribute__((destructor))
static void kcov_dtor(void)
{
	kcov_disable();

	/* Only the initial process merges all per-TID logs */
	if (getpid() != initial_pid)
		return;

	FILE *merged = fopen("kerncov.log", "w");
	if (!merged)
		return;

	char line[64];
	FILE *f;
	DIR *d = opendir(".");
	if (d) {
		struct dirent *ent;
		while ((ent = readdir(d)) != NULL) {
			if ((strncmp(ent->d_name, "local-", 6) == 0 ||
			     strncmp(ent->d_name, "remote-", 7) == 0) &&
			    strstr(ent->d_name, ".log")) {
				f = fopen(ent->d_name, "r");
				if (f) {
					while (fgets(line, sizeof(line), f))
						fputs(line, merged);
					fclose(f);
				}
			}
		}
		closedir(d);
	}

	fclose(merged);
}
