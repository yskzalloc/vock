#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/kcov.h>

#define COVER_SZ        (64 << 10)

static int kcov_remote_enable(int *fdp, unsigned long **areap)
{
    int ret;
    struct kcov_remote_arg arg;

    *fdp = open("/sys/kernel/debug/kcov", O_RDWR);
    if (*fdp == -1) {
        perror("kcov: remote open failed");
        return -1;
    }

    ret = ioctl(*fdp, KCOV_INIT_TRACE, COVER_SZ);
    if (ret) {
        perror("kcov: remote init failed");
        return -1;
    }

    *areap = mmap(NULL, COVER_SZ * sizeof(unsigned long),
              PROT_READ | PROT_WRITE, MAP_SHARED, *fdp, 0);
    if (*areap == (unsigned long *)MAP_FAILED) {
        perror("kcov: remote mmap failed");
        return -1;
    }

    memset(&arg, 0, sizeof(arg));
    arg.trace_mode = KCOV_TRACE_PC;
    arg.area_size = COVER_SZ;
    arg.common_handle = kcov_remote_handle(0x00ULL << 56, getpid());

    ret = ioctl(*fdp, KCOV_REMOTE_ENABLE, &arg);
    if (ret) {
        perror("kcov: remote enable failed");
        return -1;
    }

    fprintf(stderr, "kcov: remote coverage enabled\n");
    return 0;
}

static void write_remote_log(unsigned long *area)
{
    FILE *f;
    unsigned long n;
    unsigned long i;

    f = fopen("remote_coverage.log", "w");
    if (!f) {
        perror("kcov: fopen remote_coverage.log failed");
        return;
    }

    n = __atomic_load_n(&area[0], __ATOMIC_RELAXED);
    for (i = 0; i < n; i++)
        fprintf(f, "0x%lx\n", area[i + 1]);

    fclose(f);
}

static int run_report(const char *report_path,
              const char *kernel_src,
              const char *vmlinux,
              const char *filter)
{
    char *argv_exec[16];
    int idx = 0;
    pid_t pid;
    int status;

    argv_exec[idx++] = (char *)"python3";
    argv_exec[idx++] = (char *)report_path;
    argv_exec[idx++] = (char *)"--mode";
    argv_exec[idx++] = (char *)"merge";

    if (kernel_src) {
        argv_exec[idx++] = (char *)"--kernel-src";
        argv_exec[idx++] = (char *)kernel_src;
    }
    if (vmlinux) {
        argv_exec[idx++] = (char *)"--vmlinux";
        argv_exec[idx++] = (char *)vmlinux;
    }
    if (filter) {
        argv_exec[idx++] = (char *)"--filter";
        argv_exec[idx++] = (char *)filter;
    }
    argv_exec[idx] = NULL;

    pid = fork();
    if (pid == 0) {
        execvp("python3", argv_exec);
        perror("report: execvp failed");
        _exit(127);
    } else if (pid < 0) {
        perror("report: fork failed");
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        perror("report: waitpid failed");
        return -1;
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char *argv[])
{
    char *kernel_src = NULL;
    char *vmlinux = NULL;
    char *filter = NULL;
    int cmd_idx = -1;
    char exe_path[1024];
    ssize_t nread;
    char *exe_dir;
    char preload_path[2048];
    int rfd = -1;
    unsigned long *rarea = (unsigned long *)MAP_FAILED;
    pid_t pid;
    int status;
    int ret;
    char report_path[2048];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--kernel-src") && i + 1 < argc) {
            kernel_src = argv[++i];
        } else if (!strcmp(argv[i], "--vmlinux") && i + 1 < argc) {
            vmlinux = argv[++i];
        } else if (!strcmp(argv[i], "--filter") && i + 1 < argc) {
            filter = argv[++i];
        } else {
            cmd_idx = i;
            break;
        }
    }

    if (cmd_idx == -1) {
        fprintf(stderr,
            "usage: %s [--kernel-src PATH] [--vmlinux FILE] "
            "[--filter KW] <cmd> [args...]\n", argv[0]);
        exit(1);
    }

    nread = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (nread == -1) {
        perror("readlink failed");
        exit(1);
    }
    exe_path[nread] = '\0';
    exe_dir = dirname(exe_path);

    snprintf(preload_path, sizeof(preload_path),
         "%s/kcovpre.so", exe_dir);

    ret = kcov_remote_enable(&rfd, &rarea);
    if (ret) {
        fprintf(stderr, "kcov: remote setup failed\n");
        exit(1);
    }

    /* Optional: eBPF attach logic guarded by DEBUG_INFO_BTF.
     * When DEBUG_INFO_BTF is not defined, syscall tracing is disabled. */
#ifdef DEBUG_INFO_BTF
    /* TODO: load and attach syscall.bpf.o here (driver-side), and
     * filter events by target PID. Intentionally skipped for portability
     * when DEBUG_INFO_BTF=0. */
#endif

    pid = fork();
    if (pid == 0) {
        setenv("LD_PRELOAD", preload_path, 1);
        execvp(argv[cmd_idx], &argv[cmd_idx]);
        perror("target: execvp failed");
        _exit(127);
    } else if (pid < 0) {
        perror("target: fork failed");
        exit(1);
    }

    if (waitpid(pid, &status, 0) < 0) {
        perror("target: waitpid failed");
        exit(1);
    }

    write_remote_log(rarea);

    ioctl(rfd, KCOV_DISABLE, 0);
    munmap(rarea, COVER_SZ * sizeof(unsigned long));
    close(rfd);

    fprintf(stderr, "[vock] generating report\n");

    snprintf(report_path, sizeof(report_path), "%s/report.py", exe_dir);
    ret = run_report(report_path, kernel_src, vmlinux, filter);
    if (ret)
        fprintf(stderr, "report: exit code %d\n", ret);

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

