#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/kcov.h>

#define COVER_SIZE (64 << 10)

// Function to set up remote kcov tracing
int setup_kcov_remote(int *fd_out, unsigned long **cover_out) {
    *fd_out = open("/sys/kernel/debug/kcov", O_RDWR);
    if (*fd_out == -1) {
        perror("[VOCK Tracer] Error opening kcov");
        return -1;
    }

    if (ioctl(*fd_out, KCOV_INIT_TRACE, COVER_SIZE) != 0) {
        perror("[VOCK Tracer] Error initializing remote trace");
        return -1;
    }

    *cover_out = (unsigned long *)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
                                     PROT_READ | PROT_WRITE, MAP_SHARED, *fd_out, 0);
    if (*cover_out == MAP_FAILED) {
        perror("[VOCK Tracer] Error mmaping remote buffer");
        return -1;
    }

    struct kcov_remote_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.trace_mode = 0; // KCOV_TRACE_PC
    arg.area_size = COVER_SIZE;
    arg.common_handle = kcov_remote_handle(0x00ull << 56, getpid());

    if (ioctl(*fd_out, KCOV_REMOTE_ENABLE, &arg) != 0) {
        perror("[VOCK Tracer] Error enabling remote coverage");
        return -1;
    }
    
    fprintf(stderr, "[VOCK Tracer] Remote coverage enabled.\n");
    return 0;
}

// Function to merge log files
void merge_logs() {
    FILE *final_log, *log_to_merge;
    char buffer[4096];
    size_t bytes;

    final_log = fopen("coverage.log", "w");
    if (!final_log) return;

    // Merge local log if it exists
    log_to_merge = fopen("local_coverage.log", "r");
    if (log_to_merge) {
        while ((bytes = fread(buffer, 1, sizeof(buffer), log_to_merge)) > 0) {
            fwrite(buffer, 1, bytes, final_log);
        }
        fclose(log_to_merge);
        remove("local_coverage.log");
    }

    // Merge remote log if it exists
    log_to_merge = fopen("remote_coverage.log", "r");
    if (log_to_merge) {
        while ((bytes = fread(buffer, 1, sizeof(buffer), log_to_merge)) > 0) {
            fwrite(buffer, 1, bytes, final_log);
        }
        fclose(log_to_merge);
        remove("remote_coverage.log");
    }
    
    fclose(final_log);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        exit(1);
    }

    // Determine the path of the preload library relative to the executable
    char exe_path[1024];
    if (readlink("/proc/self/exe", exe_path, sizeof(exe_path)) == -1) {
        perror("Could not find executable path");
        exit(1);
    }
    char *exe_dir = dirname(exe_path);
    char preload_lib_path[2048];
    snprintf(preload_lib_path, sizeof(preload_lib_path), "%s/kcovpre.so", exe_dir);

    // --- Tracer (Parent) setup ---
    int remote_fd = -1;
    unsigned long *remote_cover = MAP_FAILED;
    if (setup_kcov_remote(&remote_fd, &remote_cover) != 0) {
        fprintf(stderr, "[VOCK Tracer] Failed to set up. Are you running as root?\n");
        exit(1);
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("[VOCK Tracer] fork failed");
        exit(1);
    }

    if (pid == 0) {
        // --- Tracee (Child) process ---
        setenv("LD_PRELOAD", preload_lib_path, 1);
        execvp(argv[1], &argv[1]);
        // If execvp returns, an error occurred
        perror("[VOCK Tracee] execvp failed");
        _exit(127); // Use _exit in child after fork
    }

    // --- Tracer (Parent) process continues ---
    int status;
    waitpid(pid, &status, 0);

    // Collect remote coverage data
    FILE *remote_log = fopen("remote_coverage.log", "w");
    if (remote_log) {
        unsigned long n = __atomic_load_n(&remote_cover[0], __ATOMIC_RELAXED);
        for (unsigned long i = 0; i < n; i++) {
            fprintf(remote_log, "0x%lx\n", remote_cover[i + 1]);
        }
        fclose(remote_log);
    }

    // Clean up remote kcov resources
    ioctl(remote_fd, KCOV_DISABLE, 0);
    munmap(remote_cover, COVER_SIZE * sizeof(unsigned long));
    close(remote_fd);

    // Merge logs and generate final report
    fprintf(stderr, "\n\033[93m📊 [VOCK] Generating final report...\033[0m\n");
    merge_logs();
    system("python3 $(dirname $(readlink -f \"$0\"))/report.py");

    return WEXITSTATUS(status);
}

