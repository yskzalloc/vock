#pragma once

#include "nolibc_util.h"
#include <sysdeps/kernel_sigaction.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <dlfcn.h>
#include <syscall.h>
#include <stdbool.h>

#define XSTR(X) #X
#define STR(X) XSTR(X)

#define ASSERT_ELSE_PERROR(cond) \
    do {                            \
        bool x = (bool)(cond);                \
        if (!x) {                       \
            fflush(stdout);                 \
            fflush(stderr);                     \
            fprintf(stderr,"%s:%d: %s: Assertion `%s` failed: ", __FILE__, __LINE__, __func__, #cond); \
            perror("");                                                                         \
            fflush(stderr);                                                                     \
            abort();                                                                            \
        }                                                                                       \
    } while (0)

#if __GLIBC__ != 2
#error Unknown glibc
#endif

#if __GLIBC_MINOR__ <= 31
#define SIGSETSIZE (_NSIG / 8)
#else
#define SIGSETSIZE (8)
#endif

static inline long long non_libc_rt_sigaction(int signo, const struct kernel_sigaction *newact, struct kernel_sigaction *oldact) {
    return inline_syscall6(__NR_rt_sigaction, signo, newact, oldact, SIGSETSIZE, 0, 0);
}

static inline long long non_libc_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
    return inline_syscall6(__NR_rt_sigprocmask, how, set, oset, SIGSETSIZE, 0, 0);
}

const char *get_syscall_name(size_t sysno);
