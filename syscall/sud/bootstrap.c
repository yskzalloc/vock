#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "lazypoline.h"

#include <stdlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>

__attribute__((constructor(0)))
static void load_runtime(void) {
    char *library_path = getenv("LIBLAZYPOLINE");
    if (!library_path) {
        fprintf(stderr, "'LIBLAZYPOLINE' not specified: Please set the 'LIBLAZYPOLINE' env var to the path of the lazypoline runtime library\n");
        exit(-1);
    }

    dlerror();
    void *handle = dlmopen(LM_ID_NEWLM, library_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "Failed to open %s\n", dlerror());
        exit(-1);
    }

    dlerror();
    void (*init_lazypoline_fn)(void) = (void (*)(void)) dlsym(handle, "init_lazypoline");
    char *error = dlerror();
    if (error) {
        fprintf(stderr, "dlsym: %s\n", error);
        exit(-1);
    }

    init_lazypoline_fn();
}
