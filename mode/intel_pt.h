#ifndef MODE_INTEL_PT_H
#define MODE_INTEL_PT_H

#include "hw.h"

int intel_pt_available(void);
int intel_pt_start(struct vock_hw_ctx *ctx, pid_t pid);
int intel_pt_decode(struct vock_hw_ctx *ctx, const char *vmlinux);

#endif
