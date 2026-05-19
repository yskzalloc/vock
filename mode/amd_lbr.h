#ifndef MODE_AMD_LBR_H
#define MODE_AMD_LBR_H

#include "hw.h"

int amd_lbr_available(void);
int amd_lbr_start(struct vock_hw_ctx *ctx, pid_t pid);
int amd_lbr_decode(struct vock_hw_ctx *ctx);

#endif
