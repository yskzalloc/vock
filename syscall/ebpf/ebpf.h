#ifndef VOCK_EBPF_H
#define VOCK_EBPF_H

/*
 * eBPF-based syscall tracer for vock.
 * Uses raw_syscalls:sys_enter/sys_exit tracepoints.
 * Requires: CONFIG_BPF, CONFIG_DEBUG_INFO_BTF, root.
 * Output: strace-compatible format.
 */

int vock_ebpf_available(void);
int vock_ebpf_run(int argc, char *argv[], int cmd_idx,
                  const char *output_path);

#endif
