// syscall.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 syscall_nr;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __type(value, struct syscall_event);
} sysq SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event e = {};
    e.timestamp   = bpf_ktime_get_ns();
    e.pid         = bpf_get_current_pid_tgid() >> 32;
    e.syscall_nr  = ctx->id;
    __builtin_memcpy(e.args, ctx->args, sizeof(e.args));

    // Push to queue; if full, drop
    bpf_map_push_elem(&sysq, &e, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL v2";

