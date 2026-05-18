/* syscall/ebpf/trace.bpf.c — BPF program for syscall tracing */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ARGS 6

struct event {
	int is_exit;
	long nr;
	unsigned long args[MAX_ARGS];
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} target_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 key = 0;
	u32 *tgt = bpf_map_lookup_elem(&target_pid, &key);
	if (!tgt || *tgt != pid)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->is_exit = 0;
	e->nr = ctx->id;
	e->ret = 0;
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++)
		e->args[i] = BPF_CORE_READ(ctx, args[i]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 key = 0;
	u32 *tgt = bpf_map_lookup_elem(&target_pid, &key);
	if (!tgt || *tgt != pid)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->is_exit = 1;
	e->nr = ctx->id;
	e->ret = ctx->ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
