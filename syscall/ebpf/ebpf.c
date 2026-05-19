/*
 * vock eBPF syscall tracer — zero dependencies.
 *
 * Uses raw bpf() syscall to load BPF programs and attach to tracepoints.
 * No libbpf, no skeleton, no vmlinux.h. Just syscalls.
 *
 * Traces raw_syscalls/sys_enter + sys_exit, filters by target PID,
 * emits strace-compatible format.
 */
#define _GNU_SOURCE
#include "ebpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/perf_event.h>

/* BPF instruction macros (not always in system headers) */
#ifndef BPF_MOV64_REG
#define BPF_MOV64_REG(DST, SRC) \
	((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_X, .dst_reg=DST, .src_reg=SRC, .off=0, .imm=0})
#define BPF_MOV64_IMM(DST, IMM) \
	((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=DST, .src_reg=0, .off=0, .imm=IMM})
#define BPF_ALU64_IMM(OP, DST, IMM) \
	((struct bpf_insn){.code=BPF_ALU64|(OP)|BPF_K, .dst_reg=DST, .src_reg=0, .off=0, .imm=IMM})
#define BPF_STX_MEM(SZ, DST, SRC, OFF) \
	((struct bpf_insn){.code=BPF_STX|BPF_MEM|SZ, .dst_reg=DST, .src_reg=SRC, .off=OFF, .imm=0})
#define BPF_ST_MEM(SZ, DST, OFF, IMM) \
	((struct bpf_insn){.code=BPF_ST|BPF_MEM|SZ, .dst_reg=DST, .src_reg=0, .off=OFF, .imm=IMM})
#define BPF_LDX_MEM(SZ, DST, SRC, OFF) \
	((struct bpf_insn){.code=BPF_LDX|BPF_MEM|SZ, .dst_reg=DST, .src_reg=SRC, .off=OFF, .imm=0})
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
	((struct bpf_insn){.code=BPF_JMP|(OP)|BPF_K, .dst_reg=DST, .src_reg=0, .off=OFF, .imm=IMM})
#define BPF_JMP_REG(OP, DST, SRC, OFF) \
	((struct bpf_insn){.code=BPF_JMP|(OP)|BPF_X, .dst_reg=DST, .src_reg=SRC, .off=OFF, .imm=0})
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
	((struct bpf_insn){.code=CODE, .dst_reg=DST, .src_reg=SRC, .off=OFF, .imm=IMM})
#define BPF_EXIT_INSN() \
	((struct bpf_insn){.code=BPF_JMP|BPF_EXIT, .dst_reg=0, .src_reg=0, .off=0, .imm=0})
#define BPF_LD_MAP_FD(DST, FD) \
	((struct bpf_insn){.code=BPF_LD|BPF_DW|BPF_IMM, .dst_reg=DST, .src_reg=BPF_PSEUDO_MAP_FD, .off=0, .imm=FD}), \
	((struct bpf_insn){.code=0, .dst_reg=0, .src_reg=0, .off=0, .imm=0})
#endif

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif


int vock_ebpf_available(void)
{
	return access("/sys/kernel/btf/vmlinux", F_OK) == 0;
}

/* ─── BPF helpers ─────────────────────────────────────────────────────────── */

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_create_map(int type, int key_size, int val_size, int max_entries)
{
	union bpf_attr attr = {};
	attr.map_type = type;
	attr.key_size = key_size;
	attr.value_size = val_size;
	attr.max_entries = max_entries;
	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *val)
{
	union bpf_attr attr = {};
	attr.map_fd = fd;
	attr.key = (unsigned long)key;
	attr.value = (unsigned long)val;
	attr.flags = BPF_ANY;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_prog_load(int type, const struct bpf_insn *insns, int insn_cnt,
			  const char *license)
{
	union bpf_attr attr = {};
	attr.prog_type = type;
	attr.insns = (unsigned long)insns;
	attr.insn_cnt = insn_cnt;
	attr.license = (unsigned long)license;
	char log_buf[4096] = {};
	attr.log_buf = (unsigned long)log_buf;
	attr.log_size = sizeof(log_buf);
	attr.log_level = 1;
	int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0 && errno != 0)
		fprintf(stderr, "ebpf: prog_load: %s\n%s\n", strerror(errno), log_buf);
	return fd;
}

/* ─── Perf ring buffer ────────────────────────────────────────────────────── */

#define RING_PAGES 64
#define RING_SIZE (RING_PAGES * 4096)

struct perf_ring {
	struct perf_event_mmap_page *header;
	void *data;
	int fd;
};


/* ─── Tracepoint attach ───────────────────────────────────────────────────── */

static int tp_id(const char *name)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/raw_syscalls/%s/id", name);
	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/raw_syscalls/%s/id", name);
		f = fopen(path, "r");
	}
	if (!f) return -1;
	int id = 0;
	if (fscanf(f, "%d", &id) != 1) id = -1;
	fclose(f);
	return id;
}

static int attach_tp(int prog_fd, int tp_id_val)
{
	struct perf_event_attr attr = {};
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.disabled = 0;
	attr.config = tp_id_val;
	attr.sample_type = PERF_SAMPLE_RAW;

	/* Attach on all CPUs */
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	int ok = 0;
	for (int cpu = 0; cpu < ncpus; cpu++) {
		int efd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
		if (efd < 0) continue;
		if (ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) { close(efd); continue; }
		ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
		ok++;
		/* Don't close — keep alive for duration */
	}
	return ok > 0 ? 0 : -1;
}

/* ─── BPF programs (hand-crafted bytecode) ────────────────────────────────── */

/*
 * sys_enter program:
 *   r6 = ctx
 *   r1 = pid_tgid >> 32
 *   if r1 != target_pid: return 0
 *   output event {is_exit=0, nr=ctx->id, args[0..5]=ctx->args[0..5]}
 *
 * We use BPF_MAP_TYPE_PERF_EVENT_ARRAY for output (simpler than ringbuf
 * for raw bpf() — ringbuf needs BPF_MAP_TYPE_RINGBUF which requires newer kernel).
 * Instead, use perf_event_output which works on 5.x kernels.
 */

/* Event structure (must match between BPF and userspace) */
struct event {
	int is_exit;
	long nr;
	unsigned long args[6];
	long ret;
};

/* BPF bytecode for sys_enter tracepoint */
static struct bpf_insn prog_enter[] = {
	/* r6 = ctx */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	/* r1 = bpf_get_current_pid_tgid() */
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 14), /* bpf_get_current_pid_tgid */
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32),
	/* r7 = pid */
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/* r1 = &target_pid_map, r2 = &key(0) on stack */
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0), /* key = 0 */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
	BPF_LD_MAP_FD(BPF_REG_1, 1), /* pid_map placeholder */
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 1), /* bpf_map_lookup_elem */
	/* if (!r0) return 0 */
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	/* if (*r0 != pid) return 0 */
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_7, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	/* Build event on stack: is_exit=0, nr=ctx->id, args from ctx->args */
	/* ctx+8 = id (for raw_syscalls/sys_enter: offset 8) */
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 8), /* nr = ctx->id */
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -72), /* event.nr */
	BPF_ST_MEM(BPF_W, BPF_REG_10, -80, 0), /* event.is_exit = 0 */
	/* args at ctx+16 */
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -64),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -56),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 32),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -48),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -40),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -24),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0), /* event.ret = 0 */
	/* bpf_ringbuf_output(map, data, size, flags) */
	BPF_LD_MAP_FD(BPF_REG_1, 2),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -80),
	BPF_MOV64_IMM(BPF_REG_3, 80),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 130),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
};

/* sys_exit: simpler — just emit nr + ret */
static struct bpf_insn prog_exit[] = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 14),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
	BPF_LD_MAP_FD(BPF_REG_1, 1), /* pid_map */
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_7, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	/* event: is_exit=1, nr=ctx->id, ret=ctx->ret */
	BPF_ST_MEM(BPF_W, BPF_REG_10, -80, 1), /* is_exit = 1 */
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -72), /* nr */
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, 16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -16), /* ret */
	/* zero args */
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -64, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -56, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -48, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -40, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -32, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -24, 0),
	/* bpf_ringbuf_output(map, data, size, flags) */
	BPF_LD_MAP_FD(BPF_REG_1, 2),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -80),
	BPF_MOV64_IMM(BPF_REG_3, 80),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 130),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
};

/* Patch map FDs into BPF instructions (LD_MAP_FD uses 2 insns) */
static void patch_map_fd(struct bpf_insn *insns, int cnt, int placeholder, int real_fd)
{
	for (int i = 0; i < cnt - 1; i++) {
		if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
		    insns[i].src_reg == BPF_PSEUDO_MAP_FD &&
		    insns[i].imm == placeholder) {
			insns[i].imm = real_fd;
		}
	}
}

/* ─── Output formatting ───────────────────────────────────────────────────── */

static FILE *g_output;
static long g_pending_nr;
static unsigned long g_pending_args[6];
static int g_has_pending;

static void emit_strace(long nr, unsigned long *args, long ret)
{
	extern const char *vock_syscall_name(int nr);
	const char *name = vock_syscall_name((int)nr);
	fprintf(g_output, "%s(", name ? name : "???");
	for (int i = 0; i < 6; i++) {
		if (i) fprintf(g_output, ", ");
		if (args[i] == 0)
			fprintf(g_output, "0");
		else if ((long)args[i] == -100)
			fprintf(g_output, "AT_FDCWD");
		else
			fprintf(g_output, "0x%lx", args[i]);
	}
	if (ret < 0)
		fprintf(g_output, ") = -1\n");
	else
		fprintf(g_output, ") = %ld\n", ret);
}

/* ─── Main entry ──────────────────────────────────────────────────────────── */

int vock_ebpf_run(int argc, char *argv[], int cmd_idx,
                  const char *output_path)
{
	int pid_map_fd, perf_map_fd, enter_fd, exit_fd;
	int enter_efd, exit_efd;
	pid_t pid;
	int status;

	(void)argc;

	if (!vock_ebpf_available()) {
		fprintf(stderr, "error: eBPF requires CONFIG_BPF + BTF\n");
		return -1;
	}

	/* Create maps */
	pid_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 4, 4, 1);
	if (pid_map_fd < 0) { perror("ebpf: pid map"); return -1; }

	perf_map_fd = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 256 * 1024);
	if (perf_map_fd < 0) { perror("ebpf: perf map"); close(pid_map_fd); return -1; }

	/* Patch map FDs into programs */
	patch_map_fd(prog_enter, sizeof(prog_enter)/sizeof(prog_enter[0]), 1, pid_map_fd);
	patch_map_fd(prog_enter, sizeof(prog_enter)/sizeof(prog_enter[0]), 2, perf_map_fd);
	patch_map_fd(prog_exit, sizeof(prog_exit)/sizeof(prog_exit[0]), 1, pid_map_fd);
	patch_map_fd(prog_exit, sizeof(prog_exit)/sizeof(prog_exit[0]), 2, perf_map_fd);

	/* Load programs */
	enter_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, prog_enter,
				 sizeof(prog_enter)/sizeof(prog_enter[0]), "GPL");
	if (enter_fd < 0) { fprintf(stderr, "ebpf: enter prog load failed\n"); return -1; }

	exit_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, prog_exit,
				sizeof(prog_exit)/sizeof(prog_exit[0]), "GPL");
	if (exit_fd < 0) { fprintf(stderr, "ebpf: exit prog load failed\n"); close(enter_fd); return -1; }

	/* Fork target */
	pid = fork();
	if (pid == 0) {
		raise(SIGSTOP);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		_exit(127);
	} else if (pid < 0) {
		perror("ebpf: fork");
		return -1;
	}
	waitpid(pid, &status, WUNTRACED);

	/* Set target PID in map */
	unsigned int key = 0, val = (unsigned int)pid;
	bpf_map_update(pid_map_fd, &key, &val);

	/* mmap ringbuf: consumer page (RW) + producer+data (RO) */
	#define RINGBUF_SZ (256 * 1024)
	void *cons_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, perf_map_fd, 0);
	if (cons_page == MAP_FAILED) {
		perror("ebpf: ringbuf consumer mmap");
		kill(pid, SIGKILL); waitpid(pid, NULL, 0);
		return -1;
	}
	void *prod_pages = mmap(NULL, 4096 + RINGBUF_SZ, PROT_READ, MAP_SHARED, perf_map_fd, 4096);
	if (prod_pages == MAP_FAILED) {
		perror("ebpf: ringbuf producer mmap");
		kill(pid, SIGKILL); waitpid(pid, NULL, 0);
		return -1;
	}
	unsigned long *cons_pos = (unsigned long *)cons_page;
	unsigned long *prod_pos = (unsigned long *)prod_pages;
	void *ring_data = (char *)prod_pages + 4096;

	/* Attach to tracepoints */
	int enter_id = tp_id("sys_enter");
	int exit_id = tp_id("sys_exit");
	if (enter_id < 0 || exit_id < 0) {
		fprintf(stderr, "ebpf: cannot read tracepoint IDs\n");
		kill(pid, SIGKILL); waitpid(pid, NULL, 0);
		return -1;
	}
	enter_efd = attach_tp(enter_fd, enter_id);
	exit_efd = attach_tp(exit_fd, exit_id);
	if (enter_efd < 0 || exit_efd < 0) {
		fprintf(stderr, "ebpf: attach failed\n");
		kill(pid, SIGKILL); waitpid(pid, NULL, 0);
		return -1;
	}

	/* Resume target */
	kill(pid, SIGCONT);

	/* Open output */
	g_output = fopen(output_path, "w");
	if (!g_output) g_output = stdout;

	/* Poll ringbuf for events until child exits */
	struct pollfd pfd = { .fd = perf_map_fd, .events = POLLIN };
	while (1) {
		int ret = waitpid(pid, &status, WNOHANG);
		if (ret > 0) break;
		poll(&pfd, 1, 10);
		__sync_synchronize();
		unsigned long cons = *cons_pos;
		unsigned long prod = *prod_pos;
		while (cons < prod) {
			void *rec = (char *)ring_data + (cons % RINGBUF_SZ);
			uint32_t hdr = *(uint32_t *)rec;
			uint32_t len = (hdr >> 4) & 0x0FFFFFFF;
			if (hdr & 1) break; /* BPF_RINGBUF_BUSY_BIT */
			if (len >= sizeof(struct event)) {
				struct event *e = (struct event *)((char *)rec + 8);
				if (!e->is_exit) {
					g_pending_nr = e->nr;
					memcpy(g_pending_args, e->args, sizeof(g_pending_args));
					g_has_pending = 1;
				} else if (g_has_pending && g_pending_nr == e->nr) {
					emit_strace(g_pending_nr, g_pending_args, e->ret);
					g_has_pending = 0;
				}
			}
			cons += 8 + ((len + 7) & ~7UL); /* 8-byte header + aligned data */
		}
		__sync_synchronize();
		*cons_pos = cons;
	}

	if (g_output != stdout) fclose(g_output);
	fprintf(stderr, "[vock] ebpf trace written to %s\n", output_path);

	
	close(enter_fd); close(exit_fd);
	close(pid_map_fd); close(perf_map_fd);
	return 0;
}
