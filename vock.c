#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/kcov.h>
#include "mode/hw.h"
#include "syscall/ptrace/ptrace.h"
#include "syscall/sud/sud.h"
#include "syscall/ebpf/ebpf.h"
#include "syzlang/syzlang.h"
#include "fuzz/fuzz.h"
#include "prog2c/prog2c.h"
#include "execprog/execprog.h"
#include "syscall/decode.h"
#define COVER_SZ        (64 << 10)
enum vock_mode {
	MODE_HW,
	MODE_KCOV,
};
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
	unsigned long n, i;
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
		      const char *filter,
		      int btf, int ctx_after, int ctx_before)
{
	char *argv_exec[24];
	int idx = 0;
	pid_t pid;
	int status;
	char a_buf[16], b_buf[16];
	argv_exec[idx++] = (char *)"python3";
	argv_exec[idx++] = (char *)report_path;
	if (btf) {
		argv_exec[idx++] = (char *)"--btf";
	}
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
	if (ctx_after >= 0) {
		snprintf(a_buf, sizeof(a_buf), "%d", ctx_after);
		argv_exec[idx++] = (char *)"-A";
		argv_exec[idx++] = a_buf;
	}
	if (ctx_before >= 0) {
		snprintf(b_buf, sizeof(b_buf), "%d", ctx_before);
		argv_exec[idx++] = (char *)"-B";
		argv_exec[idx++] = b_buf;
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
static int run_kcov_mode(int argc, char *argv[], int cmd_idx,
			 const char *kernel_src, const char *vmlinux,
			 const char *filter, int btf, int ctx_after, int ctx_before)
{
	char exe_path[1024];
	char *exe_dir;
	char preload_path[2048];
	char report_path[2048];
	ssize_t nread;
	int rfd = -1;
	unsigned long *rarea = (unsigned long *)MAP_FAILED;
	pid_t pid;
	int status, ret;
	nread = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (nread == -1) {
		perror("readlink failed");
		return 1;
	}
	exe_path[nread] = '\0';
	exe_dir = dirname(exe_path);
	snprintf(preload_path, sizeof(preload_path), "%s/mode/kcov.so", exe_dir);
	ret = kcov_remote_enable(&rfd, &rarea);
	if (ret) {
		fprintf(stderr, "kcov: remote setup failed\n");
		return 1;
	}
#ifdef DEBUG_INFO_BTF
	/* TODO: load and attach syscall.bpf.o here */
#endif
	pid = fork();
	if (pid == 0) {
		setenv("LD_PRELOAD", preload_path, 1);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("target: execvp failed");
		_exit(127);
	} else if (pid < 0) {
		perror("target: fork failed");
		return 1;
	}
	if (waitpid(pid, &status, 0) < 0) {
		perror("target: waitpid failed");
		return 1;
	}
	write_remote_log(rarea);
	ioctl(rfd, KCOV_DISABLE, 0);
	munmap(rarea, COVER_SZ * sizeof(unsigned long));
	close(rfd);
	fprintf(stderr, "[vock] generating report\n");
	snprintf(report_path, sizeof(report_path), "%s/output.py", exe_dir);
	ret = run_report(report_path, kernel_src, vmlinux, filter, btf, ctx_after, ctx_before);
	if (ret)
		fprintf(stderr, "report: exit code %d\n", ret);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
static int run_hw_mode(int argc, char *argv[], int cmd_idx, const char *vmlinux,
		       const char *kernel_src, const char *filter,
		       int btf, int ctx_after, int ctx_before)
{
	struct vock_hw_ctx ctx;
	pid_t pid;
	int status;
	int pipefd[2];
	vock_hw_trace_init(&ctx);
	if (pipe(pipefd) < 0) {
		perror("pipe");
		return 1;
	}
	pid = fork();
	if (pid == 0) {
		close(pipefd[1]);
		/* Wait for parent to set up tracing */
		char c;
		read(pipefd[0], &c, 1);
		close(pipefd[0]);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("target: execvp failed");
		_exit(127);
	} else if (pid < 0) {
		perror("target: fork failed");
		return 1;
	}
	close(pipefd[0]);
	if (vock_hw_trace_start(&ctx, pid) < 0) {
		fprintf(stderr, "hw_trace: start failed\n");
		close(pipefd[1]);
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		vock_hw_trace_fini(&ctx);
		return 1;
	}
	/* Signal child to exec */
	write(pipefd[1], "g", 1);
	close(pipefd[1]);
	waitpid(pid, &status, 0);
	vock_hw_trace_stop(&ctx);
	vock_hw_trace_decode(&ctx, vmlinux);
	vock_hw_trace_fini(&ctx);
	/* Generate report from kerncov.log */
	{
		char exe_path[1024], report_path[2048];
		ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
		if (n > 0) {
			exe_path[n] = '\0';
			char *dir = dirname(exe_path);
			snprintf(report_path, sizeof(report_path), "%s/output.py", dir);
			run_report(report_path, kernel_src, vmlinux, filter, btf, ctx_after, ctx_before);
		}
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
static void vock_copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "r");
	if (!in) return;
	FILE *out = fopen(dst, "w");
	if (!out) { fclose(in); return; }
	char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, n, out);
	fclose(in);
	fclose(out);
}
static int run_ptrace_mode(int argc, char *argv[], int cmd_idx, int syzlang)
{
	struct vock_trace_ctx tctx;
	struct vock_syz_ctx sctx;
	struct vock_syz_ctx syz_ctx;
	struct vock_syscall sc;
	pid_t pid;
	int status;
	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("target: execvp failed");
		_exit(127);
	} else if (pid < 0) {
		perror("target: fork failed");
		return 1;
	}
	if (vock_trace_start(&tctx, pid) < 0) {
		fprintf(stderr, "ptrace: start failed\n");
		waitpid(pid, &status, 0);
		return 1;
	}
	if (vock_syz_init(&sctx, "trace.log") < 0) {
		vock_trace_stop(&tctx);
		waitpid(pid, &status, 0);
		return 1;
	}
	sctx.pid = pid;
	int have_syz = 0;
	if (syzlang) {
		if (vock_syz_init(&syz_ctx, "trace.syz") == 0) {
			syz_ctx.pid = pid;
			have_syz = 1;
		}
	}
	while (vock_trace_next_syscall(&tctx, &sc) == 0) {
		vock_syz_emit(&sctx, &sc);
		if (have_syz)
			vock_syz_emit(&syz_ctx, &sc);
	}
	vock_syz_fini(&sctx);
	if (have_syz)
		vock_syz_fini(&syz_ctx);
	waitpid(pid, &status, 0);
	fprintf(stderr, "[vock] ptrace trace written to trace.log\n");
	if (have_syz)
		fprintf(stderr, "[vock] syzlang output written to trace.syz\n");
	return WIFEXITED(status) ? WEXITSTATUS(status) : 0;
}
int main(int argc, char *argv[])
{
	char *kernel_src = NULL;
	char *vmlinux = NULL;
	char *filter = NULL;
	int btf = 0;
	enum vock_mode mode = MODE_HW;
	int syscall_on = 0;
	int syzlang_on = 0;
	int fuzz_on = 0;
	int fuzz_repeat = 0; /* 0 = infinite (Ctrl+C) */
	int fuzz_procs = 1;
	int fuzz_kcov = 0;
	const char *syscall_backend = "ptrace";
	int ctx_after = -1, ctx_before = -1;
	int cmd_idx = -1;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "selftest")) {
			char exe_path[1024], selftest_path[2048];
			char *dir;
			ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
			if (n == -1) { perror("readlink"); return 1; }
			exe_path[n] = '\0';
			dir = dirname(exe_path);
			snprintf(selftest_path, sizeof(selftest_path), "%s/selftest/run.py", dir);
			char *new_argv[64];
			int ai = 0;
			new_argv[ai++] = "python3";
			new_argv[ai++] = selftest_path;
			for (int j = i + 1; j < argc && ai < 62; j++)
				new_argv[ai++] = argv[j];
			new_argv[ai] = NULL;
			execv("/usr/bin/python3", new_argv);
			execvp("python3", new_argv);
			perror("selftest: exec failed");
			return 1;
		} else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			fprintf(stderr,
"vock — kernel code coverage, syscall tracer, and coverage-guided fuzzer\n"
"\n"
"usage: vock [OPTIONS] <cmd> [args...]\n"
"       vock fuzz [FLAGS] <cmd> [args...]\n"
"       vock prog2c <trace.syz> [-o output.c]\n"
"       vock selftest [--on host|vng-kvm|vng-tcg]\n"
"\n"
"coverage modes:\n"
"  --mode hw       Intel PT hardware trace (default, any kernel)\n"
"  --mode kcov     KCOV local + remote coverage (needs CONFIG_KCOV)\n"
"\n"
"syscall tracing:\n"
"  --syscall [BACKEND]  trace syscalls → trace.log\n"
"                       backends: ptrace (default), sud, ebpf\n"
"  --syzlang            also emit trace.syz (for syz-trace2syz)\n"
"\n"
"subcommands:\n"
"  fuzz             coverage-guided syscall fuzzer (see: vock fuzz --help)\n"
"  execprog         execute a syscall trace (see: vock execprog --help)\n"
"  prog2c           convert trace.syz to standalone C (see: vock prog2c --help)\n"
"  selftest         run automated tests (see: vock selftest --help)\n"
"\n"
"options:\n"
"  --kernel-src PATH   kernel source for coverage report\n"
"  --vmlinux FILE      vmlinux with debug info\n"
"  --btf               resolve PCs via /proc/kallsyms (no vmlinux needed)\n"
"  --filter KW         filter coverage report to matching paths\n"
"  -A N, -B N          context lines in coverage report\n"
"\n"
"examples:\n"
"  vock /bin/ip addr show              kernel coverage (Intel PT)\n"
"  vock --mode kcov /bin/ls /tmp       kernel coverage (KCOV)\n"
"  vock --syscall /bin/ls /tmp              syscall trace\n"
"  vock --syzlang /bin/ip addr show         trace.log + trace.syz\n"
"  vock fuzz -procs=8 /bin/ip route    fuzz with 8 workers\n"
"  vock prog2c trace.syz -o repro.c         generate C reproducer\n"
			);
			return 0;
		} else if (!strcmp(argv[i], "--kernel-src") && i + 1 < argc) {
			kernel_src = argv[++i];
		} else if (!strcmp(argv[i], "--vmlinux") && i + 1 < argc) {
			vmlinux = argv[++i];
		} else if (!strcmp(argv[i], "--btf")) {
			btf = 1;
		} else if (!strcmp(argv[i], "--filter") && i + 1 < argc) {
			filter = argv[++i];
		} else if (!strcmp(argv[i], "-A") && i + 1 < argc) {
			ctx_after = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "-B") && i + 1 < argc) {
			ctx_before = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--syscall")) {
			syscall_on = 1;
			if (i + 1 < argc &&
			    (!strcmp(argv[i + 1], "ptrace") ||
			     !strcmp(argv[i + 1], "sud") ||
			     !strcmp(argv[i + 1], "ebpf"))) {
				syscall_backend = argv[++i];
			}
		} else if (!strcmp(argv[i], "--syzlang")) {
			syscall_on = 1;
			syzlang_on = 1;
		} else if (!strcmp(argv[i], "--fuzz")) {
			/* deprecated, use 'vock fuzz' instead */
			fuzz_on = 1;
			syscall_on = 1;
			syzlang_on = 1;
		} else if (!strcmp(argv[i], "fuzz")) {
			fuzz_on = 1;
			syscall_on = 1;
			syzlang_on = 1;
			/* parse fuzz flags: -repeat=N -procs=N */
			for (i++; i < argc; i++) {
				if (!strncmp(argv[i], "-repeat=", 8))
					fuzz_repeat = atoi(argv[i] + 8);
				else if (!strncmp(argv[i], "-procs=", 7))
					fuzz_procs = atoi(argv[i] + 7);
				else if (!strcmp(argv[i], "--mode") && i+1 < argc) {
					i++;
					if (!strcmp(argv[i], "kcov")) fuzz_kcov = 1;
				}
				else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
					fprintf(stderr,
					"vock fuzz — coverage-guided syscall fuzzer\n\n"
					"usage: vock fuzz [flags] <cmd> [args...]\n\n"
					"Traces target, mutates syscalls, re-executes directly via\n"
					"fork+syscall() while collecting Intel PT coverage.\n\n"
					"flags:\n"
					"  -repeat=N   iterations per worker (0 = infinite, default)\n"
					"  -procs=N    parallel workers (default: 1)\n\n"
					"output:\n"
					"  trace.syz     baseline syscall trace\n"
					"  fuzz_N.log    per-worker rankings\n"
					"  trace_N.log   per-worker corpus\n\n"
					"examples:\n"
					"  vock fuzz /bin/ip addr show\n"
					"  vock fuzz -procs=8 /bin/ip route\n"
					"  vock fuzz -repeat=100 /bin/ls /tmp\n");
					return 0;
				} else {
					/* first non-flag is the command */
					cmd_idx = i;
					break;
				}
			}
			break;
		} else if (!strcmp(argv[i], "execprog")) {
			/* vock execprog [-repeat=N] [-procs=N] <trace.syz> */
			const char *trace_file = NULL;
			int ep_repeat = 1, ep_procs = 1;
			for (i++; i < argc; i++) {
				if (!strncmp(argv[i], "-repeat=", 8))
					ep_repeat = atoi(argv[i] + 8);
				else if (!strncmp(argv[i], "-procs=", 7))
					ep_procs = atoi(argv[i] + 7);
				else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
					fprintf(stderr,
						"vock execprog — execute a syscall trace\n\n"
						"usage: vock execprog [flags] <trace.syz>\n\n"
						"Parses a syscall trace and replays it via fork+syscall().\n"
						"Like syzkaller's syz-execprog.\n\n"
						"flags:\n"
						"  -repeat=N   execute N times (0 = infinite, default: 1)\n"
						"  -procs=N    parallel execution processes (default: 1)\n\n"
						"examples:\n"
						"  vock execprog trace.syz\n"
						"  vock execprog -repeat=0 -procs=8 trace.syz\n");
					return 0;
				} else
					trace_file = argv[i];
			}
			if (!trace_file) { fprintf(stderr, "error: vock execprog requires a trace file\n"); return 1; }
			return vock_execprog(trace_file, ep_repeat, ep_procs);
		} else if (!strcmp(argv[i], "prog2c")) {
			/* vock prog2c <trace.syz> [-o output.c] */
			const char *syz_file = NULL;
			const char *out_file = "prog.c";
			for (i++; i < argc; i++) {
				if (!strcmp(argv[i], "-o") && i+1 < argc)
					out_file = argv[++i];
				else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
					fprintf(stderr,
						"vock prog2c — generate C reproducer from syscall trace\n\n"
						"usage: vock prog2c <trace.syz> [-o output.c]\n\n"
						"Converts a syscall trace (strace format) into a standalone\n"
						"C program that replays the syscalls via syscall().\n"
						"Useful for bug reproduction and reporting.\n\n"
						"options:\n"
						"  -o FILE   output file (default: prog.c)\n\n"
						"examples:\n"
						"  vock prog2c trace.syz -o repro.c\n"
						"  cc -static -o repro repro.c && ./repro\n");
					return 0;
				} else
					syz_file = argv[i];
			}
			if (!syz_file) { fprintf(stderr, "error: vock prog2c requires a trace file\n"); return 1; }
			/* Parse trace.syz and generate C */
			FILE *sf = fopen(syz_file, "r");
			if (!sf) { perror(syz_file); return 1; }
			struct sc_record traces[4096];
			int nt = 0;
			char line[1024];
			while (fgets(line, sizeof(line), sf) && nt < 4096) {
				if (line[0] == '#') continue;
				/* Parse: name(0x..., 0x...) = ret */
				long nr = -1, args[6] = {0}, ret = 0;
				char *paren = strchr(line, '(');
				if (!paren) continue;
				*paren = '\0';
				/* Find syscall number by name */
				for (int n = 0; n < 500; n++) {
					const char *nm = vock_syscall_name(n);
					if (nm && !strcmp(nm, line)) { nr = n; break; }
				}
				if (nr < 0) continue;
				/* Parse args */
				char *p = paren + 1;
				for (int a = 0; a < 6 && *p; a++) {
					args[a] = strtol(p, &p, 0);
					while (*p == ',' || *p == ' ') p++;
				}
				/* Parse return */
				char *eq = strstr(paren+1, ") = ");
				if (eq) ret = strtol(eq + 4, NULL, 0);
				traces[nt].nr = nr;
				memcpy(traces[nt].args, args, sizeof(args));
				traces[nt].ret = ret;
				nt++;
			}
			fclose(sf);
			if (prog2c_generate(traces, nt, out_file) == 0)
				fprintf(stderr, "[prog2c] Generated %s (%d syscalls)\n", out_file, nt);
			else
				fprintf(stderr, "[prog2c] Failed\n");
			return 0;
		} else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
			i++;
			if (!strcmp(argv[i], "kcov"))
				mode = MODE_KCOV;
			else if (!strcmp(argv[i], "hw"))
				mode = MODE_HW;
			else {
				fprintf(stderr, "error: unknown mode '%s'\n"
					"valid modes: hw, kcov\n"
					"run: vock --help\n", argv[i]);
				exit(1);
			}
		} else {
			cmd_idx = i;
			break;
		}
	}
	if (cmd_idx == -1) {
		fprintf(stderr,
			"usage: vock [--mode hw|kcov] [--syscall] [--syzlang] <cmd> [args...]\n"
			"       vock selftest [--help]\n"
			"       vock --help\n");
		exit(1);
	}
	/* Privilege check */
	if (btf && vmlinux) {
		fprintf(stderr, "error: --btf is mutually exclusive with --vmlinux\n");
		return 1;
	}
	if (mode == MODE_KCOV) {
		if (geteuid() != 0) {
			fprintf(stderr,
				"error: kcov mode requires root privileges\n"
				"  vock --mode kcov %s\n", argv[cmd_idx]);
			return 1;
		}
	} else if (mode == MODE_HW) {
		if (geteuid() != 0) {
			/* Check perf_event_paranoid */
			FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
			int paranoid = 2;
			if (f) { fscanf(f, "%d", &paranoid); fclose(f); }
			if (paranoid > 0) {
				fprintf(stderr,
					"error: hw mode requires privileges\n"
					"  either: vock --mode hw %s\n"
					"  or:     echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid\n",
					argv[cmd_idx]);
				return 1;
			}
		}
	}
	/* Fuzz mode: run fuzzer and exit */
	if (fuzz_on) {
		struct vock_fuzz_opts fopts = {
			.iterations = fuzz_repeat,
			.procs = fuzz_procs,
			.kcov = fuzz_kcov,
			.target = argv[cmd_idx],
			.target_argv = &argv[cmd_idx],
			.target_argc = argc - cmd_idx,
			.kernel_src = kernel_src,
			.vmlinux = vmlinux,
		};
		return vock_fuzz_run(&fopts);
	}
	/* Run syscall tracing first if requested */
	if (syscall_on) {
		if (!strcmp(syscall_backend, "ptrace")) {
			int ret = run_ptrace_mode(argc, argv, cmd_idx, syzlang_on);
			if (ret)
				return ret;
		} else if (!strcmp(syscall_backend, "sud")) {
			if (!vock_sud_available()) {
				fprintf(stderr, "error: SUD requires kernel >= 5.11\n");
				return 1;
			}
			int ret = vock_sud_run(argc, argv, cmd_idx, "trace.log");
			if (ret)
				return ret;
			if (syzlang_on) {
				vock_copy_file("trace.log", "trace.syz");
				fprintf(stderr, "[vock] syzlang output written to trace.syz\n");
			}
		} else if (!strcmp(syscall_backend, "ebpf")) {
			if (!vock_ebpf_available()) {
				fprintf(stderr, "error: eBPF requires CONFIG_BPF + BTF\n");
				return 1;
			}
			int ret = vock_ebpf_run(argc, argv, cmd_idx, "trace.log");
			if (ret)
				return ret;
			if (syzlang_on) {
				vock_copy_file("trace.log", "trace.syz");
				fprintf(stderr, "[vock] syzlang output written to trace.syz\n");
			}
		}
	}
	(void)syzlang_on;
	switch (mode) {
	case MODE_KCOV:
		return run_kcov_mode(argc, argv, cmd_idx, kernel_src, vmlinux, filter, btf, ctx_after, ctx_before);
	case MODE_HW:
		return run_hw_mode(argc, argv, cmd_idx, vmlinux, kernel_src, filter, btf, ctx_after, ctx_before);
	}
	return 1;
}
