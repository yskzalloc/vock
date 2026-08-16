//! vock — map any userspace program to the exact kernel code it exercises.
//!
//! CLI orchestrator (port of vock.c `main`). Dispatches to coverage modes
//! (KCOV / hardware trace), syscall backends (ptrace / SUD / eBPF), the
//! syzlang emitter, the fuzzer, and the prog2c / execprog / selftest tools.

mod ebpf;
mod exec;
mod execprog;
mod fuzz;
mod mode;
mod prog2c;
#[path = "fuzz/inflate.rs"]
mod inflate;
#[path = "fuzz/prog_decode.rs"]
mod prog_decode;
#[path = "fuzz/prog_exec.rs"]
mod prog_exec;
#[path = "fuzz/prog_mutate.rs"]
mod prog_mutate;
#[path = "fuzz/pseudo_ext.rs"]
mod pseudo_ext;
#[path = "fuzz/pseudo_syscalls.rs"]
mod pseudo_syscalls;
mod report;
mod selftest;
mod sud;
mod syscall;
mod syzlang;
mod util;

#[derive(Clone, Copy, PartialEq)]
enum Coverage {
    Hw,
    Kcov,
}

const HELP: &str = "\
vock — kernel code coverage and syscall tracker

usage: vock [OPTIONS] <cmd> [args...]
       vock execprog [FLAGS] <prog.syz>
       vock prog2c <trace.syz> [-o output.c]
       vock selftest [--on host|vng-kvm|vng-tcg]

With no flags, vock runs in HW mode and outputs kerncov.log.

coverage modes:
  --mode hw       hardware trace utilizing HW trace buffer (default, no CONFIG_KCOV)
                    Intel PT (x86_64), AMD LBR (x86_64), CoreSight (arm64)
                    auto-detected based on available hardware
  --mode kcov     KCOV local + remote coverage (needs CONFIG_KCOV)

syscall tracking:
  --syscall [BACKEND]  track syscalls → trace.log
                       backends: ptrace (default), sud, ebpf
                       sud requires: echo 0 > /proc/sys/vm/mmap_min_addr
  --syzlang            also emit trace.syz (for syz-trace2syz)

subcommands:
  execprog         execute or stress a syzkaller program (see: vock execprog --help)
  prog2c           convert trace.syz to standalone C (see: vock prog2c --help)
  selftest         run automated tests (see: vock selftest --help)

options:
  --kernel-src PATH   kernel source for coverage report
  --vmlinux FILE      vmlinux with debug info (enables full branch coverage)
  --btf               resolve PCs via /proc/kallsyms (no vmlinux needed)
  --ordered           sequential output: kcov per-TID coverage-<TID>.html,
                      hw a single time-ordered coverage.html
  --filter KW         filter coverage report to matching paths
  -d, --output-dir D  write all artifacts into D (created if missing)
  -A N, -B N, -C N    context lines in the processed coverage artifacts\n                      (kerncov.log, asmcov.log, coverage.html; default 3, patch-style)

examples:
  vock /bin/ip addr show              kernel coverage (HW mode, default)
  vock --vmlinux vmlinux /bin/ip addr show   full branch coverage
  vock --mode kcov /bin/ls /tmp       kernel coverage (KCOV)
  vock --mode kcov --ordered /bin/ip addr show  per-TID sequential trace
  vock --syscall /bin/ls /tmp         syscall tracking
  vock --syzlang /bin/ip addr show    trace.log + trace.syz
  vock execprog -stress prog.syz      mutate+execute variants in a loop
  vock prog2c trace.syz -o repro.c    generate C reproducer
";


const EXECPROG_HELP: &str = "\
vock execprog — execute a syzkaller program or syscall trace

usage: vock execprog [flags] <prog.syz>

Like syzkaller's syz-execprog. Three input forms are auto-detected:
  * syzkaller's &(0x7f...) memory-layout form (an unmodified syzbot
    reproducer) — deserialised into the 16 MiB data arena, with resource
    copyin/copyout and the fail_nth / async call properties;
  * vock's inline-hex USB form — driven through the raw-gadget interpreter;
  * a plain syscall trace with immediate integer arguments.

flags:
  -repeat=N     execute N times (0 = infinite, default: 1)
  -procs=N      parallel execution processes (default: 1)
  -cover        collect per-call KCOV; writes kerncov.log plus one
                kerncov_prog1.<call> file per call (PCs already shifted)
  -threaded     run each async call on its own thread
  -collide      overlap adjacent calls to shake out races (implies -threaded)
  -slowdown=N   scale the syscall/program timeout tiers (default: 1)
  -stress       local fuzzer: use the program as a corpus seed and loop
                mutating and executing variants of it, watching for a
                kernel report (syzkaller's syz-execprog -stress).
                Implies -repeat=0; pass -repeat=N to bound it.

examples:
  vock execprog repro.syz
  vock execprog -cover repro.syz
  vock execprog -repeat=0 -procs=8 -collide repro.syz
  vock execprog -stress -procs=8 prog.syz
";

const FUZZ_NOTICE: &str = "\
vock fuzz is not implemented.

Fuzzing that earns its place in vock is still being designed. vock's job is to
map a program to the kernel code it reaches, and mutation is only worth
anything once that mapping feeds back into the choice of what to run next.
Today the execution signal is (syscall, errno), which cannot tell 'reached new
code' from 'failed the same way again'. Wiring the edge signal
(pc ^ hash(prev_pc)) into the execution loop comes first; a mutator without it
is a random syscall generator. See FUZZ.md.

What exists today:
  vock --syzlang <cmd>              capture a program from a real command
  vock execprog <prog.syz>          replay it exactly (an unmodified syzbot
                                    reproducer works here)
  vock execprog -cover <prog.syz>   replay once with per-call coverage
  vock execprog -stress <prog.syz>  loop mutating and executing variants,
                                    watching for a kernel report

`execprog -stress` is the closest thing to a fuzzer vock has today, and mirrors
syzkaller's own split: syz-execprog replays, and -stress is its local fuzzer
for when syz-manager cannot be used.
";

const PROG2C_HELP: &str = "\
vock prog2c — generate C reproducer from syscall trace

usage: vock prog2c <trace.syz> [-o output.c]

Converts a syscall trace (strace format) into a standalone
C program that replays the syscalls via syscall().
Useful for bug reproduction and reporting.

options:
  -o FILE   output file (default: prog.c)

examples:
  vock prog2c trace.syz -o repro.c
  cc -static -o repro repro.c && ./repro
";

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();

    let mut kernel_src: Option<String> = None;
    let mut vmlinux: Option<String> = None;
    let mut filter: Option<String> = None;
    let mut btf = false;
    let mut mode = Coverage::Hw;
    let mut syscall_on = false;
    let mut syzlang_on = false;
    let mut fuzz_on = false;
    let mut syscall_backend = "ptrace".to_string();
    let mut ctx_after: i32 = -1;
    let mut ctx_before: i32 = -1;
    let mut output_dir: Option<String> = None;
    let mut ordered = false;
    let mut cmd_idx: i64 = -1;

    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "selftest" {
            return selftest::main(&args[i + 1..]);
        } else if a == "--help" || a == "-h" {
            eprint!("{HELP}");
            return 0;
        } else if a == "--kernel-src" && i + 1 < args.len() {
            i += 1;
            kernel_src = Some(args[i].clone());
        } else if a == "--vmlinux" && i + 1 < args.len() {
            i += 1;
            vmlinux = Some(args[i].clone());
        } else if a == "--btf" {
            btf = true;
        } else if a == "--ordered" {
            ordered = true;
        } else if a == "--filter" && i + 1 < args.len() {
            i += 1;
            filter = Some(args[i].clone());
        } else if a == "-A" && i + 1 < args.len() {
            i += 1;
            ctx_after = args[i].parse().unwrap_or(0);
        } else if a == "-B" && i + 1 < args.len() {
            i += 1;
            ctx_before = args[i].parse().unwrap_or(0);
        } else if (a == "-d" || a == "--output-dir") && i + 1 < args.len() {
            i += 1;
            output_dir = Some(args[i].clone());
        } else if a == "-C" && i + 1 < args.len() {
            // diff-style: context on both sides; -A / -B override per side.
            i += 1;
            let c: i32 = args[i].parse().unwrap_or(0);
            if ctx_after < 0 {
                ctx_after = c;
            }
            if ctx_before < 0 {
                ctx_before = c;
            }
        } else if a == "--syscall" {
            syscall_on = true;
            if i + 1 < args.len()
                && matches!(args[i + 1].as_str(), "ptrace" | "sud" | "ebpf")
            {
                i += 1;
                syscall_backend = args[i].clone();
            }
        } else if a == "--syzlang" {
            syscall_on = true;
            syzlang_on = true;
        } else if a == "--fuzz" {
            fuzz_on = true;
            syscall_on = true;
            syzlang_on = true;
        } else if a == "fuzz" {
            fuzz_on = true;
            syscall_on = true;
            syzlang_on = true;
            i += 1;
            while i < args.len() {
                let f = args[i].as_str();
                // -repeat/-procs/--mode are consumed for CLI compatibility;
                // their values are unused while `vock fuzz` is unimplemented
                // (it prints FUZZ_NOTICE and exits).
                if f.strip_prefix("-repeat=").is_some() || f.strip_prefix("-procs=").is_some() {
                    // consumed
                } else if f == "--mode" && i + 1 < args.len() {
                    i += 1;
                } else if f == "--help" || f == "-h" {
                    eprint!("{FUZZ_NOTICE}");
                    return 0;
                } else {
                    cmd_idx = i as i64;
                    break;
                }
                i += 1;
            }
            break;
        } else if a == "execprog" {
            let mut trace_file: Option<String> = None;
            let mut ep = execprog::Flags::default();
            i += 1;
            while i < args.len() {
                let f = args[i].as_str();
                if let Some(v) = f.strip_prefix("-repeat=") {
                    ep.repeat = v.parse().unwrap_or(1);
                } else if let Some(v) = f.strip_prefix("-procs=") {
                    ep.procs = v.parse().unwrap_or(1);
                } else if let Some(v) = f.strip_prefix("-slowdown=") {
                    ep.slowdown = v.parse().unwrap_or(1);
                } else if f == "-cover" {
                    ep.cover = true;
                } else if f == "-threaded" {
                    ep.threaded = true;
                } else if f == "-stress" {
                    ep.stress = true;
                    // Stress runs until interrupted unless -repeat says otherwise.
                    ep.repeat = 0;
                } else if f == "-collide" {
                    ep.collide = true;
                    ep.threaded = true;
                } else if f == "--help" || f == "-h" {
                    eprint!("{EXECPROG_HELP}");
                    return 0;
                } else {
                    trace_file = Some(args[i].clone());
                }
                i += 1;
            }
            let Some(tf) = trace_file else {
                eprintln!("error: vock execprog requires a trace file");
                return 1;
            };
            return execprog::run_with(&tf, ep);
        } else if a == "report" {
            // Standalone coverage report (replaces `python3 output.py`).
            let mut o = report::Options::default();
            let mut report_dir: Option<String> = None;
            // Track whether kernel-src / vmlinux were explicitly set so the
            // auto-detect defaults kick in exactly like output.py.
            let mut ks_set = false;
            let mut vm_set = false;
            i += 1;
            while i < args.len() {
                let f = args[i].as_str();
                match f {
                    "--kernel-src" if i + 1 < args.len() => {
                        i += 1;
                        o.kernel_src = Some(args[i].clone());
                        ks_set = true;
                    }
                    "--vmlinux" if i + 1 < args.len() => {
                        i += 1;
                        o.vmlinux = Some(args[i].clone());
                        vm_set = true;
                    }
                    "--log" if i + 1 < args.len() => {
                        i += 1;
                        o.log = args[i].clone();
                    }
                    "--filter" if i + 1 < args.len() => {
                        i += 1;
                        o.filter = Some(args[i].clone());
                    }
                    "-q" | "--quiet" => o.quiet = true,
                    "-A" if i + 1 < args.len() => {
                        i += 1;
                        o.ctx_after = args[i].parse().unwrap_or(4);
                    }
                    "-B" if i + 1 < args.len() => {
                        i += 1;
                        o.ctx_before = args[i].parse().unwrap_or(4);
                    }
                    "-C" if i + 1 < args.len() => {
                        i += 1;
                        let c: i32 = args[i].parse().unwrap_or(3);
                        o.ctx_after = c;
                        o.ctx_before = c;
                    }
                    "-d" | "--output-dir" if i + 1 < args.len() => {
                        i += 1;
                        report_dir = Some(args[i].clone());
                    }
                    "-o" | "--output" if i + 1 < args.len() => {
                        i += 1;
                        o.output = args[i].clone();
                    }
                    "--btf" => o.btf = true,
                    "--ordered" => o.ordered = true,
                    "--help" | "-h" => {
                        eprintln!(
                            "vock report — regenerate a coverage report from a log\n\nusage: vock report [--log kerncov.log] [--vmlinux F] [--kernel-src D]\n                   [--btf] [--ordered] [--filter KW] [-A N] [-B N] [-C N] [-d DIR]\n                   [-o coverage.html] [-q]"
                        );
                        return 0;
                    }
                    _ => {}
                }
                i += 1;
            }
            let _ = (ks_set, vm_set);
            if let Some(d) = &report_dir {
                // Absolutize the inputs, then produce everything inside -d.
                for p in [&mut o.log] {
                    let pb = std::path::PathBuf::from(&*p);
                    if pb.is_relative() {
                        if let Ok(c) = std::env::current_dir() {
                            *p = c.join(pb).to_string_lossy().into_owned();
                        }
                    }
                }
                for p in [&mut o.vmlinux, &mut o.kernel_src] {
                    if let Some(v) = p {
                        let pb = std::path::PathBuf::from(&*v);
                        if pb.is_relative() {
                            if let Ok(c) = std::env::current_dir() {
                                *v = c.join(pb).to_string_lossy().into_owned();
                            }
                        }
                    }
                }
                if let Err(e) = std::fs::create_dir_all(d) {
                    eprintln!("error: cannot create output dir {d}: {e}");
                    return 1;
                }
                if let Err(e) = std::env::set_current_dir(d) {
                    eprintln!("error: cannot enter output dir {d}: {e}");
                    return 1;
                }
            }
            return report::run(&o);
        } else if a == "prog2c" {
            let mut syz_file: Option<String> = None;
            let mut out_file = "prog.c".to_string();
            i += 1;
            while i < args.len() {
                let f = args[i].as_str();
                if f == "-o" && i + 1 < args.len() {
                    i += 1;
                    out_file = args[i].clone();
                } else if f == "--help" || f == "-h" {
                    eprint!("{PROG2C_HELP}");
                    return 0;
                } else {
                    syz_file = Some(args[i].clone());
                }
                i += 1;
            }
            let Some(sf) = syz_file else {
                eprintln!("error: vock prog2c requires a trace file");
                return 1;
            };
            return prog2c::cmd(&sf, &out_file);
        } else if a == "--mode" && i + 1 < args.len() {
            i += 1;
            match args[i].as_str() {
                "kcov" => mode = Coverage::Kcov,
                "hw" => mode = Coverage::Hw,
                other => {
                    eprintln!(
                        "error: unknown mode '{other}'\nvalid modes: hw, kcov\nrun: vock --help"
                    );
                    std::process::exit(1);
                }
            }
        } else {
            cmd_idx = i as i64;
            break;
        }
        i += 1;
    }

    if cmd_idx == -1 {
        eprintln!(
            "usage: vock [--mode hw|kcov] [--syscall] [--syzlang] <cmd> [args...]\n       vock selftest [--help]\n       vock --help"
        );
        std::process::exit(1);
    }
    let cmd_idx = cmd_idx as usize;
    let cmd = &args[cmd_idx..];

    // Fuzz mode manages its own execution and coverage (execprog / KCOV), so
    // it runs before the coverage-mode privilege gate below.
    if fuzz_on {
        eprint!("{FUZZ_NOTICE}");
        return 2;
    }

    // Privilege / option checks.
    if btf && vmlinux.is_some() {
        eprintln!("error: --btf is mutually exclusive with --vmlinux");
        return 1;
    }
    let euid = unsafe { libc::geteuid() };
    match mode {
        Coverage::Kcov => {
            if euid != 0 {
                eprintln!(
                    "error: kcov mode requires root privileges\n  vock --mode kcov {}",
                    cmd[0]
                );
                return 1;
            }
        }
        Coverage::Hw => {
            if euid != 0 {
                let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(2);
                // The kernel only forbids *kernel* profiling at
                // perf_event_paranoid >= 2; at <= 1 a per-process (not
                // CPU-wide) Intel PT / LBR trace of the target is permitted
                // unprivileged. Only bail early when kernel profiling is
                // definitely disallowed; otherwise let perf_event_open be the
                // authority (engine.rs reports the real error on EACCES/EPERM).
                if paranoid > 1 {
                    eprintln!(
                        "error: hw mode requires privileges\n  either: run as root: vock --mode hw {}\n  or:     echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid",
                        cmd[0]
                    );
                    return 1;
                }
            }
        }
    }

    // -d/--output-dir: every artifact vock and its preloaded children write
    // is cwd-relative, so pointing the run at a directory is one chdir. The
    // directory is created if missing; input paths are absolutized first so
    // they keep meaning from the new cwd.
    if let Some(d) = &output_dir {
        let absolutize = |p: &mut Option<String>| {
            if let Some(v) = p {
                let pb = std::path::PathBuf::from(&v);
                if pb.is_relative() {
                    if let Ok(c) = std::env::current_dir() {
                        *v = c.join(pb).to_string_lossy().into_owned();
                    }
                }
            }
        };
        absolutize(&mut vmlinux);
        absolutize(&mut kernel_src);
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("error: cannot create output dir {d}: {e}");
            return 1;
        }
        if let Err(e) = std::env::set_current_dir(d) {
            eprintln!("error: cannot enter output dir {d}: {e}");
            return 1;
        }
        eprintln!("[vock] writing artifacts to {d}/");
    }

    // SUD runs BEFORE coverage (LD_PRELOAD, same process); ptrace/eBPF fork
    // their own target and run AFTER coverage.
    if syscall_on && syscall_backend == "sud" {
        if !sud::available() {
            // The live prctl probe failed: the kernel lacks
            // SYSCALL_USER_DISPATCH (needs >= 5.11 and, per arch, generic
            // entry - arm64 kernels without CONFIG_GENERIC_ENTRY have none).
            eprintln!("error: SUD (SYSCALL_USER_DISPATCH) not supported by this kernel/arch");
            return 1;
        }
        sud::run(cmd, "trace.log");
        if syzlang_on {
            util::copy_file("trace.log", "trace.syz");
            eprintln!("[vock] syzlang output written to trace.syz");
        }
    }

    // Coverage mode.
    let cov_ret = match mode {
        Coverage::Kcov => mode::kcov::run(
            cmd,
            kernel_src.as_deref(),
            vmlinux.as_deref(),
            filter.as_deref(),
            btf,
            ctx_after,
            ctx_before,
            ordered,
        ),
        Coverage::Hw => mode::hw::run(
            cmd,
            vmlinux.as_deref(),
            kernel_src.as_deref(),
            filter.as_deref(),
            btf,
            ctx_after,
            ctx_before,
            ordered,
        ),
    };

    // ptrace / eBPF AFTER coverage.
    if syscall_on && syscall_backend == "ptrace" {
        syscall::ptrace::run(cmd, syzlang_on);
    } else if syscall_on && syscall_backend == "ebpf" {
        if !ebpf::available() {
            eprintln!("error: eBPF requires CONFIG_BPF + BTF");
            return 1;
        }
        let ret = ebpf::run(cmd, "trace.log");
        if ret >= 0 && syzlang_on {
            util::copy_file("trace.log", "trace.syz");
            eprintln!("[vock] syzlang output written to trace.syz");
        }
    }

    cov_ret
}
