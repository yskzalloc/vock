//! `vock fuzz`, syz-execprog-style program executor.
//!
//! Current behaviour (execprog only): trace the target program to capture its
//! syscall sequence, then **execute that program** `repeat` times across
//! `procs` parallel workers while collecting kernel coverage (KCOV via
//! `LD_PRELOAD=mode/kcov.so`). This mirrors syzkaller's `syz-execprog`
//! (see syzkaller/pkg/instance/execprog.go): run a program, optionally
//! repeated / in parallel, and collect coverage; a kernel bug surfaces as a
//! crash/among the console output (as in the syzkaller crash reports).
//!
//! Mutation is intentionally NOT performed yet, see the TODO in `run()`. The
//! ported mutation building blocks (mutate / signal / signal_edge / covset /
//! btf / types) are retained below for when coverage-guided mutation is
//! reintroduced.
#![allow(dead_code)]

#[path = "fuzz/rng.rs"]
mod rng;
#[path = "fuzz/covset.rs"]
mod covset;
#[path = "fuzz/signal.rs"]
mod signal;
#[path = "fuzz/signal_edge.rs"]
mod signal_edge;
#[path = "fuzz/state.rs"]
mod state;
#[path = "fuzz/mutate.rs"]
mod mutate;
#[path = "fuzz/btf.rs"]
mod btf;
#[path = "fuzz/btf_mutate.rs"]
mod btf_mutate;
#[path = "fuzz/types.rs"]
mod types;
#[path = "fuzz/prog2c_exec.rs"]
mod prog2c_exec;

use crate::syscall::ptrace::Tracer;
use crate::syscall::{syscall_name, Syscall};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SYSCALLS: usize = 4096;

pub struct Opts {
    /// Executions per worker (`-repeat`). 0 = until Ctrl+C.
    pub iterations: i32,
    /// Parallel workers (`-procs`).
    pub procs: i32,
    /// Collect KCOV coverage (via the LD_PRELOAD shim) vs. a plain replay.
    pub kcov: bool,
    pub target: String,
    pub target_argv: Vec<String>,
    pub kernel_src: Option<String>,
    pub vmlinux: Option<String>,
}

static FUZZ_RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn fuzz_sigint(_sig: libc::c_int) {
    FUZZ_RUNNING.store(false, Ordering::SeqCst);
}

fn running() -> bool {
    FUZZ_RUNNING.load(Ordering::SeqCst)
}

fn fmt_call(f: &mut String, sc: &Syscall) {
    match syscall_name(sc.nr) {
        Some(name) => f.push_str(&format!("{name}(")),
        None => f.push_str(&format!("syscall_{}(", sc.nr)),
    }
    for a in 0..6 {
        if a != 0 {
            f.push_str(", ");
        }
        f.push_str(&format!("0x{:x}", sc.args[a] as u64));
    }
    f.push_str(&format!(") = {}\n", sc.ret));
}

fn write_trace(path: &str, trace: &[Syscall]) {
    let mut s = String::new();
    for sc in trace {
        fmt_call(&mut s, sc);
    }
    let _ = std::fs::write(path, s);
}

/// Trace the target under ptrace and capture its syscall sequence, the
/// program that `syz-execprog` will then replay.
fn trace_baseline(opts: &Opts) -> Option<Vec<Syscall>> {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }
        crate::exec::execvp(&opts.target_argv);
        unsafe { libc::_exit(127) };
    }
    if pid < 0 {
        return None;
    }

    let mut tracer = match Tracer::start(pid) {
        Some(t) => t,
        None => {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            return None;
        }
    };

    let mut trace: Vec<Syscall> = Vec::new();
    while let Some(sc) = tracer.next_syscall() {
        if trace.len() >= MAX_SYSCALLS {
            break;
        }
        trace.push(sc);
    }

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    Some(trace)
}

/// One execprog worker: replay the program `repeat` times (0 = until Ctrl+C).
/// With `kcov`, each replay runs under `LD_PRELOAD=mode/kcov.so`, which writes
/// `kerncov.log`.
fn execprog_worker(prog: &[Syscall], worker_id: i32, repeat: i32, kcov: bool) {
    let mut i = 0i32;
    while running() && (repeat == 0 || i < repeat) {
        if kcov {
            prog2c_exec::exec_kcov(prog);
        } else {
            prog2c_exec::exec_direct(prog);
        }
        if (i + 1) % 100 == 0 {
            eprintln!("[fuzz:{worker_id}] executed {} programs", i + 1);
        }
        i += 1;
    }
}

/// Run `vock fuzz`: trace → syz-execprog-style execution of the program.
pub fn run(opts: &Opts) -> i32 {
    unsafe {
        libc::signal(libc::SIGINT, fuzz_sigint as *const () as usize);
    }

    // Phase 1: obtain the program by tracing the target.
    eprintln!("[fuzz] tracing baseline program...");
    let _ = std::fs::remove_file("kerncov.log"); // drop stale coverage
    let prog = match trace_baseline(opts) {
        Some(p) if !p.is_empty() => p,
        _ => {
            eprintln!("[fuzz] baseline trace failed");
            return 1;
        }
    };
    write_trace("trace.syz", &prog);
    eprintln!("[fuzz] program: {} syscalls → trace.syz", prog.len());

    // Phase 2: execute like syz-execprog, `procs` workers, each replaying the
    // program `repeat` times, collecting KCOV coverage into kerncov.log.
    let repeat = opts.iterations;
    let procs = if opts.procs > 0 { opts.procs } else { 1 };
    eprintln!(
        "[fuzz] execprog: repeat={repeat} procs={procs} coverage={}",
        if opts.kcov { "kcov" } else { "none" }
    );

    if procs == 1 {
        execprog_worker(&prog, 0, repeat, opts.kcov);
    } else {
        let mut pids = Vec::new();
        for w in 0..procs {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                execprog_worker(&prog, w, repeat, opts.kcov);
                unsafe { libc::_exit(0) };
            }
            pids.push(pid);
        }
        for pid in pids {
            if pid > 0 {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
            }
        }
    }

    if opts.kcov {
        let pcs = std::fs::read_to_string("kerncov.log")
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        eprintln!("[fuzz] coverage: {pcs} kernel PCs → kerncov.log");
    }

    // TODO(mutation): reintroduce coverage-guided mutation. The seed program is
    // in `prog` / trace.syz; the ported building blocks (mutate::mutate_sequence,
    // signal / signal_edge, covset scoring, corpus minimization, BTF-aware arg
    // mutation) live in the fuzz/ submodules. The loop would: mutate the seed,
    // execprog the variant, diff coverage/signal against the baseline, and keep
    // novel inputs in a corpus.
    eprintln!("[fuzz] done (execprog only; mutation: TODO).");
    0
}
