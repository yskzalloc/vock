//! Replay a syzkaller program (`syz-execprog`).
//!
//! Three input forms are handled, in order of precedence:
//!
//! 1. **syzkaller's `&(0x7f...)` memory-layout form** — an unmodified syzbot
//!    reproducer. Deserialised by [`crate::prog_decode`] into an argument tree,
//!    laid out into the data arena, and driven by [`crate::prog_exec`] with
//!    per-call coverage, resource copyout and the `fail_nth`/`async` call
//!    properties.
//! 2. **vock's inline-hex USB form** — routed to the raw-gadget interpreter in
//!    [`crate::pseudo_syscalls`].
//! 3. **A plain syscall trace** — immediate integer arguments only; replayed
//!    with fork+syscall.

use crate::prog_decode;
use crate::prog_mutate;
use crate::prog_exec::{self, Opts, Timeouts};

const MAX_CALLS: usize = 4096;

struct Call {
    nr: i64,
    args: [i64; 6],
}

fn parse_trace(path: &str) -> Option<Vec<Call>> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{path}: {e}");
            return None;
        }
    };
    let mut calls = Vec::new();
    for line in data.lines() {
        if calls.len() >= MAX_CALLS {
            break;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some(paren) = line.find('(') else { continue };
        let name = &line[..paren];
        let Some(nr) = crate::syscall::syscall_nr(name) else { continue };

        let mut args = [0i64; 6];
        let mut p = &line[paren + 1..];
        for a in args.iter_mut() {
            let (val, next) = crate::prog2c::parse_leading_long(p);
            *a = val;
            p = next.trim_start_matches([',', ' ']);
            if p.is_empty() {
                break;
            }
        }
        calls.push(Call { nr, args });
    }
    Some(calls)
}

fn exec_once(calls: &[Call]) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
            for c in calls {
                libc::syscall(
                    c.nr, c.args[0], c.args[1], c.args[2], c.args[3], c.args[4], c.args[5],
                );
            }
            libc::_exit(0);
        }
    }
    if pid < 0 {
        return -1;
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

fn worker(calls: &[Call], repeat: i32, id: i32) {
    let mut i = 0;
    while repeat == 0 || i < repeat {
        exec_once(calls);
        if (i + 1) % 100 == 0 {
            eprintln!("[execprog:{id}] executed {} programs", i + 1);
        }
        i += 1;
    }
}

/// Flags accepted by `vock execprog` beyond the legacy `-repeat`/`-procs`.
#[derive(Clone, Copy)]
pub struct Flags {
    pub repeat: i32,
    pub procs: i32,
    pub cover: bool,
    pub threaded: bool,
    pub collide: bool,
    pub slowdown: u32,
    /// Local fuzzer: mutate the program and run variants in a loop
    /// (syzkaller's `syz-execprog -stress`).
    pub stress: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Flags {
            repeat: 1,
            procs: 1,
            cover: false,
            threaded: false,
            collide: false,
            slowdown: 1,
            stress: false,
        }
    }
}

/// Replay an arena-based (real syzkaller) program.
fn run_arena(path: &str, text: &str, f: Flags) -> i32 {
    let mut prog = prog_decode::parse_prog(text);
    if prog.calls.is_empty() {
        eprintln!("[execprog] no runnable statements in {path}");
        return 1;
    }

    // Report anything the program needs that we cannot execute, instead of
    // silently running a program with holes in it.
    let mut unsupported: Vec<&str> = prog
        .calls
        .iter()
        .filter(|c| c.is_pseudo() && !crate::pseudo_ext::SUPPORTED.contains(&c.base.as_str()))
        .map(|c| c.base.as_str())
        .collect();
    unsupported.sort_unstable();
    unsupported.dedup();
    if !unsupported.is_empty() {
        eprintln!(
            "[execprog] warning: unimplemented pseudo-syscalls will return ENOSYS: {}",
            unsupported.join(", ")
        );
    }
    let missing: Vec<&str> = prog
        .calls
        .iter()
        .filter(|c| c.nr.is_none() && !c.is_pseudo())
        .map(|c| c.base.as_str())
        .collect();
    if !missing.is_empty() {
        eprintln!("[execprog] warning: unknown syscalls: {}", missing.join(", "));
    }

    eprintln!(
        "[execprog] {} calls from {path} (syzkaller memory-layout form)",
        prog.calls.len()
    );
    eprintln!(
        "[execprog] repeat={}, procs={}, cover={}, threaded={}, collide={}",
        f.repeat, f.procs, f.cover, f.threaded, f.collide
    );

    let opts = Opts {
        collect_cover: f.cover,
        threaded: f.threaded,
        collide: f.collide,
        timeouts: Timeouts::new(f.slowdown),
        procid: 0,
    };

    let run_worker = |id: u64, prog: &mut prog_decode::Prog| {
        let Some(mut arena) = prog_decode::Arena::map() else {
            eprintln!("[execprog] failed to map the data arena at 0x{:x}", prog_decode::DATA_OFFSET);
            return 1;
        };
        let mut o = opts;
        o.procid = id;
        let mut i = 0i32;
        while f.repeat == 0 || i < f.repeat {
            let run = prog_exec::run_prog(prog, &mut arena, &o);
            let results = &run.calls;
            if f.cover && i == 0 {
                match prog_exec::write_cover(results, &run.extra, "kerncov") {
                    Ok(n) => eprintln!("[execprog] {n} unique PCs → kerncov.log (+ per-call kerncov_prog1.N)"),
                    Err(e) => eprintln!("[execprog] failed to write coverage: {e}"),
                }
            }
            if i == 0 && id == 0 {
                for r in results {
                    let status = if r.unfinished {
                        "unfinished".to_string()
                    } else if r.ret < 0 {
                        format!("errno {}", r.errno)
                    } else {
                        format!("= {}", r.ret)
                    };
                    eprintln!("[execprog]   #{} {} {}", r.index, r.name, status);
                }
            }
            i += 1;
        }
        0
    };

    if f.stress {
        return run_stress(path, prog, f, opts);
    }

    if f.procs <= 1 {
        return run_worker(0, &mut prog);
    }
    let mut pids = Vec::new();
    for w in 0..f.procs {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let rc = run_worker(w as u64, &mut prog);
            unsafe { libc::_exit(rc) };
        }
        pids.push(pid);
    }
    for pid in pids {
        if pid > 0 {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    }
    0
}

/// `-stress`: treat the program as a corpus seed, then loop mutating and
/// executing variants of it. This is vock's counterpart to syzkaller's
/// `syz-execprog -stress` (`createStressProg`, tools/syz-execprog/execprog.go).
///
/// syzkaller alternates between generating a fresh random program from the
/// syscall descriptions and mutating a corpus one. vock carries no
/// descriptions, so it cannot synthesise a well-typed program from nothing;
/// only the mutation half applies, with the input program as the corpus.
fn run_stress(path: &str, prog: prog_decode::Prog, f: Flags, opts: Opts) -> i32 {
    eprintln!("[execprog] stress: mutating {} calls from {path}", prog.calls.len());
    eprintln!(
        "[execprog] stress: procs={}, repeat={} (0 = until interrupted)",
        f.procs, f.repeat
    );
    eprintln!("[execprog] stress: watch dmesg for a kernel report");

    let worker = |id: u64| -> i32 {
        let Some(mut arena) = prog_decode::Arena::map() else {
            eprintln!("[execprog] failed to map the data arena");
            return 1;
        };
        // Distinct stream per worker; the pid keeps runs from repeating.
        let seed = (unsafe { libc::getpid() } as u64)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(id.wrapping_mul(0x85EB_CA6B) + 1);
        let mut rng = prog_mutate::Rng::new(seed);
        let mut o = opts;
        o.procid = id;
        let mut executed: u64 = 0;
        loop {
            let mut p = prog.clone();
            prog_mutate::mutate(&mut p, &mut rng);
            prog_exec::run_prog(&mut p, &mut arena, &o);
            executed += 1;
            if executed % 100 == 0 {
                eprintln!("[execprog:{id}] executed {executed} programs");
            }
            if f.repeat != 0 && executed >= f.repeat as u64 {
                return 0;
            }
        }
    };

    if f.procs <= 1 {
        return worker(0);
    }
    let mut pids = Vec::new();
    for w in 0..f.procs {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let rc = worker(w as u64);
            unsafe { libc::_exit(rc) };
        }
        pids.push(pid);
    }
    for pid in pids {
        if pid > 0 {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    }
    0
}

pub fn run_with(trace_file: &str, f: Flags) -> i32 {
    let text = std::fs::read_to_string(trace_file).unwrap_or_default();

    // A real syzkaller reproducer uses the arena form; it needs the full
    // deserialiser rather than the immediate-argument replay below.
    if prog_decode::needs_arena(&text) {
        return run_arena(trace_file, &text, f);
    }

    // vock's own inline-hex USB form goes to the raw-gadget interpreter.
    if crate::pseudo_syscalls::program_has_pseudo(trace_file) {
        return crate::pseudo_syscalls::run_file(trace_file, f.repeat, f.procs);
    }

    let calls = match parse_trace(trace_file) {
        Some(c) if !c.is_empty() => c,
        _ => {
            eprintln!("[execprog] Failed to parse {trace_file}");
            return 1;
        }
    };
    eprintln!("[execprog] Loaded {} syscalls from {trace_file}", calls.len());
    eprintln!("[execprog] repeat={}, procs={}", f.repeat, f.procs);

    if f.procs <= 1 {
        worker(&calls, f.repeat, 0);
    } else {
        let mut pids = Vec::new();
        for i in 0..f.procs {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                worker(&calls, f.repeat, i);
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
    0
}
