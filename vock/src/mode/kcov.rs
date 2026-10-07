//! KCOV coverage mode (port of run_kcov_mode + kcov_remote_enable in vock.c).
//!
//! The parent sets up a *remote* KCOV handle for its own pid, then forks the
//! target with `LD_PRELOAD=mode/kcov.so` (the per-thread shim). After the
//! target exits, per-TID logs have been merged into `kerncov.log` by the shim;
//! the parent writes `remote_coverage.log` and generates the report in-process.

use crate::report;
use libc::c_void;
use std::io::Write;

const COVER_SZ: usize = 2 << 20; // match the shim buffer (16 MiB map)
const KCOV_INIT_TRACE: libc::c_ulong = 0x8008_6301;
const KCOV_DISABLE: libc::c_ulong = 0x6365;
const KCOV_REMOTE_ENABLE: libc::c_ulong = 0x4018_6366;
const KCOV_TRACE_PC: u32 = 0;

/// Coverage the parent collects through its own KCOV_REMOTE_ENABLE common
/// handle (in-kernel background threads: softirqs, workqueues, and network
/// server kthreads like ksmbd's). It is a sibling of the shim's per-TID logs.
const REMOTE_LOG: &str = "remote_coverage.log";

#[repr(C)]
struct KcovRemoteArg {
    trace_mode: u32,
    area_size: u32,
    num_handles: u32,
    common_handle: u64,
}

fn kcov_handle(subsys: u64, inst: u64) -> u64 {
    subsys | (inst & 0xffff_ffff)
}

/// Let the caller pin the KCOV remote *common handle* instead of the default
/// per-pid value.
///
/// The default (`kcov_handle(0, getpid())`) works when the kernel code whose
/// coverage we want runs in a task that inherited the collector's kcov handle
/// across fork (the syzkaller model). It does *not* work for an in-kernel
/// network server: the threads servicing a connection have no process
/// relationship to the collector, so the server instead routes their coverage
/// to a fixed, well-known common handle that both sides agree on out of band.
///
/// ksmbd's TCP transport is exactly this case. It derives the handle from the
/// local IPv4 address the client connected to:
///
///     KSMBD_KCOV_IP_HANDLE = 0x4b440000 | (ntohl(local_addr) & 0xffff)
///
/// (see fs/smb/server/connection.h and transport_tcp.c). A client dialing
/// 127.0.0.1 makes every ksmbd receive-loop / command-kworker thread call
/// kcov_remote_start_common(0x4b440001). To collect that server-side coverage
/// the fuzzer must KCOV_REMOTE_ENABLE the *same* handle, which this override
/// supplies. Accepts hex ("0x4b440001") or decimal.
fn common_handle_override() -> Option<u64> {
    let raw = std::env::var("VOCK_KCOV_COMMON_HANDLE").ok()?;
    let v = raw.trim();
    let parsed = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => v.parse::<u64>(),
    };
    match parsed {
        Ok(h) if h != 0 => Some(h),
        _ => {
            eprintln!("kcov: ignoring invalid VOCK_KCOV_COMMON_HANDLE={v:?} (want nonzero hex/decimal)");
            None
        }
    }
}

struct RemoteKcov {
    fd: libc::c_int,
    area: *mut libc::c_ulong,
}

unsafe fn remote_enable() -> Option<RemoteKcov> {
    let fd = libc::open(
        b"/sys/kernel/debug/kcov\0".as_ptr() as *const libc::c_char,
        libc::O_RDWR,
    );
    if fd == -1 {
        perror("kcov: remote open failed");
        return None;
    }
    if libc::ioctl(fd, KCOV_INIT_TRACE, COVER_SZ as libc::c_ulong) != 0 {
        perror("kcov: remote init failed");
        return None;
    }
    let area = libc::mmap(
        std::ptr::null_mut(),
        COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if area == libc::MAP_FAILED {
        perror("kcov: remote mmap failed");
        return None;
    }
    let common_handle =
        common_handle_override().unwrap_or_else(|| kcov_handle(0, libc::getpid() as u64));
    let arg = KcovRemoteArg {
        trace_mode: KCOV_TRACE_PC,
        area_size: COVER_SZ as u32,
        num_handles: 0,
        common_handle,
    };
    if libc::ioctl(fd, KCOV_REMOTE_ENABLE, &arg as *const _) != 0 {
        perror("kcov: remote enable failed");
        return None;
    }
    eprintln!("kcov: remote coverage enabled (common_handle=0x{common_handle:x})");
    Some(RemoteKcov {
        fd,
        area: area as *mut libc::c_ulong,
    })
}

unsafe fn write_remote_log(area: *mut libc::c_ulong) {
    let Ok(f) = std::fs::File::create(REMOTE_LOG) else {
        perror("kcov: fopen remote_coverage.log failed");
        return;
    };
    let mut w = std::io::BufWriter::new(f);
    let n = std::ptr::read_volatile(area) as usize;
    for i in 0..n {
        let pc = std::ptr::read_volatile(area.add(i + 1));
        // Same convention as every other vock coverage producer.
        let _ = writeln!(
            w,
            "0x{:x}",
            crate::prog_exec::previous_instruction_pc(pc as u64)
        );
    }
    let _ = w.flush();
}

/// ctx value from the CLI: -1 means "not set" → the report default of 4.
fn ctx(v: i32) -> i32 {
    if v >= 0 {
        v
    } else {
        3 // kernel-patch-style default context
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    cmd: &[String],
    kernel_src: Option<&str>,
    vmlinux: Option<&str>,
    filter: Option<&str>,
    btf: bool,
    ctx_after: i32,
    ctx_before: i32,
    ordered: bool,
) -> i32 {
    let preload = crate::util::kcov_preload_path();
    if !preload.exists() {
        eprintln!("kcov: preload shim not found at {}", preload.display());
        eprintln!("  build it with `make`, or set VOCK_KCOV_SO to its location");
        return 1;
    }

    // Open the vmlinux DWARF on a background thread now, so symbolization
    // has it ready the moment the target exits. In a VM guest the load is
    // mostly reading the vmlinux over the shared filesystem, which overlaps
    // fully with the target's run. VOCK_NO_PREWARM=1 disables it.
    if !btf && std::env::var_os("VOCK_NO_PREWARM").is_none() {
        report::resolve::prewarm(&report::vmlinux_path(kernel_src, vmlinux));
    }

    report::timing::mark("kcov: start");
    let remote = unsafe {
        match remote_enable() {
            Some(r) => r,
            None => {
                eprintln!("kcov: remote setup failed");
                return 1;
            }
        }
    };

    // Drop per-TID logs from any previous run: both the ordered report and
    // the post-exit merge below scan the directory by name pattern, so stale
    // files would be silently folded into this run's coverage.
    if let Ok(rd) = std::fs::read_dir(".") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy().into_owned();
            if (name.starts_with("local-") || name.starts_with("remote-"))
                && name.contains(".log")
            {
                let _ = std::fs::remove_file(ent.path());
            }
        }
    }

    report::timing::mark("kcov: fork target");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: preload the shim and exec the target.
        std::env::set_var("LD_PRELOAD", &preload);
        // The parent reads the per-TID logs itself (ordered: one report
        // per log; source report: streamed straight from them), so the
        // shim's own merge into kerncov.log would only be a wasted copy.
        // --btf still wants the merged raw log as its artifact.
        if ordered || !btf {
            std::env::set_var("VOCK_NO_MERGE", "1");
        }
        crate::exec::execvp(cmd);
        eprintln!("target: execvp failed");
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        perror("target: fork failed");
        return 1;
    }

    let mut status = 0;
    unsafe {
        if libc::waitpid(pid, &mut status, 0) < 0 {
            perror("target: waitpid failed");
            return 1;
        }
        report::timing::mark("kcov: target exited");
        write_remote_log(remote.area);
        report::timing::mark("kcov: remote log written");
        libc::ioctl(remote.fd, KCOV_DISABLE, 0);
        libc::munmap(
            remote.area as *mut c_void,
            COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        );
        libc::close(remote.fd);
    }

    // The shim is the only thing that collects the target's coverage, and it
    // is loaded by LD_PRELOAD, so it is silently absent for a statically
    // linked target, for a setuid/setgid one (the loader drops LD_PRELOAD for
    // secure-execution binaries) and for anything that resets its own
    // environment before exec'ing the real work. Without this the only
    // symptom is an empty report. The parent's own KCOV setup above already
    // succeeded, so kcov itself is available and the shim is the suspect.
    if tid_logs().is_empty() {
        eprintln!(
            "\x1b[93m[vock] warning: the target produced no per-task coverage logs.\n\
             \x1b[93m        The LD_PRELOAD shim never ran. Usual causes: the target is\n\
             \x1b[93m        statically linked, is setuid/setgid, or clears LD_PRELOAD\n\
             \x1b[93m        before exec. Tasks created by a raw clone() syscall are also\n\
             \x1b[93m        never instrumented; see --mode hw for a collector that does\n\
             \x1b[93m        not need the target's cooperation.\x1b[0m"
        );
    }

    if ordered {
        // coverage-<TID>.html for each per-TID local log.
        if let Ok(rd) = std::fs::read_dir(".") {
            for ent in rd.flatten() {
                let name = ent.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("local-") || !name.contains(".log") {
                    continue;
                }
                let tid = &name["local-".len()..name.find(".log").unwrap()];
                let out_name = format!("coverage-{tid}.html");
                let opts = report::Options {
                    kernel_src: kernel_src.map(String::from),
                    vmlinux: vmlinux.map(String::from),
                    log: name.to_string(),
                    filter: filter.map(String::from),
                    quiet: false,
                    ctx_after: ctx(ctx_after),
                    ctx_before: ctx(ctx_before),
                    output: out_name.clone(),
                    btf,
                    ordered: true,
                    parts: Vec::new(),
                };
                report::run(&opts);
                eprintln!("[vock] {name} → {out_name}");
            }
        }
    } else {
        // The shim's initial process merges the per-TID logs from its exit
        // destructor, but a shell target may _exit() without running
        // fini_arrays (dash does), leaving kerncov.log empty or stale. The
        // parent is the one process that reliably outlives every task, so
        // merge here regardless.
        let parts = if btf {
            merge_tid_logs();
            append_parent_remote_log();
            report::timing::mark("kcov: per-TID logs merged");
            Vec::new()
        } else {
            let mut parts: Vec<String> = tid_logs()
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            // The per-TID logs above come from the preload shim and only cover
            // the target's own threads. In-kernel background threads route
            // their coverage to the parent's KCOV_REMOTE_ENABLE common handle
            // instead -- for a network server like ksmbd, the connection
            // kthreads whose handle we pinned via VOCK_KCOV_COMMON_HANDLE. That
            // lands in remote_coverage.log, a sibling of the per-TID logs, not
            // one of them, so it must be added explicitly or the report omits
            // all of that server-side coverage.
            if parent_remote_log_nonempty() {
                parts.push(REMOTE_LOG.to_string());
            }
            parts
        };
        eprintln!("[vock] generating report");
        let opts = report::Options {
            kernel_src: kernel_src.map(String::from),
            vmlinux: vmlinux.map(String::from),
            log: "kerncov.log".to_string(),
            filter: filter.map(String::from),
            quiet: false,
            ctx_after: ctx(ctx_after),
            ctx_before: ctx(ctx_before),
            output: "coverage.html".to_string(),
            btf,
            ordered: false,
            parts,
        };
        report::run(&opts);
    }

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

/// True if the parent's remote coverage log exists with at least one PC.
fn parent_remote_log_nonempty() -> bool {
    std::fs::metadata(REMOTE_LOG)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Append the parent's remote coverage onto `kerncov.log`. Used on the --btf
/// path, where the report consumes the merged file rather than per-part inputs,
/// so without this the server-side (remote) coverage would be dropped there too.
fn append_parent_remote_log() {
    if !parent_remote_log_nonempty() {
        return;
    }
    let Ok(data) = std::fs::read(REMOTE_LOG) else {
        return;
    };
    if let Ok(mut dst) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("kerncov.log")
    {
        let _ = dst.write_all(&data);
        if !data.is_empty() && !data.ends_with(b"\n") {
            let _ = dst.write_all(b"\n");
        }
    }
}

/// Every per-TID `local-*.log` / `remote-*.log` in the working directory.
fn tid_logs() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(".") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with("local-") || name.starts_with("remote-")) && name.contains(".log") {
                v.push(ent.path());
            }
        }
    }
    v
}

/// Concatenate every per-TID log into `kerncov.log` (same merge the shim
/// performs on teardown).
fn merge_tid_logs() {
    let Ok(merged) = std::fs::File::create("kerncov.log") else {
        return;
    };
    let mut w = std::io::BufWriter::new(merged);
    {
        for path in tid_logs() {
            if let Ok(data) = std::fs::read(&path) {
                let _ = w.write_all(&data);
                // A log cut mid-line (a task killed inside its exit writer)
                // must not glue onto the next file's first PC: one malformed
                // token used to poison the BTF resolver's KASLR heuristic.
                if !data.is_empty() && !data.ends_with(b"\n") {
                    let _ = w.write_all(b"\n");
                }
            }
        }
    }
    let _ = w.flush();
}

fn perror(msg: &str) {
    eprintln!("{msg}: {}", std::io::Error::last_os_error());
}
