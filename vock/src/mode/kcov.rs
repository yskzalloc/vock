//! KCOV coverage mode (port of run_kcov_mode + kcov_remote_enable in vock.c).
//!
//! The parent sets up a *remote* KCOV handle for its own pid, then forks the
//! target with `LD_PRELOAD=mode/kcov.so` (the per-thread shim). After the
//! target exits, per-TID logs have been merged into `kerncov.log` by the shim;
//! the parent writes `remote_coverage.log` and generates the report in-process.

use crate::report;
use libc::c_void;
use std::io::Write;

const COVER_SZ: usize = 64 << 10;
const KCOV_INIT_TRACE: libc::c_ulong = 0x8008_6301;
const KCOV_DISABLE: libc::c_ulong = 0x6365;
const KCOV_REMOTE_ENABLE: libc::c_ulong = 0x4018_6366;
const KCOV_TRACE_PC: u32 = 0;

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
    let arg = KcovRemoteArg {
        trace_mode: KCOV_TRACE_PC,
        area_size: COVER_SZ as u32,
        num_handles: 0,
        common_handle: kcov_handle(0, libc::getpid() as u64),
    };
    if libc::ioctl(fd, KCOV_REMOTE_ENABLE, &arg as *const _) != 0 {
        perror("kcov: remote enable failed");
        return None;
    }
    eprintln!("kcov: remote coverage enabled");
    Some(RemoteKcov {
        fd,
        area: area as *mut libc::c_ulong,
    })
}

unsafe fn write_remote_log(area: *mut libc::c_ulong) {
    let Ok(f) = std::fs::File::create("remote_coverage.log") else {
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
        4
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

    let remote = unsafe {
        match remote_enable() {
            Some(r) => r,
            None => {
                eprintln!("kcov: remote setup failed");
                return 1;
            }
        }
    };

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: preload the shim and exec the target.
        std::env::set_var("LD_PRELOAD", &preload);
        if ordered {
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
        write_remote_log(remote.area);
        libc::ioctl(remote.fd, KCOV_DISABLE, 0);
        libc::munmap(
            remote.area as *mut c_void,
            COVER_SZ * std::mem::size_of::<libc::c_ulong>(),
        );
        libc::close(remote.fd);
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
                };
                report::run(&opts);
                eprintln!("[vock] {name} → {out_name}");
            }
        }
    } else {
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
        };
        report::run(&opts);
    }

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

fn perror(msg: &str) {
    eprintln!("{msg}: {}", std::io::Error::last_os_error());
}
