//! eBPF syscall backend (faithful port of syscall/ebpf/*).
//!
//! Zero external dependencies: this loads hand-crafted BPF bytecode via the
//! raw `bpf()` syscall (no libbpf, no skeleton, no vmlinux.h), attaches to the
//! `raw_syscalls:sys_enter`/`sys_exit` tracepoints through `perf_event_open`,
//! and drains a `BPF_MAP_TYPE_RINGBUF`. sys_enter records `{nr, args[6]}`,
//! sys_exit records `{nr, ret}`; the two are matched per target-PID and each
//! completed syscall is rendered through the shared `decode_syscall`
//! formatter (via `SyzWriter`) so `trace.log` lines are identical in shape to
//! the ptrace backend and always contain `) = `.
//!
//! If the program cannot be loaded or attached (missing toolchain / kernel
//! support), we print `ebpf backend not built` and return -1 so the selftest
//! records a SKIP instead of a hard failure.

use crate::syscall::Syscall;
use crate::syzlang::SyzWriter;

// ─── bpf() command numbers ──────────────────────────────────────────────────
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;

// map types
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

// prog types
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;

// map update flags
const BPF_ANY: u64 = 0;

// ─── BPF instruction encoding ───────────────────────────────────────────────
// Instruction classes / ops (from linux/bpf_common.h + bpf.h).
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;

const BPF_W: u8 = 0x00; // 4 bytes
const BPF_DW: u8 = 0x18; // 8 bytes
const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_ADD: u8 = 0x00;
const BPF_RSH: u8 = 0x70;
const BPF_MOV: u8 = 0xb0;
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

const BPF_PSEUDO_MAP_FD: u8 = 1;

// BPF helper function ids.
const HELPER_MAP_LOOKUP_ELEM: i32 = 1;
const HELPER_GET_CURRENT_PID_TGID: i32 = 14;
const HELPER_RINGBUF_OUTPUT: i32 = 130;

// registers
const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R6: u8 = 6;
const R7: u8 = 7;
const R10: u8 = 10;

/// Encode a single BPF instruction into its little-endian 64-bit form.
/// Layout: `u8 code; u8 (dst:4|src:4); i16 off; i32 imm`.
#[inline]
fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    let regs = (dst & 0x0f) | (src << 4);
    (code as u64)
        | ((regs as u64) << 8)
        | (((off as u16) as u64) << 16)
        | (((imm as u32) as u64) << 32)
}

/// `BPF_LD_MAP_FD(dst, fd)` — occupies two instruction slots.
fn ld_map_fd(prog: &mut Vec<u64>, dst: u8, fd: i32) {
    prog.push(insn(BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_FD, 0, fd));
    prog.push(0);
}

/// Build the sys_enter program: filter on target pid, then emit
/// `{is_exit=0, nr, args[0..6], ret=0}` via `bpf_ringbuf_output`.
fn build_enter(pid_fd: i32, ring_fd: i32) -> Vec<u64> {
    let mut p = Vec::new();
    // r6 = ctx
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R6, R1, 0, 0));
    // r0 = bpf_get_current_pid_tgid()
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_GET_CURRENT_PID_TGID));
    // r0 >>= 32
    p.push(insn(BPF_ALU64 | BPF_RSH | BPF_K, R0, 0, 0, 32));
    // r7 = pid
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R7, R0, 0, 0));
    // key = 0 on stack (-4); r2 = &key
    p.push(insn(BPF_ST | BPF_MEM | BPF_W, R10, 0, -4, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R2, R10, 0, 0));
    p.push(insn(BPF_ALU64 | BPF_ADD | BPF_K, R2, 0, 0, -4));
    // r1 = &target_pid map
    ld_map_fd(&mut p, R1, pid_fd);
    // r0 = bpf_map_lookup_elem(map, &key)
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_MAP_LOOKUP_ELEM));
    // if (r0 != 0) skip 2; else return 0
    p.push(insn(BPF_JMP | BPF_JNE | BPF_K, R0, 0, 2, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    // r1 = *r0; if (r1 == pid) skip 2; else return 0
    p.push(insn(BPF_LDX | BPF_MEM | BPF_W, R1, R0, 0, 0));
    p.push(insn(BPF_JMP | BPF_JEQ | BPF_X, R1, R7, 2, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    // event.nr = ctx->id (ctx+8); event.is_exit = 0
    p.push(insn(BPF_LDX | BPF_MEM | BPF_DW, R1, R6, 8, 0));
    p.push(insn(BPF_STX | BPF_MEM | BPF_DW, R10, R1, -72, 0));
    p.push(insn(BPF_ST | BPF_MEM | BPF_W, R10, 0, -80, 0));
    // args[0..6] = ctx->args[0..6] (ctx+16 .. ctx+56) -> stack -64 .. -24
    let arg_pairs = [(16i16, -64i16), (24, -56), (32, -48), (40, -40), (48, -32), (56, -24)];
    for (src_off, dst_off) in arg_pairs {
        p.push(insn(BPF_LDX | BPF_MEM | BPF_DW, R1, R6, src_off, 0));
        p.push(insn(BPF_STX | BPF_MEM | BPF_DW, R10, R1, dst_off, 0));
    }
    // event.ret = 0
    p.push(insn(BPF_ST | BPF_MEM | BPF_DW, R10, 0, -16, 0));
    // bpf_ringbuf_output(&events, &event, 80, 0)
    ld_map_fd(&mut p, R1, ring_fd);
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R2, R10, 0, 0));
    p.push(insn(BPF_ALU64 | BPF_ADD | BPF_K, R2, 0, 0, -80));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R3, 0, 0, 80));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R4, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_RINGBUF_OUTPUT));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    p
}

/// Build the sys_exit program: filter on target pid, then emit
/// `{is_exit=1, nr, args=0, ret}`.
fn build_exit(pid_fd: i32, ring_fd: i32) -> Vec<u64> {
    let mut p = Vec::new();
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R6, R1, 0, 0));
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_GET_CURRENT_PID_TGID));
    p.push(insn(BPF_ALU64 | BPF_RSH | BPF_K, R0, 0, 0, 32));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R7, R0, 0, 0));
    p.push(insn(BPF_ST | BPF_MEM | BPF_W, R10, 0, -4, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R2, R10, 0, 0));
    p.push(insn(BPF_ALU64 | BPF_ADD | BPF_K, R2, 0, 0, -4));
    ld_map_fd(&mut p, R1, pid_fd);
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_MAP_LOOKUP_ELEM));
    p.push(insn(BPF_JMP | BPF_JNE | BPF_K, R0, 0, 2, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    p.push(insn(BPF_LDX | BPF_MEM | BPF_W, R1, R0, 0, 0));
    p.push(insn(BPF_JMP | BPF_JEQ | BPF_X, R1, R7, 2, 0));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    // event.is_exit = 1
    p.push(insn(BPF_ST | BPF_MEM | BPF_W, R10, 0, -80, 1));
    // event.nr = ctx->id (ctx+8)
    p.push(insn(BPF_LDX | BPF_MEM | BPF_DW, R1, R6, 8, 0));
    p.push(insn(BPF_STX | BPF_MEM | BPF_DW, R10, R1, -72, 0));
    // event.ret = ctx->ret (ctx+16)
    p.push(insn(BPF_LDX | BPF_MEM | BPF_DW, R1, R6, 16, 0));
    p.push(insn(BPF_STX | BPF_MEM | BPF_DW, R10, R1, -16, 0));
    // zero args[0..6]
    for dst_off in [-64i16, -56, -48, -40, -32, -24] {
        p.push(insn(BPF_ST | BPF_MEM | BPF_DW, R10, 0, dst_off, 0));
    }
    // bpf_ringbuf_output(&events, &event, 80, 0)
    ld_map_fd(&mut p, R1, ring_fd);
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_X, R2, R10, 0, 0));
    p.push(insn(BPF_ALU64 | BPF_ADD | BPF_K, R2, 0, 0, -80));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R3, 0, 0, 80));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R4, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER_RINGBUF_OUTPUT));
    p.push(insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0));
    p.push(insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    p
}

// ─── bpf_attr views (union members overlay at offset 0; each padded to 128) ──
#[repr(C)]
struct AttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    _pad: [u8; 108],
}

#[repr(C)]
struct AttrMapElem {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
    _pad: [u8; 96],
}

#[repr(C)]
struct AttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    _pad: [u8; 80],
}

const ATTR_SIZE: u32 = 128;

#[inline]
unsafe fn sys_bpf(cmd: i32, attr: *mut libc::c_void) -> i64 {
    libc::syscall(libc::SYS_bpf, cmd, attr, ATTR_SIZE) as i64
}

fn bpf_create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> i32 {
    let mut attr: AttrMapCreate = unsafe { std::mem::zeroed() };
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    unsafe { sys_bpf(BPF_MAP_CREATE, &mut attr as *mut _ as *mut libc::c_void) as i32 }
}

fn bpf_map_update(fd: i32, key: &u32, val: &u32) {
    let mut attr: AttrMapElem = unsafe { std::mem::zeroed() };
    attr.map_fd = fd as u32;
    attr.key = key as *const u32 as u64;
    attr.value = val as *const u32 as u64;
    attr.flags = BPF_ANY;
    unsafe {
        sys_bpf(BPF_MAP_UPDATE_ELEM, &mut attr as *mut _ as *mut libc::c_void);
    }
}

fn bpf_prog_load(prog_type: u32, insns: &[u64]) -> i32 {
    let mut log = vec![0u8; 8192];
    let license = b"GPL\0";
    let mut attr: AttrProgLoad = unsafe { std::mem::zeroed() };
    attr.prog_type = prog_type;
    attr.insn_cnt = insns.len() as u32;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license.as_ptr() as u64;
    attr.log_buf = log.as_mut_ptr() as u64;
    attr.log_size = log.len() as u32;
    attr.log_level = 1;
    let fd = unsafe { sys_bpf(BPF_PROG_LOAD, &mut attr as *mut _ as *mut libc::c_void) as i32 };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let end = log.iter().position(|&b| b == 0).unwrap_or(0);
        let msg = String::from_utf8_lossy(&log[..end]);
        eprintln!("ebpf: prog_load: {}\n{}", err, msg);
    }
    fd
}

// ─── perf_event_open tracepoint attach ──────────────────────────────────────
const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
// _IO('$', 0)
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
// _IOW('$', 8, __u32)
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;

#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    _pad: [u8; 96],
}

/// Read a raw_syscalls tracepoint id from tracefs.
fn tp_id(name: &str) -> i32 {
    for base in [
        "/sys/kernel/tracing/events/raw_syscalls",
        "/sys/kernel/debug/tracing/events/raw_syscalls",
    ] {
        let path = format!("{}/{}/id", base, name);
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(id) = s.trim().parse::<i32>() {
                return id;
            }
        }
    }
    -1
}

/// Attach `prog_fd` to tracepoint `tp` on every online CPU. Returns the list
/// of opened perf-event fds (kept alive for the duration of the trace).
fn attach_tp(prog_fd: i32, tp: i32) -> Vec<i32> {
    let mut fds = Vec::new();
    let ncpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let ncpus = if ncpus < 1 { 1 } else { ncpus as i32 };
    for cpu in 0..ncpus {
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = PERF_TYPE_TRACEPOINT;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = tp as u64;
        attr.sample_type = PERF_SAMPLE_RAW;
        let efd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const _ as *const libc::c_void,
                -1i32, // pid: any
                cpu,   // cpu
                -1i32, // group_fd
                0u64,  // flags
            ) as i32
        };
        if efd < 0 {
            continue;
        }
        if unsafe { libc::ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd) } < 0 {
            unsafe { libc::close(efd) };
            continue;
        }
        unsafe { libc::ioctl(efd, PERF_EVENT_IOC_ENABLE, 0) };
        fds.push(efd);
    }
    fds
}

// ─── Event record (overlays the 80-byte ringbuf payload) ────────────────────
#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    is_exit: i32,
    _pad: i32,
    nr: i64,
    args: [u64; 6],
    ret: i64,
}

const EVENT_SIZE: usize = std::mem::size_of::<Event>(); // 72

// ─── ringbuf constants ──────────────────────────────────────────────────────
const RINGBUF_SZ: usize = 256 * 1024;
const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
const BPF_RINGBUF_HDR_SZ: usize = 8;

/// eBPF needs CONFIG_BPF_SYSCALL + BTF; BTF presence is the cheap proxy.
pub fn available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// Print the SKIP sentinel the selftest greps for, and return -1.
fn not_built() -> i32 {
    eprintln!("ebpf backend not built");
    -1
}

/// bpf() failed with EPERM: the backend exists but this user may not call
/// bpf(2). Say exactly why and how to enable it instead of the generic
/// "not built" — kernel.unprivileged_bpf_disabled=1/2 blocks the very first
/// map creation for normal users.
fn eperm_hint() -> i32 {
    let v = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .unwrap_or_default()
        .trim()
        .to_string();
    eprintln!("ebpf backend: bpf() returned EPERM (kernel.unprivileged_bpf_disabled={v})");
    eprintln!("  as a normal user: sudo sysctl kernel.unprivileged_bpf_disabled=0");
    eprintln!("  (value 1 is locked until reboot; tracepoint attach additionally");
    eprintln!("   needs CAP_BPF+CAP_PERFMON, or run vock as root)");
    -1
}

/// Distinguish a permissions failure from real unavailability.
fn bpf_fail() -> i32 {
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        && unsafe { libc::geteuid() } != 0
    {
        eperm_hint()
    } else {
        not_built()
    }
}

/// Trace syscalls via eBPF into `trace_log`. Returns >= 0 on success, -1 on
/// failure (with `ebpf backend not built` emitted for the SKIP path).
pub fn run(cmd: &[String], trace_log: &str) -> i32 {
    if cmd.is_empty() || !available() {
        return not_built();
    }

    // Create maps.
    let pid_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 4, 4, 1);
    if pid_map_fd < 0 {
        return bpf_fail();
    }
    let ring_fd = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, RINGBUF_SZ as u32);
    if ring_fd < 0 {
        unsafe { libc::close(pid_map_fd) };
        return bpf_fail();
    }

    // Build + load programs (with real map fds baked in).
    let enter_prog = build_enter(pid_map_fd, ring_fd);
    let exit_prog = build_exit(pid_map_fd, ring_fd);
    let enter_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, &enter_prog);
    if enter_fd < 0 {
        unsafe {
            libc::close(pid_map_fd);
            libc::close(ring_fd);
        }
        return bpf_fail();
    }
    let exit_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, &exit_prog);
    if exit_fd < 0 {
        unsafe {
            libc::close(enter_fd);
            libc::close(pid_map_fd);
            libc::close(ring_fd);
        }
        return not_built();
    }

    // Fork the target, stopped, so we can install the pid filter + attach
    // before it makes any syscalls.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        crate::exec::execvp(cmd);
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        eprintln!("ebpf: fork failed");
        return not_built();
    }
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };

    // Install target pid in the filter map.
    let key: u32 = 0;
    let val: u32 = pid as u32;
    bpf_map_update(pid_map_fd, &key, &val);

    // mmap the ringbuf: consumer page (RW) then producer page + data (RO).
    let cons_page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            ring_fd,
            0,
        )
    };
    if cons_page == libc::MAP_FAILED {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        return not_built();
    }
    let prod_pages = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096 + RINGBUF_SZ,
            libc::PROT_READ,
            libc::MAP_SHARED,
            ring_fd,
            4096,
        )
    };
    if prod_pages == libc::MAP_FAILED {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        return not_built();
    }
    let cons_pos = cons_page as *const core::sync::atomic::AtomicU64;
    let prod_pos = prod_pages as *const core::sync::atomic::AtomicU64;
    let ring_data = unsafe { (prod_pages as *mut u8).add(4096) };

    // Read tracepoint ids and attach on all CPUs.
    let enter_id = tp_id("sys_enter");
    let exit_id = tp_id("sys_exit");
    if enter_id < 0 || exit_id < 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        // tracefs is mounted 700 root:root on most systems, and file
        // capabilities do not bypass path permissions, so this is the
        // step that still fails after setcap. Name the fix.
        let id_denied = |p: &str| {
            matches!(std::fs::read_to_string(p),
                Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied)
        };
        if unsafe { libc::geteuid() } != 0
            && (id_denied("/sys/kernel/tracing/events/raw_syscalls/sys_enter/id")
                || matches!(
                    std::fs::metadata("/sys/kernel/tracing/events"),
                    Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied
                ))
        {
            eprintln!("ebpf backend: tracefs not readable (tracepoint ids live in /sys/kernel/tracing)");
            eprintln!("  as a normal user: sudo mount -o remount,mode=755,gid=$(id -g) /sys/kernel/tracing");
            eprintln!("  (the id files are 0440 root:root, so mode= alone is not enough —");
            eprintln!("   gid= hands them to your group; or run vock as root)");
            return -1;
        }
        return not_built();
    }
    let enter_efds = attach_tp(enter_fd, enter_id);
    let exit_efds = attach_tp(exit_fd, exit_id);
    if enter_efds.is_empty() || exit_efds.is_empty() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        return not_built();
    }

    // Open the trace log (shared strace/syzlang formatter).
    let mut log = match SyzWriter::create(trace_log, pid) {
        Ok(w) => w,
        Err(_) => {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return not_built();
        }
    };

    // Resume the target.
    unsafe { libc::kill(pid, libc::SIGCONT) };

    let mut pending: Option<(i64, [u64; 6])> = None;

    // Drain the ringbuf until the child exits, then drain once more.
    loop {
        let done = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } > 0;
        if !done {
            let mut pfd = libc::pollfd {
                fd: ring_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut pfd, 1, 10) };
        }
        drain(cons_pos, prod_pos, ring_data, &mut pending, &mut log);
        if done {
            break;
        }
    }
    // Final drain to catch anything produced after the last poll.
    drain(cons_pos, prod_pos, ring_data, &mut pending, &mut log);
    log.flush();

    // Cleanup.
    unsafe {
        libc::munmap(cons_page, 4096);
        libc::munmap(prod_pages, 4096 + RINGBUF_SZ);
        for &fd in enter_efds.iter().chain(exit_efds.iter()) {
            libc::close(fd);
        }
        libc::close(enter_fd);
        libc::close(exit_fd);
        libc::close(pid_map_fd);
        libc::close(ring_fd);
    }

    eprintln!("[vock] ebpf trace written to {}", trace_log);
    0
}

/// Consume all currently-committed ringbuf records, matching sys_enter to the
/// following sys_exit per target pid and emitting completed syscalls.
fn drain(
    cons_pos: *const core::sync::atomic::AtomicU64,
    prod_pos: *const core::sync::atomic::AtomicU64,
    ring_data: *mut u8,
    pending: &mut Option<(i64, [u64; 6])>,
    log: &mut SyzWriter,
) {
    use core::sync::atomic::{AtomicU32, Ordering};

    core::sync::atomic::fence(Ordering::SeqCst);
    let cons_atomic = unsafe { &*cons_pos };
    let prod_atomic = unsafe { &*prod_pos };
    let mut cons = cons_atomic.load(Ordering::Acquire);
    let prod = prod_atomic.load(Ordering::Acquire);

    while cons < prod {
        let off = (cons as usize) & (RINGBUF_SZ - 1);
        let len_ptr = unsafe { ring_data.add(off) } as *const AtomicU32;
        let hdr = unsafe { (*len_ptr).load(Ordering::Acquire) };
        if hdr & BPF_RINGBUF_BUSY_BIT != 0 {
            break; // producer still writing
        }
        let data_len = (hdr << 2) >> 2;
        let rec_len = ((data_len as usize + BPF_RINGBUF_HDR_SZ + 7) / 8) * 8;
        if hdr & BPF_RINGBUF_DISCARD_BIT == 0 && data_len as usize >= EVENT_SIZE {
            let ev_ptr = unsafe { (len_ptr as *const u8).add(BPF_RINGBUF_HDR_SZ) } as *const Event;
            let e = unsafe { std::ptr::read_unaligned(ev_ptr) };
            if e.is_exit == 0 {
                *pending = Some((e.nr, e.args));
            } else if let Some((pnr, pargs)) = *pending {
                if pnr == e.nr {
                    let sc = Syscall {
                        nr: pnr,
                        args: [
                            pargs[0] as i64,
                            pargs[1] as i64,
                            pargs[2] as i64,
                            pargs[3] as i64,
                            pargs[4] as i64,
                            pargs[5] as i64,
                        ],
                        ret: e.ret,
                    };
                    log.emit(&sc);
                    *pending = None;
                }
            }
        }
        cons += rec_len as u64;
    }
    cons_atomic.store(cons, Ordering::Release);
}
