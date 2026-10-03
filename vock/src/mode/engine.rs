//! Hardware-trace engine backend.
//!
//! Faithful Rust port of the C hardware-trace coverage backend:
//!   - mode/hw.c         (dispatcher: prefer Intel PT, else AMD LBR)
//!   - mode/intel_pt.c   (perf_event_open with Intel PT PMU, AUX ring mmap)
//!   - mode/pt_decode.c  (Intel PT packet decode: PSB/TNT/TIP/FUP → kernel PCs)
//!   - mode/amd_lbr.c    (AMD LBR sampling: branch records → kernel PCs)
//!
//! Public interface (kept stable; mode/hw.rs depends on it):
//!   - `available() -> bool`
//!   - `Session::start(pid) -> Option<Session>`
//!   - `Session::stop(&mut self)`
//!   - `Session::decode(&mut self, vmlinux: Option<&str>)`
//!
//! Only `std` and `libc` are used. `perf_event_attr`, `perf_event_mmap_page`,
//! the PERF_* constants and PERF_EVENT_IOC_* ioctls are not exposed by
//! libc 0.2, so they are defined locally below.

use std::io::Write;
use std::ptr;

// ─── perf constants (not in libc 0.2) ────────────────────────────────────────

// ioctl requests: PERF_EVENT_IOC_ENABLE = _IO('$', 0), DISABLE = _IO('$', 1).
// _IO(type,nr) with dir=NONE(0), size=0 → (type << 8) | nr, '$' == 0x24.
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;

const PERF_SAMPLE_IP: u64 = 1 << 0;
const PERF_SAMPLE_TIME: u64 = 1 << 2;
const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;

const PERF_SAMPLE_BRANCH_KERNEL: u64 = 1 << 1;
const PERF_SAMPLE_BRANCH_ANY: u64 = 1 << 3;

const PERF_RECORD_SAMPLE: u32 = 9;

// perf_event_attr bitfield flags (within the single `flags` u64 word).
const ATTR_DISABLED: u64 = 1 << 0;
const ATTR_EXCLUDE_USER: u64 = 1 << 4;
const ATTR_FREQ: u64 = 1 << 10; // sample_period_or_freq is a frequency (Hz)
// exclude_kernel would be `1 << 5`, kept 0 to trace the kernel.

// Byte offsets into perf_event_mmap_page (stable kernel ABI; the control
// fields live at fixed offset 1024).
const OFF_DATA_HEAD: usize = 1024;
const OFF_DATA_TAIL: usize = 1032;
const OFF_AUX_HEAD: usize = 1056;
const OFF_AUX_OFFSET: usize = 1072;
const OFF_AUX_SIZE: usize = 1080;

const AUX_SIZE: usize = 4 * 1024 * 1024; // intel_pt.c: AUX_SIZE (4 MiB)
const INTEL_MMAP_PAGES: usize = 1; // intel_pt.c: MMAP_PAGES
const AMD_MMAP_PAGES: usize = 128; // amd_lbr.c: MMAP_PAGES (larger ring)

/// perf_event_attr, matches the kernel ABI (PERF_ATTR_SIZE_VER8, 136 bytes).
/// C bitfields (`disabled`, `exclude_user`, …) are collapsed into `flags`.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup: u32, // wakeup_events / wakeup_watermark
    bp_type: u32,
    config1: u64, // bp_addr / kprobe_func / config1
    config2: u64, // bp_len / kprobe_addr / config2
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
    aux_sample_size: u32,
    reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

// ─── raw mmap-page field access ──────────────────────────────────────────────

#[inline]
unsafe fn read_u64(base: *const libc::c_void, off: usize) -> u64 {
    ((base as *const u8).add(off) as *const u64).read_volatile()
}

#[inline]
unsafe fn write_u64(base: *mut libc::c_void, off: usize, val: u64) {
    ((base as *mut u8).add(off) as *mut u64).write_volatile(val);
}

// ─── availability probes (port of *_available) ───────────────────────────────

fn intel_pt_available() -> bool {
    std::path::Path::new("/sys/bus/event_source/devices/intel_pt").exists()
        || std::path::Path::new("/sys/bus/event_source/devices/cs_etm").exists()
}

fn amd_lbr_available() -> bool {
    match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s.contains("AuthenticAMD"),
        Err(_) => false,
    }
}

/// Whether any supported HW-trace PMU is present (port of
// ─── perf_event_open helper ──────────────────────────────────────────────────

unsafe fn perf_event_open(attr: &PerfEventAttr, pid: libc::pid_t) -> i32 {
    // perf_event_open(attr, pid, cpu=-1, group_fd=-1, flags=0)
    libc::syscall(
        libc::SYS_perf_event_open,
        attr as *const PerfEventAttr,
        pid,
        -1i32,
        -1i32,
        0u64,
    ) as i32
}

/// Dynamic PMU type from sysfs (e.g. ibs_op), None when the PMU is absent,
/// notably inside KVM guests, which virtualize neither IBS nor branch stacks.
fn pmu_type(name: &str) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/sys/bus/event_source/devices/{name}/type")).ok()?;
    parse_leading_int(&s).map(|v| v as u32)
}

// ─── Session ─────────────────────────────────────────────────────────────────

/// An armed hardware-trace session over a target pid (owns the perf fd and the
/// base + AUX mmaps; frees them on Drop, equivalent to vock_hw_trace_fini).
pub struct Session {
    perf_fd: i32,
    _pid: libc::pid_t,
    base: *mut libc::c_void,
    mmap_size: usize,
    aux_buf: *mut libc::c_void,
    aux_size: usize,
    amd_lbr: bool,
    // Second concurrent AMD event: IBS op precise sampling running alongside
    // the LBR event. Both rings are decoded and merged - IBS contributes
    // skid-0 retired-op rips, LBR contributes 16-branch breadth per PMI.
    ibs_fd: i32,
    ibs_base: *mut libc::c_void,
    ibs_size: usize,
}

impl Session {
    pub fn start(pid: libc::pid_t) -> Option<Session> {
        if intel_pt_available() {
            if let Some(s) = Self::intel_pt_start(pid) {
                return Some(s);
            }
            return None;
        }
        if amd_lbr_available() {
            if let Some(s) = Self::amd_lbr_start(pid) {
                return Some(s);
            }
            return None;
        }
        eprintln!("hw_trace: no hardware trace PMU found");
        None
    }

    /// Port of intel_pt_start().
    fn intel_pt_start(pid: libc::pid_t) -> Option<Session> {
        // Read the Intel PT (or CoreSight) PMU type from sysfs.
        let type_str = std::fs::read_to_string("/sys/bus/event_source/devices/intel_pt/type")
            .or_else(|_| {
                std::fs::read_to_string("/sys/bus/event_source/devices/cs_etm/type")
            })
            .ok()?;
        // atoi-style: parse the leading integer.
        let type_ = parse_leading_int(&type_str)?;
        if type_ < 0 {
            return None;
        }

        let attr = PerfEventAttr {
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            type_: type_ as u32,
            // disabled = 1, exclude_kernel = 0, exclude_user = 1
            flags: ATTR_DISABLED | ATTR_EXCLUDE_USER,
            ..Default::default()
        };

        let perf_fd = unsafe { perf_event_open(&attr, pid) };
        if perf_fd < 0 {
            eprintln!(
                "intel_pt: perf_event_open: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }

        let mmap_size = (INTEL_MMAP_PAGES + 1) * 4096;
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                perf_fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            eprintln!("intel_pt: mmap ring: {}", std::io::Error::last_os_error());
            unsafe { libc::close(perf_fd) };
            return None;
        }

        // Program the AUX area in the mmap header, then map it.
        unsafe {
            write_u64(base, OFF_AUX_OFFSET, mmap_size as u64);
            write_u64(base, OFF_AUX_SIZE, AUX_SIZE as u64);
        }

        let aux_buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                AUX_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                perf_fd,
                mmap_size as libc::off_t,
            )
        };
        if aux_buf == libc::MAP_FAILED {
            eprintln!("intel_pt: aux mmap: {}", std::io::Error::last_os_error());
            unsafe {
                libc::munmap(base, mmap_size);
                libc::close(perf_fd);
            }
            return None;
        }

        unsafe { libc::ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) };

        Some(Session {
            perf_fd,
            _pid: pid,
            base,
            mmap_size,
            aux_buf,
            aux_size: AUX_SIZE,
            amd_lbr: false,
            ibs_fd: -1,
            ibs_base: libc::MAP_FAILED,
            ibs_size: 0,
        })
    }

    /// AMD sampling engine: two concurrent perf events, merged at decode.
    ///
    /// * LBR branch stacks (cycles clock, 10 kHz): 16 taken branches per
    ///   PMI - the breadth. A tight period is degenerate here (the counter
    ///   re-arms instantly, or unthrottles on the tick, and every snapshot
    ///   captures the same 16-branch PMI entry window); frequency mode
    ///   spreads snapshots across the target's real kernel work.
    /// * IBS op (`ibs_op` PMU, 10 kHz): precise instruction-based sampling.
    ///   The rip of IBS samples has skid 0 (arch/x86/events/amd/ibs.c), each
    ///   sample is a retired op, and the hardware randomizes the sample
    ///   interval, decorrelating it from the LBR PMI clock.
    ///
    /// Alone, IBS yields ~1 PC per sample vs LBR's ~32 (measured: 21 vs ~500
    /// unique PCs on the same run), so it complements rather than replaces
    /// LBR. Guests get neither (KVM virtualizes neither facility) and fall
    /// back to plain IP sampling.
    fn amd_lbr_start(pid: libc::pid_t) -> Option<Session> {
        let lbr_attr = PerfEventAttr {
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            type_: PERF_TYPE_HARDWARE,
            config: PERF_COUNT_HW_CPU_CYCLES,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_USER | ATTR_FREQ,
            sample_period_or_freq: 10_000, // Hz; clear of the PMI throttle
            sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME | PERF_SAMPLE_BRANCH_STACK,
            branch_sample_type: PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_ANY,
            wakeup: 1,
            ..Default::default()
        };

        let mut perf_fd = unsafe { perf_event_open(&lbr_attr, pid) };
        if perf_fd < 0 {
            // Fallback: IP-only cycle sampling. Reached on kernels without
            // LBR and notably inside KVM guests, where AMD branch stacks
            // (BRS / LbrExtV2) are not virtualized. Statistical IP samples
            // are sparse and biased toward interrupt/exception entry code,
            // so say so instead of quietly producing a misleading report.
            eprintln!(
                "amd_lbr: branch-stack sampling unavailable ({}); falling back to \
IP sampling every 4000 kernel cycles",
                std::io::Error::last_os_error()
            );
            eprintln!(
                "amd_lbr: expect sparse, interrupt-biased coverage - KVM guests do not \
virtualize AMD branch stacks; use --mode kcov in VMs, or run on bare metal for real LBR"
            );
            let attr = PerfEventAttr {
                size: std::mem::size_of::<PerfEventAttr>() as u32,
                type_: PERF_TYPE_HARDWARE,
                config: PERF_COUNT_HW_CPU_CYCLES,
                flags: ATTR_DISABLED | ATTR_EXCLUDE_USER,
                sample_period_or_freq: 4000,
                sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME,
                wakeup: 1,
                ..Default::default()
            };
            perf_fd = unsafe { perf_event_open(&attr, pid) };
            if perf_fd < 0 {
                eprintln!(
                    "amd_lbr: perf_event_open (fallback): {}",
                    std::io::Error::last_os_error()
                );
                return None;
            }
        }

        let mmap_size = (AMD_MMAP_PAGES + 1) * 4096;
        let base = match Self::map_ring(perf_fd, mmap_size) {
            Some(b) => b,
            None => {
                unsafe { libc::close(perf_fd) };
                return None;
            }
        };

        // Secondary: IBS op, when the PMU exists (bare metal only).
        // exclude_user is filtered in the IBS IRQ handler on recent kernels
        // and rejected with EINVAL on older ones - retry without it; the
        // decoder keeps only kernel addresses anyway.
        let mut ibs_fd = -1;
        let mut ibs_base = libc::MAP_FAILED;
        if let Some(t) = pmu_type("ibs_op") {
            for flags in [
                ATTR_DISABLED | ATTR_FREQ | ATTR_EXCLUDE_USER,
                ATTR_DISABLED | ATTR_FREQ,
            ] {
                let attr = PerfEventAttr {
                    size: std::mem::size_of::<PerfEventAttr>() as u32,
                    type_: t,
                    config: 0,
                    flags,
                    sample_period_or_freq: 10_000, // Hz
                    sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME,
                    wakeup: 1,
                    ..Default::default()
                };
                let fd = unsafe { perf_event_open(&attr, pid) };
                if fd >= 0 {
                    if let Some(b) = Self::map_ring(fd, mmap_size) {
                        eprintln!("amd hw: + IBS op precise sampling (skid 0, retired ops)");
                        ibs_fd = fd;
                        ibs_base = b;
                        break;
                    }
                    unsafe { libc::close(fd) };
                }
            }
        }

        unsafe {
            libc::ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
            if ibs_fd >= 0 {
                libc::ioctl(ibs_fd, PERF_EVENT_IOC_ENABLE, 0);
            }
        }

        Some(Session {
            perf_fd,
            _pid: pid,
            base,
            mmap_size,
            aux_buf: libc::MAP_FAILED,
            aux_size: 0,
            amd_lbr: true,
            ibs_fd,
            ibs_base,
            ibs_size: mmap_size,
        })
    }

    /// mmap a perf sample ring (consumer page + data pages).
    fn map_ring(fd: i32, mmap_size: usize) -> Option<*mut libc::c_void> {
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            eprintln!("amd hw: mmap: {}", std::io::Error::last_os_error());
            return None;
        }
        Some(base)
    }

    /// Port of vock_hw_trace_stop().
    pub fn stop(&mut self) {
        if self.perf_fd >= 0 {
            unsafe { libc::ioctl(self.perf_fd, PERF_EVENT_IOC_DISABLE, 0) };
        }
        if self.ibs_fd >= 0 {
            unsafe { libc::ioctl(self.ibs_fd, PERF_EVENT_IOC_DISABLE, 0) };
        }
    }

    /// Port of vock_hw_trace_decode(): dispatch to the AMD or Intel decoder,
    /// each of which writes kerncov.log (one "0x<pc>" per line).
    pub fn decode(&mut self, vmlinux: Option<&str>) {
        if self.base == libc::MAP_FAILED {
            return;
        }
        if self.amd_lbr {
            self.amd_lbr_decode();
        } else {
            self.intel_pt_decode(vmlinux);
        }
    }

    /// Port of amd_lbr_decode().
    fn amd_lbr_decode(&mut self) {
        // Chronological merge: both events sample PERF_SAMPLE_TIME, so the
        // LBR/IP stream and the IBS stream interleave by timestamp instead
        // of being concatenated. Within one LBR sample perf orders the
        // branch entries newest-first; they are reversed here so the log
        // reads oldest-to-newest. kerncov.log is therefore a true execution
        // sequence (duplicates preserved) - the normal report dedups it,
        // and --ordered renders it as-is.
        let mut samples: Vec<(u64, Vec<u64>)> = Vec::new();
        Self::drain_sample_ring(self.base, self.mmap_size, &mut samples);
        if self.ibs_base != libc::MAP_FAILED {
            Self::drain_sample_ring(self.ibs_base, self.ibs_size, &mut samples);
        }
        samples.sort_by_key(|(t, _)| *t);

        let mut out = String::new();
        let mut pc_count: i32 = 0;
        for (_, pcs) in &samples {
            for pc in pcs {
                out.push_str(&format!("0x{:x}\n", pc));
                pc_count += 1;
            }
        }

        if let Ok(mut f) = std::fs::File::create("kerncov.log") {
            let _ = f.write_all(out.as_bytes());
        }
        eprintln!("[vock] AMD hw: {} kernel PCs sampled", pc_count);
    }

    /// Drain one perf sample ring into timestamped samples. Record layout
    /// (sample_type = IP | TIME [| BRANCH_STACK]): header, ip, time, then
    /// optionally nr + nr x {from, to, flags}. Kernel addresses only; branch
    /// entries are reversed to oldest-first (perf returns them newest-first).
    fn drain_sample_ring(
        base: *mut libc::c_void,
        mmap_size: usize,
        samples: &mut Vec<(u64, Vec<u64>)>,
    ) {
        let head = unsafe { read_u64(base, OFF_DATA_HEAD) };
        let mut tail = unsafe { read_u64(base, OFF_DATA_TAIL) };
        let data_size = (mmap_size - 4096) as u64;
        let ring = unsafe { (base as *const u8).add(4096) };

        while tail < head {
            let ev = unsafe { ring.add((tail % data_size) as usize) };
            // struct perf_event_header { u32 type; u16 misc; u16 size; }
            let ev_type = unsafe { (ev as *const u32).read_unaligned() };
            let ev_size = unsafe { (ev.add(6) as *const u16).read_unaligned() } as u64;

            if ev_type == PERF_RECORD_SAMPLE && ev_size >= 8 + 8 + 8 {
                let mut p = unsafe { ev.add(8) };
                let ip = unsafe { (p as *const u64).read_unaligned() };
                p = unsafe { p.add(8) };
                let time = unsafe { (p as *const u64).read_unaligned() };
                p = unsafe { p.add(8) };

                let mut pcs: Vec<u64> = Vec::new();

                // Branch stack present when the record extends past ip+time+nr.
                if ev_size > 8 + 8 + 8 + 8 {
                    let nr = unsafe { (p as *const u64).read_unaligned() };
                    p = unsafe { p.add(8) };
                    let n = nr.min(32) as usize;
                    let mut branches: Vec<(u64, u64)> = Vec::with_capacity(n);
                    for _ in 0..n {
                        let from = unsafe { (p as *const u64).read_unaligned() };
                        let to = unsafe { (p.add(8) as *const u64).read_unaligned() };
                        p = unsafe { p.add(24) };
                        branches.push((from, to));
                    }
                    for (from, to) in branches.into_iter().rev() {
                        if from >= 0xffff_8000_0000_0000 {
                            pcs.push(from);
                        }
                        if to >= 0xffff_8000_0000_0000 {
                            pcs.push(to);
                        }
                    }
                }
                // The sampled ip itself is the newest point in the record.
                if ip >= 0xffff_8000_0000_0000 {
                    pcs.push(ip);
                }
                if !pcs.is_empty() {
                    samples.push((time, pcs));
                }
            }
            tail += ev_size;
        }

        unsafe { write_u64(base, OFF_DATA_TAIL, head) };
    }

    /// Port of intel_pt_decode().
    fn intel_pt_decode(&mut self, vmlinux: Option<&str>) {
        if self.aux_buf == libc::MAP_FAILED {
            return;
        }

        let mut len = unsafe { read_u64(self.base, OFF_AUX_HEAD) } as usize;
        if len > self.aux_size {
            len = self.aux_size;
        }
        if len == 0 {
            eprintln!("[vock] intel_pt: no data captured");
            return;
        }

        let data: &[u8] = unsafe { std::slice::from_raw_parts(self.aux_buf as *const u8, len) };

        // Save raw trace.
        let _ = std::fs::write("hw_trace.bin", data);

        let mut out = String::new();
        let mut pc_count: i32 = 0;

        // Try full decode with vmlinux; on load failure fall back to TIP-only.
        let mut did_full = false;
        if let Some(vm) = vmlinux {
            match PtDecoder::init(vm, data) {
                Some(mut dec) => {
                    pc_count = dec.run();
                    out = dec.out;
                    did_full = true;
                }
                None => {
                    eprintln!("[vock] intel_pt: vmlinux load failed, TIP-only mode");
                }
            }
        }

        if !did_full {
            pc_count = tip_only_decode(data, &mut out);
        }

        if let Ok(mut f) = std::fs::File::create("kerncov.log") {
            let _ = f.write_all(out.as_bytes());
        } else {
            eprintln!("intel_pt: fopen kerncov.log failed");
            return;
        }
        eprintln!("[vock] intel_pt: {} kernel PCs \u{2192} kerncov.log", pc_count);
    }
}

impl Drop for Session {
    /// Port of vock_hw_trace_fini().
    fn drop(&mut self) {
        unsafe {
            if self.aux_buf != libc::MAP_FAILED {
                libc::munmap(self.aux_buf, self.aux_size);
            }
            if self.base != libc::MAP_FAILED {
                libc::munmap(self.base, self.mmap_size);
            }
            if self.perf_fd >= 0 {
                libc::close(self.perf_fd);
            }
            if self.ibs_base != libc::MAP_FAILED {
                libc::munmap(self.ibs_base, self.ibs_size);
            }
            if self.ibs_fd >= 0 {
                libc::close(self.ibs_fd);
            }
        }
    }
}

// atoi-style leading-integer parse (permits leading whitespace / trailing junk).
fn parse_leading_int(s: &str) -> Option<i32> {
    let t = s.trim_start();
    let mut end = 0;
    let bytes = t.as_bytes();
    if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return Some(0); // atoi("") == 0
    }
    t[..end].parse::<i32>().ok().or(Some(0))
}

// ─── Intel PT packet layer ───────────────────────────────────────────────────
//
// Every packet in the stream is scanned through one length table, so a packet
// the decoder does not act on is still skipped by its *true* encoded length.
// Advancing a single byte past an unhandled packet (what this decoder used to
// do) re-interprets its payload bytes as opcodes, which aliases into spurious
// TNT and IP packets and corrupts the instruction walk.
//
// Constant names follow libipt's `pt_opcodes.h` so the two can be compared
// side by side; the encodings and lengths are from the Intel SDM Vol. 3C,
// "Intel Processor Trace".

// Single-byte opcodes.
const OPC_PAD: u8 = 0x00;
const OPC_EXT: u8 = 0x02; // two-byte opcode; the second byte selects
const OPC_MODE: u8 = 0x99;
const OPC_TSC: u8 = 0x19;
const OPC_MTC: u8 = 0x59;

// Masked opcode families.
const OPM_IP: u8 = 0x1f;
const OPC_TIP: u8 = 0x0d;
const OPC_TIP_PGE: u8 = 0x11;
const OPC_TIP_PGD: u8 = 0x01;
const OPC_FUP: u8 = 0x1d;

/// BIP: bits 2:0 are the opcode, bits 7:3 the block-item id. The byte is
/// **even**, so it overlaps the short-TNT mask. The architecture resolves the
/// ambiguity by scope: a BIP is only valid inside a block, between a BBP and
/// its BEP. Outside a block the same byte is a short TNT.
const OPM_BIP: u8 = 0x07;
const OPC_BIP: u8 = 0x04;

// Short TNT is the **even**-byte opcode: `(b & 0x01) == 0x00`. The other even
// opcodes — PAD (0x00), the extended opcode (0x02) and an in-block BIP — are
// matched before this test. Testing for an *odd* byte instead, which is what
// this decoder did, both rejects every real TNT8 and accepts a large set of
// bytes that are not TNT at all (TIP's 0x0d is odd).
const OPM_TNT8: u8 = 0x01;
const OPC_TNT8: u8 = 0x00;

// CYC: bits 1:0 == 0b11. Bit 2 of byte 0 is the EXP continuation flag; for
// every following byte the continuation flag is bit 0.
const OPM_CYC: u8 = 0x03;
const OPC_CYC: u8 = 0x03;
const CYC_EXP0: u8 = 0x04;
const CYC_EXPN: u8 = 0x01;
/// 5 payload bits in byte 0 + 7 per continuation byte covers the full 64-bit
/// counter in 9 bytes; anything longer is malformed.
const CYC_MAX_LEN: usize = 9;

// Extended opcodes: the second byte of an `0x02 xx` pair.
const EXT_PSB: u8 = 0x82;
const EXT_TNT64: u8 = 0xa3;
const EXT_PIP: u8 = 0x43;
const EXT_OVF: u8 = 0xf3;
const EXT_PSBEND: u8 = 0x23;
const EXT_CBR: u8 = 0x03;
const EXT_TMA: u8 = 0x73;
const EXT_STOP: u8 = 0x83;
const EXT_VMCS: u8 = 0xc8;
const EXT_EXT2: u8 = 0xc3;
const EXT_EXSTOP: u8 = 0x62;
const EXT_EXSTOP_IP: u8 = 0xe2;
const EXT_MWAIT: u8 = 0xc2;
const EXT_PWRE: u8 = 0x22;
const EXT_PWRX: u8 = 0xa2;
const EXT_BBP: u8 = 0x63;
const EXT_BEP: u8 = 0x33;
const EXT_BEP_IP: u8 = 0xb3;
const EXT_CFE: u8 = 0x13;
const EXT_EVD: u8 = 0x53;
/// PTW is matched under `OPM_IP`: bits 6:5 hold the payload-length code and
/// bit 7 the IP flag, so the ext byte is one of 0x12, 0x32, 0x52, … 0xf2.
const EXT_PTW: u8 = 0x12;
const EXT2_MNT: u8 = 0x88;

/// PSB is the 16-byte sequence `02 82` repeated eight times. The architecture
/// guarantees it cannot occur inside any other packet, which is what makes it
/// the resynchronization point.
const PSB: [u8; 16] = [
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
];

/// The packets the decoder acts on, plus the three outcomes that are not
/// packets. Everything architecturally defined but uninteresting collapses
/// into `Skip`, which still carries a correct length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pkt {
    Pad,
    /// Short TNT: 7 payload bits (stop bit included).
    Tnt8 { payload: u64 },
    /// Long TNT: 47 payload bits (stop bit included).
    Tnt64 { payload: u64 },
    /// TIP / FUP / TIP.PGE / TIP.PGD. `enc` is the IPBytes field.
    Ip { opcode: u8, enc: u8 },
    Psb,
    /// Buffer overflow: trace was lost between here and the next TIP.PGE/FUP.
    Ovf,
    /// Block Begin: opens a block and fixes the payload width of the BIP
    /// packets inside it.
    Bbp { wide: bool },
    /// Block End: closes the block opened by a BBP.
    Bep,
    /// Defined, nothing to do.
    Skip,
    /// Reserved or undefined encoding: the stream is not what we think it is.
    Bad,
    /// Well-formed opcode whose payload runs past the end of the buffer.
    Truncated,
}

#[derive(Debug, Clone, Copy)]
struct Scan {
    pkt: Pkt,
    /// Total encoded length in bytes, including the opcode. Zero for
    /// `Bad`/`Truncated`, where the length is by definition unknown.
    len: usize,
}

impl Scan {
    #[inline]
    fn of(pkt: Pkt, len: usize) -> Scan {
        Scan { pkt, len }
    }
    #[inline]
    fn bad() -> Scan {
        Scan { pkt: Pkt::Bad, len: 0 }
    }
    #[inline]
    fn trunc() -> Scan {
        Scan { pkt: Pkt::Truncated, len: 0 }
    }
}

/// Payload size of a TIP-family packet from its IPBytes field.
/// `None` marks the two reserved encodings (5 and 7).
#[inline]
fn ip_payload_len(enc: u8) -> Option<usize> {
    match enc {
        0 => Some(0), // IP suppressed: no payload
        1 => Some(2),
        2 => Some(4),
        3 | 4 => Some(6),
        6 => Some(8),
        _ => None, // 5, 7 reserved
    }
}

/// Decode one packet header at `pos` and return its kind and total length.
///
/// `block` is the state a BBP/BEP pair establishes: `Some(width)` while inside
/// a block, naming the BIP payload width in bytes, `None` otherwise. It is the
/// only cross-packet state the length table needs, and it is what
/// disambiguates an in-block BIP from a short TNT.
fn scan_packet(data: &[u8], pos: usize, block: Option<usize>) -> Scan {
    let len = data.len();
    if pos >= len {
        return Scan::trunc();
    }
    let avail = len - pos;
    let b = data[pos];

    // Fixed single-byte opcodes first: PAD and the extended opcode are both
    // even and would otherwise be swallowed by the TNT8 mask.
    if b == OPC_PAD {
        return Scan::of(Pkt::Pad, 1);
    }

    if b == OPC_EXT {
        if avail < 2 {
            return Scan::trunc();
        }
        let e = data[pos + 1];
        // Lengths below are opcode bytes + payload bytes.
        let (pkt, total) = match e {
            EXT_PSB => (Pkt::Psb, 16),
            EXT_PSBEND => (Pkt::Skip, 2),
            EXT_TNT64 => {
                if avail < 8 {
                    return Scan::trunc();
                }
                let mut payload: u64 = 0;
                for i in 0..6 {
                    payload |= (data[pos + 2 + i] as u64) << (8 * i);
                }
                (Pkt::Tnt64 { payload }, 8)
            }
            EXT_PIP => (Pkt::Skip, 8),      // 2 + 6
            EXT_OVF => (Pkt::Ovf, 2),
            EXT_CBR => (Pkt::Skip, 4),      // 2 + 2
            EXT_TMA => (Pkt::Skip, 7),      // 2 + 5
            EXT_STOP => (Pkt::Skip, 2),     // TraceStop
            EXT_VMCS => (Pkt::Skip, 7),     // 2 + 5
            EXT_EXSTOP | EXT_EXSTOP_IP => (Pkt::Skip, 2),
            EXT_MWAIT => (Pkt::Skip, 12),   // 2 + 10
            EXT_PWRE => (Pkt::Skip, 4),     // 2 + 2
            EXT_PWRX => (Pkt::Skip, 7),     // 2 + 5
            EXT_CFE => (Pkt::Skip, 4),      // 2 + 2
            EXT_EVD => (Pkt::Skip, 9),      // 2 + 7
            EXT_BEP | EXT_BEP_IP => (Pkt::Bep, 2),
            EXT_BBP => {
                if avail < 3 {
                    return Scan::trunc();
                }
                // Bit 7 of the payload byte selects 8-byte BIPs.
                (Pkt::Bbp { wide: data[pos + 2] & 0x80 != 0 }, 3)
            }
            EXT_EXT2 => {
                if avail < 3 {
                    return Scan::trunc();
                }
                match data[pos + 2] {
                    EXT2_MNT => (Pkt::Skip, 11), // 3 + 8
                    _ => return Scan::bad(),
                }
            }
            _ => {
                // PTW carries its length code in bits 6:5 of the ext byte.
                if e & OPM_IP == EXT_PTW {
                    let payload = match (e >> 5) & 0x3 {
                        0 => 4,
                        1 => 8,
                        _ => return Scan::bad(), // 2, 3 reserved
                    };
                    (Pkt::Skip, 2 + payload)
                } else {
                    return Scan::bad();
                }
            }
        };
        if avail < total {
            return Scan::trunc();
        }
        return Scan::of(pkt, total);
    }

    if b == OPC_MODE {
        return if avail < 2 { Scan::trunc() } else { Scan::of(Pkt::Skip, 2) };
    }
    if b == OPC_TSC {
        return if avail < 8 { Scan::trunc() } else { Scan::of(Pkt::Skip, 8) };
    }
    if b == OPC_MTC {
        return if avail < 2 { Scan::trunc() } else { Scan::of(Pkt::Skip, 2) };
    }

    // TIP family.
    let short = b & OPM_IP;
    if short == OPC_TIP || short == OPC_FUP || short == OPC_TIP_PGE || short == OPC_TIP_PGD {
        let enc = (b >> 5) & 0x7;
        let payload = match ip_payload_len(enc) {
            Some(n) => n,
            None => return Scan::bad(),
        };
        if avail < 1 + payload {
            return Scan::trunc();
        }
        return Scan::of(Pkt::Ip { opcode: short, enc }, 1 + payload);
    }

    // BIP, but only inside a block: outside one this byte is a short TNT.
    // The payload width was announced by the BBP that opened the block.
    if let Some(bip_size) = block {
        if b & OPM_BIP == OPC_BIP {
            return if avail < 1 + bip_size {
                Scan::trunc()
            } else {
                Scan::of(Pkt::Skip, 1 + bip_size)
            };
        }
    }

    // CYC: variable length, driven by the EXP continuation flags.
    if b & OPM_CYC == OPC_CYC {
        let mut n = 1usize;
        let mut more = b & CYC_EXP0 != 0;
        while more {
            if n >= CYC_MAX_LEN {
                return Scan::bad();
            }
            if pos + n >= len {
                return Scan::trunc();
            }
            more = data[pos + n] & CYC_EXPN != 0;
            n += 1;
        }
        return Scan::of(Pkt::Skip, n);
    }

    // Short TNT: any remaining even byte.
    if b & OPM_TNT8 == OPC_TNT8 {
        return Scan::of(Pkt::Tnt8 { payload: (b >> 1) as u64 }, 1);
    }

    Scan::bad()
}

/// Scan forward for the next PSB, the architectural resynchronization point.
/// Returns the offset of its first byte.
fn find_psb(data: &[u8], from: usize) -> Option<usize> {
    if data.len() < PSB.len() {
        return None;
    }
    let last = data.len() - PSB.len();
    (from.min(last + 1)..=last).find(|&i| data[i..i + PSB.len()] == PSB)
}

/// Stream-health counters, reported on stderr after a decode so a caller can
/// tell a clean trace from one the decoder had to guess its way through.
#[derive(Debug, Default, Clone, Copy)]
struct PtStats {
    bad_packets: u64,
    resyncs: u64,
    overflows: u64,
    truncated: bool,
}

impl PtStats {
    fn report(&self, label: &str) {
        if self.bad_packets == 0 && self.overflows == 0 && !self.truncated {
            return;
        }
        let mut parts: Vec<String> = Vec::new();
        if self.bad_packets > 0 {
            parts.push(format!(
                "{} undecodable packet(s), {} PSB resync(s)",
                self.bad_packets, self.resyncs
            ));
        }
        if self.overflows > 0 {
            parts.push(format!("{} buffer overflow(s)", self.overflows));
        }
        if self.truncated {
            parts.push("trace ends mid-packet".to_string());
        }
        eprintln!("[vock] {}: {}", label, parts.join(", "));
    }
}

// ─── TIP-only decode (intel_pt.c fallback path) ──────────────────────────────

/// Follow TIP/FUP last-IP updates only (no TNT following), emitting kernel
/// PCs. Returns the count.
///
/// Used when no `--vmlinux` was given or the ELF load failed. Every packet is
/// still measured by `scan_packet`, so the IP-bearing packets this path cares
/// about are the real ones rather than payload bytes of packets it ignores.
fn tip_only_decode(data: &[u8], out: &mut String) -> i32 {
    let len = data.len();
    let mut last_ip: u64 = 0;
    let mut pos: usize = 0;
    let mut pc_count: i32 = 0;
    let mut block: Option<usize> = None;
    let mut stats = PtStats::default();

    while pos < len {
        let scan = scan_packet(data, pos, block);
        match scan.pkt {
            Pkt::Ip { enc, .. } => {
                let ip_bytes = ip_payload_len(enc).unwrap_or(0);
                if ip_bytes > 0 {
                    let mut ip: u64 = 0;
                    for i in 0..ip_bytes {
                        ip |= (data[pos + 1 + i] as u64) << (8 * i);
                    }
                    match enc {
                        1 => last_ip = (last_ip & !0xFFFFu64) | ip,
                        2 => last_ip = (last_ip & !0xFFFF_FFFFu64) | ip,
                        3 => {
                            last_ip = ip;
                            if ip & (1u64 << 47) != 0 {
                                last_ip |= 0xFFFF_0000_0000_0000;
                            }
                        }
                        4 => last_ip = (last_ip & !0xFFFF_FFFF_FFFFu64) | ip,
                        6 => last_ip = ip,
                        _ => {}
                    }
                    if last_ip >= 0xffff_0000_0000_0000 {
                        out.push_str(&format!("0x{:x}\n", last_ip));
                        pc_count += 1;
                    }
                }
                pos += scan.len;
            }
            Pkt::Ovf => {
                // Trace was lost; the last IP is no longer current.
                last_ip = 0;
                stats.overflows += 1;
                pos += scan.len;
            }
            Pkt::Bbp { wide } => {
                block = Some(if wide { 8 } else { 4 });
                pos += scan.len;
            }
            Pkt::Bep => {
                block = None;
                pos += scan.len;
            }
            Pkt::Truncated => {
                stats.truncated = true;
                break;
            }
            Pkt::Bad => {
                stats.bad_packets += 1;
                last_ip = 0;
                block = None;
                match find_psb(data, pos + 1) {
                    Some(next) => {
                        stats.resyncs += 1;
                        pos = next;
                    }
                    None => break,
                }
            }
            _ => pos += scan.len,
        }
    }

    stats.report("intel_pt");
    pc_count
}

// ─── Intel PT full decoder (port of pt_decode.c) ─────────────────────────────

struct PtDecoder<'a> {
    // vmlinux .text section
    text: Vec<u8>,
    text_vaddr: u64,
    text_size: usize,

    // PT trace data
    trace: &'a [u8],
    trace_len: usize,
    pos: usize,

    // State
    ip: u64,
    tnt_bits: u64,
    tnt_count: i32,
    /// `Some(width)` while inside a BBP/BEP block, naming the BIP payload
    /// width; `None` outside one. Disambiguates BIP from a short TNT.
    block: Option<usize>,
    stats: PtStats,

    // Output
    out: String,
    pc_count: i32,
}

impl<'a> PtDecoder<'a> {
    /// Port of pt_decoder_init() + load_vmlinux_text().
    fn init(vmlinux: &str, trace: &'a [u8]) -> Option<PtDecoder<'a>> {
        let (text, text_vaddr, text_size) = load_vmlinux_text(vmlinux)?;
        Some(PtDecoder {
            text,
            text_vaddr,
            text_size,
            trace,
            trace_len: trace.len(),
            pos: 0,
            ip: 0,
            tnt_bits: 0,
            tnt_count: 0,
            block: None,
            stats: PtStats::default(),
            out: String::new(),
            pc_count: 0,
        })
    }

    #[inline]
    fn emit_ip(&mut self, ip: u64) {
        if ip >= 0xffff_0000_0000_0000 {
            self.out.push_str(&format!("0x{:x}\n", ip));
            self.pc_count += 1;
        }
    }

    /// Port of pt_read_ip(): decode an IP payload of the given encoding,
    /// update `self.ip` with last-IP compression. Returns bytes read, or -1.
    fn pt_read_ip(&mut self, enc: u8) -> i32 {
        let bytes: usize = match enc {
            1 => 2,
            2 => 4,
            3 | 4 => 6,
            6 => 8,
            _ => return 0,
        };
        if self.pos + bytes > self.trace_len {
            return -1;
        }
        let mut val: u64 = 0;
        for i in 0..bytes {
            val |= (self.trace[self.pos] as u64) << (8 * i);
            self.pos += 1;
        }
        match enc {
            1 => self.ip = (self.ip & !0xFFFFu64) | val,
            2 => self.ip = (self.ip & !0xFFFF_FFFFu64) | val,
            3 => {
                self.ip = val;
                if val & (1u64 << 47) != 0 {
                    self.ip |= 0xFFFF_0000_0000_0000;
                }
            }
            4 => self.ip = (self.ip & !0xFFFF_FFFF_FFFFu64) | val,
            6 => self.ip = val,
            _ => {}
        }
        bytes as i32
    }

    /// Port of walk_tnt(): step the kernel binary from the current IP,
    /// consuming TNT bits at conditional branches and following direct
    /// unconditional branches. Applies a one-shot KASLR offset correction.
    fn walk_tnt(&mut self) {
        // Detect KASLR offset on first valid IP outside the ELF .text range.
        if self.ip >= 0xffff_0000_0000_0000 && self.ip != 0 && !self.text.is_empty() {
            if self.ip < self.text_vaddr
                || self.ip >= self.text_vaddr.wrapping_add(self.text_size as u64)
            {
                let offset = ((self.ip.wrapping_sub(self.text_vaddr)) >> 21) << 21;
                if offset > 0 && offset < 0x8000_0000 {
                    self.text_vaddr = self.text_vaddr.wrapping_add(offset);
                }
            }
        }

        while self.tnt_count > 0
            && self.ip >= self.text_vaddr
            && self.ip < self.text_vaddr.wrapping_add(self.text_size as u64)
        {
            let off = (self.ip - self.text_vaddr) as usize;
            if self.text_size < off {
                break;
            }
            let remain = self.text_size - off;
            if remain < 1 {
                break;
            }

            let maxl = if remain > 15 { 15 } else { remain };
            let (ilen, is_branch, is_cond, branch_rel) =
                decode_insn(&self.text[off..off + maxl], maxl);
            if ilen == 0 {
                break;
            }

            if is_branch && is_cond {
                // Consume a TNT bit (MSB-first within the current window).
                let taken = (self.tnt_bits >> (self.tnt_count - 1)) & 1;
                self.tnt_count -= 1;

                if taken != 0 {
                    self.ip = self
                        .ip
                        .wrapping_add(ilen as u64)
                        .wrapping_add(branch_rel as u64);
                } else {
                    self.ip = self.ip.wrapping_add(ilen as u64);
                }
                let ip = self.ip;
                self.emit_ip(ip);
            } else if is_branch && !is_cond {
                if branch_rel != 0 && ilen > 1 {
                    // Direct call/jmp: follow it.
                    self.ip = self
                        .ip
                        .wrapping_add(ilen as u64)
                        .wrapping_add(branch_rel as u64);
                    let ip = self.ip;
                    self.emit_ip(ip);
                } else {
                    // Indirect or ret, need a TIP packet.
                    break;
                }
            } else {
                // Not a branch, advance.
                self.ip = self.ip.wrapping_add(ilen as u64);
            }
        }
    }

    /// Load a TNT payload and immediately walk it against the kernel text.
    ///
    /// The highest set bit of the payload is the stop bit; the bits below it
    /// are the branch outcomes, oldest next to the stop bit. A payload of zero
    /// has no stop bit and is a malformed packet.
    fn load_tnt(&mut self, payload: u64) {
        if payload == 0 {
            self.stats.bad_packets += 1;
            self.tnt_bits = 0;
            self.tnt_count = 0;
            return;
        }
        let stop = 63 - payload.leading_zeros(); // index of the stop bit
        self.tnt_bits = payload & ((1u64 << stop) - 1);
        self.tnt_count = stop as i32;
        if !self.text.is_empty() && self.ip != 0 && self.tnt_count > 0 {
            self.walk_tnt();
        }
    }

    /// Drop any TNT bits still held. Used at synchronization points and
    /// wherever the stream is known to have lost continuity: outcomes that
    /// cannot be placed against an instruction must not be placed at all.
    #[inline]
    fn drop_tnt(&mut self) {
        self.tnt_bits = 0;
        self.tnt_count = 0;
    }

    /// The main packet state machine.
    ///
    /// Every packet is measured by `scan_packet`, so a packet the decoder
    /// ignores is skipped by its true length and can never have its payload
    /// re-read as an opcode. An undefined encoding resynchronizes to the next
    /// PSB rather than sliding one byte forward.
    fn run(&mut self) -> i32 {
        self.pos = 0;
        self.ip = 0;
        self.drop_tnt();
        self.pc_count = 0;
        self.block = None;
        self.stats = PtStats::default();

        while self.pos < self.trace_len {
            let scan = scan_packet(self.trace, self.pos, self.block);
            match scan.pkt {
                Pkt::Pad | Pkt::Skip => self.pos += scan.len,

                Pkt::Tnt8 { payload } => {
                    self.pos += scan.len;
                    self.load_tnt(payload);
                }

                Pkt::Tnt64 { payload } => {
                    self.pos += scan.len;
                    self.load_tnt(payload);
                }

                Pkt::Ip { enc, .. } => {
                    // IP suppressed: a 1-byte packet that binds nothing.
                    if enc == 0 {
                        self.pos += scan.len;
                        continue;
                    }
                    // `pt_read_ip` consumes the payload itself, so step over
                    // the opcode byte first; it lands exactly on scan.len.
                    let start = self.pos;
                    self.pos += 1;
                    if self.pt_read_ip(enc) < 0 {
                        self.stats.truncated = true;
                        break;
                    }
                    debug_assert_eq!(self.pos, start + scan.len);
                    let ip = self.ip;
                    self.emit_ip(ip);
                    // Resume the walk with any TNT bits still pending.
                    if !self.text.is_empty() && self.tnt_count > 0 {
                        self.walk_tnt();
                    }
                }

                Pkt::Psb => {
                    self.pos += scan.len;
                    // A PSB is a synchronization point: TNT bits held across
                    // it belong to the stream before it and cannot be placed.
                    self.drop_tnt();
                }

                Pkt::Ovf => {
                    self.pos += scan.len;
                    // The AUX buffer overflowed and trace was lost. Drop the
                    // IP as well as the TNT; the decoder re-arms on the
                    // TIP.PGE/FUP that architecturally follows OVF.
                    self.drop_tnt();
                    self.ip = 0;
                    self.stats.overflows += 1;
                }

                Pkt::Bbp { wide } => {
                    self.pos += scan.len;
                    self.block = Some(if wide { 8 } else { 4 });
                }

                Pkt::Bep => {
                    self.pos += scan.len;
                    self.block = None;
                }

                Pkt::Truncated => {
                    self.stats.truncated = true;
                    break;
                }

                Pkt::Bad => {
                    self.stats.bad_packets += 1;
                    // Nothing after an undecodable byte can be trusted to be
                    // a packet boundary, so neither the TNT window nor the
                    // last IP survives.
                    self.drop_tnt();
                    self.ip = 0;
                    self.block = None;
                    match find_psb(self.trace, self.pos + 1) {
                        Some(next) => {
                            self.stats.resyncs += 1;
                            self.pos = next;
                        }
                        None => break,
                    }
                }
            }
        }

        self.stats.report("intel_pt");
        self.pc_count
    }
}

/// Port of load_vmlinux_text(): mmap the ELF and copy out the `.text` section.
/// Returns (text bytes, sh_addr, sh_size).
fn load_vmlinux_text(vmlinux: &str) -> Option<(Vec<u8>, u64, usize)> {
    let map = match std::fs::read(vmlinux) {
        Ok(m) => m,
        Err(_) => return None,
    };
    // Minimal ELF64 parse.
    if map.len() < 64 {
        return None;
    }
    let rd_u16 = |o: usize| -> u16 { u16::from_le_bytes([map[o], map[o + 1]]) };
    let rd_u32 =
        |o: usize| -> u32 { u32::from_le_bytes([map[o], map[o + 1], map[o + 2], map[o + 3]]) };
    let rd_u64 = |o: usize| -> u64 {
        u64::from_le_bytes([
            map[o],
            map[o + 1],
            map[o + 2],
            map[o + 3],
            map[o + 4],
            map[o + 5],
            map[o + 6],
            map[o + 7],
        ])
    };

    // Elf64_Ehdr: e_shoff @ 0x28, e_shentsize @ 0x3a, e_shnum @ 0x3c,
    // e_shstrndx @ 0x3e.
    let e_shoff = rd_u64(0x28) as usize;
    let e_shentsize = rd_u16(0x3a) as usize;
    let e_shnum = rd_u16(0x3c) as usize;
    let e_shstrndx = rd_u16(0x3e) as usize;
    if e_shentsize == 0 || e_shoff == 0 {
        return None;
    }

    // Section header field offsets (Elf64_Shdr): sh_name @0, sh_addr @0x10,
    // sh_offset @0x18, sh_size @0x20.
    let shdr = |i: usize| -> usize { e_shoff + i * e_shentsize };
    if e_shstrndx >= e_shnum {
        return None;
    }
    let shstr_off = rd_u64(shdr(e_shstrndx) + 0x18) as usize;

    for i in 0..e_shnum {
        let base = shdr(i);
        if base + 0x28 > map.len() {
            break;
        }
        let sh_name = rd_u32(base) as usize;
        // Compare the null-terminated name against ".text".
        let name_pos = shstr_off + sh_name;
        if section_name_is(&map, name_pos, b".text") {
            let sh_addr = rd_u64(base + 0x10);
            let sh_offset = rd_u64(base + 0x18) as usize;
            let sh_size = rd_u64(base + 0x20) as usize;
            if sh_offset + sh_size > map.len() {
                return None;
            }
            let text = map[sh_offset..sh_offset + sh_size].to_vec();
            return Some((text, sh_addr, sh_size));
        }
    }

    None
}

fn section_name_is(map: &[u8], pos: usize, want: &[u8]) -> bool {
    if pos + want.len() >= map.len() {
        return false;
    }
    &map[pos..pos + want.len()] == want && map[pos + want.len()] == 0
}

// ─── Minimal x86-64 instruction decoder (port of decode_insn) ────────────────

/// Returns (length, is_branch, is_cond, branch_rel).
fn decode_insn(code: &[u8], max_len: usize) -> (i32, bool, bool, i64) {
    let mut is_branch = false;
    let mut is_cond = false;
    let mut branch_rel: i64 = 0;

    if max_len < 1 {
        return (0, false, false, 0);
    }

    let p = code;
    let mut len: usize = 0;

    // Skip legacy + REX prefixes.
    while len < 15 && len < max_len {
        let b = p[len];
        if b == 0x66
            || b == 0x67
            || b == 0xf0
            || b == 0xf2
            || b == 0xf3
            || b == 0x2e
            || b == 0x3e
            || b == 0x26
            || b == 0x64
            || b == 0x65
            || b == 0x36
        {
            len += 1;
            continue;
        }
        // REX prefix
        if (b & 0xf0) == 0x40 {
            len += 1;
            continue;
        }
        break;
    }

    if len >= max_len {
        return (if len != 0 { len as i32 } else { 1 }, false, false, 0);
    }

    let op = p[len];
    len += 1;

    // Jcc short (0x70-0x7F)
    if (0x70..=0x7f).contains(&op) {
        if len < max_len {
            is_branch = true;
            is_cond = true;
            branch_rel = (p[len] as i8) as i64;
            len += 1;
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // JMP short (0xEB)
    if op == 0xeb {
        if len < max_len {
            is_branch = true;
            is_cond = false;
            branch_rel = (p[len] as i8) as i64;
            len += 1;
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // CALL rel32 (0xE8)
    if op == 0xe8 {
        if len + 4 <= max_len {
            is_branch = true;
            is_cond = false;
            let rel = i32::from_le_bytes([p[len], p[len + 1], p[len + 2], p[len + 3]]);
            branch_rel = rel as i64;
            len += 4;
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // JMP rel32 (0xE9)
    if op == 0xe9 {
        if len + 4 <= max_len {
            is_branch = true;
            is_cond = false;
            let rel = i32::from_le_bytes([p[len], p[len + 1], p[len + 2], p[len + 3]]);
            branch_rel = rel as i64;
            len += 4;
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // RET (0xC3, 0xCB)
    if op == 0xc3 || op == 0xcb {
        is_branch = true;
        is_cond = false;
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // Two-byte opcode (0x0F)
    if op == 0x0f && len < max_len {
        let op2 = p[len];
        len += 1;
        // Jcc near (0x0F 0x80-0x8F)
        if (0x80..=0x8f).contains(&op2) {
            if len + 4 <= max_len {
                is_branch = true;
                is_cond = true;
                let rel = i32::from_le_bytes([p[len], p[len + 1], p[len + 2], p[len + 3]]);
                branch_rel = rel as i64;
                len += 4;
            }
            return (len as i32, is_branch, is_cond, branch_rel);
        }
        // SYSCALL (0x0F 0x05), SYSRET (0x0F 0x07)
        if op2 == 0x05 || op2 == 0x07 {
            is_branch = true;
            is_cond = false;
            return (len as i32, is_branch, is_cond, branch_rel);
        }
        // Skip other 0F xx, approximate length via ModRM.
        if len < max_len {
            let modrm = p[len];
            len += 1;
            let mod_ = (modrm >> 6) & 3;
            let rm = modrm & 7;
            if mod_ == 0 && rm == 5 {
                len += 4; // RIP-relative
            } else if mod_ == 0 && rm == 4 {
                len += 1; // SIB
            } else if mod_ == 1 {
                len += 1;
                if rm == 4 {
                    len += 1;
                }
            } else if mod_ == 2 {
                len += 4;
                if rm == 4 {
                    len += 1;
                }
            }
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // Indirect CALL/JMP (0xFF /2, /4)
    if op == 0xff && len < max_len {
        let modrm = p[len];
        let reg = (modrm >> 3) & 7;
        if reg == 2 || reg == 4 {
            is_branch = true;
            is_cond = false;
        }
        len += 1;
        let mod_ = (modrm >> 6) & 3;
        let rm = modrm & 7;
        if mod_ == 0 && rm == 5 {
            len += 4;
        } else if mod_ == 0 && rm == 4 {
            len += 1;
        } else if mod_ == 1 {
            len += 1;
            if rm == 4 {
                len += 1;
            }
        } else if mod_ == 2 {
            len += 4;
            if rm == 4 {
                len += 1;
            }
        }
        return (len as i32, is_branch, is_cond, branch_rel);
    }

    // Generic: approximate using ModRM if present.
    if len < max_len
        && (op <= 0x3f
            || (0x80..=0x8f).contains(&op)
            || op == 0x63
            || op == 0x69
            || op == 0x6b
            || op == 0xc0
            || op == 0xc1
            || op == 0xc6
            || op == 0xc7
            || op == 0xd0
            || op == 0xd1
            || op == 0xd2
            || op == 0xd3
            || op == 0xf6
            || op == 0xf7
            || op == 0xfe)
    {
        let modrm = p[len];
        len += 1;
        let mod_ = (modrm >> 6) & 3;
        let rm = modrm & 7;
        if mod_ == 0 && rm == 5 {
            len += 4;
        } else if mod_ == 0 && rm == 4 {
            len += 1;
        } else if mod_ == 1 {
            len += 1;
            if rm == 4 {
                len += 1;
            }
        } else if mod_ == 2 {
            len += 4;
            if rm == 4 {
                len += 1;
            }
        }
        // Immediate bytes.
        if op == 0x80 || op == 0x82 || op == 0xc0 || op == 0xc6 {
            len += 1;
        } else if op == 0x81 || op == 0xc1 || op == 0xc7 || op == 0x69 {
            len += 4;
        } else if op == 0x83 || op == 0x6b {
            len += 1;
        }
    }

    (if len != 0 { len as i32 } else { 1 }, is_branch, is_cond, branch_rel)
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A decoder over a synthetic trace with no kernel text loaded: the packet
    /// walk and `emit_ip` run, `walk_tnt` is skipped (it is guarded on
    /// `!text.is_empty()`), which is exactly what isolates the packet layer.
    fn decoder(trace: &[u8]) -> PtDecoder<'_> {
        PtDecoder {
            text: Vec::new(),
            text_vaddr: 0,
            text_size: 0,
            trace,
            trace_len: trace.len(),
            pos: 0,
            ip: 0,
            tnt_bits: 0,
            tnt_count: 0,
            block: None,
            stats: PtStats::default(),
            out: String::new(),
            pc_count: 0,
        }
    }

    fn scan(bytes: &[u8]) -> Scan {
        scan_packet(bytes, 0, None)
    }

    // ── the short-TNT opcode test ────────────────────────────────────────────

    #[test]
    fn short_tnt_is_the_even_byte_opcode() {
        // SDM / libipt: pt_opc_tnt_8 = 0x00 under mask pt_opm_tnt_8 = 0x01.
        // 0x5a >> 1 = 0b0101101: stop bit at index 5, outcomes 0b01101.
        match scan(&[0x5a]).pkt {
            Pkt::Tnt8 { payload } => assert_eq!(payload, 0x5a >> 1),
            other => panic!("0x5a should be a short TNT, got {other:?}"),
        }
        // Every even byte except PAD (0x00), the extended opcode (0x02) and
        // the BIP family (bits 2:0 == 0b100, and only inside a block) is a
        // short TNT.
        for b in (0u16..=255).step_by(2) {
            let b = b as u8;
            if b == OPC_PAD || b == OPC_EXT {
                continue;
            }
            assert!(
                matches!(scan(&[b]).pkt, Pkt::Tnt8 { .. }),
                "even byte {b:#04x} should be a short TNT outside a block"
            );
        }
    }

    #[test]
    fn bip_shadows_short_tnt_only_inside_a_block() {
        // 0x24: bits 2:0 == 0b100, so it is BIP-shaped. Outside a block it is
        // a short TNT; inside one it is a BIP whose width the BBP announced.
        let bytes = [0x24u8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(scan_packet(&bytes, 0, None).pkt, Pkt::Tnt8 { .. }));
        assert_eq!(scan_packet(&bytes, 0, None).len, 1);

        let s = scan_packet(&bytes, 0, Some(4));
        assert_eq!(s.pkt, Pkt::Skip);
        assert_eq!(s.len, 5);
        assert_eq!(scan_packet(&bytes, 0, Some(8)).len, 9);
    }

    #[test]
    fn odd_bytes_are_never_short_tnt() {
        // The old test was `(b & 0x01) != 0`, which accepted odd bytes. TIP
        // (0x0d), FUP (0x1d), TIP.PGE (0x11), TIP.PGD (0x01), TSC (0x19),
        // MTC (0x59), MODE (0x99) and CYC are all odd.
        let mut buf = [0u8; 16];
        for b in (1u16..=255).step_by(2) {
            buf[0] = b as u8;
            assert!(
                !matches!(scan_packet(&buf, 0, None).pkt, Pkt::Tnt8 { .. }),
                "odd byte {:#04x} must not decode as a short TNT",
                b
            );
        }
    }

    #[test]
    fn pad_and_ext_are_matched_before_the_tnt_mask() {
        assert_eq!(scan(&[OPC_PAD]).pkt, Pkt::Pad);
        assert_eq!(scan(&[OPC_PAD]).len, 1);
        // 0x02 is even but is the extended opcode, not a TNT.
        assert_eq!(scan(&[0x02, EXT_PSBEND]).pkt, Pkt::Skip);
    }

    #[test]
    fn tnt_stop_bit_and_bit_order() {
        // payload 0b0101101 → stop at index 5, 5 outcomes 0b01101, consumed
        // MSB-first: 0, 1, 1, 0, 1.
        let trace = [0x5a];
        let mut d = decoder(&trace);
        d.run();
        assert_eq!(d.tnt_count, 5);
        assert_eq!(d.tnt_bits, 0b01101);

        // A payload with no stop bit is malformed.
        let trace = [0x00u8; 0];
        let mut d = decoder(&trace);
        d.load_tnt(0);
        assert_eq!(d.tnt_count, 0);
        assert_eq!(d.stats.bad_packets, 1);
    }

    #[test]
    fn long_tnt_carries_up_to_47_outcomes() {
        // 0x02 0xa3 + 6 payload bytes, stop bit at bit 47.
        let mut t = vec![OPC_EXT, EXT_TNT64];
        t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
        let s = scan(&t);
        assert_eq!(s.len, 8);
        match s.pkt {
            Pkt::Tnt64 { payload } => assert_eq!(payload, 1u64 << 47),
            other => panic!("expected long TNT, got {other:?}"),
        }
        let mut d = decoder(&t);
        d.run();
        assert_eq!(d.tnt_count, 47);
    }

    // ── the one-byte-skip aliasing bug ───────────────────────────────────────

    #[test]
    fn tsc_payload_does_not_alias_into_tip_or_tnt() {
        // TSC is 0x19 + 7 payload bytes. Byte 0x8d inside that payload has
        // (0x8d & 0x1f) == 0x0d (TIP) with IPBytes = 4, so a one-byte skip
        // would consume six payload bytes as an address and emit a kernel PC
        // that never executed.
        let trace = [0x19, 0x8d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let s = scan(&trace);
        assert_eq!(s.pkt, Pkt::Skip);
        assert_eq!(s.len, 8, "TSC is 8 bytes: opcode + 7 payload");

        let mut d = decoder(&trace);
        let n = d.run();
        assert_eq!(n, 0, "no PC may be emitted from a TSC payload");
        assert!(d.out.is_empty());
        assert_eq!(d.ip, 0, "last IP must be untouched");
        assert_eq!(d.stats.bad_packets, 0);
    }

    #[test]
    fn psbend_second_byte_does_not_alias_into_tnt() {
        // PSBEND is 0x02 0x23. Skipping the 0x02 alone leaves 0x23, whose low
        // five bits are 0x03 — not a TIP opcode — so the old decoder read it
        // as a short TNT of four bits.
        let trace = [OPC_EXT, EXT_PSBEND];
        assert_eq!(scan(&trace).pkt, Pkt::Skip);
        assert_eq!(scan(&trace).len, 2);

        let mut d = decoder(&trace);
        d.run();
        assert_eq!(d.tnt_count, 0, "PSBEND must not load any TNT bits");
        assert_eq!(d.pos, 2);
    }

    #[test]
    fn mode_is_two_bytes_not_sixteen() {
        // The old TIP-only path skipped 16 bytes on `0x99 0x01` — 16 is the
        // PSB length, MODE.Exec is 2 bytes. A real TIP after it was lost.
        let mut t = vec![OPC_MODE, 0x01];
        // 0x6d: (0x6d & 0x1f) == 0x0d → TIP, IPBytes = 3 → 6-byte payload,
        // bit 47 set so it sign-extends into the kernel half.
        t.extend_from_slice(&[0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
        assert_eq!(scan(&t).len, 2);

        let mut out = String::new();
        let n = tip_only_decode(&t, &mut out);
        assert_eq!(n, 1, "the TIP after a MODE packet must be decoded");
        assert_eq!(out.trim(), "0xffff800000000000");
    }

    // ── the length table ─────────────────────────────────────────────────────

    #[test]
    fn packet_lengths_match_the_sdm() {
        let big = [0xffu8; 32];
        let ext = |e: u8| {
            let mut v = vec![OPC_EXT, e];
            v.extend_from_slice(&big);
            v
        };
        let cases: &[(Vec<u8>, usize)] = &[
            (vec![OPC_PAD], 1),
            (vec![0x5a], 1),               // TNT8
            (ext(EXT_PSB), 16),
            (ext(EXT_PSBEND), 2),
            (ext(EXT_TNT64), 8),           // 2 + 6
            (ext(EXT_PIP), 8),             // 2 + 6
            (ext(EXT_OVF), 2),
            (ext(EXT_CBR), 4),             // 2 + 2
            (ext(EXT_TMA), 7),             // 2 + 5
            (ext(EXT_STOP), 2),
            (ext(EXT_VMCS), 7),            // 2 + 5
            (ext(EXT_EXSTOP), 2),
            (ext(EXT_EXSTOP_IP), 2),
            (ext(EXT_MWAIT), 12),          // 2 + 10
            (ext(EXT_PWRE), 4),            // 2 + 2
            (ext(EXT_PWRX), 7),            // 2 + 5
            (ext(EXT_CFE), 4),             // 2 + 2
            (ext(EXT_EVD), 9),             // 2 + 7
            (ext(EXT_BEP), 2),
            (ext(EXT_BEP_IP), 2),
            (vec![OPC_MODE, 0x01], 2),     // 1 + 1
            (vec![OPC_TSC, 0, 0, 0, 0, 0, 0, 0], 8),  // 1 + 7
            (vec![OPC_MTC, 0x00], 2),      // 1 + 1
        ];
        for (bytes, want) in cases {
            let s = scan_packet(bytes, 0, None);
            assert_eq!(s.len, *want, "wrong length for {:02x?}", &bytes[..2.min(bytes.len())]);
            assert!(!matches!(s.pkt, Pkt::Bad | Pkt::Truncated));
        }
        // MNT is a three-byte opcode: 0x02 0xc3 0x88 + 8 payload.
        let mut mnt = vec![OPC_EXT, EXT_EXT2, EXT2_MNT];
        mnt.extend_from_slice(&big);
        assert_eq!(scan_packet(&mnt, 0, None).len, 11);
    }

    #[test]
    fn ip_packet_lengths_follow_the_ipbytes_field() {
        // IPBytes → payload size, for each of the four IP-bearing opcodes.
        let want: &[(u8, Option<usize>)] = &[
            (0, Some(0)),
            (1, Some(2)),
            (2, Some(4)),
            (3, Some(6)),
            (4, Some(6)),
            (5, None), // reserved
            (6, Some(8)),
            (7, None), // reserved
        ];
        for opc in [OPC_TIP, OPC_FUP, OPC_TIP_PGE, OPC_TIP_PGD] {
            for (enc, payload) in want {
                let mut t = vec![opc | (enc << 5)];
                t.extend_from_slice(&[0u8; 8]);
                let s = scan_packet(&t, 0, None);
                match payload {
                    Some(n) => {
                        assert_eq!(s.len, 1 + n, "opcode {opc:#04x} enc {enc}");
                        assert_eq!(s.pkt, Pkt::Ip { opcode: opc, enc: *enc });
                    }
                    None => assert_eq!(
                        s.pkt, Pkt::Bad,
                        "reserved IPBytes {enc} must not be decoded"
                    ),
                }
            }
        }
    }

    #[test]
    fn cyc_length_follows_the_exp_chain() {
        // Byte 0: bits 1:0 = 0b11, bit 2 = EXP. Continuation bytes: bit 0 = EXP.
        assert_eq!(scan(&[0b1111_1011]).len, 1, "EXP clear → 1 byte");
        assert_eq!(scan(&[0b1111_1111, 0b1111_1110]).len, 2, "one continuation");
        assert_eq!(
            scan(&[0b0000_0111, 0b0000_0001, 0b0000_0000]).len,
            3,
            "two continuations"
        );
        // An EXP chain that never terminates is malformed, not an infinite loop.
        let runaway = [0xffu8; 32];
        assert_eq!(scan(&runaway).pkt, Pkt::Bad);
    }

    #[test]
    fn ptw_length_comes_from_its_payload_code() {
        let pad = [0u8; 16];
        for (plc, payload) in [(0u8, 4usize), (1, 8)] {
            let mut t = vec![OPC_EXT, EXT_PTW | (plc << 5)];
            t.extend_from_slice(&pad);
            assert_eq!(scan_packet(&t, 0, None).len, 2 + payload);
        }
        for plc in [2u8, 3] {
            let mut t = vec![OPC_EXT, EXT_PTW | (plc << 5)];
            t.extend_from_slice(&pad);
            assert_eq!(scan_packet(&t, 0, None).pkt, Pkt::Bad, "reserved PLC {plc}");
        }
    }

    #[test]
    fn bip_width_comes_from_the_governing_bbp() {
        // BBP payload bit 7 selects 8-byte BIPs.
        let narrow = [OPC_EXT, EXT_BBP, 0x00];
        let wide = [OPC_EXT, EXT_BBP, 0x80];
        assert_eq!(scan(&narrow).pkt, Pkt::Bbp { wide: false });
        assert_eq!(scan(&wide).pkt, Pkt::Bbp { wide: true });
        assert_eq!(scan(&narrow).len, 3);
        assert_eq!(scan(&[OPC_EXT, EXT_BEP]).pkt, Pkt::Bep);

        let bip = [OPC_BIP, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(scan_packet(&bip, 0, Some(4)).len, 5);
        assert_eq!(scan_packet(&bip, 0, Some(8)).len, 9);

        // The decoder opens the block, sizes the BIP from it, and closes it.
        let mut t = wide.to_vec();
        t.extend_from_slice(&bip);
        t.extend_from_slice(&[OPC_EXT, EXT_BEP]);
        let mut d = decoder(&t);
        d.run();
        assert_eq!(d.block, None, "BEP must close the block");
        assert_eq!(d.pos, 3 + 9 + 2);
        assert_eq!(d.stats.bad_packets, 0);
    }

    #[test]
    fn no_defined_packet_ever_reports_zero_length() {
        // A zero-length Skip would spin the run loop forever.
        let mut buf = [0u8; 64];
        for b in 0u16..=255 {
            buf[0] = b as u8;
            for e in 0u16..=255 {
                buf[1] = e as u8;
                for block in [None, Some(4), Some(8)] {
                    let s = scan_packet(&buf, 0, block);
                    match s.pkt {
                        Pkt::Bad | Pkt::Truncated => assert_eq!(s.len, 0),
                        _ => assert!(s.len >= 1, "{b:#04x} {e:#04x} reported len 0"),
                    }
                }
            }
        }
    }

    // ── resynchronization ────────────────────────────────────────────────────

    #[test]
    fn psb_is_found_and_bad_packets_resync_to_it() {
        assert_eq!(find_psb(&PSB, 0), Some(0));
        assert_eq!(find_psb(&[0u8; 8], 0), None);

        let mut t = vec![0x05]; // odd, undefined → Bad
        t.extend_from_slice(&[0xff; 7]);
        let psb_at = t.len();
        t.extend_from_slice(&PSB);
        t.push(OPC_PAD);

        assert_eq!(find_psb(&t, 1), Some(psb_at));

        let mut d = decoder(&t);
        d.run();
        assert_eq!(d.stats.bad_packets, 1);
        assert_eq!(d.stats.resyncs, 1);
        assert_eq!(d.pos, t.len(), "decode resumed at the PSB and ran to the end");
    }

    #[test]
    fn a_bad_packet_with_no_following_psb_ends_the_decode() {
        let t = [0x05u8, 0xff, 0xff];
        let mut d = decoder(&t);
        d.run();
        assert_eq!(d.stats.bad_packets, 1);
        assert_eq!(d.stats.resyncs, 0);
    }

    #[test]
    fn truncated_packets_stop_the_decode_rather_than_misreading() {
        // TSC with only three of its seven payload bytes present.
        let t = [OPC_TSC, 0x11, 0x22, 0x33];
        assert_eq!(scan(&t).pkt, Pkt::Truncated);
        let mut d = decoder(&t);
        assert_eq!(d.run(), 0);
        assert!(d.stats.truncated);

        // A lone extended opcode at the very end.
        assert_eq!(scan(&[OPC_EXT]).pkt, Pkt::Truncated);
        // A TIP whose address payload is cut short.
        assert_eq!(scan(&[OPC_TIP | (6 << 5), 0x01, 0x02]).pkt, Pkt::Truncated);
    }

    // ── synchronization and overflow semantics ───────────────────────────────

    #[test]
    fn psb_and_ovf_drop_pending_tnt() {
        // TNT8, then PSB: the outcomes cannot be placed across the sync point.
        let mut t = vec![0x5a];
        t.extend_from_slice(&PSB);
        let mut d = decoder(&t);
        d.run();
        assert_eq!(d.tnt_count, 0, "PSB must drop pending TNT");

        // OVF also invalidates the last IP.
        let mut t = vec![OPC_TIP | (6 << 5)];
        t.extend_from_slice(&0xffff_8000_0012_3456u64.to_le_bytes());
        t.extend_from_slice(&[0x5a, OPC_EXT, EXT_OVF]);
        let mut d = decoder(&t);
        assert_eq!(d.run(), 1, "the TIP before the overflow is real coverage");
        assert_eq!(d.stats.overflows, 1);
        assert_eq!(d.ip, 0, "OVF must invalidate the last IP");
        assert_eq!(d.tnt_count, 0);
    }

    // ── end to end ───────────────────────────────────────────────────────────

    #[test]
    fn a_realistic_stream_decodes_to_exactly_its_ip_packets() {
        // PSB, CBR, TSC, MODE.Exec, TIP.PGE (full IP), PAD, TNT8, TIP
        // (2-byte update), MTC, TIP.PGD, PSBEND.
        let mut t = Vec::new();
        t.extend_from_slice(&PSB);
        t.extend_from_slice(&[OPC_EXT, EXT_CBR, 0x2a, 0x00]);
        t.extend_from_slice(&[OPC_TSC, 1, 2, 3, 4, 5, 6, 7]);
        t.extend_from_slice(&[OPC_MODE, 0x19]);
        t.push(OPC_TIP_PGE | (6 << 5));
        t.extend_from_slice(&0xffff_ffff_8100_1000u64.to_le_bytes());
        t.push(OPC_PAD);
        t.push(0x5a); // TNT8
        t.extend_from_slice(&[OPC_TIP | (1 << 5), 0x34, 0x12]); // low 16 bits
        t.extend_from_slice(&[OPC_MTC, 0x08]);
        t.push(OPC_TIP_PGD | (0 << 5)); // IP suppressed, 1 byte
        t.extend_from_slice(&[OPC_EXT, EXT_PSBEND]);

        let mut d = decoder(&t);
        let n = d.run();

        assert_eq!(d.pos, t.len(), "every packet consumed by its true length");
        assert_eq!(d.stats.bad_packets, 0);
        assert_eq!(d.stats.overflows, 0);
        assert!(!d.stats.truncated);
        assert_eq!(n, 2, "only the two IP-bearing packets emit a PC");
        let pcs: Vec<&str> = d.out.lines().collect();
        assert_eq!(pcs, vec!["0xffffffff81001000", "0xffffffff81001234"]);

        // Same stream through the TIP-only path.
        let mut out = String::new();
        assert_eq!(tip_only_decode(&t, &mut out), 2);
        assert_eq!(out.lines().collect::<Vec<_>>(), pcs);
    }

    #[test]
    fn decode_terminates_on_arbitrary_bytes() {
        // Pseudo-random noise must neither spin nor panic.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut t = Vec::with_capacity(8192);
        for _ in 0..8192 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            t.push((x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8);
        }
        let mut d = decoder(&t);
        d.run();
        let mut out = String::new();
        tip_only_decode(&t, &mut out);
    }
}

