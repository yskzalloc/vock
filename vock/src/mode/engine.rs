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

// ─── TIP-only decode (intel_pt.c fallback path) ──────────────────────────────

/// Port of the `tip_only` loop in intel_pt_decode(): follow TIP/FUP last-IP
/// updates only (no TNT following), emitting kernel PCs. Returns the count.
fn tip_only_decode(data: &[u8], out: &mut String) -> i32 {
    let len = data.len();
    let mut last_ip: u64 = 0;
    let mut pos: usize = 0;
    let mut pc_count: i32 = 0;

    while pos < len {
        let b = data[pos];
        let opcode = b & 0x1f;
        let mut ip_bytes: usize = 0;

        if opcode == 0x0d || opcode == 0x1d || opcode == 0x11 || opcode == 0x01 {
            let enc = (b >> 5) & 0x7;
            match enc {
                1 => ip_bytes = 2,
                2 => ip_bytes = 4,
                3 | 4 => ip_bytes = 6,
                6 => ip_bytes = 8,
                _ => {}
            }
            if ip_bytes > 0 && pos + 1 + ip_bytes <= len {
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
                pos += 1 + ip_bytes;
                continue;
            }
        }

        if b == 0x99 && pos + 1 < len && data[pos + 1] == 0x01 {
            pos += 16;
        } else {
            pos += 1;
        }
    }

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

    /// Port of pt_decoder_run(): the main packet state machine.
    fn run(&mut self) -> i32 {
        self.pos = 0;
        self.ip = 0;
        self.tnt_count = 0;
        self.pc_count = 0;

        while self.pos < self.trace_len {
            let b = self.trace[self.pos];
            self.pos += 1;

            // PAD
            if b == 0x00 {
                continue;
            }

            // Short TNT: bit 0 set, and not a TIP/FUP opcode nor 0x99.
            if (b & 0x01) != 0
                && b != 0x99
                && (b & 0x1f) != 0x0d
                && (b & 0x1f) != 0x1d
                && (b & 0x1f) != 0x11
                && (b & 0x1f) != 0x01
            {
                let payload = b >> 1;
                let mut bits: i32 = 0;
                let mut tmp = payload;
                while tmp > 1 {
                    tmp >>= 1;
                    bits += 1;
                }
                self.tnt_bits =
                    (payload as u32 & ((1u32 << bits) - 1)) as u64;
                self.tnt_count = bits;
                if !self.text.is_empty() && self.ip != 0 {
                    self.walk_tnt();
                }
                continue;
            }

            // PSB (0x02 0x82): skip the full 16-byte packet.
            if b == 0x02 && self.pos < self.trace_len && self.trace[self.pos] == 0x82 {
                self.pos += 15;
                continue;
            }

            // TIP / FUP / TIP.PGE / TIP.PGD
            let opcode = b & 0x1f;
            if opcode == 0x0d || opcode == 0x1d || opcode == 0x11 || opcode == 0x01 {
                let enc = (b >> 5) & 0x7;
                if enc > 0 {
                    self.pt_read_ip(enc);
                    let ip = self.ip;
                    self.emit_ip(ip);
                    // After a TIP, resume walking with any pending TNT.
                    if !self.text.is_empty() && self.tnt_count > 0 {
                        self.walk_tnt();
                    }
                }
                continue;
            }

            // Long TNT (0x02 0xA3): 6-byte payload.
            if b == 0x02 && self.pos < self.trace_len && self.trace[self.pos] == 0xa3 {
                self.pos += 1;
                if self.pos + 6 <= self.trace_len {
                    let mut payload: u64 = 0;
                    for i in 0..6 {
                        payload |= (self.trace[self.pos] as u64) << (8 * i);
                        self.pos += 1;
                    }
                    let mut bits: i32 = 0;
                    let mut tmp = payload;
                    while tmp > 1 {
                        tmp >>= 1;
                        bits += 1;
                    }
                    self.tnt_bits = payload & ((1u64 << bits) - 1);
                    self.tnt_count = bits;
                    if !self.text.is_empty() && self.ip != 0 {
                        self.walk_tnt();
                    }
                }
                continue;
            }

            // Skip other packets.
        }

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
