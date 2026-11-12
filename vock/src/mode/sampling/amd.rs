//! AMD `--mode hw` backend (x86_64): LBR branch-stack + IBS op sampling.
//!
//! Port of mode/amd_lbr.c. Two concurrent perf events, merged at decode:
//!
//! * LBR branch stacks (cycles clock, 10 kHz): 16 taken branches per PMI -
//!   the breadth. A tight period is degenerate here (the counter re-arms
//!   instantly, or unthrottles on the tick, and every snapshot captures the
//!   same 16-branch PMI entry window); frequency mode spreads snapshots
//!   across the target's real kernel work.
//! * IBS op (`ibs_op` PMU, 10 kHz): precise instruction-based sampling. The
//!   rip of IBS samples has skid 0 (arch/x86/events/amd/ibs.c), each sample
//!   is a retired op, and the hardware randomizes the sample interval,
//!   decorrelating it from the LBR PMI clock.
//!
//! Alone, IBS yields ~1 PC per sample vs LBR's ~32 (measured: 21 vs ~500
//! unique PCs on the same run), so it complements rather than replaces LBR.
//! Guests get neither (KVM virtualizes neither facility) and fall back to
//! plain IP sampling.
//!
//! Every event is opened per CPU and inherited by the target's descendants
//! (see mode::perf).

use std::io::Write;

use crate::mode::perf::{coverage_scope, open_rings, pmu_type, read_u64, write_u64};
use crate::mode::perf::{PerfEventAttr, Ring};
use crate::mode::perf::{
    ATTR_DISABLED, ATTR_EXCLUDE_USER, ATTR_FREQ, OFF_DATA_HEAD, OFF_DATA_TAIL, PAGE_SIZE,
    PERF_COUNT_HW_CPU_CYCLES, PERF_RECORD_SAMPLE, PERF_SAMPLE_BRANCH_ANY,
    PERF_SAMPLE_BRANCH_KERNEL, PERF_SAMPLE_BRANCH_STACK, PERF_SAMPLE_IP, PERF_SAMPLE_TIME,
    PERF_TYPE_HARDWARE,
};

/// Sample-ring data pages per CPU (amd_lbr.c: MMAP_PAGES, larger ring).
const MMAP_PAGES: usize = 128;

/// Lowest kernel address on x86_64 (canonical upper half).
const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;

/// Whether this is an AMD CPU.
pub fn available() -> bool {
    match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s.contains("AuthenticAMD"),
        Err(_) => false,
    }
}

/// An armed AMD session.
pub struct Amd {
    /// The LBR (or IP-sampling fallback) event, one per CPU.
    rings: Vec<Ring>,
    /// IBS op precise sampling running alongside the LBR event; empty when
    /// the PMU is absent. Both are decoded and merged - IBS contributes
    /// skid-0 retired-op rips, LBR contributes 16-branch breadth per PMI.
    ibs: Vec<Ring>,
}

impl Amd {
    /// Port of amd_lbr_start(), one event (pair) per CPU.
    pub fn start(pid: libc::pid_t) -> Option<Amd> {
        let lbr_attr = PerfEventAttr {
            config: PERF_COUNT_HW_CPU_CYCLES,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_USER | ATTR_FREQ,
            sample_period_or_freq: 10_000, // Hz; clear of the PMI throttle
            sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME | PERF_SAMPLE_BRANCH_STACK,
            branch_sample_type: PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_ANY,
            wakeup: 1,
            ..PerfEventAttr::kernel_only(PERF_TYPE_HARDWARE)
        };
        let map = |fd, cpu| Ring::sample(fd, cpu, MMAP_PAGES, "amd hw");

        let rings = match open_rings("amd_lbr", &lbr_attr, pid, map) {
            Ok(r) => r,
            Err(e) => {
                // Fallback: IP-only cycle sampling. Reached on kernels without
                // LBR and notably inside KVM guests, where AMD branch stacks
                // (BRS / LbrExtV2) are not virtualized. Statistical IP samples
                // are sparse and biased toward interrupt/exception entry code,
                // so say so instead of quietly producing a misleading report.
                eprintln!(
                    "amd_lbr: branch-stack sampling unavailable ({e}); falling back to \
IP sampling every 4000 kernel cycles"
                );
                eprintln!(
                    "amd_lbr: expect sparse, interrupt-biased coverage - KVM guests do not \
virtualize AMD branch stacks; use --mode kcov in VMs, or run on bare metal for real LBR"
                );
                let attr = PerfEventAttr {
                    config: PERF_COUNT_HW_CPU_CYCLES,
                    sample_period_or_freq: 4000,
                    sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME,
                    wakeup: 1,
                    ..PerfEventAttr::kernel_only(PERF_TYPE_HARDWARE)
                };
                match open_rings("amd_lbr", &attr, pid, map) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("amd_lbr: perf_event_open (fallback): {e}");
                        return None;
                    }
                }
            }
        };

        // Secondary: IBS op, when the PMU exists (bare metal only).
        // exclude_user is filtered in the IBS IRQ handler on recent kernels
        // and rejected with EINVAL on older ones - retry without it; the
        // decoder keeps only kernel addresses anyway. IBS must cover the
        // same tasks as the primary event, or the merged log would weight
        // some CPUs/tasks with precise samples and not others: keep it only
        // when it armed exactly as many CPUs.
        let mut ibs = Vec::new();
        if let Some(t) = pmu_type("ibs_op") {
            for flags in [
                ATTR_DISABLED | ATTR_FREQ | ATTR_EXCLUDE_USER,
                ATTR_DISABLED | ATTR_FREQ,
            ] {
                let attr = PerfEventAttr {
                    config: 0,
                    flags,
                    sample_period_or_freq: 10_000, // Hz
                    sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TIME,
                    wakeup: 1,
                    ..PerfEventAttr::kernel_only(t)
                };
                if let Ok(r) = open_rings("amd ibs", &attr, pid, map) {
                    if r.len() == rings.len() {
                        eprintln!("amd hw: + IBS op precise sampling (skid 0, retired ops)");
                        ibs = r;
                    } else {
                        eprintln!(
                            "amd hw: IBS armed on {}/{} CPUs, not used",
                            r.len(),
                            rings.len()
                        );
                    }
                    break;
                }
            }
        }

        for r in rings.iter().chain(ibs.iter()) {
            r.enable();
        }
        eprintln!("[vock] amd hw: tracing {}", coverage_scope(&rings));
        Some(Amd { rings, ibs })
    }

    /// Port of vock_hw_trace_stop().
    pub fn stop(&mut self) {
        for r in self.rings.iter().chain(self.ibs.iter()) {
            r.disable();
        }
    }

    /// Port of amd_lbr_decode(): write kerncov.log (one "0x<pc>" per line).
    pub fn decode(&mut self) {
        // Chronological merge: every event samples PERF_SAMPLE_TIME, so the
        // per-CPU LBR/IP streams and the IBS streams interleave by timestamp
        // instead of being concatenated. Within one LBR sample perf orders
        // the branch entries newest-first; they are reversed here so the log
        // reads oldest-to-newest. kerncov.log is therefore a true execution
        // sequence (duplicates preserved) - the normal report dedups it,
        // and --ordered renders it as-is.
        let mut samples: Vec<(u64, Vec<u64>)> = Vec::new();
        for r in self.rings.iter().chain(self.ibs.iter()) {
            drain_sample_ring(r.base, r.size, &mut samples);
        }
        // Stable: equal timestamps keep ring order.
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
}

/// Drain one perf sample ring into timestamped samples. Record layout
/// (sample_type = IP | TIME [| BRANCH_STACK]): header, ip, time, then
/// optionally nr + nr x {from, to, flags}. Kernel addresses only; branch
/// entries are reversed to oldest-first (perf returns them newest-first).
fn drain_sample_ring(base: *mut libc::c_void, mmap_size: usize, samples: &mut Vec<(u64, Vec<u64>)>) {
    let head = unsafe { read_u64(base, OFF_DATA_HEAD) };
    let mut tail = unsafe { read_u64(base, OFF_DATA_TAIL) };
    let data_size = (mmap_size - PAGE_SIZE) as u64;
    let ring = unsafe { (base as *const u8).add(PAGE_SIZE) };

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
                    if from >= KERNEL_BASE {
                        pcs.push(from);
                    }
                    if to >= KERNEL_BASE {
                        pcs.push(to);
                    }
                }
            }
            // The sampled ip itself is the newest point in the record.
            if ip >= KERNEL_BASE {
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
