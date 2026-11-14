//! Arm CoreSight ETMv4 `--mode hw` backend (aarch64).
//!
//! Captures kernel-only ETMv4 instruction trace across all online CPUs using
//! inherited per-CPU `cs_etm` perf events (`PerfEventAttr::kernel_only` +
//! `ATTR_INHERIT`), saves `hw_trace.cpu<N>.bin` and `hw_trace.meta`, and
//! decodes formatted CoreSight trace into timestamp-merged `kerncov.log`.

use super::{
    clear_raw_traces, load_vmlinux_text, merge_streams, save_raw_trace, write_kerncov, Stream,
};
use crate::mode::perf::{
    coverage_scope, open_rings, perf_event_open, pmu_config_bit, pmu_config_range, pmu_exists,
    pmu_type, read_u64, write_u64, PerfEventAttr, Ring, OFF_DATA_HEAD, OFF_DATA_TAIL, PAGE_SIZE,
    PERF_AUX_FLAG_COLLISION, PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW, PERF_AUX_FLAG_OVERWRITE,
    PERF_AUX_FLAG_PARTIAL, PERF_AUX_FLAG_TRUNCATED, PERF_EVENT_IOC_SET_FILTER, PERF_RECORD_AUX,
    PERF_RECORD_AUX_OUTPUT_HW_ID, PERF_RECORD_LOST,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

const PMU: &str = "cs_etm";

/// 64 data pages (256 KiB) per CPU holds up to 8,192 32-byte `PERF_RECORD_AUX`
/// records before overflowing, avoiding `PERF_RECORD_LOST` on workloads with
/// frequent context switches or ETF drains.
const CS_DATA_PAGES: usize = 64;

// ETMv4 TRCCONFIGR bit positions (ARM IHI 0064 / drivers/hwtracing/coresight/coresight-etm4x.h).
const ETM4_CFG_BIT_CYCACC: u32 = 4;
const ETM4_CFG_BIT_CTXTID: u32 = 6;
const ETM4_CFG_BIT_VMID: u32 = 7;
const ETM4_CFG_BIT_TS: u32 = 11;
const ETM4_CFG_BIT_RETSTK: u32 = 12;
const ETM4_CFG_BIT_VMID_OPT: u32 = 15;

/// One `PERF_RECORD_AUX` record drained from a CPU's perf data ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuxRecord {
    pub(crate) cpu: i32,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) flags: u64,
}

/// Per-CPU ETMv4 hardware registers read from `/sys/bus/coresight/devices/etm<N>/`
/// (or loaded from `hw_trace.meta` for offline decoding).
#[derive(Debug, Clone, Default)]
pub(crate) struct EtmCpuMeta {
    pub(crate) cpu: i32,
    pub(crate) trace_id: u8,
    pub(crate) trcidr0: u32,
    pub(crate) trcidr1: u32,
    pub(crate) trcidr2: u32,
    pub(crate) trcidr3: u32,
    pub(crate) trcidr4: u32,
    pub(crate) trcidr5: u32,
    pub(crate) trcidr8: u32,
    pub(crate) trcidr9: u32,
    pub(crate) trcidr10: u32,
    pub(crate) trcidr11: u32,
    pub(crate) trcidr12: u32,
    pub(crate) trcidr13: u32,
    pub(crate) trcconfig: u32,
    pub(crate) trctraceid: u32,
    pub(crate) trcdevarch: u32,
    pub(crate) aux_size: usize,
    pub(crate) lost: u64,
}

/// Complete CoreSight capture state (live session or loaded from `hw_trace.meta` + `hw_trace.cpu*.bin`).
#[derive(Debug, Clone, Default)]
pub(crate) struct CsCapture {
    pub(crate) uname: String,
    pub(crate) runtime_text: u64,
    pub(crate) runtime_stext: u64,
    pub(crate) sink_name: String,
    pub(crate) sink_id: u32,
    pub(crate) sink_buffer_size: usize,
    pub(crate) attr_config: u64,
    pub(crate) etm_config: u32,
    pub(crate) addr_filter: String,
    pub(crate) cpus: Vec<EtmCpuMeta>,
    pub(crate) aux_records: Vec<AuxRecord>,
    /// Raw AUX buffer bytes per CPU (indexed matching `cpus`).
    pub(crate) aux_bufs: Vec<(i32, Vec<u8>)>,
}

/// Whether the CoreSight ETM/ETE PMU is registered.
pub fn available() -> bool {
    pmu_exists(PMU)
}

/// An armed CoreSight session: one AUX-carrying event per CPU.
pub struct CoreSight {
    rings: Vec<Ring>,
    sink_name: String,
    sink_id: u32,
    sink_buffer_size: usize,
    attr_config: u64,
    etm_config: u32,
    addr_filter: String,
    drain_stop: Option<Arc<AtomicBool>>,
    drain_thread: Option<JoinHandle<()>>,
}

impl CoreSight {
    /// Open per-CPU inherited `cs_etm` events on `pid`, configure the sink and
    /// ETMv4 address range comparator (`PERF_EVENT_IOC_SET_FILTER`), and enable them.
    pub fn start(
        pid: libc::pid_t,
        vmlinux: Option<&str>,
        filter: Option<&str>,
        target_bin: Option<&str>,
    ) -> Option<CoreSight> {
        let Some(type_) = pmu_type(PMU) else {
            eprintln!("cs_etm: cannot read PMU type");
            return None;
        };

        let mut attr = PerfEventAttr::kernel_only(type_);
        if std::env::var("VOCK_CS_USERSPACE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            // Allow tracing userspace when explicitly requested with @<binary>.
            attr.flags &= !(1u64 << 4); // clear ATTR_EXCLUDE_USER
            attr.flags |= 1u64 << 5; // set ATTR_EXCLUDE_KERNEL
        }

        let Some((sink_name, sink_id)) = select_sink(&attr) else {
            eprintln!("cs_etm: no usable sink under /sys/bus/event_source/devices/cs_etm/sinks");
            return None;
        };
        apply_sink_id(&mut attr, sink_id);
        let sink_buffer_size = read_sink_buffer_size(&sink_name);
        let is_small_etf = sink_name.starts_with("tmc_etf")
            || sink_name.starts_with("tmc_etb")
            || (sink_buffer_size > 0 && sink_buffer_size <= 64 * 1024);

        let mut etm_config: u32 = 0;

        // On small on-chip SRAM sinks (`tmc_etf0`), the hardware timestamp
        // counter may be unclocked (reads 0) or emit a 2..10 byte `Timestamp`
        // packet after every single branch, forcing ETMv4 to flush 1-atom `F1`
        // packets (`0xf6, 0x02, 0x00, ...`) instead of packing up to 24
        // conditional branches into a single `Atom F2..F6` byte.
        // For example: on AMD Kria KV260 (ZynqMP), `tmc_etf0` has a 4 KiB SRAM
        // buffer and an unclocked timestamp counter that emits `0x02, 0x00`
        // after every branch. Omit `ETM_OPT_TS` by default on `tmc_etf*`
        // (equivalent to timeless `Z` mode in `perf script --itrace=Zi1`)
        // unless explicitly requested via `VOCK_CS_TIMESTAMP=1`.
        let want_ts = match std::env::var("VOCK_CS_TIMESTAMP") {
            Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
            Err(_) => !is_small_etf,
        };
        if want_ts {
            if let Some(bit) = pmu_config_bit(PMU, "timestamp") {
                attr.config |= 1u64 << bit;
                etm_config |= 1u32 << ETM4_CFG_BIT_TS;
            }
        }
        if let Some(bit) = pmu_config_bit(PMU, "contextid") {
            attr.config |= 1u64 << bit;
            if Some(bit) == pmu_config_bit(PMU, "contextid2") {
                etm_config |= (1u32 << ETM4_CFG_BIT_VMID) | (1u32 << ETM4_CFG_BIT_VMID_OPT);
            } else {
                etm_config |= 1u32 << ETM4_CFG_BIT_CTXTID;
            }
        }
        if let Some(bit) = pmu_config_bit(PMU, "cycacc") {
            if (attr.config & (1u64 << bit)) != 0 {
                etm_config |= 1u32 << ETM4_CFG_BIT_CYCACC;
            }
        }
        if let Some(bit) = pmu_config_bit(PMU, "retstack") {
            if (attr.config & (1u64 << bit)) != 0 {
                etm_config |= 1u32 << ETM4_CFG_BIT_RETSTK;
            }
        }

        let rings = match open_rings(PMU, &attr, pid, |fd, cpu| {
            Ring::aux_with_data_pages(fd, cpu, CS_DATA_PAGES, PMU)
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("cs_etm: perf_event_open (sink {sink_name}=0x{sink_id:x}): {e}");
                return None;
            }
        };

        let uname = read_uname_r();
        let (_runtime_text, runtime_stext) = read_runtime_text_addrs(&uname);
        let addr_filter = build_coresight_addr_filter(
            &sink_name,
            sink_buffer_size,
            filter,
            &uname,
            vmlinux,
            target_bin,
            runtime_stext,
        )
        .unwrap_or_default();

        if !addr_filter.is_empty() {
            let mut applied = 0usize;
            for r in &rings {
                if r.set_filter(&addr_filter).is_ok() {
                    applied += 1;
                }
            }
            if applied > 0 {
                eprintln!(
                    "[vock] cs_etm: applied ETMv4 IP filter ({applied}/{} ring(s)): {addr_filter}",
                    rings.len()
                );
            } else {
                eprintln!(
                    "[vock] cs_etm: warning: PERF_EVENT_IOC_SET_FILTER rejected '{addr_filter}'; continuing unfiltered"
                );
            }
        }

        for r in &rings {
            r.enable();
        }
        eprintln!(
            "[vock] cs_etm: tracing {} via sink {} (0x{:x}, buffer={} KiB{})",
            coverage_scope(&rings),
            sink_name,
            sink_id,
            sink_buffer_size / 1024,
            if want_ts { ", timestamped" } else { ", timeless-Z" }
        );

        // Optional periodic ETF drain for small on-chip SRAM sinks (`tmc_etf*`,
        // enabled via `VOCK_CS_PERIODIC_DRAIN=1`).
        // For example: on AMD Kria KV260 (`tmc_etf0`, 4 KiB SRAM), re-applying
        // `PERF_EVENT_IOC_SET_FILTER` triggers `perf_event_stop(event, 1)` on
        // active CPUs to flush ETF SRAM into the 4 MiB DRAM AUX ring mid-run.
        let want_drain = std::env::var("VOCK_CS_PERIODIC_DRAIN")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let (drain_stop, drain_thread) = if want_drain && is_small_etf && !addr_filter.is_empty() {
            let stop_flag = Arc::new(AtomicBool::new(false));
            let stop_clone = Arc::clone(&stop_flag);
            let fds: Vec<i32> = rings.iter().map(|r| r.fd).collect();
            let filter_cstr = std::ffi::CString::new(addr_filter.as_str()).ok();
            let handle = std::thread::spawn(move || {
                let Some(cstr) = filter_cstr else { return };
                while !stop_clone.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    for &fd in &fds {
                        unsafe {
                            libc::ioctl(fd, PERF_EVENT_IOC_SET_FILTER as _, cstr.as_ptr());
                        }
                    }
                }
            });
            (Some(stop_flag), Some(handle))
        } else {
            (None, None)
        };

        Some(CoreSight {
            rings,
            sink_name,
            sink_id,
            sink_buffer_size,
            attr_config: attr.config,
            etm_config,
            addr_filter,
            drain_stop,
            drain_thread,
        })
    }

    /// Disable all per-CPU CoreSight events.
    pub fn stop(&mut self) {
        if let Some(flag) = self.drain_stop.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.drain_thread.take() {
            let _ = handle.join();
        }
        for r in &self.rings {
            r.disable();
        }
    }

    /// Drain AUX rings, write `hw_trace.cpu*.bin` and `hw_trace.meta`, and
    /// decode into `kerncov.log`.
    pub fn decode(&mut self, vmlinux: Option<&str>) {
        clear_raw_traces();

        let cap = self.collect_capture();
        for &(cpu, ref data) in &cap.aux_bufs {
            if !data.is_empty() {
                save_raw_trace(cpu, data);
            }
        }
        if let Err(e) = cap.write_meta_file("hw_trace.meta") {
            eprintln!("[vock] cs_etm: failed to write hw_trace.meta: {e}");
        }

        let total_aux_bytes: usize = cap.aux_bufs.iter().map(|(_, b)| b.len()).sum();
        let total_rec_bytes: u64 = cap.aux_records.iter().map(|r| r.size).sum();
        let truncated_recs = cap
            .aux_records
            .iter()
            .filter(|r| (r.flags & PERF_AUX_FLAG_TRUNCATED) != 0)
            .count();
        let overwrite_recs = cap
            .aux_records
            .iter()
            .filter(|r| (r.flags & PERF_AUX_FLAG_OVERWRITE) != 0)
            .count();
        let total_lost: u64 = cap.cpus.iter().map(|c| c.lost).sum();

        if total_lost > 0 {
            eprintln!(
                "[vock] cs_etm: warning: {total_lost} data ring record(s) lost (PERF_RECORD_LOST)"
            );
        }
        if truncated_recs > 0 || overwrite_recs > 0 {
            eprintln!(
                "[vock] cs_etm: sink {} wrapped on {}/{} AUX chunk(s) (buffer_size={} KiB, flags: truncated={}, overwrite={})",
                cap.sink_name,
                truncated_recs + overwrite_recs,
                cap.aux_records.len(),
                cap.sink_buffer_size / 1024,
                truncated_recs,
                overwrite_recs
            );
        }
        eprintln!(
            "[vock] cs_etm: captured {} AUX bytes across {} ring(s) ({} PERF_RECORD_AUX chunk(s), {} chunk bytes)",
            total_aux_bytes,
            cap.aux_bufs.iter().filter(|(_, b)| !b.is_empty()).count(),
            cap.aux_records.len(),
            total_rec_bytes
        );

        let max_ring_bytes = cap.aux_bufs.iter().map(|(_, b)| b.len()).max().unwrap_or(0);
        if cap.sink_name.starts_with("tmc_etr") && max_ring_bytes <= 16 {
            // For example: on AMD Kria KV260 (ZynqMP) with an unpatched kernel,
            // `tmc_etr0` (`0xfe970000`) triggers `MemErr` (`STS=0x0000000C` at
            // `0xfe97000c`) because DDR XMPU / TrustZone rejects the default
            // `AXICTL=0x00000F3E` (`AxPROT[1]=1` Non-secure, `smmu@fd800000`
            // disabled in DT), producing only a 16-byte empty formatter flush frame.
            eprintln!(
                "[vock] cs_etm: warning: sink {} (System DRAM sink) produced only {} bytes (empty formatter flush frame; possible DMA/AXI MemErr). Try --sink tmc_etf0 (On-chip SRAM sink).",
                cap.sink_name, max_ring_bytes
            );
        }

        let text_opt = vmlinux
            .and_then(|vm| {
                let t = load_vmlinux_text(vm);
                if t.is_none() {
                    eprintln!("[vock] cs_etm: vmlinux load failed ({vm}), address-only mode");
                }
                t
            })
            .or_else(|| {
                let default_vm = format!("/lib/modules/{}/build/vmlinux", cap.uname);
                load_vmlinux_text(&default_vm)
            });

        let streams = match &text_opt {
            Some((text, text_vaddr, _)) => cap.decode_to_streams(Some((text, *text_vaddr))),
            None => cap.decode_to_streams(None),
        };
        let non_empty: Vec<Stream> = streams.into_iter().filter(|s| s.pcs > 0).collect();
        let pc_count: i64 = non_empty.iter().map(|s| s.pcs as i64).sum();
        if non_empty.is_empty() {
            eprintln!("[vock] cs_etm: no kernel PCs decoded");
            return;
        }
        if !write_kerncov(&merge_streams(&non_empty)) {
            eprintln!("cs_etm: fopen kerncov.log failed");
            return;
        }
        eprintln!(
            "[vock] cs_etm: {} kernel PCs from {} CPU stream(s) \u{2192} kerncov.log",
            pc_count,
            non_empty.len()
        );
    }

    fn collect_capture(&self) -> CsCapture {
        let uname = read_uname_r();
        let (runtime_text, runtime_stext) = read_runtime_text_addrs(&uname);
        let mut cpus = Vec::with_capacity(self.rings.len());
        let mut aux_records = Vec::new();
        let mut aux_bufs = Vec::with_capacity(self.rings.len());

        for r in &self.rings {
            let mut hw_id: Option<u8> = None;
            let mut lost: u64 = 0;
            drain_aux_ring(r.base, r.size, r.cpu, &mut aux_records, &mut hw_id, &mut lost);

            let data = r.aux_data();
            if data.len() + r.aux_size / 64 >= r.aux_size {
                let label = if r.cpu < 0 {
                    PMU.to_string()
                } else {
                    format!("{PMU} cpu{}", r.cpu)
                };
                eprintln!(
                    "[vock] {label}: AUX area full ({} KiB), later trace on this CPU may be lost",
                    r.aux_size / 1024
                );
            }

            let mut meta = read_etm_cpu_meta(r.cpu, self.etm_config);
            meta.aux_size = r.aux_size;
            meta.lost = lost;
            if let Some(id) = hw_id {
                if (0x01..0x70).contains(&id) {
                    meta.trace_id = id;
                }
            }
            cpus.push(meta);
            aux_bufs.push((r.cpu, data.to_vec()));
        }

        CsCapture {
            uname,
            runtime_text,
            runtime_stext,
            sink_name: self.sink_name.clone(),
            sink_id: self.sink_id,
            sink_buffer_size: self.sink_buffer_size,
            attr_config: self.attr_config,
            etm_config: self.etm_config,
            addr_filter: self.addr_filter.clone(),
            cpus,
            aux_records,
            aux_bufs,
        }
    }
}

/// Apply `sink_id` into `attr` according to `/sys/bus/event_source/devices/cs_etm/format/sinkid`
/// (typically `config2:0-31`).
fn apply_sink_id(attr: &mut PerfEventAttr, sink_id: u32) {
    let (idx, lo, hi) = pmu_config_range(PMU, "sinkid").unwrap_or((2, 0, 31));
    let width = (hi - lo + 1).min(64);
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let val = ((sink_id as u64) & mask) << lo;
    match idx {
        0 => attr.config |= val,
        1 => attr.config1 |= val,
        2 => attr.config2 |= val,
        3 => attr.config3 |= val,
        _ => attr.config2 |= val,
    }
}

/// Priority order for sink selection:
/// 1. `trbe*` (per-CPU Armv9 Trace Buffer Extension)
/// 2. `tmc_etr*` (System DRAM sink, e.g. `tmc_etr0`)
/// 3. `tmc_etf*` (On-chip SRAM FIFO sink, e.g. `tmc_etf0`)
/// 4. `tmc_etb*` (Legacy on-chip trace buffer)
fn sink_priority(name: &str) -> u8 {
    if name.starts_with("trbe") {
        0
    } else if name.starts_with("tmc_etr") {
        1
    } else if name.starts_with("tmc_etf") {
        2
    } else if name.starts_with("tmc_etb") {
        3
    } else {
        4
    }
}

/// Enumerate `/sys/bus/event_source/devices/cs_etm/sinks/*` and choose a
/// working sink. `VOCK_CS_SINK` (`--sink` / `--cs-sink`) overrides automatic
/// selection.
///
/// By default, tries `tmc_etr0` (System DRAM sink) first, and if `probe_sink`
/// detects that `tmc_etr0` fails to capture trace data (`<= 16` bytes),
/// automatically falls back to `tmc_etf0` (On-chip SRAM sink).
/// For example: on AMD Kria KV260 (ZynqMP), `tmc_etr0` (`0xfe970000`) hits
/// `MemErr` (`STS=0x0000000C`) on unpatched kernels due to DDR XMPU / TrustZone
/// rejecting `AXICTL=0x00000F3E` (`AxPROT[1]=1` Non-secure) when `smmu@fd800000`
/// is disabled, so `probe_sink` rejects `tmc_etr0` (16 bytes) and selects
/// `tmc_etf0` (`0xfe940000`).
fn select_sink(base_attr: &PerfEventAttr) -> Option<(String, u32)> {
    let sinks_dir = format!("/sys/bus/event_source/devices/{PMU}/sinks");
    if let Ok(want) = std::env::var("VOCK_CS_SINK") {
        let want = want.trim().trim_start_matches('@');
        if !want.is_empty() {
            if let Some(id) = read_hex_u32(&format!("{sinks_dir}/{want}")) {
                return Some((want.to_string(), id));
            }
            eprintln!(
                "[vock] cs_etm: requested sink '{want}' not found under {sinks_dir}; falling back to auto-select"
            );
        }
    }

    let mut sinks: Vec<(String, u32)> = Vec::new();
    let rd = std::fs::read_dir(&sinks_dir).ok()?;
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = read_hex_u32(&entry.path().to_string_lossy()) {
            sinks.push((name, id));
        }
    }
    if sinks.is_empty() {
        return None;
    }
    sinks.sort_by(|a, b| {
        sink_priority(&a.0)
            .cmp(&sink_priority(&b.0))
            .then_with(|| a.0.cmp(&b.0))
    });

    if sinks.len() == 1 {
        return sinks.into_iter().next();
    }

    // Probe each candidate sink in priority order (`tmc_etr0` first, then
    // `tmc_etf0`) with a brief self-trace to verify the hardware ATB path to
    // that sink delivers ETM trace bytes (> 16-byte empty formatter flush frame).
    for (name, id) in &sinks {
        if probe_sink(base_attr, *id) {
            return Some((name.clone(), *id));
        }
    }
    sinks.into_iter().next()
}

/// Open a short-lived self-trace (`pid = 0, cpu = -1`) on `sink_id` and check
/// whether more than a single 16-byte empty formatter flush frame arrives.
fn probe_sink(base_attr: &PerfEventAttr, sink_id: u32) -> bool {
    let mut attr = *base_attr;
    apply_sink_id(&mut attr, sink_id);
    let fd = unsafe { perf_event_open(&attr, 0, -1) };
    if fd < 0 {
        return false;
    }
    let Some(ring) = Ring::aux(fd, -1, PMU) else {
        return false;
    };
    ring.enable();
    for _ in 0..32 {
        unsafe { libc::getpid() };
    }
    ring.disable();
    let bytes = ring.aux_data().len();
    bytes > 16
}

fn read_sink_buffer_size(sink_name: &str) -> usize {
    let path = format!("/sys/bus/coresight/devices/{sink_name}/buffer_size");
    read_hex_u64(&path).unwrap_or(0) as usize
}

/// Drain `PERF_RECORD_AUX`, `PERF_RECORD_LOST`, and `PERF_RECORD_AUX_OUTPUT_HW_ID`
/// from one ring's data pages. Wrap-safe across the circular data ring boundary.
fn drain_aux_ring(
    base: *mut libc::c_void,
    mmap_size: usize,
    cpu: i32,
    records: &mut Vec<AuxRecord>,
    hw_id: &mut Option<u8>,
    lost_total: &mut u64,
) {
    if base == libc::MAP_FAILED || mmap_size <= PAGE_SIZE {
        return;
    }
    let head = unsafe { read_u64(base, OFF_DATA_HEAD) };
    let mut tail = unsafe { read_u64(base, OFF_DATA_TAIL) };
    let data_size = (mmap_size - PAGE_SIZE) as u64;
    let ring = unsafe { std::slice::from_raw_parts((base as *const u8).add(PAGE_SIZE), data_size as usize) };

    let rd_u16 = |pos: u64| -> u16 {
        let b0 = ring[(pos % data_size) as usize];
        let b1 = ring[((pos + 1) % data_size) as usize];
        u16::from_le_bytes([b0, b1])
    };
    let rd_u32 = |pos: u64| -> u32 {
        let mut b = [0u8; 4];
        for i in 0..4 {
            b[i] = ring[((pos + i as u64) % data_size) as usize];
        }
        u32::from_le_bytes(b)
    };
    let rd_u64 = |pos: u64| -> u64 {
        let mut b = [0u8; 8];
        for i in 0..8 {
            b[i] = ring[((pos + i as u64) % data_size) as usize];
        }
        u64::from_le_bytes(b)
    };

    while tail + 8 <= head {
        let ev_type = rd_u32(tail);
        let ev_size = rd_u16(tail + 6) as u64;
        if ev_size < 8 || tail + ev_size > head {
            break;
        }
        match ev_type {
            PERF_RECORD_AUX if ev_size >= 32 => {
                let offset = rd_u64(tail + 8);
                let size = rd_u64(tail + 16);
                let flags = rd_u64(tail + 24);
                records.push(AuxRecord { cpu, offset, size, flags });
            }
            PERF_RECORD_LOST if ev_size >= 24 => {
                *lost_total += rd_u64(tail + 16);
            }
            PERF_RECORD_AUX_OUTPUT_HW_ID if ev_size >= 16 => {
                let id = (rd_u64(tail + 8) & 0x7f) as u8;
                *hw_id = Some(id);
            }
            _ => {}
        }
        tail += ev_size;
    }

    unsafe { write_u64(base, OFF_DATA_TAIL, head) };
}

fn read_hex_u32(path: &str) -> Option<u32> {
    read_hex_u64(path).map(|v| v as u32)
}

fn read_hex_u64(path: &str) -> Option<u64> {
    let s = std::fs::read_to_string(path).ok()?;
    parse_hex_or_dec(s.trim())
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok().or_else(|| u64::from_str_radix(t, 16).ok())
    }
}

fn read_etm_cpu_meta(cpu: i32, fallback_etm_config: u32) -> EtmCpuMeta {
    let idx = if cpu < 0 { 0 } else { cpu };
    let base = format!("/sys/bus/coresight/devices/etm{idx}");
    let trcidr = |n: u32| read_hex_u32(&format!("{base}/trcidr/trcidr{n}")).unwrap_or(0);
    let mgmt = |name: &str| read_hex_u32(&format!("{base}/mgmt/{name}")).unwrap_or(0);

    // Note: when the ETM is disabled after stop(), mgmt/trcconfig may read as 0 or 1
    // (only bit 0 default) instead of the active perf session config. Prefer the
    // synthesized session config whenever live_trcconfig has no feature bits set.
    let live_trcconfig = mgmt("trcconfig");
    let trcconfig = if live_trcconfig > 1 {
        live_trcconfig
    } else {
        fallback_etm_config
    };
    let trctraceid = mgmt("trctraceid");
    // Linux coresight-pmu.h: CORESIGHT_ETM_PMU_SEED = 0x10, trace_id = 0x10 + cpu * 2.
    let static_id = (0x10u32 + (idx as u32) * 2) as u8;
    let trace_id = if (0x01..0x70).contains(&(trctraceid as u8)) {
        trctraceid as u8
    } else {
        static_id
    };

    EtmCpuMeta {
        cpu,
        trace_id,
        trcidr0: trcidr(0),
        trcidr1: trcidr(1),
        trcidr2: trcidr(2),
        trcidr3: trcidr(3),
        trcidr4: trcidr(4),
        trcidr5: trcidr(5),
        trcidr8: trcidr(8),
        trcidr9: trcidr(9),
        trcidr10: trcidr(10),
        trcidr11: trcidr(11),
        trcidr12: trcidr(12),
        trcidr13: trcidr(13),
        trcconfig,
        trctraceid,
        trcdevarch: mgmt("trcdevarch"),
        aux_size: 0,
        lost: 0,
    }
}

fn read_uname_r() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Read runtime `_text` and `_stext` from `/proc/kallsyms`, falling back to
/// `/boot/System.map-<uname>` when `kptr_restrict` zeroes `/proc/kallsyms`.
fn read_runtime_text_addrs(uname: &str) -> (u64, u64) {
    let mut text = 0u64;
    let mut stext = 0u64;
    fn scan(content: &str, text: &mut u64, stext: &mut u64) {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let Some(addr_s) = it.next() else { continue };
            let Some(_ty) = it.next() else { continue };
            let Some(sym) = it.next() else { continue };
            if sym == "_text" || sym == "_stext" {
                if let Ok(addr) = u64::from_str_radix(addr_s, 16) {
                    if addr != 0 {
                        if sym == "_text" {
                            *text = addr;
                        } else {
                            *stext = addr;
                        }
                    }
                }
            }
            if *text != 0 && *stext != 0 {
                break;
            }
        }
    }
    if let Ok(kallsyms) = std::fs::read_to_string("/proc/kallsyms") {
        scan(&kallsyms, &mut text, &mut stext);
    }
    if (text == 0 || stext == 0) && !uname.is_empty() {
        let sysmap_path = format!("/boot/System.map-{uname}");
        if let Ok(sysmap) = std::fs::read_to_string(sysmap_path) {
            scan(&sysmap, &mut text, &mut stext);
        }
    }
    (text, stext)
}

/// Maximum ETMv4 address range comparator pairs (`ETM_ADDR_CMP_MAX / 2 = 4`
/// on Cortex-A53 ETMv4.0 where `trcidr4.NUMACPAIRS = 4`).
const ETM_MAX_ADDR_RANGE_FILTERS: usize = 4;

/// Build the `PERF_EVENT_IOC_SET_FILTER` string for CoreSight ETMv4.
///
/// Priority:
/// 1. Explicit `VOCK_CS_FILTER` (`--addr-filter` / `--cs-filter`):
///    - `"none"` / `"off"` / `"0"` disables hardware filtering.
///    - Raw perf syntax (`filter ...`, `start ...`, `stop ...`) passes through.
///    - `@<binary>` / `userspace:<binary>` / `elf:<binary>` builds an ELF
///      executable `PT_LOAD` (`PF_X`) range filter (`filter 0x<off>/0x<sz>@<path>`).
///    - `0x<addr>/0x<size>` or `0x<off>/0x<size>@<path>` prepends `filter `.
///    - Comma-separated kernel symbol names (e.g. `read_zero,write_null,urandom_read_iter`)
///      resolve to `filter 0x<start>/0x<size>` via `/proc/kallsyms` or `vmlinux`.
/// 2. `--filter <KW>`: if `<KW>` resolves to 1..=4 kernel function symbols in
///    `/proc/kallsyms` or `vmlinux`, programs those symbol ranges into the ETMv4
///    comparators so `tmc_etf0` only records trace inside those functions.
/// 3. Default on `tmc_etf*` (or any small SRAM sink `<= 64 KiB`):
///    - When `VOCK_CS_USERSPACE=1`, builds an ELF executable segment filter
///      (`filter 0x<off>/0x<sz>@<target_bin>`) from the target binary's `PT_LOAD`
///      (`PF_X`) segments.
///    - Otherwise, programs the kernel executable text range (`[_stext .. _etext)`)
///      into ETMv4 comparator pair 0 (`filter 0x<_stext>/0x<size>`).
fn build_coresight_addr_filter(
    sink_name: &str,
    sink_buffer_size: usize,
    cli_filter: Option<&str>,
    uname: &str,
    vmlinux: Option<&str>,
    target_bin: Option<&str>,
    runtime_stext: u64,
) -> Option<String> {
    if let Ok(raw) = std::env::var("VOCK_CS_FILTER") {
        let spec = raw.trim();
        if spec.eq_ignore_ascii_case("none")
            || spec.eq_ignore_ascii_case("off")
            || spec == "0"
        {
            return None;
        }
        if !spec.is_empty() {
            if let Some(f) = parse_filter_spec(spec, uname, vmlinux, runtime_stext) {
                return Some(f);
            }
        }
    }

    if let Some(kw) = cli_filter {
        let kw = kw.trim();
        if !kw.is_empty() && !kw.contains('/') {
            if let Some(f) = resolve_kernel_symbol_filter(kw, uname, vmlinux, runtime_stext) {
                return Some(f);
            }
        }
    }

    let is_small_etf = sink_name.starts_with("tmc_etf")
        || sink_name.starts_with("tmc_etb")
        || (sink_buffer_size > 0 && sink_buffer_size <= 64 * 1024);
    if !is_small_etf {
        return None;
    }

    if std::env::var("VOCK_CS_USERSPACE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        if let Some(bin) = target_bin {
            if let Some(f) = build_elf_exec_filter(bin) {
                return Some(f);
            }
        }
    }

    resolve_kernel_text_filter(uname, vmlinux, runtime_stext)
}

fn parse_filter_spec(
    spec: &str,
    uname: &str,
    vmlinux: Option<&str>,
    runtime_stext: u64,
) -> Option<String> {
    let spec = spec.trim();
    if spec.starts_with("filter ") || spec.starts_with("start ") || spec.starts_with("stop ") {
        return Some(spec.to_string());
    }
    if let Some(bin) = spec
        .strip_prefix('@')
        .or_else(|| spec.strip_prefix("userspace:"))
        .or_else(|| spec.strip_prefix("elf:"))
    {
        return build_elf_exec_filter(bin.trim());
    }
    if spec.contains('/') && (spec.starts_with("0x") || spec.starts_with("0X") || spec.contains('@')) {
        let parts: Vec<String> = spec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .take(ETM_MAX_ADDR_RANGE_FILTERS)
            .map(|p| {
                if p.starts_with("filter ") || p.starts_with("start ") || p.starts_with("stop ") {
                    p.to_string()
                } else {
                    format!("filter {p}")
                }
            })
            .collect();
        if !parts.is_empty() {
            return Some(parts.join(","));
        }
    }
    resolve_kernel_symbol_filter(spec, uname, vmlinux, runtime_stext)
}

/// Parse an ELF64 binary's executable `PT_LOAD` (`PF_X`) segments and format
/// `filter 0x<p_offset>/0x<p_filesz>@<canonical_path>` for `PERF_EVENT_IOC_SET_FILTER`.
pub(crate) fn build_elf_exec_filter(binary_path: &str) -> Option<String> {
    let resolved = resolve_executable_path(binary_path)?;
    let data = std::fs::read(&resolved).ok()?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None;
    }
    let e_phoff = u64::from_le_bytes(data[32..40].try_into().ok()?) as usize;
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
    if e_phentsize < 56 {
        return None;
    }

    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;

    let mut clauses = Vec::new();
    for i in 0..e_phnum {
        let Some(off) = e_phoff.checked_add(i.checked_mul(e_phentsize)?) else {
            break;
        };
        if off + 56 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        let p_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
        if p_type != PT_LOAD || (p_flags & PF_X) == 0 {
            continue;
        }
        let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?);
        if p_filesz == 0 {
            continue;
        }
        clauses.push(format!(
            "filter 0x{p_offset:x}/0x{p_filesz:x}@{}",
            resolved.display()
        ));
        if clauses.len() >= ETM_MAX_ADDR_RANGE_FILTERS {
            break;
        }
    }
    if clauses.is_empty() {
        None
    } else {
        Some(clauses.join(","))
    }
}

fn resolve_executable_path(bin: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(bin);
    if p.components().count() > 1 || p.is_absolute() {
        return std::fs::canonicalize(p).ok().or_else(|| {
            if p.exists() {
                Some(p.to_path_buf())
            } else {
                None
            }
        });
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let cand = std::path::Path::new(dir).join(bin);
            if cand.exists() {
                return std::fs::canonicalize(&cand).ok().or(Some(cand));
            }
        }
    }
    None
}

/// Resolve 1..=4 comma-separated kernel function symbols to `filter 0x<start>/0x<size>`
/// using `/proc/kallsyms`, `/boot/System.map-<uname>`, or `vmlinux`'s `.symtab`.
pub(crate) fn resolve_kernel_symbol_filter(
    spec: &str,
    uname: &str,
    vmlinux: Option<&str>,
    runtime_stext: u64,
) -> Option<String> {
    let want: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if want.is_empty() || want.len() > ETM_MAX_ADDR_RANGE_FILTERS {
        return None;
    }

    let mut found: Vec<(u64, u64)> = Vec::new();

    if let Some(vm) = vmlinux {
        if let Some(ranges) = resolve_symbols_from_vmlinux(vm, &want, runtime_stext) {
            found = ranges;
        }
    }
    if found.len() != want.len() {
        if let Some(ranges) = resolve_symbols_from_kallsyms(&want, uname) {
            found = ranges;
        }
    }
    if found.len() != want.len() {
        return None;
    }

    let clauses: Vec<String> = found
        .into_iter()
        .map(|(addr, size)| format!("filter 0x{addr:x}/0x{size:x}"))
        .collect();
    Some(clauses.join(","))
}

fn resolve_symbols_from_kallsyms(want: &[&str], uname: &str) -> Option<Vec<(u64, u64)>> {
    let content = std::fs::read_to_string("/proc/kallsyms")
        .ok()
        .filter(|s| s.lines().any(|l| !l.starts_with("0000000000000000 ")))
        .or_else(|| {
            if uname.is_empty() {
                None
            } else {
                std::fs::read_to_string(format!("/boot/System.map-{uname}")).ok()
            }
        })?;
    resolve_symbols_from_kallsyms_str(&content, want)
}

pub(crate) fn resolve_symbols_from_kallsyms_str(
    content: &str,
    want: &[&str],
) -> Option<Vec<(u64, u64)>> {
    let mut syms: Vec<(u64, &str)> = Vec::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let Some(addr_s) = it.next() else { continue };
        let Some(ty) = it.next() else { continue };
        let Some(name) = it.next() else { continue };
        if !matches!(ty, "t" | "T" | "w" | "W") {
            continue;
        }
        if let Ok(addr) = u64::from_str_radix(addr_s, 16) {
            if addr != 0 {
                let base_name = name.split('.').next().unwrap_or(name);
                syms.push((addr, name));
                if base_name != name {
                    syms.push((addr, base_name));
                }
            }
        }
    }
    if syms.is_empty() {
        return None;
    }
    syms.sort_by_key(|&(addr, _)| addr);

    let mut out = Vec::with_capacity(want.len());
    for &target in want {
        let pos = syms.iter().position(|&(_, n)| n == target)?;
        let start = syms[pos].0;
        let mut end = start + 0x1000;
        for &(next_addr, _) in &syms[pos + 1..] {
            if next_addr > start {
                end = next_addr;
                break;
            }
        }
        let size = (end - start).clamp(4, 0x10_0000);
        out.push((start, size));
    }
    Some(out)
}

fn resolve_symbols_from_vmlinux(
    vmlinux: &str,
    want: &[&str],
    runtime_stext: u64,
) -> Option<Vec<(u64, u64)>> {
    let data = std::fs::read(vmlinux).ok()?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None;
    }
    let (_, text_vaddr, _) = load_vmlinux_text(vmlinux)?;
    let slide = if runtime_stext != 0 && runtime_stext != text_vaddr {
        runtime_stext.wrapping_sub(text_vaddr)
    } else {
        0
    };

    let e_shoff = u64::from_le_bytes(data[40..48].try_into().ok()?) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().ok()?) as usize;
    if e_shentsize < 64 || e_shnum == 0 {
        return None;
    }

    const SHT_SYMTAB: u32 = 2;
    let mut found: Vec<Option<(u64, u64)>> = vec![None; want.len()];

    for i in 0..e_shnum {
        let sh = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
        if sh + 64 > data.len() {
            break;
        }
        let sh_type = u32::from_le_bytes(data[sh + 4..sh + 8].try_into().ok()?);
        if sh_type != SHT_SYMTAB {
            continue;
        }
        let sh_offset = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().ok()?) as usize;
        let sh_size = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().ok()?) as usize;
        let sh_link = u32::from_le_bytes(data[sh + 40..sh + 44].try_into().ok()?) as usize;
        let sh_entsize = u64::from_le_bytes(data[sh + 56..sh + 64].try_into().ok()?) as usize;
        if sh_entsize < 24 || sh_link >= e_shnum {
            continue;
        }
        let str_sh = e_shoff.checked_add(sh_link.checked_mul(e_shentsize)?)?;
        if str_sh + 64 > data.len() {
            continue;
        }
        let str_off = u64::from_le_bytes(data[str_sh + 24..str_sh + 32].try_into().ok()?) as usize;
        let str_sz = u64::from_le_bytes(data[str_sh + 32..str_sh + 40].try_into().ok()?) as usize;
        if str_off.checked_add(str_sz)? > data.len() || sh_offset.checked_add(sh_size)? > data.len()
        {
            continue;
        }
        let strtab = &data[str_off..str_off + str_sz];
        let count = sh_size / sh_entsize;
        for s in 0..count {
            let off = sh_offset + s * sh_entsize;
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
            let st_size = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
            if st_value == 0 || st_name >= strtab.len() {
                continue;
            }
            let end_name = strtab[st_name..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| st_name + p)
                .unwrap_or(strtab.len());
            let Ok(sym_name) = std::str::from_utf8(&strtab[st_name..end_name]) else {
                continue;
            };
            let base_name = sym_name.split('.').next().unwrap_or(sym_name);
            for (idx, &w) in want.iter().enumerate() {
                if found[idx].is_none() && (sym_name == w || base_name == w) {
                    let sz = if st_size > 0 { st_size } else { 0x200 };
                    found[idx] = Some((st_value.wrapping_add(slide), sz));
                }
            }
        }
    }

    let resolved: Vec<(u64, u64)> = found.into_iter().flatten().collect();
    if resolved.len() == want.len() {
        Some(resolved)
    } else {
        None
    }
}

/// Resolve the kernel executable `.text` range (`[_stext .. _etext)`) for
/// default ETMv4 comparator filtering on `tmc_etf*`.
fn resolve_kernel_text_filter(
    uname: &str,
    vmlinux: Option<&str>,
    runtime_stext: u64,
) -> Option<String> {
    let mut stext = 0u64;
    let mut etext = 0u64;
    let scan = |content: &str, stext: &mut u64, etext: &mut u64| {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let Some(addr_s) = it.next() else { continue };
            let Some(_ty) = it.next() else { continue };
            let Some(sym) = it.next() else { continue };
            if sym == "_stext" || sym == "_etext" {
                if let Ok(addr) = u64::from_str_radix(addr_s, 16) {
                    if addr != 0 {
                        if sym == "_stext" {
                            *stext = addr;
                        } else {
                            *etext = addr;
                        }
                    }
                }
            }
            if *stext != 0 && *etext != 0 {
                break;
            }
        }
    };
    if let Ok(kallsyms) = std::fs::read_to_string("/proc/kallsyms") {
        scan(&kallsyms, &mut stext, &mut etext);
    }
    if (stext == 0 || etext == 0) && !uname.is_empty() {
        if let Ok(sysmap) = std::fs::read_to_string(format!("/boot/System.map-{uname}")) {
            scan(&sysmap, &mut stext, &mut etext);
        }
    }
    if stext != 0 && etext > stext {
        return Some(format!("filter 0x{:x}/0x{:x}", stext, etext - stext));
    }

    if let Some(vm) = vmlinux {
        if let Some((text_bytes, text_vaddr, _)) = load_vmlinux_text(vm) {
            let start = if runtime_stext != 0 {
                runtime_stext
            } else {
                text_vaddr
            };
            if !text_bytes.is_empty() {
                return Some(format!("filter 0x{:x}/0x{:x}", start, text_bytes.len()));
            }
        }
    }
    None
}

impl CsCapture {
    /// Serialize `hw_trace.meta` as a deterministic key-value file.
    pub(crate) fn write_meta_file(&self, path: &str) -> std::io::Result<()> {
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "uname={}", self.uname)?;
        writeln!(f, "runtime_text=0x{:x}", self.runtime_text)?;
        writeln!(f, "runtime_stext=0x{:x}", self.runtime_stext)?;
        writeln!(f, "sink={}", self.sink_name)?;
        writeln!(f, "sink_id=0x{:x}", self.sink_id)?;
        writeln!(f, "sink_buffer_size=0x{:x}", self.sink_buffer_size)?;
        writeln!(f, "attr_config=0x{:x}", self.attr_config)?;
        writeln!(f, "etm_config=0x{:x}", self.etm_config)?;
        if !self.addr_filter.is_empty() {
            writeln!(f, "addr_filter={}", self.addr_filter)?;
        }
        for c in &self.cpus {
            let p = format!("cpu.{}", c.cpu);
            writeln!(f, "{p}.trace_id=0x{:02x}", c.trace_id)?;
            writeln!(f, "{p}.trcidr0=0x{:08x}", c.trcidr0)?;
            writeln!(f, "{p}.trcidr1=0x{:08x}", c.trcidr1)?;
            writeln!(f, "{p}.trcidr2=0x{:08x}", c.trcidr2)?;
            writeln!(f, "{p}.trcidr3=0x{:08x}", c.trcidr3)?;
            writeln!(f, "{p}.trcidr4=0x{:08x}", c.trcidr4)?;
            writeln!(f, "{p}.trcidr5=0x{:08x}", c.trcidr5)?;
            writeln!(f, "{p}.trcidr8=0x{:08x}", c.trcidr8)?;
            writeln!(f, "{p}.trcidr9=0x{:08x}", c.trcidr9)?;
            writeln!(f, "{p}.trcidr10=0x{:08x}", c.trcidr10)?;
            writeln!(f, "{p}.trcidr11=0x{:08x}", c.trcidr11)?;
            writeln!(f, "{p}.trcidr12=0x{:08x}", c.trcidr12)?;
            writeln!(f, "{p}.trcidr13=0x{:08x}", c.trcidr13)?;
            writeln!(f, "{p}.trcconfig=0x{:08x}", c.trcconfig)?;
            writeln!(f, "{p}.trctraceid=0x{:08x}", c.trctraceid)?;
            writeln!(f, "{p}.trcdevarch=0x{:08x}", c.trcdevarch)?;
            writeln!(f, "{p}.aux_size=0x{:x}", c.aux_size)?;
            writeln!(f, "{p}.lost={}", c.lost)?;
        }
        for r in &self.aux_records {
            let mut flag_names = Vec::new();
            if (r.flags & PERF_AUX_FLAG_TRUNCATED) != 0 {
                flag_names.push("TRUNCATED");
            }
            if (r.flags & PERF_AUX_FLAG_OVERWRITE) != 0 {
                flag_names.push("OVERWRITE");
            }
            if (r.flags & PERF_AUX_FLAG_PARTIAL) != 0 {
                flag_names.push("PARTIAL");
            }
            if (r.flags & PERF_AUX_FLAG_COLLISION) != 0 {
                flag_names.push("COLLISION");
            }
            if (r.flags & PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW) != 0 {
                flag_names.push("RAW");
            }
            writeln!(
                f,
                "aux_record=cpu:{},offset:0x{:x},size:0x{:x},flags:0x{:x}({})",
                r.cpu,
                r.offset,
                r.size,
                r.flags,
                flag_names.join("|")
            )?;
        }
        Ok(())
    }

    /// Load a `CsCapture` from a directory containing `hw_trace.meta` and
    /// `hw_trace.cpu*.bin` (or `hw_trace.bin`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn load_from_dir(dir: &std::path::Path) -> Result<CsCapture, String> {
        let meta_path = dir.join("hw_trace.meta");
        let content = std::fs::read_to_string(&meta_path)
            .map_err(|e| format!("read {}: {e}", meta_path.display()))?;
        let mut cap = CsCapture::default();
        let mut cpu_map: std::collections::BTreeMap<i32, EtmCpuMeta> =
            std::collections::BTreeMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "uname" => cap.uname = v.to_string(),
                "runtime_text" => cap.runtime_text = parse_hex_or_dec(v).unwrap_or(0),
                "runtime_stext" => cap.runtime_stext = parse_hex_or_dec(v).unwrap_or(0),
                "sink" => cap.sink_name = v.to_string(),
                "sink_id" => cap.sink_id = parse_hex_or_dec(v).unwrap_or(0) as u32,
                "sink_buffer_size" => cap.sink_buffer_size = parse_hex_or_dec(v).unwrap_or(0) as usize,
                "attr_config" => cap.attr_config = parse_hex_or_dec(v).unwrap_or(0),
                "etm_config" => cap.etm_config = parse_hex_or_dec(v).unwrap_or(0) as u32,
                "addr_filter" => cap.addr_filter = v.to_string(),
                "aux_record" => {
                    if let Some(rec) = parse_aux_record_line(v) {
                        cap.aux_records.push(rec);
                    }
                }
                _ if k.starts_with("cpu.") => {
                    let rest = &k[4..];
                    let Some((cpu_s, field)) = rest.split_once('.') else {
                        continue;
                    };
                    let Ok(cpu) = cpu_s.parse::<i32>() else {
                        continue;
                    };
                    let entry = cpu_map.entry(cpu).or_insert_with(|| EtmCpuMeta {
                        cpu,
                        ..Default::default()
                    });
                    let val = parse_hex_or_dec(v).unwrap_or(0);
                    match field {
                        "trace_id" => entry.trace_id = val as u8,
                        "trcidr0" => entry.trcidr0 = val as u32,
                        "trcidr1" => entry.trcidr1 = val as u32,
                        "trcidr2" => entry.trcidr2 = val as u32,
                        "trcidr3" => entry.trcidr3 = val as u32,
                        "trcidr4" => entry.trcidr4 = val as u32,
                        "trcidr5" => entry.trcidr5 = val as u32,
                        "trcidr8" => entry.trcidr8 = val as u32,
                        "trcidr9" => entry.trcidr9 = val as u32,
                        "trcidr10" => entry.trcidr10 = val as u32,
                        "trcidr11" => entry.trcidr11 = val as u32,
                        "trcidr12" => entry.trcidr12 = val as u32,
                        "trcidr13" => entry.trcidr13 = val as u32,
                        "trcconfig" => entry.trcconfig = val as u32,
                        "trctraceid" => entry.trctraceid = val as u32,
                        "trcdevarch" => entry.trcdevarch = val as u32,
                        "aux_size" => entry.aux_size = val as usize,
                        "lost" => entry.lost = val,
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        for (cpu, meta) in cpu_map {
            let fname = if cpu < 0 {
                "hw_trace.bin".to_string()
            } else {
                format!("hw_trace.cpu{cpu}.bin")
            };
            let fpath = dir.join(fname);
            let data = std::fs::read(&fpath).unwrap_or_default();
            cap.cpus.push(meta);
            cap.aux_bufs.push((cpu, data));
        }
        Ok(cap)
    }

    /// Decode all captured AUX buffers into per-CPU `Stream`s adjusted by the
    /// KASLR slide (`runtime_stext - text_vaddr`) when applicable.
    pub(crate) fn decode_to_streams(&self, text_info: Option<(&[u8], u64)>) -> Vec<Stream> {
        let (text, text_vaddr, slide) = match text_info {
            Some((t, vaddr)) => {
                let s = if self.runtime_stext != 0 && self.runtime_stext != vaddr {
                    self.runtime_stext.wrapping_sub(vaddr)
                } else {
                    0
                };
                (t, vaddr, s)
            }
            None => (&[][..], 0u64, 0u64),
        };

        let mut trace_id_to_cpu: BTreeMap<u8, usize> = BTreeMap::new();
        for (idx, c) in self.cpus.iter().enumerate() {
            if (0x01..0x70).contains(&c.trace_id) {
                trace_id_to_cpu.insert(c.trace_id, idx);
            }
        }

        let mut streams: Vec<Stream> = (0..self.cpus.len()).map(|_| Stream::default()).collect();
        if streams.is_empty() {
            streams.push(Stream::default());
        }

        let mut seq_counter: u64 = 1;

        for (buf_idx, &(cpu, ref raw_buf)) in self.aux_bufs.iter().enumerate() {
            if raw_buf.is_empty() {
                continue;
            }
            let chunks = extract_cpu_aux_chunks(cpu, raw_buf, &self.aux_records);
            for (chunk, flags) in chunks {
                if chunk.is_empty() {
                    continue;
                }
                let is_raw = (flags & PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW) != 0;
                if is_raw {
                    let target_idx = buf_idx.min(streams.len() - 1);
                    let meta = self.cpus.get(target_idx);
                    let mut dec = Etmv4Decoder::new(
                        text,
                        text_vaddr,
                        slide,
                        meta,
                        self.etm_config,
                        &mut seq_counter,
                    );
                    dec.decode_byte_stream(chunk, &mut streams[target_idx]);
                } else {
                    let demuxed = demux_frames(chunk);
                    for (trace_id, etm_bytes) in demuxed {
                        if etm_bytes.is_empty() {
                            continue;
                        }
                        let target_idx = trace_id_to_cpu
                            .get(&trace_id)
                            .copied()
                            .unwrap_or_else(|| buf_idx.min(streams.len() - 1));
                        let meta = self.cpus.get(target_idx);
                        let mut dec = Etmv4Decoder::new(
                            text,
                            text_vaddr,
                            slide,
                            meta,
                            self.etm_config,
                            &mut seq_counter,
                        );
                        dec.decode_byte_stream(&etm_bytes, &mut streams[target_idx]);
                    }
                }
            }
        }

        streams
    }
}

/// Slice a CPU's contiguous AUX buffer dump into individual `PERF_RECORD_AUX`
/// chunks so the frame deformatter and ETMv4 decoder reset cleanly at each
/// buffer wrap/flush boundary.
fn extract_cpu_aux_chunks<'a>(
    cpu: i32,
    raw_buf: &'a [u8],
    records: &[AuxRecord],
) -> Vec<(&'a [u8], u64)> {
    let cpu_recs: Vec<&AuxRecord> = records
        .iter()
        .filter(|r| r.cpu == cpu && r.size > 0)
        .collect();
    if cpu_recs.is_empty() {
        return vec![(raw_buf, 0)];
    }

    let mut out = Vec::new();
    let mut cursor = 0usize;
    for r in cpu_recs {
        let sz = r.size as usize;
        let off = r.offset as usize;
        if off + sz <= raw_buf.len() {
            out.push((&raw_buf[off..off + sz], r.flags));
            cursor = off + sz;
        } else if cursor + sz <= raw_buf.len() {
            out.push((&raw_buf[cursor..cursor + sz], r.flags));
            cursor += sz;
        }
    }
    if out.is_empty() {
        out.push((raw_buf, 0));
    }
    out
}

// ============================================================================
// Phase 2: CoreSight 16-Byte Formatter Frame Demuxer (ARM IHI 0029 / OpenCSD)
// ============================================================================

/// CoreSight frame sync word (`0x7fff_ffff` little-endian = `[0xff, 0xff, 0xff, 0x7f]`).
/// Also appears 4 times in a row as the 16-byte Linux kernel barrier packet at
/// the start of wrapped TMC ETF/ETR chunks.
const CORESIGHT_FSYNC: [u8; 4] = [0xff, 0xff, 0xff, 0x7f];

/// Unpack a formatted CoreSight ATB trace buffer (16-byte frames) into per-trace-ID
/// byte streams.
///
/// Follows ARM IHI 0029D §D4 ("Frame format") and OpenCSD
/// `TrcFrmDeformatter::unpackFrames`:
/// - Any run of 4-byte `FSYNC` words (`ff ff ff 7f`) outside a frame is skipped
///   and resets `curr_id = 0`.
/// - Each 16-byte frame contains:
///   - 7 pairs `h = 0..6` at `even = frame[2*h]`, `odd = frame[2*h + 1]`, with
///     `abit = (frame[15] >> h) & 1`.
///   - If `(even & 1) != 0`: `new_id = (even >> 1) & 0x7f`. When `abit == 1`,
///     `odd` belongs to the *old* `curr_id` before switching to `new_id`; when
///     `abit == 0`, `curr_id` updates to `new_id` immediately and `odd` belongs
///     to `new_id`.
///   - If `(even & 1) == 0`: both `(even & 0xfe) | abit` and `odd` belong to
///     `curr_id`.
///   - Byte 14 (`h = 7`, `even = frame[14]`, `abit = (frame[15] >> 7) & 1`):
///     if `(even & 1) != 0`, `curr_id = (even >> 1) & 0x7f` (no `odd` byte);
///     otherwise `(even & 0xfe) | abit` belongs to `curr_id`.
/// - Trace IDs `0x00` (null/padding) and `0x70..=0x7f` (reserved/trigger) are
///   discarded.
pub(crate) fn demux_frames(raw: &[u8]) -> BTreeMap<u8, Vec<u8>> {
    let mut out: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut curr_id: u8 = 0;
    let mut pos = 0usize;

    let mut push_byte = |id: u8, b: u8| {
        if (0x01..0x70).contains(&id) {
            out.entry(id).or_default().push(b);
        }
    };

    while pos < raw.len() {
        if pos + 4 <= raw.len() && raw[pos..pos + 4] == CORESIGHT_FSYNC {
            curr_id = 0;
            pos += 4;
            continue;
        }
        if pos + 16 > raw.len() {
            break;
        }
        let frame = &raw[pos..pos + 16];
        pos += 16;

        // 16-byte Linux kernel barrier packet (4 consecutive FSYNC words).
        if frame[0..4] == CORESIGHT_FSYNC
            && frame[4..8] == CORESIGHT_FSYNC
            && frame[8..12] == CORESIGHT_FSYNC
            && frame[12..16] == CORESIGHT_FSYNC
        {
            curr_id = 0;
            continue;
        }

        let aux = frame[15];
        for h in 0..7usize {
            let even = frame[2 * h];
            let odd = frame[2 * h + 1];
            let abit = (aux >> h) & 1;
            if (even & 1) != 0 {
                let new_id = (even >> 1) & 0x7f;
                if abit != 0 {
                    push_byte(curr_id, odd);
                    curr_id = new_id;
                } else {
                    curr_id = new_id;
                    push_byte(curr_id, odd);
                }
            } else {
                let d0 = (even & 0xfe) | abit;
                push_byte(curr_id, d0);
                push_byte(curr_id, odd);
            }
        }

        // Unpack byte 14 (h = 7).
        let even14 = frame[14];
        let abit7 = (aux >> 7) & 1;
        if (even14 & 1) != 0 {
            curr_id = (even14 >> 1) & 0x7f;
        } else {
            let d14 = (even14 & 0xfe) | abit7;
            push_byte(curr_id, d14);
        }
    }

    out
}

// ============================================================================
// Phase 3: ETMv4 Packet Scanner & Decoder (ARM IHI 0064 / OpenCSD)
// ============================================================================

/// Decoded ETMv4 instruction trace packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EtmPacket {
    /// Alignment synchronization packet (`0x00 x 11+, 0x80`).
    ASync,
    /// Trace Info (`0x01`): resets address history registers.
    TraceInfo { plctl: u32, info: u32 },
    /// Trace On (`0x04`): discontinuity in trace stream.
    TraceOn,
    /// Timestamp (`0x02`, `0x03`): variable-length Gray/natural timestamp update.
    Timestamp { ts: u64, bits: u8 },
    /// Exception (`0x06`): `addr_interp` indicates whether the following Address
    /// packet also closes a linear execution range `[ip .. excep_ret_addr)`.
    Exception { exc_type: u16, addr_interp: u8 },
    /// Exception Return (`0x07`).
    ExceptionReturn,
    /// Function Return (`0x05`).
    FuncRet,
    /// Context packet (`0x80`, `0x81`).
    Context { el: Option<u8>, sf: Option<bool> },
    ///Exact-match address packet (`0x90..=0x92`), indexing `addr_reg[idx]`.
    ExactMatch { idx: u8 },
    /// Short address IS0 (`0x95`): updates low `bits` (9 or 17) of `addr_reg[0]`.
    ShortAddrIs0 { val: u64, bits: u8 },
    /// Short address IS1 (`0x96`): updates low `bits` (8 or 16) of `addr_reg[0]`.
    ShortAddrIs1 { val: u64, bits: u8 },
    /// 32-bit Long address IS0 (`0x9a`).
    LongAddr32Is0 { addr: u64 },
    /// 32-bit Long address IS1 (`0x9b`).
    LongAddr32Is1 { addr: u64 },
    /// 64-bit Long address IS0 (`0x9d`).
    LongAddr64Is0 { addr: u64 },
    /// 64-bit Long address IS1 (`0x9e`).
    LongAddr64Is1 { addr: u64 },
    /// Combined Address + Context (`0x82`, `0x83`, `0x85`, `0x86`).
    AddrContext {
        addr: u64,
        bits: u8,
        is1: bool,
        el: u8,
        sf: bool,
    },
    /// Atom packet (`F1..F6`): `bits` holds `count` atoms from LSB (bit 0 = oldest)
    /// to bit `count - 1` (newest), where `1 = E` (taken) and `0 = N` (not-taken).
    Atom { bits: u32, count: u8 },
    /// Q packet (`0xa0..=0xaf`).
    Q { count: u32, has_count: bool },
    /// Packets ignored for non-speculative kernel coverage (`Overflow`, `Discard`,
    /// `Commit`, `Cancel`, `CycleCount`, `Cond*`, `Event`, `DataSyncMarker`, `Mispredict`).
    Ignore,
    /// Unrecognized or truncated byte(s).
    Bad,
}

/// Read an unsigned LEB128-style continuation integer (up to `max_bytes`),
/// where bit 7 of bytes `0..max_bytes-1` is the continue bit, and the final
/// byte `max_bytes - 1` (if reached) contributes all 8 bits.
fn read_varint(buf: &[u8], start: usize, max_bytes: usize) -> Option<(u64, usize, u8)> {
    let mut val = 0u64;
    let mut shift = 0u8;
    for i in 0..max_bytes {
        let b = *buf.get(start + i)?;
        if i == max_bytes - 1 {
            val |= (b as u64) << shift;
            shift = shift.saturating_add(8);
            return Some((val, i + 1, shift));
        }
        val |= ((b & 0x7f) as u64) << shift;
        shift = shift.saturating_add(7);
        if (b & 0x80) == 0 {
            return Some((val, i + 1, shift));
        }
    }
    None
}

fn decode_long_addr32_is0(b: &[u8]) -> u64 {
    ((b[0] as u64 & 0x7f) << 2)
        | ((b[1] as u64 & 0x7f) << 9)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
}

fn decode_long_addr32_is1(b: &[u8]) -> u64 {
    ((b[0] as u64 & 0x7f) << 1)
        | ((b[1] as u64) << 8)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
}

fn decode_long_addr64_is0(b: &[u8]) -> u64 {
    ((b[0] as u64 & 0x7f) << 2)
        | ((b[1] as u64 & 0x7f) << 9)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32)
        | ((b[5] as u64) << 40)
        | ((b[6] as u64) << 48)
        | ((b[7] as u64) << 56)
}

fn decode_long_addr64_is1(b: &[u8]) -> u64 {
    ((b[0] as u64 & 0x7f) << 1)
        | ((b[1] as u64) << 8)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32)
        | ((b[5] as u64) << 40)
        | ((b[6] as u64) << 48)
        | ((b[7] as u64) << 56)
}

/// Compute the byte length of the Context payload (`info_byte` + optional VMID
/// + optional 32-bit CONTEXTID) given ETMv4 `trcconfig` and `trcidr2`.
fn context_payload_len(info_byte: u8, trcconfig: u32, vmid_bytes: usize, cid_bytes: usize) -> usize {
    let mut len = 1usize; // info_byte
    let vmid_enabled = (trcconfig & (1 << ETM4_CFG_BIT_VMID)) != 0;
    let ctxtid_enabled = (trcconfig & (1 << ETM4_CFG_BIT_CTXTID)) != 0;
    if (info_byte & 0x40) != 0 && vmid_enabled {
        len += vmid_bytes;
    }
    if (info_byte & 0x80) != 0 && ctxtid_enabled {
        len += cid_bytes;
    }
    len
}

/// Scan a single ETMv4 packet starting at `buf[pos]`, returning `(packet, bytes_consumed)`.
///
/// Exact header encodings follow ARM IHI 0064H §6.4 and OpenCSD
/// `TrcPktProcEtmV4I::processPacket`.
pub(crate) fn scan_etmv4_packet(
    buf: &[u8],
    pos: usize,
    trcconfig: u32,
    vmid_bytes: usize,
    cid_bytes: usize,
) -> (EtmPacket, usize) {
    let Some(&b0) = buf.get(pos) else {
        return (EtmPacket::Bad, 0);
    };

    match b0 {
        // 0x00: A-Sync (11 or more 0x00 bytes followed by 0x80).
        0x00 => {
            let mut z = 0usize;
            while pos + z < buf.len() && buf[pos + z] == 0x00 {
                z += 1;
            }
            if z >= 11 && buf.get(pos + z) == Some(&0x80) {
                (EtmPacket::ASync, z + 1)
            } else {
                (EtmPacket::Bad, z.max(1))
            }
        }

        // 0x01: Trace Info (PLCTL varint + optional INFO, KEY, SPEC, CYCT varints).
        0x01 => {
            let Some((plctl, n, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            let mut cur = pos + 1 + n;
            let mut info = 0u32;
            for bit in 0..4u32 {
                if (plctl & (1 << bit)) != 0 {
                    let Some((v, vn, _)) = read_varint(buf, cur, 4) else {
                        return (EtmPacket::Bad, 1);
                    };
                    if bit == 0 {
                        info = v as u32;
                    }
                    cur += vn;
                }
            }
            (
                EtmPacket::TraceInfo {
                    plctl: plctl as u32,
                    info,
                },
                cur - pos,
            )
        }

        // 0x02, 0x03: Timestamp (up to 9 payload bytes + optional 3-byte cycle count on 0x03).
        0x02 | 0x03 => {
            let Some((ts, n, bits)) = read_varint(buf, pos + 1, 9) else {
                return (EtmPacket::Bad, 1);
            };
            let mut cur = pos + 1 + n;
            if b0 == 0x03 {
                let Some((_, cn, _)) = read_varint(buf, cur, 3) else {
                    return (EtmPacket::Bad, 1);
                };
                cur += cn;
            }
            (EtmPacket::Timestamp { ts, bits }, cur - pos)
        }

        // 0x04: Trace On.
        0x04 => (EtmPacket::TraceOn, 1),

        // 0x05: Function Return.
        0x05 => (EtmPacket::FuncRet, 1),

        // 0x06: Exception (E1:E2 byte + optional E3 byte when E1.bit7 == 1).
        0x06 => {
            let Some(&b1) = buf.get(pos + 1) else {
                return (EtmPacket::Bad, 1);
            };
            let addr_interp = ((b1 & 0x40) >> 5) | (b1 & 1);
            let exc_type = ((b1 >> 1) & 0x1f) as u16;
            let len = if (b1 & 0x80) != 0 { 3 } else { 2 };
            if pos + len > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            (
                EtmPacket::Exception {
                    exc_type,
                    addr_interp,
                },
                len,
            )
        }

        // 0x07: Exception Return.
        0x07 => (EtmPacket::ExceptionReturn, 1),

        // 0x0c, 0x0d: Cycle Count Format 2 (1 payload byte).
        0x0c | 0x0d => {
            if pos + 2 > buf.len() {
                (EtmPacket::Bad, 1)
            } else {
                (EtmPacket::Ignore, 2)
            }
        }

        // 0x0e, 0x0f: Cycle Count Format 1 (1..=2 varint bytes + optional 1..=3 CC bytes).
        0x0e | 0x0f => {
            let Some((_, n1, _)) = read_varint(buf, pos + 1, 2) else {
                return (EtmPacket::Bad, 1);
            };
            let mut cur = pos + 1 + n1;
            if b0 == 0x0e {
                let Some((_, n2, _)) = read_varint(buf, cur, 3) else {
                    return (EtmPacket::Bad, 1);
                };
                cur += n2;
            }
            (EtmPacket::Ignore, cur - pos)
        }

        // 0x10..=0x1f: Cycle Count Format 3 (single byte).
        0x10..=0x1f => (EtmPacket::Ignore, 1),

        // 0x20..=0x27: Numbered Data Sync Marker (single byte).
        0x20..=0x27 => (EtmPacket::Ignore, 1),

        // 0x28..=0x2c: Unnumbered Data Sync Marker (single byte).
        0x28..=0x2c => (EtmPacket::Ignore, 1),

        // 0x2d: Commit (varint up to 4 bytes).
        0x2d => {
            let Some((_, n, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            (EtmPacket::Ignore, 1 + n)
        }

        // 0x2e, 0x2f: Cancel Format 1 (varint up to 4 bytes).
        0x2e | 0x2f => {
            let Some((_, n, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            (EtmPacket::Ignore, 1 + n)
        }

        // 0x30..=0x33: Mispredict (single byte).
        0x30..=0x33 => (EtmPacket::Ignore, 1),

        // 0x34..=0x37: Cancel Format 2 (single byte).
        0x34..=0x37 => (EtmPacket::Ignore, 1),

        // 0x38..=0x3f: Cancel Format 3 (single byte).
        0x38..=0x3f => (EtmPacket::Ignore, 1),

        // 0x40..=0x42: Conditional Instruction Format 2 (1 payload byte).
        0x40..=0x42 => {
            if pos + 2 > buf.len() {
                (EtmPacket::Bad, 1)
            } else {
                (EtmPacket::Ignore, 2)
            }
        }

        // 0x43: Conditional Flush (single byte).
        0x43 => (EtmPacket::Ignore, 1),

        // 0x44..=0x46: Conditional Result Format 4 (single byte).
        0x44..=0x46 => (EtmPacket::Ignore, 1),

        // 0x48..=0x4a, 0x4c..=0x4e: Conditional Result Format 2 (1 payload byte).
        0x48..=0x4a | 0x4c..=0x4e => {
            if pos + 2 > buf.len() {
                (EtmPacket::Bad, 1)
            } else {
                (EtmPacket::Ignore, 2)
            }
        }

        // 0x50..=0x5f: Conditional Result Format 3 (2 bytes total: b0 + b1).
        0x50..=0x5f => {
            if pos + 2 > buf.len() {
                (EtmPacket::Bad, 1)
            } else {
                (EtmPacket::Ignore, 2)
            }
        }

        // 0x68..=0x6b: Conditional Result Format 1 (1 or 2 varints).
        0x68..=0x6b => {
            let Some((_, n1, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            let mut cur = pos + 1 + n1;
            if b0 != 0x6b {
                let Some((_, n2, _)) = read_varint(buf, cur, 4) else {
                    return (EtmPacket::Bad, 1);
                };
                cur += n2;
            }
            (EtmPacket::Ignore, cur - pos)
        }

        // 0x6c: Conditional Instruction Format 1 (varint up to 4 bytes).
        0x6c => {
            let Some((_, n, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            (EtmPacket::Ignore, 1 + n)
        }

        // 0x6d: Conditional Instruction Format 3 (1 payload byte).
        0x6d => {
            if pos + 2 > buf.len() {
                (EtmPacket::Bad, 1)
            } else {
                (EtmPacket::Ignore, 2)
            }
        }

        // 0x70..=0x7f: Ignore (0x70) and Event Trace (0x71..=0x7f), all 1 byte.
        0x70..=0x7f => (EtmPacket::Ignore, 1),

        // 0x80, 0x81: Context Packet (P=0: 1 byte; P=1: 1 + context_payload_len).
        0x80 => (EtmPacket::Context { el: None, sf: None }, 1),
        0x81 => {
            let Some(&info) = buf.get(pos + 1) else {
                return (EtmPacket::Bad, 1);
            };
            let clen = context_payload_len(info, trcconfig, vmid_bytes, cid_bytes);
            if pos + 1 + clen > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            let el = info & 0x03;
            let sf = (info & 0x10) != 0;
            (
                EtmPacket::Context {
                    el: Some(el),
                    sf: Some(sf),
                },
                1 + clen,
            )
        }

        // 0x82, 0x83: 32-bit Address + Context IS0 / IS1.
        0x82 | 0x83 => {
            if pos + 6 > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            let is1 = b0 == 0x83;
            let addr_bytes = &buf[pos + 1..pos + 5];
            let addr = if is1 {
                decode_long_addr32_is1(addr_bytes)
            } else {
                decode_long_addr32_is0(addr_bytes)
            };
            let info = buf[pos + 5];
            let clen = context_payload_len(info, trcconfig, vmid_bytes, cid_bytes);
            if pos + 5 + clen > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            (
                EtmPacket::AddrContext {
                    addr,
                    bits: 32,
                    is1,
                    el: info & 0x03,
                    sf: (info & 0x10) != 0,
                },
                5 + clen,
            )
        }

        // 0x85, 0x86: 64-bit Address + Context IS0 / IS1.
        0x85 | 0x86 => {
            if pos + 10 > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            let is1 = b0 == 0x86;
            let addr_bytes = &buf[pos + 1..pos + 9];
            let addr = if is1 {
                decode_long_addr64_is1(addr_bytes)
            } else {
                decode_long_addr64_is0(addr_bytes)
            };
            let info = buf[pos + 9];
            let clen = context_payload_len(info, trcconfig, vmid_bytes, cid_bytes);
            if pos + 9 + clen > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            (
                EtmPacket::AddrContext {
                    addr,
                    bits: 64,
                    is1,
                    el: info & 0x03,
                    sf: (info & 0x10) != 0,
                },
                9 + clen,
            )
        }

        // 0x90..=0x92: Exact Match Address.
        0x90..=0x92 => (EtmPacket::ExactMatch { idx: b0 & 0x03 }, 1),

        // 0x95, 0x96: Short Address IS0 / IS1 (1 or 2 payload bytes).
        0x95 | 0x96 => {
            let Some(&b1) = buf.get(pos + 1) else {
                return (EtmPacket::Bad, 1);
            };
            let is1 = b0 == 0x96;
            let sh = if is1 { 1u8 } else { 2u8 };
            if (b1 & 0x80) != 0 {
                let Some(&b2) = buf.get(pos + 2) else {
                    return (EtmPacket::Bad, 1);
                };
                let val = (((b1 & 0x7f) as u64) << sh) | ((b2 as u64) << (7 + sh));
                let bits = 15 + sh;
                let pkt = if is1 {
                    EtmPacket::ShortAddrIs1 { val, bits }
                } else {
                    EtmPacket::ShortAddrIs0 { val, bits }
                };
                (pkt, 3)
            } else {
                let val = ((b1 & 0x7f) as u64) << sh;
                let bits = 7 + sh;
                let pkt = if is1 {
                    EtmPacket::ShortAddrIs1 { val, bits }
                } else {
                    EtmPacket::ShortAddrIs0 { val, bits }
                };
                (pkt, 2)
            }
        }

        // 0x9a, 0x9b: 32-bit Long Address IS0 / IS1 (4 payload bytes).
        0x9a | 0x9b => {
            if pos + 5 > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            let addr_bytes = &buf[pos + 1..pos + 5];
            if b0 == 0x9a {
                (
                    EtmPacket::LongAddr32Is0 {
                        addr: decode_long_addr32_is0(addr_bytes),
                    },
                    5,
                )
            } else {
                (
                    EtmPacket::LongAddr32Is1 {
                        addr: decode_long_addr32_is1(addr_bytes),
                    },
                    5,
                )
            }
        }

        // 0x9d, 0x9e: 64-bit Long Address IS0 / IS1 (8 payload bytes).
        0x9d | 0x9e => {
            if pos + 9 > buf.len() {
                return (EtmPacket::Bad, 1);
            }
            let addr_bytes = &buf[pos + 1..pos + 9];
            if b0 == 0x9d {
                (
                    EtmPacket::LongAddr64Is0 {
                        addr: decode_long_addr64_is0(addr_bytes),
                    },
                    9,
                )
            } else {
                (
                    EtmPacket::LongAddr64Is1 {
                        addr: decode_long_addr64_is1(addr_bytes),
                    },
                    9,
                )
            }
        }

        // 0xa0..=0xaf: Q Packet.
        // 0xaf has no count payload; 0xa0..=0xae carry a varint count payload.
        0xa0..=0xae => {
            let Some((cnt, n, _)) = read_varint(buf, pos + 1, 4) else {
                return (EtmPacket::Bad, 1);
            };
            (
                EtmPacket::Q {
                    count: cnt as u32,
                    has_count: true,
                },
                1 + n,
            )
        }
        0xaf => (
            EtmPacket::Q {
                count: 0,
                has_count: false,
            },
            1,
        ),

        // Atom Format 6: 0xc0..=0xd4 (A=0: E^(count) followed by N) and
        // 0xe0..=0xf4 (A=1: E^(count) followed by E), where count = (b0 & 0x1f) + 3.
        0xc0..=0xd4 | 0xe0..=0xf4 => {
            let e_count = (b0 & 0x1f) + 3;
            let mut bits: u32 = (1u32 << e_count) - 1;
            if (b0 & 0x20) == 0 {
                bits |= 1u32 << e_count;
            }
            (
                EtmPacket::Atom {
                    bits,
                    count: e_count + 1,
                },
                1,
            )
        }

        // Atom Format 5: 5 atoms (0xd5, 0xd6, 0xd7, 0xf5).
        // OpenCSD trc_pkt_proc_etmv4i.cpp:
        //   0xf5 -> 0b11110 (0x1e): N, E, E, E, E (oldest=E, E, E, E, newest=N)
        //   0xd5 -> 0b00000 (0x00): N, N, N, N, N
        //   0xd6 -> 0b01010 (0x0a): N, E, N, E, N
        //   0xd7 -> 0b10101 (0x15): E, N, E, N, E
        0xf5 => (
            EtmPacket::Atom {
                bits: 0x1e,
                count: 5,
            },
            1,
        ),
        0xd5 => (
            EtmPacket::Atom {
                bits: 0x00,
                count: 5,
            },
            1,
        ),
        0xd6 => (
            EtmPacket::Atom {
                bits: 0x0a,
                count: 5,
            },
            1,
        ),
        0xd7 => (
            EtmPacket::Atom {
                bits: 0x15,
                count: 5,
            },
            1,
        ),

        // Atom Format 2: 2 atoms (0xd8..=0xdb), bit 0 = oldest, bit 1 = newest.
        0xd8..=0xdb => (
            EtmPacket::Atom {
                bits: (b0 & 0x03) as u32,
                count: 2,
            },
            1,
        ),

        // Atom Format 4: 4 atoms (0xdc..=0xdf).
        //   0xdc -> 0b1110 (0x0e): oldest=N, E, E, newest=E
        //   0xdd -> 0b0000 (0x00): N, N, N, N
        //   0xde -> 0b1010 (0x0a): oldest=N, E, N, newest=E
        //   0xdf -> 0b0101 (0x05): oldest=E, N, E, newest=N
        0xdc..=0xdf => {
            const F4_BITS: [u32; 4] = [0x0e, 0x00, 0x0a, 0x05];
            (
                EtmPacket::Atom {
                    bits: F4_BITS[(b0 & 0x03) as usize],
                    count: 4,
                },
                1,
            )
        }

        // Atom Format 1: 1 atom (0xf6 = N, 0xf7 = E).
        0xf6 | 0xf7 => (
            EtmPacket::Atom {
                bits: (b0 & 0x01) as u32,
                count: 1,
            },
            1,
        ),

        // Atom Format 3: 3 atoms (0xf8..=0xff), bit 0 = oldest, bit 2 = newest.
        0xf8..=0xff => (
            EtmPacket::Atom {
                bits: (b0 & 0x07) as u32,
                count: 3,
            },
            1,
        ),

        // 0x08 (Discard), 0x0a (Overflow) -> 1 byte.
        0x08 | 0x0a => (EtmPacket::Ignore, 1),

        _ => (EtmPacket::Bad, 1),
    }
}

// ============================================================================
// Phase 4: A64 Instruction Classifier & ETMv4 P0 Instruction Walker
// ============================================================================

/// Classification of a 32-bit A64 instruction at `pc` for ETMv4 P0 atom walking
/// (`TRCIDR0.COMMOPT == 0`, `TRCIDR2.WFXMODE == 0`, matching OpenCSD
/// `trc_idec_arminst.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum A64Insn {
    /// Non-branch sequential instruction (`pc + 4`).
    Linear,
    /// Unconditional direct branch `B` or `BL` (`1001_01..` / `0001_01..`).
    /// Consumes 1 atom (`E`), jumps to `target`.
    DirectBranch { target: u64 },
    /// Conditional direct branch (`B.cond`, `CBZ`, `CBNZ`, `TBZ`, `TBNZ`).
    /// Consumes 1 atom (`E` -> `target`, `N` -> `pc + 4`).
    CondBranch { target: u64 },
    /// Indirect branch or exception-generating / return instruction
    /// (`BR`, `BLR`, `RET`, `ERET`, `BRAA/AB/Z`, `BLRAA/AB/Z`, `RETAA/AB`,
    /// `DRPS`, `SVC`, `HVC`, `SMC`, `BRK`, `HLT`).
    /// Consumes 1 atom (`E`); target comes from the next ETM Address packet.
    IndirectBranch,
}

#[inline]
fn sign_extend(val: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}

/// Classify a 32-bit little-endian A64 instruction at `pc` into an `A64Insn`.
pub(crate) fn decode_a64_p0(insn: u32, pc: u64) -> A64Insn {
    // Unconditional branch immediate: B / BL (op0: bit31 = op, bits[30:26] = 0b00101).
    if (insn & 0x7c00_0000) == 0x1400_0000 {
        let imm26 = (insn & 0x03ff_ffff) as u64;
        let offset = sign_extend(imm26, 26) * 4;
        return A64Insn::DirectBranch {
            target: pc.wrapping_add(offset as u64),
        };
    }

    // Conditional branch immediate: B.cond / BC.cond (bits[31:25] = 0b0101010, bit4 = 0).
    if (insn & 0xff00_0010) == 0x5400_0000 {
        let imm19 = ((insn >> 5) & 0x0007_ffff) as u64;
        let offset = sign_extend(imm19, 19) * 4;
        return A64Insn::CondBranch {
            target: pc.wrapping_add(offset as u64),
        };
    }

    // Compare and branch: CBZ / CBNZ (bits[30:25] = 0b011010).
    if (insn & 0x7e00_0000) == 0x3400_0000 {
        let imm19 = ((insn >> 5) & 0x0007_ffff) as u64;
        let offset = sign_extend(imm19, 19) * 4;
        return A64Insn::CondBranch {
            target: pc.wrapping_add(offset as u64),
        };
    }

    // Test bit and branch: TBZ / TBNZ (bits[30:25] = 0b011011).
    if (insn & 0x7e00_0000) == 0x3600_0000 {
        let imm14 = ((insn >> 5) & 0x3fff) as u64;
        let offset = sign_extend(imm14, 14) * 4;
        return A64Insn::CondBranch {
            target: pc.wrapping_add(offset as u64),
        };
    }

    // Unconditional branch (register): BR, BLR, RET, ERET, DRPS, and pointer-auth variants
    // (bits[31:25] = 0b1101011).
    if (insn & 0xfe00_0000) == 0xd600_0000 {
        return A64Insn::IndirectBranch;
    }

    // Exception generation: SVC, HVC, SMC, BRK, HLT (bits[31:24] = 0b11010100).
    if (insn & 0xff00_0000) == 0xd400_0000 {
        let opc = (insn >> 21) & 0x7;
        let ll = insn & 0x3;
        if (opc == 0 && (ll == 1 || ll == 2 || ll == 3))
            || (opc == 1 && ll == 0)
            || (opc == 2 && ll == 0)
        {
            return A64Insn::IndirectBranch;
        }
    }

    A64Insn::Linear
}

/// Per-stream ETMv4 instruction trace decoder.
pub(crate) struct Etmv4Decoder<'a> {
    text: &'a [u8],
    text_vaddr: u64,
    text_end: u64,
    slide: u64,
    trcconfig: u32,
    vmid_bytes: usize,
    cid_bytes: usize,
    addr_reg: [u64; 3],
    ip: Option<u64>,
    need_addr: bool,
    pending_exc_interp: u8,
    ts: u64,
    seq: &'a mut u64,
}

impl<'a> Etmv4Decoder<'a> {
    pub(crate) fn new(
        text: &'a [u8],
        text_vaddr: u64,
        slide: u64,
        meta: Option<&EtmCpuMeta>,
        fallback_etm_config: u32,
        seq: &'a mut u64,
    ) -> Self {
        let trcconfig = meta
            .map(|m| {
                if m.trcconfig > 1 {
                    m.trcconfig
                } else {
                    fallback_etm_config
                }
            })
            .unwrap_or(fallback_etm_config);
        let trcidr2 = meta.map(|m| m.trcidr2).unwrap_or(0x0000_0488);
        let cidsize = (trcidr2 >> 5) & 0x1f;
        let vmidsize = (trcidr2 >> 10) & 0x1f;
        let cid_bytes = if cidsize == 4 { 4 } else { 0 };
        let vmid_bytes = match vmidsize {
            1 => 1,
            2 => 2,
            4 => 4,
            _ => 0,
        };

        let default_hi = text_vaddr.wrapping_add(slide) & !0xffff_ffff;
        Self {
            text,
            text_vaddr,
            text_end: text_vaddr.wrapping_add(text.len() as u64),
            slide,
            trcconfig,
            vmid_bytes,
            cid_bytes,
            addr_reg: [default_hi; 3],
            ip: None,
            need_addr: false,
            pending_exc_interp: 0,
            ts: 0,
            seq,
        }
    }

    #[inline]
    fn effective_ts(&self) -> u64 {
        if self.ts != 0 {
            self.ts
        } else {
            *self.seq
        }
    }

    #[inline]
    fn emit_pc(out: &mut Stream, pc: u64) {
        use std::fmt::Write as _;
        let _ = writeln!(out.out, "0x{pc:x}");
        out.pcs += 1;
    }

    #[inline]
    fn record_ts(&self, out: &mut Stream) {
        let ts = self.effective_ts();
        let off = out.out.len();
        if let Some(last) = out.segs.last_mut() {
            if last.1 == off {
                last.0 = ts;
                return;
            }
        }
        out.segs.push((ts, off));
    }

    #[inline]
    fn in_text(&self, vmlinux_pc: u64) -> bool {
        if self.text.is_empty() {
            return vmlinux_pc >= 0xffff_0000_0000_0000 && (vmlinux_pc & 3) == 0;
        }
        vmlinux_pc >= self.text_vaddr
            && vmlinux_pc + 4 <= self.text_end
            && (vmlinux_pc & 3) == 0
    }

    #[inline]
    fn read_insn(&self, vmlinux_pc: u64) -> Option<u32> {
        if self.text.is_empty() || !self.in_text(vmlinux_pc) {
            return None;
        }
        let off = (vmlinux_pc - self.text_vaddr) as usize;
        let b = self.text.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn push_addr(&mut self, runtime_addr: u64) {
        self.addr_reg[2] = self.addr_reg[1];
        self.addr_reg[1] = self.addr_reg[0];
        self.addr_reg[0] = runtime_addr;
    }

    fn on_address(&mut self, runtime_addr: u64, out: &mut Stream) {
        let vmlinux_addr = runtime_addr.wrapping_sub(self.slide);
        if self.text.is_empty() {
            if self.in_text(vmlinux_addr) {
                Self::emit_pc(out, vmlinux_addr);
            }
            self.pending_exc_interp = 0;
            return;
        }
        if self.pending_exc_interp != 0 {
            let interp = self.pending_exc_interp;
            self.pending_exc_interp = 0;
            // ARM IHI 0064 / OpenCSD: when addr_interp == 0b01, instructions
            // between the current IP and the preferred exception return address
            // executed linearly before the exception was taken.
            if interp == 1 {
                if let Some(mut cur_ip) = self.ip {
                    let span = vmlinux_addr.wrapping_sub(cur_ip);
                    if span <= 4096 && (span & 3) == 0 && self.in_text(vmlinux_addr) {
                        while cur_ip < vmlinux_addr {
                            if self.in_text(cur_ip) {
                                Self::emit_pc(out, cur_ip);
                            }
                            cur_ip = cur_ip.wrapping_add(4);
                        }
                    }
                }
            }
            if self.in_text(vmlinux_addr) {
                self.ip = Some(vmlinux_addr);
                self.need_addr = false;
            } else {
                self.ip = None;
                self.need_addr = true;
            }
            return;
        }

        if self.in_text(vmlinux_addr) {
            self.ip = Some(vmlinux_addr);
            self.need_addr = false;
        } else {
            self.ip = None;
            self.need_addr = true;
        }
    }

    fn step_one_atom(&mut self, taken: bool, out: &mut Stream) {
        if self.need_addr || self.text.is_empty() {
            return;
        }
        let Some(mut pc) = self.ip else {
            return;
        };

        // Bound linear walk per atom to 16,384 instructions (64 KiB) to guard
        // against desynchronized trace or self-loops without branches.
        for _ in 0..16_384 {
            let Some(insn) = self.read_insn(pc) else {
                self.ip = None;
                self.need_addr = true;
                return;
            };
            Self::emit_pc(out, pc);
            match decode_a64_p0(insn, pc) {
                A64Insn::Linear => {
                    pc = pc.wrapping_add(4);
                }
                A64Insn::DirectBranch { target } => {
                    if taken && self.in_text(target) {
                        self.ip = Some(target);
                    } else {
                        self.ip = Some(pc.wrapping_add(4));
                    }
                    return;
                }
                A64Insn::CondBranch { target } => {
                    let next = if taken { target } else { pc.wrapping_add(4) };
                    if self.in_text(next) {
                        self.ip = Some(next);
                    } else {
                        self.ip = None;
                        self.need_addr = true;
                    }
                    return;
                }
                A64Insn::IndirectBranch => {
                    self.ip = None;
                    self.need_addr = true;
                    return;
                }
            }
        }
        self.ip = None;
        self.need_addr = true;
    }

    /// Find the starting offset in a per-trace-ID ETMv4 byte stream.
    ///
    /// - If `A-Sync` (`0x00 x 11, 0x80`) appears at the start of the chunk,
    ///   decoding starts there (`0`).
    /// - When a 4 KiB TMC ETF buffer wraps, `TRCSYNCPR = 4096` means `A-Sync`
    ///   can fall near the end of the chunk (or not appear at all in that
    ///   chunk). In that case, we look for the earliest 64-bit/32-bit Long
    ///   Address packet (`0x9d`, `0x85`) whose target is a valid 4-byte-aligned
    ///   kernel `.text` address and from which `scan_etmv4_packet` parses cleanly
    ///   without a single `Bad` packet up to `first_async` (or end of buffer).
    fn find_sync_start(&self, buf: &[u8]) -> Option<usize> {
        let first_async = find_first_async(buf);
        if first_async == Some(0) {
            return Some(0);
        }

        let check_end = first_async.unwrap_or(buf.len());
        let search_limit = check_end.min(512);
        let default_hi = self.text_vaddr.wrapping_add(self.slide) & !0xffff_ffff;
        for cand in 0..search_limit {
            let b0 = buf[cand];
            if b0 != 0x9d && b0 != 0x85 && b0 != 0x9a && b0 != 0x82 {
                continue;
            }
            let (pkt, len) =
                scan_etmv4_packet(buf, cand, self.trcconfig, self.vmid_bytes, self.cid_bytes);
            let addr = match pkt {
                EtmPacket::LongAddr64Is0 { addr } => addr,
                EtmPacket::AddrContext {
                    addr,
                    bits: 64,
                    is1: false,
                    ..
                } => addr,
                EtmPacket::LongAddr32Is0 { addr: a32 }
                | EtmPacket::AddrContext {
                    addr: a32,
                    bits: 32,
                    is1: false,
                    ..
                } => default_hi | (a32 & 0xffff_ffff),
                _ => continue,
            };
            let vmlinux_addr = addr.wrapping_sub(self.slide);
            if !self.in_text(vmlinux_addr) {
                continue;
            }
            if is_clean_packet_run(
                buf,
                cand + len,
                check_end,
                self.trcconfig,
                self.vmid_bytes,
                self.cid_bytes,
            ) {
                return Some(cand);
            }
        }

        first_async
    }

    /// Decode one demuxed ETMv4 byte stream into `out`.
    pub(crate) fn decode_byte_stream(&mut self, buf: &[u8], out: &mut Stream) {
        let Some(mut pos) = self.find_sync_start(buf) else {
            return;
        };
        self.record_ts(out);

        while pos < buf.len() {
            let (pkt, len) =
                scan_etmv4_packet(buf, pos, self.trcconfig, self.vmid_bytes, self.cid_bytes);
            if len == 0 {
                break;
            }
            pos += len;

            match pkt {
                EtmPacket::ASync => {
                    self.pending_exc_interp = 0;
                }
                EtmPacket::TraceInfo { .. } => {
                    let default_hi = self.text_vaddr.wrapping_add(self.slide) & !0xffff_ffff;
                    self.addr_reg = [default_hi; 3];
                    self.ip = None;
                    self.need_addr = true;
                    self.pending_exc_interp = 0;
                }
                EtmPacket::TraceOn => {
                    self.ip = None;
                    self.need_addr = true;
                    self.pending_exc_interp = 0;
                }
                EtmPacket::Timestamp { ts, bits } => {
                    if bits >= 64 {
                        self.ts = ts;
                    } else if bits > 0 {
                        let mask = (1u64 << bits) - 1;
                        self.ts = (self.ts & !mask) | (ts & mask);
                    }
                    *self.seq = self.seq.wrapping_add(1);
                    self.record_ts(out);
                }
                EtmPacket::Exception { addr_interp, .. } => {
                    self.pending_exc_interp = addr_interp;
                    self.need_addr = true;
                }
                EtmPacket::ExceptionReturn | EtmPacket::FuncRet => {}
                EtmPacket::Context { .. } => {}
                EtmPacket::ExactMatch { idx } => {
                    let addr = self.addr_reg[(idx as usize).min(2)];
                    self.push_addr(addr);
                    self.on_address(addr, out);
                }
                EtmPacket::ShortAddrIs0 { val, bits } | EtmPacket::ShortAddrIs1 { val, bits } => {
                    let mask = (1u64 << bits) - 1;
                    let addr = (self.addr_reg[0] & !mask) | (val & mask);
                    self.push_addr(addr);
                    self.on_address(addr, out);
                }
                EtmPacket::LongAddr32Is0 { addr: a32 } | EtmPacket::LongAddr32Is1 { addr: a32 } => {
                    let addr = (self.addr_reg[0] & !0xffff_ffff) | (a32 & 0xffff_ffff);
                    self.push_addr(addr);
                    self.on_address(addr, out);
                }
                EtmPacket::LongAddr64Is0 { addr } | EtmPacket::LongAddr64Is1 { addr } => {
                    self.push_addr(addr);
                    self.on_address(addr, out);
                }
                EtmPacket::AddrContext { addr, bits, .. } => {
                    let full = if bits == 32 {
                        (self.addr_reg[0] & !0xffff_ffff) | (addr & 0xffff_ffff)
                    } else {
                        addr
                    };
                    self.push_addr(full);
                    self.on_address(full, out);
                }
                EtmPacket::Atom { bits, count } => {
                    for i in 0..count {
                        let taken = ((bits >> i) & 1) != 0;
                        self.step_one_atom(taken, out);
                    }
                }
                EtmPacket::Q { .. } | EtmPacket::Ignore => {}
                EtmPacket::Bad => {
                    // Lost packet alignment: drop current IP and fast-forward to
                    // the next A-Sync or validated 64-bit Long Address packet.
                    self.ip = None;
                    self.need_addr = true;
                    self.pending_exc_interp = 0;
                    if let Some(rel) = self.find_sync_start(&buf[pos..]) {
                        pos += rel;
                    } else {
                        break;
                    }
                }
            }
        }
        *self.seq = self.seq.wrapping_add(1);
    }
}

/// Find the byte offset of the first ETMv4 `A-Sync` (`11 x 0x00, 0x80`) in `buf`.
fn find_first_async(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let mut i = 0usize;
    while i + 12 <= buf.len() {
        if buf[i..i + 11] == [0u8; 11] && buf[i + 11] == 0x80 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Verify that `buf[start..end]` scans cleanly into valid ETMv4 packets with
/// zero `EtmPacket::Bad` (allowing at most 8 trailing bytes truncated by a
/// chunk/frame boundary at the very end of the buffer).
fn is_clean_packet_run(
    buf: &[u8],
    start: usize,
    end: usize,
    trcconfig: u32,
    vmid_bytes: usize,
    cid_bytes: usize,
) -> bool {
    let mut p = start;
    let mut pkt_count = 0usize;
    while p < end {
        let (pkt, len) = scan_etmv4_packet(buf, p, trcconfig, vmid_bytes, cid_bytes);
        if matches!(pkt, EtmPacket::Bad) {
            return p + 8 >= end && pkt_count >= 4;
        }
        p += len;
        pkt_count += 1;
    }
    pkt_count >= 1
}

fn parse_aux_record_line(s: &str) -> Option<AuxRecord> {
    let mut cpu = None;
    let mut offset = None;
    let mut size = None;
    let mut flags = None;
    for part in s.split(',') {
        let (k, v) = part.split_once(':')?;
        let v_clean = v.split('(').next().unwrap_or(v);
        match k.trim() {
            "cpu" => cpu = v_clean.trim().parse::<i32>().ok(),
            "offset" => offset = parse_hex_or_dec(v_clean),
            "size" => size = parse_hex_or_dec(v_clean),
            "flags" => flags = parse_hex_or_dec(v_clean),
            _ => {}
        }
    }
    Some(AuxRecord {
        cpu: cpu?,
        offset: offset?,
        size: size?,
        flags: flags?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real 13-frame (208-byte) CoreSight ETF capture fixture.
    /// For example: captured on AMD Kria KV260 (`5.15.224-coresight-xilinx-zynqmp`,
    /// CPU 3 `trace_id=0x16`). Starts with trace ID change `0x2d` (`0x16 << 1 | 1`)
    /// and `A-Sync`, followed by `TraceInfo`, `AddrContext` (64-bit IS0),
    /// `Timestamp`, `Atom` F1/F2, `LongAddr64Is0`, `ShortAddrIs0`, `LongAddr32Is0`,
    /// and ends with flush ID `0x00`.
    const ETMV4_ETF_FIXTURE_FRAMES: &[u8] = &[
        0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x81,
        0x00, 0x00, 0x84, 0x76, 0x78, 0x29, 0x08, 0x00, 0x80, 0xff, 0xfe, 0xb1, 0x2a, 0x69, 0x00, 0x63,
        0x00, 0xf7, 0x02, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0xf6, 0x02, 0x00, 0x00,
        0xf6, 0x02, 0x00, 0xf7, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf7, 0x9c, 0x3a, 0x76, 0x29, 0x08, 0x29,
        0x00, 0x80, 0xfe, 0xff, 0x02, 0x00, 0xd8, 0x02, 0x00, 0xf7, 0x02, 0x00, 0xf6, 0x02, 0x00, 0x4a,
        0xf6, 0x02, 0x00, 0xda, 0x94, 0xd0, 0xae, 0x02, 0x00, 0xf7, 0x94, 0x9e, 0xf4, 0x02, 0x00, 0x25,
        0xf6, 0x95, 0x50, 0x02, 0x00, 0xf7, 0x9a, 0x28, 0x28, 0x0e, 0x08, 0x02, 0x00, 0xf7, 0x02, 0x21,
        0x00, 0xf6, 0x02, 0x00, 0xd8, 0x02, 0x00, 0xf7, 0x94, 0xed, 0x26, 0x02, 0x00, 0xf6, 0x02, 0x34,
        0x00, 0xf6, 0x02, 0x00, 0xd8, 0x02, 0x2d, 0x00, 0xda, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf6, 0x80,
        0x94, 0x7c, 0x02, 0x00, 0xda, 0x95, 0xc2, 0x88, 0x02, 0x00, 0xd8, 0x02, 0x00, 0xf6, 0x02, 0x09,
        0x00, 0xd9, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xda, 0x02, 0x24,
        0x00, 0xf7, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf7, 0x02, 0x00, 0xf6, 0x02, 0x00, 0xf6, 0x02, 0x20,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn meta_file_roundtrips_cpu_regs_and_aux_records() {
        let dir = std::env::temp_dir().join(format!("vock-cs-meta-test-{}", unsafe { libc::getpid() }));
        let _ = std::fs::create_dir_all(&dir);
        let meta_path = dir.join("hw_trace.meta");
        let cpu0_path = dir.join("hw_trace.cpu0.bin");
        std::fs::write(&cpu0_path, [0x00u8, 0x10, 0x20, 0x30]).unwrap();

        let cap = CsCapture {
            // For example: uname from an arm64 CoreSight testbed (such as AMD Kria KV260).
            uname: "5.15.0-coresight-arm64".into(),
            runtime_text: 0xffff_8000_0800_0000,
            runtime_stext: 0xffff_8000_0801_0000,
            sink_name: "tmc_etf0".into(),
            sink_id: 0x9797_9549,
            sink_buffer_size: 0x1000,
            attr_config: 0x1000_4000,
            etm_config: 0x840,
            addr_filter: "filter 0xffff800008010000/0x1100000".into(),
            cpus: vec![EtmCpuMeta {
                cpu: 0,
                trace_id: 0x10,
                trcidr0: 0x2800_0ea1,
                trcidr1: 0x4100_f404,
                trcidr2: 0x0000_0488,
                trcidr3: 0x0d7b_0004,
                trcidr4: 0x1117_0004,
                trcidr5: 0x28c7_081e,
                trcidr8: 0,
                trcidr9: 0,
                trcidr10: 0,
                trcidr11: 0,
                trcidr12: 0,
                trcidr13: 0,
                trcconfig: 0x840,
                trctraceid: 0x10,
                trcdevarch: 0x4770_4a13,
                aux_size: 0x40_0000,
                lost: 0,
            }],
            aux_records: vec![AuxRecord {
                cpu: 0,
                offset: 0,
                size: 0x1000,
                flags: PERF_AUX_FLAG_TRUNCATED,
            }],
            aux_bufs: vec![(0, vec![0x00, 0x10, 0x20, 0x30])],
        };

        cap.write_meta_file(meta_path.to_str().unwrap()).unwrap();
        let loaded = CsCapture::load_from_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(loaded.uname, cap.uname);
        assert_eq!(loaded.runtime_text, cap.runtime_text);
        assert_eq!(loaded.runtime_stext, cap.runtime_stext);
        assert_eq!(loaded.sink_name, "tmc_etf0");
        assert_eq!(loaded.sink_id, 0x9797_9549);
        assert_eq!(loaded.sink_buffer_size, 0x1000);
        assert_eq!(loaded.etm_config, 0x840);
        assert_eq!(loaded.addr_filter, "filter 0xffff800008010000/0x1100000");
        assert_eq!(loaded.cpus.len(), 1);
        assert_eq!(loaded.cpus[0].trace_id, 0x10);
        assert_eq!(loaded.cpus[0].trcidr0, 0x2800_0ea1);
        assert_eq!(loaded.cpus[0].trcidr1, 0x4100_f404);
        assert_eq!(loaded.cpus[0].trcidr2, 0x0000_0488);
        assert_eq!(loaded.aux_records, cap.aux_records);
        assert_eq!(loaded.aux_bufs, cap.aux_bufs);
    }

    #[test]
    fn demux_frames_handles_id_switches_lsb_restoration_and_fsync() {
        // Prepend a 16-byte barrier packet (4x FSYNC) followed by a synthetic frame:
        // - h=0: immediate ID switch to 0x10 ((0x10 << 1) | 1 = 0x21, abit=0), odd = 0xaa -> stream 0x10 gets [0xaa]
        // - h=1: data pair even=0x84, odd=0x55 with abit=1 -> stream 0x10 gets [0x85, 0x55]
        // - h=2: deferred ID switch to 0x12 ((0x12 << 1) | 1 = 0x25, abit=1), odd = 0xbb -> stream 0x10 gets [0xbb], curr_id becomes 0x12
        // - h=3: data pair even=0xf6, odd=0x04 with abit=0 -> stream 0x12 gets [0xf6, 0x04]
        // - h=4..6: switch to ID 0x00 (null) at h=4 ((0x00 << 1) | 1 = 0x01, abit=0)
        // - h=7 (byte 14): switch to ID 0x10 ((0x10 << 1) | 1 = 0x21, abit=0)
        let mut raw = Vec::new();
        for _ in 0..4 {
            raw.extend_from_slice(&CORESIGHT_FSYNC);
        }
        let frame: [u8; 16] = [
            0x21, 0xaa, // h=0: abit=0 -> id=0x10, emit 0xaa
            0x84, 0x55, // h=1: abit=1 -> emit 0x85, 0x55 to 0x10
            0x25, 0xbb, // h=2: abit=1 -> emit 0xbb to 0x10, then id=0x12
            0xf6, 0x04, // h=3: abit=0 -> emit 0xf6, 0x04 to 0x12
            0x01, 0x00, // h=4: abit=0 -> id=0x00 (ignored)
            0x00, 0x00, // h=5
            0x00, 0x00, // h=6
            0x22,       // h=7 (byte 14): even=0x22, abit7=1 -> emit 0x23 if curr_id valid (curr_id is 0 here)
            0b1000_0110, // aux: bits 1, 2, 7 set
        ];
        raw.extend_from_slice(&frame);

        let streams = demux_frames(&raw);
        assert_eq!(streams.get(&0x10).unwrap(), &vec![0xaa, 0x85, 0x55, 0xbb]);
        assert_eq!(streams.get(&0x12).unwrap(), &vec![0xf6, 0x04]);
        assert!(!streams.contains_key(&0x00));
    }

    #[test]
    fn etf_fixture_demuxes_and_scans_with_zero_bad_packets() {
        let demuxed = demux_frames(ETMV4_ETF_FIXTURE_FRAMES);
        let stream = demuxed.get(&0x16).expect("trace_id 0x16 stream present");
        assert_eq!(stream.len(), 178);

        let trcconfig = (1 << ETM4_CFG_BIT_TS) | (1 << ETM4_CFG_BIT_CTXTID);
        let mut pos = 0usize;
        let mut pkts = Vec::new();
        while pos < stream.len() {
            let (pkt, len) = scan_etmv4_packet(stream, pos, trcconfig, 1, 4);
            assert_ne!(pkt, EtmPacket::Bad, "unexpected Bad packet at offset {pos}");
            pkts.push(pkt);
            pos += len;
        }

        assert_eq!(pkts[0], EtmPacket::ASync);
        assert_eq!(
            pkts[1],
            EtmPacket::TraceInfo {
                plctl: 1,
                info: 0
            }
        );
        assert_eq!(
            pkts[2],
            EtmPacket::AddrContext {
                addr: 0xffff_8000_0829_f1d8,
                bits: 64,
                is1: false,
                el: 1,
                sf: true,
            }
        );
        assert!(pkts.iter().any(|p| matches!(
            p,
            EtmPacket::LongAddr64Is0 {
                addr: 0xffff_8000_0829_ece8
            }
        )));
        assert!(pkts.iter().any(|p| matches!(
            p,
            EtmPacket::LongAddr32Is0 { addr: 0x090e_50a0 }
        )));
    }

    #[test]
    fn etmv4_decoder_walks_synthetic_a64_branches_and_atoms() {
        // Build a 7-instruction (28-byte) synthetic A64 `.text` image at 0xffff_8000_0801_0000:
        //   +0x00: 0xd503201f  nop                        (Linear)
        //   +0x04: 0x54000060  b.eq +0x10 (to +0x10)      (CondBranch)
        //   +0x08: 0xd503201f  nop                        (Linear, fallthrough when N)
        //   +0x0c: 0x14000002  b +0x08 (to +0x14)         (DirectBranch, E)
        //   +0x10: 0xd503201f  nop                        (Linear, target when E)
        //   +0x14: 0xd65f03c0  ret                        (IndirectBranch, E)
        //   +0x18: 0xd503201f  nop                        (Return target via ShortAddrIs0)
        let base: u64 = 0xffff_8000_0801_0000;
        let insns: [u32; 7] = [
            0xd503_201f, // +0x00 nop
            0x5400_0060, // +0x04 b.eq +0x10 (imm19 = 3 -> +12 -> 0x04 + 0x0c = 0x10)
            0xd503_201f, // +0x08 nop
            0x1400_0002, // +0x0c b +0x14 (imm26 = 2 -> +8 -> 0x0c + 0x08 = 0x14)
            0xd503_201f, // +0x10 nop
            0xd65f_03c0, // +0x14 ret
            0xd503_201f, // +0x18 nop
        ];
        let mut text = Vec::with_capacity(insns.len() * 4);
        for w in insns {
            text.extend_from_slice(&w.to_le_bytes());
        }

        // Construct ETMv4 stream:
        // 1. A-Sync (11x 0x00, 0x80)
        // 2. TraceInfo (0x01, 0x00)
        // 3. LongAddr64Is0 (0x9d) = 0xffff_8000_0801_0000
        // 4. Timestamp (0x02, 0x2a) -> ts = 42
        // 5. Atom F3 (0xf8 | 0b110 = 0xfe): 3 atoms:
        //    - atom 0 (bit 0 = 0 = N): walks +0x00 (nop), +0x04 (b.eq not-taken -> +0x08)
        //    - atom 1 (bit 1 = 1 = E): walks +0x08 (nop), +0x0c (b -> +0x14)
        //    - atom 2 (bit 2 = 1 = E): walks +0x14 (ret -> IndirectBranch, waits for addr)
        let mut stream = vec![0u8; 11];
        stream.push(0x80);
        stream.extend_from_slice(&[0x01, 0x00]);
        stream.extend_from_slice(&[
            0x9d, 0x00, 0x00, 0x01, 0x08, 0x00, 0x80, 0xff, 0xff,
        ]);
        stream.extend_from_slice(&[0x02, 42]);
        stream.push(0xfe); // F3: bits = 0b110 (oldest=N, E, newest=E)

        let mut seq = 1u64;
        let mut dec = Etmv4Decoder::new(&text, base, 0, None, 0, &mut seq);
        let mut out = Stream::default();
        dec.decode_byte_stream(&stream, &mut out);

        assert_eq!(out.pcs, 5);
        assert_eq!(
            out.out,
            format!(
                "0x{:x}\n0x{:x}\n0x{:x}\n0x{:x}\n0x{:x}\n",
                base + 0x00,
                base + 0x04,
                base + 0x08,
                base + 0x0c,
                base + 0x14,
            )
        );
        assert_eq!(out.segs, vec![(42, 0)]);
    }

    #[test]
    fn etmv4_decoder_handles_exception_range_short_addr_and_exact_match() {
        // 8-NOP synthetic .text at 0xffff_8000_0801_0000 .. +0x20.
        let base: u64 = 0xffff_8000_0801_0000;
        let mut text = Vec::with_capacity(32);
        for _ in 0..7 {
            text.extend_from_slice(&0xd503_201fu32.to_le_bytes()); // nop
        }
        text.extend_from_slice(&0xd65f_03c0u32.to_le_bytes()); // +0x1c: ret

        let mut stream = vec![0u8; 11];
        stream.push(0x80);
        stream.extend_from_slice(&[0x01, 0x00]); // TraceInfo
        // LongAddr64Is0 = base (+0x00)
        stream.extend_from_slice(&[0x9d, 0x00, 0x00, 0x01, 0x08, 0x00, 0x80, 0xff, 0xff]);
        // Exception (0x06) with addr_interp = 0b01 (b1 = 0x01) followed by ShortAddrIs0 (0x95) = +0x0c (0x0c >> 2 = 0x03).
        // Should emit linear range [base+0x00, base+0x04, base+0x08] and set IP = base+0x0c.
        stream.extend_from_slice(&[0x06, 0x01]);
        stream.extend_from_slice(&[0x95, 0x03]);
        // ExactMatch idx=1 (0x91) -> restores previous addr_reg[1] = base+0x00, then Atom F1 E (0xf7)
        // which walks from base+0x00 to +0x1c (ret).
        stream.push(0x91);
        stream.push(0xf7);

        let mut seq = 1u64;
        let mut dec = Etmv4Decoder::new(&text, base, 0, None, 0, &mut seq);
        let mut out = Stream::default();
        dec.decode_byte_stream(&stream, &mut out);

        // 3 PCs from exception linear range (+0x00, +0x04, +0x08) + 8 PCs from atom walk (+0x00..=+0x1c) = 11 PCs.
        assert_eq!(out.pcs, 11);
    }

    #[test]
    fn offline_etf_capture_decodes_if_present() {
        // For example: verifies offline decoding of a captured ETF session
        // (such as `../captures/run-01` from AMD Kria KV260) when present.
        let cap_dir = std::path::Path::new("../captures/run-01");
        let vmlinux_path = std::path::Path::new("../captures/vmlinux");
        if !cap_dir.exists() || !vmlinux_path.exists() {
            return;
        }
        let cap = CsCapture::load_from_dir(cap_dir).expect("load run-01");
        let (text, text_vaddr, _) =
            load_vmlinux_text(vmlinux_path.to_str().unwrap()).expect("load vmlinux .text");
        let streams = cap.decode_to_streams(Some((&text, text_vaddr)));
        let total_pcs: i32 = streams.iter().map(|s| s.pcs).sum();
        assert_eq!(total_pcs, 5955);
        let merged = merge_streams(&streams);
        assert!(merged.contains("0xffff80000829f1d8\n")); // ctx_sched_out
        assert!(merged.contains("0xffff80000829ece8\n")); // group_sched_out.part.0
        assert!(merged.contains("0xffff8000090e50a0\n")); // etm_event_del
    }

    #[test]
    fn sink_priority_orders_trbe_etr_etf_etb() {
        // Common fallback order: try trbe* first, then tmc_etr0 (System DRAM sink),
        // and if probe_sink fails on tmc_etr0, fall back to tmc_etf0 (On-chip SRAM sink).
        assert!(sink_priority("trbe0") < sink_priority("tmc_etr0"));
        assert!(sink_priority("tmc_etr0") < sink_priority("tmc_etf0"));
        assert!(sink_priority("tmc_etf0") < sink_priority("tmc_etb0"));
    }

    #[test]
    fn kallsyms_and_elf_exec_filters_format_perf_ioc_set_filter_clauses() {
        let fake_kallsyms = "\
ffff800008a346e0 t read_zero\n\
ffff800008a347d0 t write_null\n\
ffff800008a34800 t write_full\n\
ffff800008a3a7a8 t urandom_read_iter\n\
ffff800008a3a860 t random_read_iter\n";
        let ranges = resolve_symbols_from_kallsyms_str(
            fake_kallsyms,
            &["read_zero", "write_null", "urandom_read_iter"],
        )
        .expect("resolve 3 kernel symbols");
        assert_eq!(
            ranges,
            vec![
                (0xffff_8000_08a3_46e0, 0xf0),
                (0xffff_8000_08a3_47d0, 0x30),
                (0xffff_8000_08a3_a7a8, 0xb8),
            ]
        );

        // Build a minimal 120-byte ELF64 LE header + 1 PT_LOAD PF_X program header.
        let tmp_elf = std::env::temp_dir().join(format!("vock-test-elf-{}", unsafe { libc::getpid() }));
        let mut elf = vec![0u8; 120];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
        // Program header at offset 64: PT_LOAD (1), PF_R | PF_X (5), p_offset=0x1000, p_filesz=0x2340
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&0x2340u64.to_le_bytes());
        std::fs::write(&tmp_elf, &elf).unwrap();

        let f = build_elf_exec_filter(tmp_elf.to_str().unwrap()).expect("ELF PT_LOAD PF_X filter");
        let _ = std::fs::remove_file(&tmp_elf);
        assert!(
            f.starts_with("filter 0x1000/0x2340@"),
            "unexpected ELF filter: {f}"
        );
    }

    #[test]
    fn etmv4_decoder_handles_timeless_z_mode_and_cycle_accurate_packets() {
        // 4 instructions: nop, b.eq +0x0c, nop, ret
        let base: u64 = 0xffff_8000_0801_0000;
        let insns: [u32; 4] = [
            0xd503_201f, // +0x00 nop
            0x5400_0040, // +0x04 b.eq +0x0c (imm19 = 2 -> +8 -> 0x0c)
            0xd503_201f, // +0x08 nop
            0xd65f_03c0, // +0x0c ret
        ];
        let mut text = Vec::with_capacity(16);
        for w in insns {
            text.extend_from_slice(&w.to_le_bytes());
        }

        // Stream without ANY Timestamp packets (timeless Z mode), plus Cycle Count
        // Format 2 (`0x0c`, `0x05`) and Cycle Count Format 3 (`0x15`) packets interspersed:
        let mut stream = vec![0u8; 11];
        stream.push(0x80); // A-Sync
        stream.extend_from_slice(&[0x01, 0x00]); // TraceInfo (cc_enabled=0)
        stream.extend_from_slice(&[0x9d, 0x00, 0x00, 0x01, 0x08, 0x00, 0x80, 0xff, 0xff]); // LongAddr64Is0 = base
        stream.extend_from_slice(&[0x0c, 0x05]); // Cycle count F2
        stream.push(0x15); // Cycle count F3
        stream.push(0xd9); // Atom F2: EN (bit 0 = 1 taken -> +0x0c, bit 1 = 1 taken -> ret)

        let mut seq = 1u64;
        let mut dec = Etmv4Decoder::new(&text, base, 0, None, 0, &mut seq);
        let mut out = Stream::default();
        dec.decode_byte_stream(&stream, &mut out);

        // Walked +0x00 (nop), +0x04 (b.eq taken -> +0x0c), +0x0c (ret) = 3 PCs.
        assert_eq!(out.pcs, 3);
        assert_eq!(
            out.out,
            format!("0x{:x}\n0x{:x}\n0x{:x}\n", base + 0x00, base + 0x04, base + 0x0c)
        );
        // Synthetic monotonic sequence timestamp recorded even without 0x02/0x03 packets.
        assert_eq!(out.segs, vec![(1, 0)]);
    }
}

