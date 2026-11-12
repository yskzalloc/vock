//! perf_event plumbing shared by the `--mode hw` backends
//! (streaming::intel, sampling::amd, and later streaming::arm).
//!
//! Task following: every event is opened once per online CPU with
//! `attr.inherit = 1` on the target pid, so the kernel clones it into every
//! task the target later forks, vforks or spawns as a thread (exec keeps it),
//! and the clones write into the parent event's ring/AUX buffer on that CPU
//! (kernel/events/ring_buffer.c). This needs no help from inside the target,
//! unlike KCOV's per-thread handles (kcov-preload). Per-CPU events are
//! required: the kernel refuses to mmap an inherited `cpu == -1` event
//! (perf_mmap: "Don't allow mmap() of inherited per-task counters"). When
//! per-CPU events cannot be opened at all, `open_rings` falls back to the old
//! single-task `cpu == -1` event and says so.
//!
//! Only `std` and `libc` are used. `perf_event_attr`, `perf_event_mmap_page`,
//! the PERF_* constants and PERF_EVENT_IOC_* ioctls are not exposed by
//! libc 0.2, so they are defined locally below.

use std::ptr;

// ─── perf constants (not in libc 0.2) ────────────────────────────────────────

// ioctl requests: PERF_EVENT_IOC_ENABLE = _IO('$', 0), DISABLE = _IO('$', 1).
// _IO(type,nr) with dir=NONE(0), size=0 → (type << 8) | nr, '$' == 0x24.
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;

pub(crate) const PERF_TYPE_HARDWARE: u32 = 0;
pub(crate) const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;

pub(crate) const PERF_SAMPLE_IP: u64 = 1 << 0;
pub(crate) const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub(crate) const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;

pub(crate) const PERF_SAMPLE_BRANCH_KERNEL: u64 = 1 << 1;
pub(crate) const PERF_SAMPLE_BRANCH_ANY: u64 = 1 << 3;

pub(crate) const PERF_RECORD_SAMPLE: u32 = 9;

// perf_event_attr bitfield flags (within the single `flags` u64 word).
pub(crate) const ATTR_DISABLED: u64 = 1 << 0;
const ATTR_INHERIT: u64 = 1 << 1; // follow tasks forked/cloned after open
pub(crate) const ATTR_EXCLUDE_USER: u64 = 1 << 4;
pub(crate) const ATTR_FREQ: u64 = 1 << 10; // sample_period_or_freq is a frequency (Hz)
// exclude_kernel would be `1 << 5`, kept 0 to trace the kernel.

// Byte offsets into perf_event_mmap_page (stable kernel ABI; the control
// fields live at fixed offset 1024).
pub(crate) const OFF_DATA_HEAD: usize = 1024;
pub(crate) const OFF_DATA_TAIL: usize = 1032;
const OFF_AUX_HEAD: usize = 1056;
const OFF_AUX_OFFSET: usize = 1072;
const OFF_AUX_SIZE: usize = 1080;

pub(crate) const PAGE_SIZE: usize = 4096;

/// AUX area per CPU (intel_pt.c: AUX_SIZE, 4 MiB).
const AUX_SIZE: usize = 4 * 1024 * 1024;
/// Smallest per-CPU AUX area tried when the locked-memory budget
/// (perf_event_mlock_kb x CPUs + RLIMIT_MEMLOCK) cannot fit `AUX_SIZE` on
/// every CPU. Only unprivileged runs with perf_event_paranoid >= 0 hit it.
const AUX_SIZE_MIN: usize = 64 * 1024;
/// Data pages in front of an AUX area (intel_pt.c: MMAP_PAGES); only the
/// control page is read, the records there are not consumed.
const AUX_RING_DATA_PAGES: usize = 1;
/// Smallest sample ring tried under the same budget.
const SAMPLE_PAGES_MIN: usize = 8;

/// perf_event_attr, matches the kernel ABI (PERF_ATTR_SIZE_VER8, 136 bytes).
/// C bitfields (`disabled`, `exclude_user`, …) are collapsed into `flags`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct PerfEventAttr {
    pub(crate) type_: u32,
    pub(crate) size: u32,
    pub(crate) config: u64,
    pub(crate) sample_period_or_freq: u64,
    pub(crate) sample_type: u64,
    pub(crate) read_format: u64,
    pub(crate) flags: u64,
    pub(crate) wakeup: u32, // wakeup_events / wakeup_watermark
    pub(crate) bp_type: u32,
    pub(crate) config1: u64, // bp_addr / kprobe_func / config1
    pub(crate) config2: u64, // bp_len / kprobe_addr / config2
    pub(crate) branch_sample_type: u64,
    pub(crate) sample_regs_user: u64,
    pub(crate) sample_stack_user: u32,
    pub(crate) clockid: i32,
    pub(crate) sample_regs_intr: u64,
    pub(crate) aux_watermark: u32,
    pub(crate) sample_max_stack: u16,
    pub(crate) reserved_2: u16,
    pub(crate) aux_sample_size: u32,
    pub(crate) reserved_3: u32,
    pub(crate) sig_data: u64,
    pub(crate) config3: u64,
}

impl PerfEventAttr {
    /// A disabled, kernel-only attr of the given PMU type; callers fill in
    /// the event-specific fields.
    pub(crate) fn kernel_only(type_: u32) -> PerfEventAttr {
        PerfEventAttr {
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            type_,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_USER,
            ..Default::default()
        }
    }
}

// ─── raw mmap-page field access ──────────────────────────────────────────────

#[inline]
pub(crate) unsafe fn read_u64(base: *const libc::c_void, off: usize) -> u64 {
    ((base as *const u8).add(off) as *const u64).read_volatile()
}

#[inline]
pub(crate) unsafe fn write_u64(base: *mut libc::c_void, off: usize, val: u64) {
    ((base as *mut u8).add(off) as *mut u64).write_volatile(val);
}

// ─── perf_event_open / sysfs helpers ─────────────────────────────────────────

unsafe fn perf_event_open(attr: &PerfEventAttr, pid: libc::pid_t, cpu: i32) -> i32 {
    // perf_event_open(attr, pid, cpu, group_fd=-1, flags=0)
    libc::syscall(
        libc::SYS_perf_event_open,
        attr as *const PerfEventAttr,
        pid,
        cpu,
        -1i32,
        0u64,
    ) as i32
}

/// Whether a PMU is registered (`/sys/bus/event_source/devices/<name>`).
pub(crate) fn pmu_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/bus/event_source/devices/{name}")).exists()
}

/// Dynamic PMU type from sysfs (e.g. intel_pt, ibs_op), None when the PMU is
/// absent, notably inside KVM guests, which virtualize neither Intel PT, IBS
/// nor AMD branch stacks.
pub(crate) fn pmu_type(name: &str) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/sys/bus/event_source/devices/{name}/type")).ok()?;
    parse_leading_int(&s).filter(|v| *v >= 0).map(|v| v as u32)
}

/// Single-bit `attr.config` field of a PMU, from its sysfs format directory
/// (e.g. intel_pt `tsc` is "config:10"). None when absent or multi-bit.
pub(crate) fn pmu_config_bit(pmu: &str, field: &str) -> Option<u32> {
    let s =
        std::fs::read_to_string(format!("/sys/bus/event_source/devices/{pmu}/format/{field}"))
            .ok()?;
    let bit = s.trim().strip_prefix("config:")?;
    bit.parse::<u32>().ok().filter(|b| *b < 64)
}

/// Parse a sysfs CPU list ("0-3,5,7-8").
fn parse_cpu_list(s: &str) -> Option<Vec<i32>> {
    let mut v = Vec::new();
    for part in s.trim().split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (a.parse::<i32>().ok()?, b.parse::<i32>().ok()?);
                if b < a {
                    return None;
                }
                v.extend(a..=b);
            }
            None => v.push(part.parse().ok()?),
        }
    }
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Online CPU ids; falls back to 0..nproc when sysfs is unreadable.
fn online_cpus() -> Vec<i32> {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| parse_cpu_list(&s))
        .unwrap_or_else(|| {
            let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1);
            (0..n as i32).collect()
        })
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

// ─── per-CPU perf buffers ────────────────────────────────────────────────────

/// One opened perf event and its mmaps: the sample/control ring and, for
/// AUX-based tracers (Intel PT, CoreSight), the AUX trace area. Unmapped and
/// closed on Drop.
pub(crate) struct Ring {
    /// CPU the event is bound to; -1 for the single-task fallback.
    pub(crate) cpu: i32,
    fd: i32,
    pub(crate) base: *mut libc::c_void,
    pub(crate) size: usize,
    aux: *mut libc::c_void,
    pub(crate) aux_size: usize,
}

impl Ring {
    fn new(fd: i32, cpu: i32) -> Ring {
        Ring {
            cpu,
            fd,
            base: libc::MAP_FAILED,
            size: 0,
            aux: libc::MAP_FAILED,
            aux_size: 0,
        }
    }

    fn mmap(fd: i32, len: usize, prot: i32, off: usize) -> Option<*mut libc::c_void> {
        let p = unsafe {
            libc::mmap(ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, off as libc::off_t)
        };
        (p != libc::MAP_FAILED).then_some(p)
    }

    /// Sample ring of up to `data_pages` data pages (power of two). Shrinks
    /// when the locked-memory budget is exhausted, so every CPU gets a ring.
    pub(crate) fn sample(fd: i32, cpu: i32, data_pages: usize, label: &str) -> Option<Ring> {
        let mut r = Ring::new(fd, cpu);
        let mut pages = data_pages;
        loop {
            let size = (pages + 1) * PAGE_SIZE;
            if let Some(b) = Self::mmap(fd, size, libc::PROT_READ | libc::PROT_WRITE, 0) {
                r.base = b;
                r.size = size;
                return Some(r);
            }
            let err = std::io::Error::last_os_error();
            if pages <= SAMPLE_PAGES_MIN || err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("{label}: mmap (cpu {cpu}): {err}");
                return None;
            }
            pages /= 2;
        }
    }

    /// AUX tracer: control page + data page, then the AUX area. The AUX
    /// size halves down to `AUX_SIZE_MIN` on EPERM/ENOMEM (mlock budget).
    pub(crate) fn aux(fd: i32, cpu: i32, label: &str) -> Option<Ring> {
        let mut r = Ring::new(fd, cpu);
        let size = (AUX_RING_DATA_PAGES + 1) * PAGE_SIZE;
        match Self::mmap(fd, size, libc::PROT_READ | libc::PROT_WRITE, 0) {
            Some(b) => {
                r.base = b;
                r.size = size;
            }
            None => {
                eprintln!("{label}: mmap ring (cpu {cpu}): {}", std::io::Error::last_os_error());
                return None;
            }
        }
        let mut aux_size = AUX_SIZE;
        loop {
            // Program the AUX area in the mmap header, then map it.
            unsafe {
                write_u64(r.base, OFF_AUX_OFFSET, size as u64);
                write_u64(r.base, OFF_AUX_SIZE, aux_size as u64);
            }
            if let Some(a) = Self::mmap(fd, aux_size, libc::PROT_READ, size) {
                r.aux = a;
                r.aux_size = aux_size;
                if aux_size < AUX_SIZE {
                    eprintln!(
                        "{label}: cpu {cpu}: AUX area reduced to {} KiB (locked-memory limit)",
                        aux_size / 1024
                    );
                }
                return Some(r);
            }
            let err = std::io::Error::last_os_error();
            let budget = matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::ENOMEM));
            if !budget || aux_size <= AUX_SIZE_MIN {
                eprintln!("{label}: aux mmap (cpu {cpu}): {err}");
                return None;
            }
            aux_size /= 2;
        }
    }

    /// Bytes of trace the kernel committed to the AUX area.
    pub(crate) fn aux_data(&self) -> &[u8] {
        if self.aux == libc::MAP_FAILED || self.base == libc::MAP_FAILED {
            return &[];
        }
        let len = (unsafe { read_u64(self.base, OFF_AUX_HEAD) } as usize).min(self.aux_size);
        unsafe { std::slice::from_raw_parts(self.aux as *const u8, len) }
    }

    /// PERF_EVENT_IOC_ENABLE.
    pub(crate) fn enable(&self) {
        unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE, 0) };
    }

    /// PERF_EVENT_IOC_DISABLE. On an inherited event this also disables
    /// every child copy (perf_event_for_each_child).
    pub(crate) fn disable(&self) {
        unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0) };
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            if self.aux != libc::MAP_FAILED {
                libc::munmap(self.aux, self.aux_size);
            }
            if self.base != libc::MAP_FAILED {
                libc::munmap(self.base, self.size);
            }
            if self.fd >= 0 {
                libc::close(self.fd);
            }
        }
    }
}

/// Open `attr` on every online CPU with `inherit` set, following `pid` and
/// every task it forks or clones afterwards. `map` mmaps each event (and
/// owns/closes the fd on failure).
///
/// If no per-CPU event can be opened and mapped, falls back to the legacy
/// single `cpu == -1` event without `inherit`: that one traces only the
/// initial task, so the fallback is announced under `label`. Err carries the
/// first per-CPU error when both fail; nothing is printed then, so callers
/// with their own fallback (AMD LBR -> IP sampling) stay quiet.
pub(crate) fn open_rings(
    label: &str,
    attr: &PerfEventAttr,
    pid: libc::pid_t,
    map: impl Fn(i32, i32) -> Option<Ring>,
) -> Result<Vec<Ring>, std::io::Error> {
    let cpus = online_cpus();
    let mut inherited = *attr;
    inherited.flags |= ATTR_INHERIT;
    let mut rings = Vec::with_capacity(cpus.len());
    let mut first_err: Option<std::io::Error> = None;
    for &cpu in &cpus {
        let fd = unsafe { perf_event_open(&inherited, pid, cpu) };
        if fd < 0 {
            first_err.get_or_insert_with(std::io::Error::last_os_error);
            continue;
        }
        if let Some(r) = map(fd, cpu) {
            rings.push(r);
        }
    }
    if !rings.is_empty() {
        if rings.len() < cpus.len() {
            eprintln!(
                "{label}: only {}/{} CPUs armed{}; tasks running on the others are not traced",
                rings.len(),
                cpus.len(),
                first_err.map(|e| format!(" ({e})")).unwrap_or_default()
            );
        }
        return Ok(rings);
    }

    let fd = unsafe { perf_event_open(attr, pid, -1) };
    if fd < 0 {
        return Err(first_err.unwrap_or_else(std::io::Error::last_os_error));
    }
    let r = map(fd, -1).ok_or_else(|| {
        first_err.take().unwrap_or_else(|| std::io::Error::other("mmap failed"))
    })?;
    eprintln!(
        "{label}: per-CPU inherited events unavailable ({}); tracing the initial task only, \
forked children and new threads are not covered",
        first_err.map(|e| e.to_string()).unwrap_or_else(|| "mmap failed".into())
    );
    Ok(vec![r])
}

/// Human summary of what a set of rings follows.
pub(crate) fn coverage_scope(rings: &[Ring]) -> String {
    match rings {
        [r] if r.cpu < 0 => "initial task only".to_string(),
        _ => format!("target + descendants, {} CPU(s)", rings.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_lists_parse_like_sysfs() {
        assert_eq!(parse_cpu_list("0-3\n"), Some(vec![0, 1, 2, 3]));
        assert_eq!(parse_cpu_list("0,2-3,7"), Some(vec![0, 2, 3, 7]));
        assert_eq!(parse_cpu_list(""), None);
        assert_eq!(parse_cpu_list("3-1"), None);
        assert_eq!(parse_cpu_list("x"), None);
    }

    #[test]
    fn attr_matches_the_kernel_abi_size() {
        // PERF_ATTR_SIZE_VER8
        assert_eq!(std::mem::size_of::<PerfEventAttr>(), 136);
    }
}
