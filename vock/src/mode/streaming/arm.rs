//! Arm CoreSight ETM/ETE `--mode hw` backend (aarch64). TODO: not implemented.
//!
//! Until this lands, a `cs_etm` PMU is detected but `start()` refuses to
//! trace (the previous code fed CoreSight AUX data to the Intel PT decoder,
//! which cannot decode it). The plan, mirroring streaming::intel:
//!
//! TODO(coresight): capture
//!   - PMU `cs_etm` (`pmu_type("cs_etm")`), kernel-only attr
//!     (`PerfEventAttr::kernel_only`), one inherited event per CPU through
//!     `perf::open_rings` with `Ring::aux`, exactly as Intel PT does.
//!   - Select a sink: `attr.config2` (`format/sinkid`) = the id read from
//!     /sys/bus/event_source/devices/cs_etm/sinks/<sink> (TRBE per-CPU sink
//!     on ARMv9 ETE; ETR/ETF otherwise). Without a per-CPU sink (TRBE),
//!     check that per-CPU AUX buffers are accepted at all.
//!   - Enable timestamps (`format/timestamp`) and context IDs
//!     (`format/contextid`) so streams can be merged and tasks told apart;
//!     read the bit positions from sysfs with `perf::pmu_config_bit`.
//!
//! TODO(coresight): decode
//!   - ETMv4 / ETE trace packet decoder (A-sync, I-sync/trace-info,
//!     address, atom E/N, exception, timestamp packets), walking kernel
//!     text from a matching vmlinux like PtDecoder does for TNT/TIP.
//!   - With a trace formatter (ETR/ETF sinks) demultiplex the 16-byte frames
//!     by trace ID first; TRBE writes raw (unformatted) ETE trace per CPU.
//!   - Emit `streaming::Stream` per CPU with timestamp segments and reuse
//!     `streaming::merge_streams`, `save_raw_trace`, `write_kerncov`.
//!
//! TODO(coresight): validate on bare-metal arm64 (hypervisors do not expose
//! ETM/ETE to guests) and enable selftest 2 for it.

use crate::mode::perf::pmu_exists;

const PMU: &str = "cs_etm";

/// Whether the CoreSight ETM/ETE PMU is registered.
pub fn available() -> bool {
    pmu_exists(PMU)
}

/// An armed CoreSight session. TODO(coresight): per-CPU AUX rings.
pub enum CoreSight {}

impl CoreSight {
    /// TODO(coresight): open per-CPU inherited cs_etm events (see module
    /// docs). Always refuses for now.
    pub fn start(_pid: libc::pid_t) -> Option<CoreSight> {
        eprintln!(
            "cs_etm: CoreSight ETM/ETE tracing is not implemented yet (no packet decoder); \
use --mode kcov on arm64"
        );
        None
    }

    pub fn stop(&mut self) {
        match *self {}
    }

    pub fn decode(&mut self, _vmlinux: Option<&str>) {
        match *self {}
    }
}
