//! vock's own DWARF symbolizer: PC → (function, file:line) straight from a
//! mapped vmlinux, with no external program and no DWARF crate.
//!
//! It does exactly what the report needs and nothing else. The ELF is
//! mmap'd read-only and every section is a slice of the mapping; the unit
//! index comes from `.debug_aranges` alone (one small sequential read), and
//! a unit's line table and function table are parsed only when a PC lands
//! in it. The result follows `addr2line -f`: the innermost inlined
//! function containing the PC (else the subprogram, else the ELF symbol),
//! and the line-table row for the PC. DWARF 2 through 5, little-endian
//! ELF64; compressed debug sections are refused so the caller can fall
//! back to an external tool.
//!
//! Cold-cache behaviour is the design driver: inside a VM guest the first
//! touch of every page is a host round trip, so the tables a run reads
//! end to end are fetched in parallel up front (`tables`), and the bodies
//! of the units a batch of PCs hits are fetched in parallel before the
//! sequential parse (`prefault_units`).

mod abbrev;
mod elf;
mod line;
mod reader;
mod unit;

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::ffi::CString;
use std::rc::Rc;

use abbrev::Abbrevs;
use elf::{Elf, SymTab};
use reader::{cstr_at, Cur, Val};
use unit::{Name, Unit};

use crate::report::timing;

pub struct Sections {
    pub info: &'static [u8],
    pub abbrev: &'static [u8],
    pub str_: &'static [u8],
    pub line: &'static [u8],
    pub line_str: &'static [u8],
    pub ranges: &'static [u8],
    pub rnglists: &'static [u8],
    pub addr: &'static [u8],
    pub str_offsets: &'static [u8],
    pub aranges: &'static [u8],
}

#[derive(Clone, Copy)]
struct Range {
    start: u64,
    end: u64,
    unit: usize,
}

pub struct Symbolizer {
    pub(crate) sec: Sections,
    symtab_raw: (&'static [u8], &'static [u8]),
    symtab: OnceCell<SymTab>,
    /// From .debug_aranges, sorted by start.
    aranges: Vec<Range>,
    /// Every unit offset .debug_aranges names, sorted.
    unit_offsets: Vec<usize>,
    /// Built from every unit header when .debug_aranges misses a PC.
    full: RefCell<Option<Vec<Range>>>,
    units: RefCell<HashMap<usize, Rc<Unit>>>,
    abbrevs: RefCell<HashMap<usize, Rc<Abbrevs>>>,
    threads: usize,
}

// Interior caches are Rc/RefCell; every use goes through one Mutex.
unsafe impl Send for Symbolizer {}

/// Map the whole file read-only for the life of the process. The mapping is
/// never unmapped: the report is the last thing a run does, and every
/// section slice borrows it as `'static`.
fn mmap_file(path: &str) -> Result<&'static [u8], String> {
    let c = CString::new(path).map_err(|e| e.to_string())?;
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e.to_string());
        }
        let len = st.st_size as usize;
        if len == 0 {
            libc::close(fd);
            return Err("empty file".into());
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        libc::close(fd);
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(std::slice::from_raw_parts(p as *const u8, len))
    }
}

const PAGE: usize = 4096;

/// Bring a byte range of the mapping into memory. `MADV_POPULATE_READ`
/// (Linux 5.14) faults the whole range in one call with readahead; older
/// kernels get a manual touch of every page.
pub fn populate(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let start = bytes.as_ptr() as usize & !(PAGE - 1);
    let end = (bytes.as_ptr() as usize + bytes.len() + PAGE - 1) & !(PAGE - 1);
    let len = end - start;
    // MADV_POPULATE_READ = 22; not in every libc crate release.
    let rc = unsafe { libc::madvise(start as *mut libc::c_void, len, 22) };
    if rc == 0 {
        return;
    }
    let mut sum = 0u8;
    let mut p = start;
    while p < end {
        sum = sum.wrapping_add(unsafe { std::ptr::read_volatile(p as *const u8) });
        p += PAGE;
    }
    std::hint::black_box(sum);
}

/// Populate many ranges from `n` threads: the point is to keep several
/// host round trips in flight at once, the ranges themselves are
/// independent.
pub fn populate_parallel(ranges: &[&'static [u8]], n: usize) {
    if ranges.is_empty() {
        return;
    }
    let n = n.clamp(1, ranges.len());
    let per = ranges.len().div_ceil(n);
    std::thread::scope(|s| {
        for chunk in ranges.chunks(per) {
            s.spawn(move || {
                for r in chunk {
                    populate(r);
                }
            });
        }
    });
}

pub fn prefetch_threads() -> usize {
    std::env::var("VOCK_PREFETCH_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8)
}

/// Parse .debug_aranges into sorted ranges plus the set of unit offsets.
fn parse_aranges(sec: &'static [u8]) -> (Vec<Range>, Vec<usize>) {
    let mut out = Vec::new();
    let mut units = Vec::new();
    let mut c = Cur::new(sec, 0);
    while !c.at_end() {
        let Some((len, format64)) = c.initial_length() else { break };
        let Some(end) = c.pos.checked_add(len) else { break };
        let Some(version) = c.u16() else { break };
        if version != 2 {
            break;
        }
        let Some(unit) = c.off(format64) else { break };
        let Some(addr_size) = c.u8() else { break };
        let Some(_seg) = c.u8() else { break };
        let tuple = 2 * addr_size as usize;
        if tuple == 0 {
            break;
        }
        // Tuples are aligned to their own size from the section start.
        let pad = (tuple - c.pos % tuple) % tuple;
        if c.skip(pad).is_none() {
            break;
        }
        units.push(unit);
        while c.pos + tuple <= end.min(sec.len()) {
            let (Some(a), Some(l)) = (c.addr(addr_size), c.addr(addr_size)) else { break };
            if a == 0 && l == 0 {
                break;
            }
            if l != 0 {
                out.push(Range {
                    start: a,
                    end: a.wrapping_add(l),
                    unit,
                });
            }
        }
        c.pos = end;
    }
    out.sort_unstable_by_key(|r| r.start);
    units.sort_unstable();
    units.dedup();
    (out, units)
}

fn find_range(ranges: &[Range], pc: u64) -> Option<usize> {
    let i = ranges.partition_point(|r| r.start <= pc);
    for j in (i.saturating_sub(3)..i).rev() {
        let r = ranges[j];
        if r.start <= pc && pc < r.end {
            return Some(r.unit);
        }
    }
    None
}

impl Symbolizer {
    pub fn open(path: &str) -> Result<Symbolizer, String> {
        timing::mark("dwarf: mmap");
        let data = mmap_file(path)?;
        let elf = Elf::parse(data).map_err(|e| format!("{path}: {e}"))?;
        let s = |n: &str| elf.section(n).map_err(|e| format!("{path}: {e}"));
        let sec = Sections {
            info: s(".debug_info")?,
            abbrev: s(".debug_abbrev")?,
            str_: s(".debug_str")?,
            line: s(".debug_line")?,
            line_str: s(".debug_line_str")?,
            ranges: s(".debug_ranges")?,
            rnglists: s(".debug_rnglists")?,
            addr: s(".debug_addr")?,
            str_offsets: s(".debug_str_offsets")?,
            aranges: s(".debug_aranges")?,
        };
        if sec.info.is_empty() {
            return Err(format!("{path}: no .debug_info (built without DEBUG_INFO?)"));
        }
        timing::mark("dwarf: ELF parsed");
        let threads = prefetch_threads();
        if threads > 0 {
            populate(sec.aranges);
        }
        let (aranges, unit_offsets) = parse_aranges(sec.aranges);
        timing::mark(&format!(
            "dwarf: unit index from .debug_aranges ({} units)",
            unit_offsets.len()
        ));
        Ok(Symbolizer {
            sec,
            symtab_raw: elf.symtab(),
            symtab: OnceCell::new(),
            aranges,
            unit_offsets,
            full: RefCell::new(None),
            units: RefCell::new(HashMap::new()),
            abbrevs: RefCell::new(HashMap::new()),
            threads,
        })
    }

    /// Sections a run reads scattered pieces of, worth fetching whole in
    /// the background: abbreviations, range lists, strings, symbols.
    pub fn tables(&self) -> Vec<&'static [u8]> {
        [
            self.sec.abbrev,
            self.sec.ranges,
            self.sec.rnglists,
            self.sec.str_,
            self.sec.line_str,
            self.sec.str_offsets,
            self.sec.addr,
            self.symtab_raw.0,
            self.symtab_raw.1,
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .flat_map(|s| s.chunks(8 << 20))
        .collect()
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    fn symtab(&self) -> &SymTab {
        self.symtab.get_or_init(|| {
            let t = SymTab::parse(self.symtab_raw.0, self.symtab_raw.1);
            timing::mark("dwarf: symbol table built");
            t
        })
    }

    /// Address of a named ELF symbol (e.g. `_stext`), what `nm` was used for.
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symtab().address_of(name)
    }

    pub(crate) fn abbrevs(&self, off: usize) -> Option<Rc<Abbrevs>> {
        if let Some(a) = self.abbrevs.borrow().get(&off) {
            return Some(a.clone());
        }
        let a = Rc::new(Abbrevs::parse(self.sec.abbrev, off)?);
        self.abbrevs.borrow_mut().insert(off, a.clone());
        Some(a)
    }

    pub(crate) fn unit(&self, off: usize) -> Option<Rc<Unit>> {
        if let Some(u) = self.units.borrow().get(&off) {
            return Some(u.clone());
        }
        let u = Rc::new(Unit::parse(self, off)?);
        self.units.borrow_mut().insert(off, u.clone());
        Some(u)
    }

    /// The unit whose DIEs contain .debug_info offset `off`.
    fn unit_containing(&self, off: usize) -> Option<Rc<Unit>> {
        let i = self.unit_offsets.partition_point(|&u| u <= off);
        let uoff = *self.unit_offsets.get(i.checked_sub(1)?)?;
        let u = self.unit(uoff)?;
        (off < u.end).then_some(u)
    }

    /// A string-class attribute value.
    pub(crate) fn string(&self, unit: &Unit, v: &Val) -> Option<&'static [u8]> {
        match *v {
            Val::Str(s) => Some(s),
            Val::Strp(o) => cstr_at(self.sec.str_, o),
            Val::LineStrp(o) => cstr_at(self.sec.line_str, o),
            Val::Strx(i) => {
                let osz = if unit.shape.format64 { 8 } else { 4 };
                let at = unit.str_offsets_base.checked_add((i as usize).checked_mul(osz)?)?;
                let mut c = Cur::new(self.sec.str_offsets, at);
                let o = c.off(unit.shape.format64)?;
                cstr_at(self.sec.str_, o)
            }
            _ => None,
        }
    }

    /// An address-class value (DW_FORM_addr or an index into .debug_addr).
    fn address(&self, unit: &Unit, v: &Val) -> Option<u64> {
        match *v {
            Val::Addr(a) => Some(a),
            Val::Addrx(i) => {
                let asz = unit.shape.addr_size as usize;
                let at = unit.addr_base.checked_add((i as usize).checked_mul(asz)?)?;
                Cur::new(self.sec.addr, at).addr(unit.shape.addr_size)
            }
            _ => None,
        }
    }

    /// Address ranges of a DIE from low_pc/high_pc or a range list.
    pub(crate) fn die_ranges(
        &self,
        unit: &Unit,
        lo: Option<Val>,
        hi: Option<Val>,
        ranges: Option<Val>,
    ) -> Vec<(u64, u64)> {
        let base = unit.low_pc.and_then(|v| self.address(unit, &v)).unwrap_or(0);
        if let Some(r) = ranges {
            return self.range_list(unit, &r, base);
        }
        let (Some(lo), Some(hi)) = (lo, hi) else { return Vec::new() };
        let Some(lo) = self.address(unit, &lo) else { return Vec::new() };
        let hi = match hi {
            Val::Addr(_) | Val::Addrx(_) => self.address(unit, &hi),
            Val::Udata(n) => Some(lo.wrapping_add(n)),
            Val::Sdata(n) => Some(lo.wrapping_add(n as u64)),
            _ => None,
        };
        match hi {
            Some(hi) if hi > lo => vec![(lo, hi)],
            _ => Vec::new(),
        }
    }

    fn range_list(&self, unit: &Unit, v: &Val, mut base: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        if unit.shape.version < 5 {
            let Val::SecOff(off) = *v else { return out };
            let mut c = Cur::new(self.sec.ranges, off);
            let asz = unit.shape.addr_size;
            let max = if asz == 8 { u64::MAX } else { (1u64 << (8 * asz as u32)) - 1 };
            while let (Some(b), Some(e)) = (c.addr(asz), c.addr(asz)) {
                if b == 0 && e == 0 {
                    break;
                }
                if b == max {
                    base = e;
                    continue;
                }
                if e > b {
                    out.push((base.wrapping_add(b), base.wrapping_add(e)));
                }
            }
            return out;
        }
        let off = match *v {
            Val::SecOff(o) => o,
            Val::Rnglistx(i) => {
                let osz = if unit.shape.format64 { 8 } else { 4 };
                let Some(at) = unit.rnglists_base.checked_add(i as usize * osz) else {
                    return out;
                };
                let Some(rel) = Cur::new(self.sec.rnglists, at).off(unit.shape.format64) else {
                    return out;
                };
                unit.rnglists_base + rel
            }
            _ => return out,
        };
        let mut c = Cur::new(self.sec.rnglists, off);
        let asz = unit.shape.addr_size;
        let addrx = |i: u64| self.address(unit, &Val::Addrx(i));
        while let Some(kind) = c.u8() {
            let pair = match kind {
                0 => break,
                1 => {
                    let Some(i) = c.uleb() else { break };
                    base = addrx(i).unwrap_or(0);
                    continue;
                }
                2 => {
                    let (Some(s), Some(e)) = (c.uleb(), c.uleb()) else { break };
                    (addrx(s), addrx(e))
                }
                3 => {
                    let (Some(s), Some(l)) = (c.uleb(), c.uleb()) else { break };
                    let s = addrx(s);
                    (s, s.map(|s| s.wrapping_add(l)))
                }
                4 => {
                    let (Some(s), Some(e)) = (c.uleb(), c.uleb()) else { break };
                    (Some(base.wrapping_add(s)), Some(base.wrapping_add(e)))
                }
                5 => {
                    let Some(b) = c.addr(asz) else { break };
                    base = b;
                    continue;
                }
                6 => {
                    let (Some(s), Some(e)) = (c.addr(asz), c.addr(asz)) else { break };
                    (Some(s), Some(e))
                }
                7 => {
                    let (Some(s), Some(l)) = (c.addr(asz), c.uleb()) else { break };
                    (Some(s), Some(s.wrapping_add(l)))
                }
                _ => break,
            };
            if let (Some(s), Some(e)) = pair {
                if e > s {
                    out.push((s, e));
                }
            }
        }
        out
    }

    /// Index built from every unit header, for files whose .debug_aranges
    /// is absent or incomplete (clang emits none by default).
    fn full_index(&self) -> std::cell::Ref<'_, Vec<Range>> {
        if self.full.borrow().is_none() {
            let mut v = Vec::new();
            let mut off = 0usize;
            while off < self.sec.info.len() {
                let Some(h) = unit::parse_header(self.sec.info, off) else { break };
                if let Some(u) = self.unit(off) {
                    for (s, e) in u.address_ranges(self) {
                        v.push(Range {
                            start: s,
                            end: e,
                            unit: off,
                        });
                    }
                }
                off = h.end;
            }
            v.sort_unstable_by_key(|r| r.start);
            timing::mark(&format!("dwarf: full unit index built ({} ranges)", v.len()));
            *self.full.borrow_mut() = Some(v);
        }
        std::cell::Ref::map(self.full.borrow(), |o| o.as_ref().unwrap())
    }

    /// .debug_aranges first; on a miss, the index built from every unit
    /// header. clang emits .debug_aranges only for assembler units, so a
    /// present-but-partial table is the normal LLVM=1 case and a miss is
    /// the only way to tell.
    fn unit_offset_for_pc(&self, pc: u64) -> Option<usize> {
        if std::env::var_os("VOCK_DWARF_FULL_INDEX").is_none() {
            if let Some(u) = find_range(&self.aranges, pc) {
                return Some(u);
            }
        }
        find_range(&self.full_index(), pc)
    }

    /// Name held by a DIE anywhere in .debug_info.
    pub(crate) fn die_name(&self, off: usize, hops: u32) -> Option<std::borrow::Cow<'static, str>> {
        let u = self.unit_containing(off)?;
        u.die_name(self, off, hops)
    }

    fn name_string(&self, unit: &Unit, n: &Name) -> Option<String> {
        match n {
            Name::None => None,
            Name::Direct(s) => Some(s.to_string()),
            Name::Die(off) => {
                if *off >= unit.die_off && *off < unit.end {
                    unit.die_name(self, *off, 0)
                } else {
                    self.die_name(*off, 0)
                }
                .map(|c| c.into_owned())
            }
        }
    }

    /// `addr2line -f` for one PC: ("??", "??:0") when nothing is known.
    pub fn resolve(&self, pc: u64) -> (String, String) {
        let mut func: Option<String> = None;
        let mut loc: Option<String> = None;
        if let Some(u) = self.unit_offset_for_pc(pc).and_then(|o| self.unit(o)) {
            if let Some((file, line)) = u.lines(self).and_then(|t| t.find(pc)) {
                loc = Some(format!("{file}:{line}"));
            }
            func = u.funcs(self).find(pc).and_then(|n| self.name_string(&u, n));
        }
        if func.is_none() {
            func = self
                .symtab()
                .before(pc)
                .map(|s| crate::report::resolve::canonical_function(&reader::lossy(s)).to_string());
        }
        (
            func.unwrap_or_else(|| "??".to_string()),
            loc.unwrap_or_else(|| "??:0".to_string()),
        )
    }

    /// Fault in the .debug_info bodies and line programs of every unit the
    /// PCs fall into, in parallel, before the sequential parse walks them.
    pub fn prefault_units(&self, pcs: &[u64]) {
        if self.threads == 0 {
            return;
        }
        let mut offs: Vec<usize> = pcs.iter().filter_map(|&pc| self.unit_offset_for_pc(pc)).collect();
        offs.sort_unstable();
        offs.dedup();
        let mut ranges: Vec<&'static [u8]> = Vec::with_capacity(offs.len() * 2);
        for &off in &offs {
            // The header and root DIE are one page; reading them here
            // costs that page now instead of during the parse.
            let Some(u) = self.unit(off) else { continue };
            if let Some(body) = self.sec.info.get(off..u.end) {
                ranges.push(body);
            }
            if let Some(lp) = u.stmt_list.and_then(|o| line::LineTable::extent(self.sec.line, o)) {
                ranges.push(lp);
            }
        }
        populate_parallel(&ranges, self.threads);
        timing::mark(&format!(
            "dwarf: {} units prefetched for {} PCs",
            offs.len(),
            pcs.len()
        ));
    }
}
