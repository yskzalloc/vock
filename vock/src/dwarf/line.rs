//! .debug_line: one line-number program per unit, parsed on first use into
//! rows sorted by address, plus the resolved file table.

use std::borrow::Cow;

use super::reader::{lossy, read_form, Cur, UnitShape};
use super::unit::Unit;
use super::Symbolizer;

pub struct Row {
    pub addr: u64,
    pub file: u32,
    pub line: u32,
    /// DW_LNE_end_sequence: the address is one past the sequence.
    pub end: bool,
}

pub struct LineTable {
    rows: Vec<Row>,
    files: Vec<String>,
    v5: bool,
}

/// Directory + name joined the way addr2line prints it: the compilation
/// directory prefixes anything relative, and "./include/x.h" stays as
/// written (the report normalizes the path afterwards).
fn join(comp_dir: &str, dir: &str, name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    let dir_full: Cow<str> = if dir.starts_with('/') {
        Cow::Borrowed(dir)
    } else if dir.is_empty() {
        Cow::Borrowed(comp_dir)
    } else if comp_dir.is_empty() {
        Cow::Borrowed(dir)
    } else {
        Cow::Owned(format!("{comp_dir}/{dir}"))
    };
    if dir_full.is_empty() {
        name.to_string()
    } else {
        format!("{dir_full}/{name}")
    }
}

/// DWARF 5 directory/file entry lists: (path, directory index) per entry.
fn read_entries_v5(
    c: &mut Cur,
    sym: &Symbolizer,
    unit: &Unit,
    shape: &UnitShape,
) -> Option<Vec<(Cow<'static, str>, u64)>> {
    let nfmt = c.u8()?;
    let mut fmts = Vec::with_capacity(nfmt as usize);
    for _ in 0..nfmt {
        fmts.push((c.uleb()?, c.uleb()? as u16));
    }
    let n = c.uleb()?;
    let mut out = Vec::with_capacity(n.min(1 << 16) as usize);
    for _ in 0..n {
        let mut path: Cow<'static, str> = Cow::Borrowed("");
        let mut dir = 0u64;
        for &(ct, form) in &fmts {
            let v = read_form(c, form, shape, 0)?;
            match ct {
                1 => {
                    if let Some(s) = sym.string(unit, &v) {
                        path = lossy(s).into_owned().into();
                    }
                }
                2 => dir = v.as_u64().unwrap_or(0),
                _ => {}
            }
        }
        out.push((path, dir));
    }
    Some(out)
}

impl LineTable {
    pub fn parse(sym: &Symbolizer, unit: &Unit, off: usize) -> Option<LineTable> {
        let sec = sym.sec.line;
        let mut c = Cur::new(sec, off);
        let (len, format64) = c.initial_length()?;
        let end = c.pos.checked_add(len)?.min(sec.len());
        let version = c.u16()?;
        if !(2..=5).contains(&version) {
            return None;
        }
        let mut addr_size = unit.shape.addr_size;
        if version >= 5 {
            addr_size = c.u8()?;
            let _segment_selector_size = c.u8()?;
        }
        let header_length = c.off(format64)?;
        let prog_start = c.pos.checked_add(header_length)?;
        let min_inst = u64::from(c.u8()?);
        if version >= 4 {
            let _max_ops = c.u8()?;
        }
        let default_is_stmt = c.u8()? != 0;
        let line_base = i64::from(c.i8()?);
        let line_range = u64::from(c.u8()?);
        if line_range == 0 {
            return None;
        }
        let opcode_base = c.u8()?;
        let mut std_lens = vec![0u8; opcode_base as usize];
        for l in std_lens.iter_mut().skip(1) {
            *l = c.u8()?;
        }
        let shape = UnitShape {
            off: unit.shape.off,
            version,
            format64,
            addr_size,
        };
        let comp_dir: &str = unit.comp_dir.as_deref().unwrap_or("");
        type Entries = Vec<(Cow<'static, str>, u64)>;
        let (dirs, files): (Vec<Cow<'static, str>>, Entries) =
            if version >= 5 {
                let d = read_entries_v5(&mut c, sym, unit, &shape)?
                    .into_iter()
                    .map(|(p, _)| p)
                    .collect();
                let f = read_entries_v5(&mut c, sym, unit, &shape)?;
                (d, f)
            } else {
                let mut d = Vec::new();
                loop {
                    let s = c.cstr()?;
                    if s.is_empty() {
                        break;
                    }
                    d.push(lossy(s).into_owned().into());
                }
                let mut f = Vec::new();
                loop {
                    let s = c.cstr()?;
                    if s.is_empty() {
                        break;
                    }
                    let dir = c.uleb()?;
                    c.uleb()?;
                    c.uleb()?;
                    f.push((lossy(s).into_owned().into(), dir));
                }
                (d, f)
            };
        let dir_of = |idx: u64| -> &str {
            if version >= 5 {
                dirs.get(idx as usize).map(|s| s.as_ref()).unwrap_or("")
            } else if idx == 0 {
                ""
            } else {
                dirs.get(idx as usize - 1).map(|s| s.as_ref()).unwrap_or("")
            }
        };
        let files: Vec<String> = files
            .iter()
            .map(|(name, dir)| join(comp_dir, dir_of(*dir), name))
            .collect();

        // The program.
        c.pos = prog_start;
        let mut rows: Vec<Row> = Vec::new();
        let (mut addr, mut file, mut line) = (0u64, 1u32, 1u32);
        let mut is_stmt = default_is_stmt;
        while c.pos < end {
            let op = c.u8()?;
            if op >= opcode_base {
                let adj = u64::from(op - opcode_base);
                addr = addr.wrapping_add((adj / line_range) * min_inst);
                line = (i64::from(line) + line_base + (adj % line_range) as i64).max(0) as u32;
                rows.push(Row { addr, file, line, end: false });
                continue;
            }
            match op {
                0 => {
                    let len = c.uleb()? as usize;
                    let start = c.pos;
                    let sub = c.u8()?;
                    match sub {
                        1 => {
                            rows.push(Row { addr, file, line, end: true });
                            addr = 0;
                            file = 1;
                            line = 1;
                            is_stmt = default_is_stmt;
                        }
                        2 => addr = c.addr(len.saturating_sub(1) as u8)?,
                        _ => {}
                    }
                    c.pos = start.checked_add(len)?;
                }
                1 => rows.push(Row { addr, file, line, end: false }),
                2 => addr = addr.wrapping_add(c.uleb()?.wrapping_mul(min_inst)),
                3 => line = (i64::from(line) + c.sleb()?).max(0) as u32,
                4 => file = c.uleb()? as u32,
                5 => {
                    c.uleb()?;
                }
                6 => is_stmt = !is_stmt,
                7 | 10 | 11 => {}
                8 => {
                    let adj = u64::from(255 - opcode_base);
                    addr = addr.wrapping_add((adj / line_range) * min_inst);
                }
                9 => addr = addr.wrapping_add(u64::from(c.u16()?)),
                12 => {
                    c.uleb()?;
                }
                _ => {
                    for _ in 0..std_lens[op as usize] {
                        c.uleb()?;
                    }
                }
            }
        }
        let _ = is_stmt;
        // End-of-sequence rows sort before real rows at the same address, so
        // the last row at or below a PC is a real one whenever a sequence
        // starts there.
        rows.sort_by_key(|r| (r.addr, !r.end));
        Some(LineTable {
            rows,
            files,
            v5: version >= 5,
        })
    }

    /// (file path, line) for the row at the greatest address <= pc.
    pub fn find(&self, pc: u64) -> Option<(&str, u32)> {
        let i = self.rows.partition_point(|r| r.addr <= pc);
        let r = self.rows.get(i.checked_sub(1)?)?;
        if r.end {
            return None;
        }
        let idx = if self.v5 {
            r.file as usize
        } else {
            (r.file as usize).checked_sub(1)?
        };
        Some((self.files.get(idx)?.as_str(), r.line))
    }

    /// Byte range of this program in .debug_line, for prefetching.
    pub fn extent(sec: &'static [u8], off: usize) -> Option<&'static [u8]> {
        let mut c = Cur::new(sec, off);
        let (len, _) = c.initial_length()?;
        sec.get(off..c.pos.checked_add(len)?.min(sec.len()))
    }
}
