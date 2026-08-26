//! Compilation units: header + root attributes, and on demand the line
//! table and the function table (subprogram / inlined-subroutine ranges
//! with names) built from one sequential walk of the unit's DIEs.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::abbrev::Abbrevs;
use super::line::LineTable;
use super::reader::{lossy, read_form, Cur, UnitShape, Val};
use super::Symbolizer;

const DW_TAG_CLASS_TYPE: u16 = 0x02;
const DW_TAG_ENUMERATION_TYPE: u16 = 0x04;
const DW_TAG_COMPILE_UNIT: u16 = 0x11;
const DW_TAG_STRUCTURE_TYPE: u16 = 0x13;
const DW_TAG_UNION_TYPE: u16 = 0x17;
const DW_TAG_INLINED_SUBROUTINE: u16 = 0x1d;
const DW_TAG_SUBPROGRAM: u16 = 0x2e;
const DW_TAG_NAMESPACE: u16 = 0x39;
const DW_TAG_PARTIAL_UNIT: u16 = 0x3c;

const DW_AT_NAME: u16 = 0x03;
const DW_AT_STMT_LIST: u16 = 0x10;
const DW_AT_LOW_PC: u16 = 0x11;
const DW_AT_HIGH_PC: u16 = 0x12;
const DW_AT_LANGUAGE: u16 = 0x13;
const DW_AT_COMP_DIR: u16 = 0x1b;
const DW_AT_ABSTRACT_ORIGIN: u16 = 0x31;
const DW_AT_SPECIFICATION: u16 = 0x47;
const DW_AT_RANGES: u16 = 0x55;
const DW_AT_STR_OFFSETS_BASE: u16 = 0x72;
const DW_AT_ADDR_BASE: u16 = 0x73;
const DW_AT_RNGLISTS_BASE: u16 = 0x74;

/// Languages whose functions live in namespaces worth printing.
fn qualifies(lang: u16) -> bool {
    matches!(lang, 0x04 | 0x19 | 0x1a | 0x1c | 0x21 | 0x2b)
}

/// A function name as recorded during the walk: resolved, or the DIE that
/// holds it (DW_AT_abstract_origin / DW_AT_specification targets).
#[derive(Clone)]
pub enum Name {
    None,
    Direct(Cow<'static, str>),
    Die(usize),
}

pub struct Inl {
    pub start: u64,
    pub end: u64,
    pub depth: u16,
    pub name: Name,
}

pub struct Sub {
    pub name: Name,
    pub inlines: Vec<Inl>,
}

pub struct FuncTable {
    /// (start, end, index into subs), sorted by start.
    ranges: Vec<(u64, u64, u32)>,
    subs: Vec<Sub>,
    /// Subprogram DIE offset → its (qualified) DW_AT_name, for resolving
    /// abstract-origin references without re-reading the DIE.
    pub names: HashMap<usize, Cow<'static, str>>,
}

impl FuncTable {
    /// The innermost function containing `pc`.
    pub fn find(&self, pc: u64) -> Option<&Name> {
        let i = self.ranges.partition_point(|r| r.0 <= pc);
        // Subprogram ranges do not overlap in practice; look a few back in
        // case a nested function sits inside its parent's range.
        let mut best: Option<&Sub> = None;
        for j in (i.saturating_sub(4)..i).rev() {
            let (s, e, idx) = self.ranges[j];
            if s <= pc && pc < e {
                best = self.subs.get(idx as usize);
                break;
            }
        }
        let sub = best?;
        let mut inner: Option<&Inl> = None;
        for inl in &sub.inlines {
            if inl.start <= pc && pc < inl.end && inner.is_none_or(|b| inl.depth > b.depth) {
                inner = Some(inl);
            }
        }
        Some(inner.map(|i| &i.name).unwrap_or(&sub.name))
    }
}

pub struct Unit {
    pub shape: UnitShape,
    pub end: usize,
    pub die_off: usize,
    pub abbrevs: Rc<Abbrevs>,
    pub lang: u16,
    pub comp_dir: Option<Cow<'static, str>>,
    pub stmt_list: Option<usize>,
    pub low_pc: Option<Val>,
    pub high_pc: Option<Val>,
    pub ranges: Option<Val>,
    pub str_offsets_base: usize,
    pub addr_base: usize,
    pub rnglists_base: usize,
    lines: OnceCell<Option<LineTable>>,
    funcs: OnceCell<FuncTable>,
}

/// Parsed unit header: shape, end of unit, first DIE, abbrev offset, type.
pub struct Header {
    pub shape: UnitShape,
    pub end: usize,
    pub die_off: usize,
    pub abbrev_off: usize,
    pub unit_type: u8,
}

pub fn parse_header(info: &'static [u8], off: usize) -> Option<Header> {
    let mut c = Cur::new(info, off);
    let (len, format64) = c.initial_length()?;
    let end = c.pos.checked_add(len)?;
    if end > info.len() {
        return None;
    }
    let version = c.u16()?;
    if !(2..=5).contains(&version) {
        return None;
    }
    let (unit_type, addr_size, abbrev_off) = if version >= 5 {
        let ut = c.u8()?;
        let asz = c.u8()?;
        let ao = c.off(format64)?;
        match ut {
            0x02 | 0x06 => {
                c.u64()?;
                c.off(format64)?;
            }
            0x04 | 0x05 => {
                c.u64()?;
            }
            _ => {}
        }
        (ut, asz, ao)
    } else {
        let ao = c.off(format64)?;
        let asz = c.u8()?;
        (0x01, asz, ao)
    };
    Some(Header {
        shape: UnitShape {
            off,
            version,
            format64,
            addr_size,
        },
        end,
        die_off: c.pos,
        abbrev_off,
        unit_type,
    })
}

impl Unit {
    pub fn parse(sym: &Symbolizer, off: usize) -> Option<Unit> {
        let h = parse_header(sym.sec.info, off)?;
        if !matches!(h.unit_type, 0x01 | 0x03 | 0x04 | 0x05) {
            return None;
        }
        let abbrevs = sym.abbrevs(h.abbrev_off)?;
        let mut c = Cur::new(sym.sec.info, h.die_off);
        let code = c.uleb()?;
        let ab = abbrevs.get(code)?;
        if ab.tag != DW_TAG_COMPILE_UNIT && ab.tag != DW_TAG_PARTIAL_UNIT {
            return None;
        }
        let mut u = Unit {
            shape: h.shape,
            end: h.end,
            die_off: h.die_off,
            abbrevs: abbrevs.clone(),
            lang: 0,
            comp_dir: None,
            stmt_list: None,
            low_pc: None,
            high_pc: None,
            ranges: None,
            str_offsets_base: 8,
            addr_base: 8,
            rnglists_base: 0,
            lines: OnceCell::new(),
            funcs: OnceCell::new(),
        };
        let mut comp_dir = None;
        for &(at, form, imp) in &ab.attrs {
            let v = read_form(&mut c, form, &h.shape, imp)?;
            match at {
                DW_AT_STMT_LIST => u.stmt_list = v.as_u64().map(|o| o as usize),
                DW_AT_LOW_PC => u.low_pc = Some(v),
                DW_AT_HIGH_PC => u.high_pc = Some(v),
                DW_AT_RANGES => u.ranges = Some(v),
                DW_AT_LANGUAGE => u.lang = v.as_u64().unwrap_or(0) as u16,
                DW_AT_COMP_DIR => comp_dir = Some(v),
                DW_AT_STR_OFFSETS_BASE => u.str_offsets_base = v.as_u64().unwrap_or(8) as usize,
                DW_AT_ADDR_BASE => u.addr_base = v.as_u64().unwrap_or(8) as usize,
                DW_AT_RNGLISTS_BASE => u.rnglists_base = v.as_u64().unwrap_or(0) as usize,
                _ => {}
            }
        }
        // Bases are known now; string forms may depend on them.
        u.comp_dir = comp_dir
            .and_then(|v| sym.string(&u, &v))
            .map(|s| lossy(s).into_owned().into());
        Some(u)
    }

    /// The unit's own address ranges (for the index built without
    /// .debug_aranges).
    pub fn address_ranges(&self, sym: &Symbolizer) -> Vec<(u64, u64)> {
        sym.die_ranges(self, self.low_pc, self.high_pc, self.ranges)
    }

    pub fn lines(&self, sym: &Symbolizer) -> Option<&LineTable> {
        self.lines
            .get_or_init(|| self.stmt_list.and_then(|o| LineTable::parse(sym, self, o)))
            .as_ref()
    }

    pub fn funcs(&self, sym: &Symbolizer) -> &FuncTable {
        self.funcs.get_or_init(|| self.walk(sym))
    }

    /// One pass over the DIE tree collecting concrete subprograms, their
    /// inlined subroutines, and the names of every subprogram DIE.
    fn walk(&self, sym: &Symbolizer) -> FuncTable {
        let mut ft = FuncTable {
            ranges: Vec::new(),
            subs: Vec::new(),
            names: HashMap::new(),
        };
        let qualify = qualifies(self.lang);
        let mut c = Cur::new(sym.sec.info, self.die_off);
        let mut depth: i32 = 0;
        let mut scopes: Vec<(i32, Cow<'static, str>)> = Vec::new();
        let mut cur_sub: Option<(usize, i32)> = None;
        let mut inl_stack: Vec<i32> = Vec::new();

        while c.pos < self.end {
            let die_off = c.pos;
            let Some(code) = c.uleb() else { break };
            if code == 0 {
                depth -= 1;
                if depth <= 0 {
                    break;
                }
                while scopes.last().is_some_and(|s| s.0 >= depth) {
                    scopes.pop();
                }
                while inl_stack.last().is_some_and(|&d| d >= depth) {
                    inl_stack.pop();
                }
                if cur_sub.is_some_and(|(_, d)| d >= depth) {
                    cur_sub = None;
                }
                continue;
            }
            let Some(ab) = self.abbrevs.get(code) else { break };
            let mut name = None;
            let mut lo = None;
            let mut hi = None;
            let mut ranges = None;
            let mut origin = None;
            let mut spec = None;
            let mut ok = true;
            for &(at, form, imp) in &ab.attrs {
                let Some(v) = read_form(&mut c, form, &self.shape, imp) else {
                    ok = false;
                    break;
                };
                match at {
                    DW_AT_NAME => name = Some(v),
                    DW_AT_LOW_PC => lo = Some(v),
                    DW_AT_HIGH_PC => hi = Some(v),
                    DW_AT_RANGES => ranges = Some(v),
                    DW_AT_ABSTRACT_ORIGIN => origin = Some(v),
                    DW_AT_SPECIFICATION => spec = Some(v),
                    _ => {}
                }
            }
            if !ok {
                break;
            }
            let direct: Option<Cow<'static, str>> = name.and_then(|v| sym.string(self, &v)).map(|s| {
                let s = lossy(s);
                if qualify && !scopes.is_empty() {
                    let mut q = String::new();
                    for (_, sc) in &scopes {
                        q.push_str(sc);
                        q.push_str("::");
                    }
                    q.push_str(&s);
                    Cow::Owned(q)
                } else {
                    Cow::Owned(s.into_owned())
                }
            });
            let resolved = match (&direct, origin, spec) {
                (Some(d), _, _) => Name::Direct(d.clone()),
                (None, Some(Val::Ref(o)), _) | (None, None, Some(Val::Ref(o))) => Name::Die(o),
                _ => Name::None,
            };
            match ab.tag {
                DW_TAG_SUBPROGRAM => {
                    if let Some(d) = &direct {
                        ft.names.insert(die_off, d.clone());
                    }
                    let rs = sym.die_ranges(self, lo, hi, ranges);
                    if !rs.is_empty() {
                        let idx = ft.subs.len();
                        ft.subs.push(Sub {
                            name: resolved,
                            inlines: Vec::new(),
                        });
                        for (s, e) in rs {
                            ft.ranges.push((s, e, idx as u32));
                        }
                        if ab.children {
                            cur_sub = Some((idx, depth));
                        }
                    }
                }
                DW_TAG_INLINED_SUBROUTINE => {
                    if let Some((idx, _)) = cur_sub {
                        let d = inl_stack.len() as u16 + 1;
                        for (s, e) in sym.die_ranges(self, lo, hi, ranges) {
                            ft.subs[idx].inlines.push(Inl {
                                start: s,
                                end: e,
                                depth: d,
                                name: resolved.clone(),
                            });
                        }
                    }
                    if ab.children {
                        inl_stack.push(depth);
                    }
                }
                DW_TAG_NAMESPACE
                | DW_TAG_STRUCTURE_TYPE
                | DW_TAG_CLASS_TYPE
                | DW_TAG_UNION_TYPE
                | DW_TAG_ENUMERATION_TYPE
                    if qualify && ab.children =>
                {
                    let plain = name
                        .and_then(|v| sym.string(self, &v))
                        .map(|s| Cow::Owned(lossy(s).into_owned()))
                        .unwrap_or(Cow::Borrowed("{anon}"));
                    scopes.push((depth, plain));
                }
                _ => {}
            }
            if ab.children {
                depth += 1;
            }
        }
        ft.ranges.sort_unstable_by_key(|r| r.0);
        ft
    }

    /// DW_AT_name of the DIE at `off` in this unit, following
    /// abstract_origin / specification a few steps.
    pub fn die_name(&self, sym: &Symbolizer, off: usize, hops: u32) -> Option<Cow<'static, str>> {
        if let Some(n) = self.funcs.get().and_then(|f| f.names.get(&off)) {
            return Some(n.clone());
        }
        if hops > 4 || off < self.die_off || off >= self.end {
            return None;
        }
        let mut c = Cur::new(sym.sec.info, off);
        let code = c.uleb()?;
        let ab = self.abbrevs.get(code)?;
        let mut name = None;
        let mut next = None;
        for &(at, form, imp) in &ab.attrs {
            let v = read_form(&mut c, form, &self.shape, imp)?;
            match at {
                DW_AT_NAME => name = Some(v),
                DW_AT_ABSTRACT_ORIGIN | DW_AT_SPECIFICATION => {
                    if let Val::Ref(o) = v {
                        next = Some(o);
                    }
                }
                _ => {}
            }
        }
        if let Some(s) = name.and_then(|v| sym.string(self, &v)) {
            return Some(Cow::Owned(lossy(s).into_owned()));
        }
        sym.die_name(next?, hops + 1)
    }
}
