//! Byte cursor over a mapped section: little-endian scalars, LEB128, DWARF
//! offsets and attribute forms. Every read returns `None` on truncation so
//! a damaged unit aborts its own parse instead of the whole report.

/// One attribute value, kept as a reference into the mapping where the
/// form allows (strings are never copied).
#[derive(Clone, Copy, Debug)]
pub enum Val {
    None,
    Addr(u64),
    Udata(u64),
    Sdata(i64),
    Flag,
    /// Inline string (DW_FORM_string).
    Str(&'static [u8]),
    /// Offset into .debug_str.
    Strp(usize),
    /// Offset into .debug_line_str.
    LineStrp(usize),
    /// Index into the unit's string-offsets table.
    Strx(u64),
    /// Absolute .debug_info offset (unit-relative refs are rebased).
    Ref(usize),
    /// Offset into some other section (DW_FORM_sec_offset).
    SecOff(usize),
    /// Index into the unit's address table.
    Addrx(u64),
    /// Index into the unit's range-list offsets table.
    Rnglistx(u64),
    Block,
}

#[derive(Clone, Copy)]
pub struct Cur {
    pub data: &'static [u8],
    pub pos: usize,
}

impl Cur {
    pub fn new(data: &'static [u8], pos: usize) -> Cur {
        Cur { data, pos }
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        let np = self.pos.checked_add(n)?;
        if np > self.data.len() {
            return None;
        }
        self.pos = np;
        Some(())
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'static [u8]> {
        let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Option<u32> {
        let b = self.bytes(3)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], 0]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let b = self.bytes(8)?;
        Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    pub fn i8(&mut self) -> Option<i8> {
        self.u8().map(|b| b as i8)
    }

    pub fn uleb(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                result |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(result);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    pub fn sleb(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                result |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// A DWARF offset: 4 bytes in the 32-bit format, 8 in the 64-bit one.
    pub fn off(&mut self, format64: bool) -> Option<usize> {
        if format64 {
            self.u64().map(|v| v as usize)
        } else {
            self.u32().map(|v| v as usize)
        }
    }

    pub fn addr(&mut self, size: u8) -> Option<u64> {
        match size {
            8 => self.u64(),
            4 => self.u32().map(u64::from),
            2 => self.u16().map(u64::from),
            1 => self.u8().map(u64::from),
            _ => None,
        }
    }

    /// NUL-terminated string, without the NUL.
    pub fn cstr(&mut self) -> Option<&'static [u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        self.pos += n + 1;
        Some(&rest[..n])
    }

    /// The initial length of a unit/set: (length, 64-bit format).
    pub fn initial_length(&mut self) -> Option<(usize, bool)> {
        let l = self.u32()?;
        if l == 0xffff_ffff {
            Some((self.u64()? as usize, true))
        } else if l >= 0xffff_fff0 {
            None
        } else {
            Some((l as usize, false))
        }
    }
}

/// What a form reader needs to know about the enclosing unit.
#[derive(Clone, Copy)]
pub struct UnitShape {
    /// Absolute .debug_info offset of the unit header.
    pub off: usize,
    pub version: u16,
    pub format64: bool,
    pub addr_size: u8,
}

/// Read one attribute value of `form`. Unknown forms return `None`, which
/// aborts the enclosing DIE parse (there is no way to skip them).
pub fn read_form(c: &mut Cur, form: u16, u: &UnitShape, implicit: i64) -> Option<Val> {
    Some(match form {
        0x01 => Val::Addr(c.addr(u.addr_size)?),
        0x03 => {
            let n = c.u16()? as usize;
            c.skip(n)?;
            Val::Block
        }
        0x04 => {
            let n = c.u32()? as usize;
            c.skip(n)?;
            Val::Block
        }
        0x05 => Val::Udata(u64::from(c.u16()?)),
        0x06 => Val::Udata(u64::from(c.u32()?)),
        0x07 => Val::Udata(c.u64()?),
        0x08 => Val::Str(c.cstr()?),
        0x09 | 0x18 => {
            let n = c.uleb()? as usize;
            c.skip(n)?;
            Val::Block
        }
        0x0a => {
            let n = c.u8()? as usize;
            c.skip(n)?;
            Val::Block
        }
        0x0b => Val::Udata(u64::from(c.u8()?)),
        0x0c => {
            c.u8()?;
            Val::Flag
        },
        0x0d => Val::Sdata(c.sleb()?),
        0x0e => Val::Strp(c.off(u.format64)?),
        0x0f => Val::Udata(c.uleb()?),
        0x10 => {
            if u.version <= 2 {
                Val::Ref(c.addr(u.addr_size)? as usize)
            } else {
                Val::Ref(c.off(u.format64)?)
            }
        }
        0x11 => Val::Ref(u.off + c.u8()? as usize),
        0x12 => Val::Ref(u.off + c.u16()? as usize),
        0x13 => Val::Ref(u.off + c.u32()? as usize),
        0x14 => Val::Ref(u.off + c.u64()? as usize),
        0x15 => Val::Ref(u.off + c.uleb()? as usize),
        0x16 => {
            let f = c.uleb()? as u16;
            return read_form(c, f, u, implicit);
        }
        0x17 => Val::SecOff(c.off(u.format64)?),
        0x19 => Val::Flag,
        0x1a | 0x1f02 => Val::Strx(c.uleb()?),
        0x1b | 0x1f01 => Val::Addrx(c.uleb()?),
        0x1c => {
            c.u32()?;
            Val::None
        }
        0x1d | 0x1f20 | 0x1f21 => {
            c.off(u.format64)?;
            Val::None
        }
        0x1e => {
            c.skip(16)?;
            Val::None
        }
        0x1f => Val::LineStrp(c.off(u.format64)?),
        0x20 | 0x24 => {
            c.u64()?;
            Val::None
        }
        0x21 => Val::Sdata(implicit),
        0x22 => {
            c.uleb()?;
            Val::None
        }
        0x23 => Val::Rnglistx(c.uleb()?),
        0x25 => Val::Strx(u64::from(c.u8()?)),
        0x26 => Val::Strx(u64::from(c.u16()?)),
        0x27 => Val::Strx(u64::from(c.u24()?)),
        0x28 => Val::Strx(u64::from(c.u32()?)),
        0x29 => Val::Addrx(u64::from(c.u8()?)),
        0x2a => Val::Addrx(u64::from(c.u16()?)),
        0x2b => Val::Addrx(u64::from(c.u24()?)),
        0x2c => Val::Addrx(u64::from(c.u32()?)),
        _ => return None,
    })
}

impl Val {
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Val::Udata(v) | Val::Addr(v) => Some(v),
            Val::Sdata(v) => Some(v as u64),
            Val::SecOff(v) | Val::Ref(v) => Some(v as u64),
            _ => None,
        }
    }
}

/// NUL-terminated string at `off` in `sec`.
pub fn cstr_at(sec: &'static [u8], off: usize) -> Option<&'static [u8]> {
    let rest = sec.get(off..)?;
    let n = rest.iter().position(|&b| b == 0)?;
    Some(&rest[..n])
}

pub fn lossy(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}
