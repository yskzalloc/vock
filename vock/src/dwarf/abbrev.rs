//! .debug_abbrev: one table per compilation unit, indexed by code.

use super::reader::Cur;

pub struct Abbrev {
    pub tag: u16,
    pub children: bool,
    /// (attribute, form, implicit_const value)
    pub attrs: Vec<(u16, u16, i64)>,
}

pub struct Abbrevs {
    /// Indexed by code; codes are small and dense in practice.
    dense: Vec<Option<Abbrev>>,
}

impl Abbrevs {
    pub fn parse(sec: &'static [u8], off: usize) -> Option<Abbrevs> {
        let mut c = Cur::new(sec, off);
        let mut dense: Vec<Option<Abbrev>> = Vec::new();
        loop {
            let code = c.uleb()?;
            if code == 0 {
                break;
            }
            let tag = c.uleb()? as u16;
            let children = c.u8()? != 0;
            let mut attrs = Vec::new();
            loop {
                let at = c.uleb()? as u16;
                let form = c.uleb()? as u16;
                let implicit = if form == 0x21 { c.sleb()? } else { 0 };
                if at == 0 && form == 0 {
                    break;
                }
                attrs.push((at, form, implicit));
            }
            let code = code as usize;
            if code > 1 << 20 {
                return None;
            }
            if dense.len() <= code {
                dense.resize_with(code + 1, || None);
            }
            dense[code] = Some(Abbrev {
                tag,
                children,
                attrs,
            });
        }
        Some(Abbrevs { dense })
    }

    pub fn get(&self, code: u64) -> Option<&Abbrev> {
        self.dense.get(code as usize)?.as_ref()
    }
}
