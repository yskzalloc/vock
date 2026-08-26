//! Minimal ELF64 little-endian reader: section table by name, symbol table.

use super::reader::{cstr_at, Cur};

pub struct Section {
    pub name: &'static [u8],
    pub sh_type: u32,
    pub flags: u64,
    pub data: &'static [u8],
    pub link: u32,
}

pub struct Elf {
    pub sections: Vec<Section>,
}

const SHF_COMPRESSED: u64 = 0x800;
const SHT_NOBITS: u32 = 8;
pub const SHT_SYMTAB: u32 = 2;

impl Elf {
    pub fn parse(data: &'static [u8]) -> Result<Elf, String> {
        if data.len() < 64 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        if data[4] != 2 {
            return Err("not a 64-bit ELF".into());
        }
        if data[5] != 1 {
            return Err("big-endian ELF is not supported in-process".into());
        }
        let mut c = Cur::new(data, 0x28);
        let shoff = c.u64().ok_or("truncated header")? as usize;
        let mut c = Cur::new(data, 0x3a);
        let shentsize = c.u16().ok_or("truncated header")? as usize;
        let shnum = c.u16().ok_or("truncated header")? as usize;
        let shstrndx = c.u16().ok_or("truncated header")? as usize;
        if shentsize < 64 || shnum == 0 {
            return Err("no section table".into());
        }
        let mut raw = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let mut c = Cur::new(data, shoff + i * shentsize);
            let name = c.u32().ok_or("truncated section table")?;
            let sh_type = c.u32().ok_or("truncated section table")?;
            let flags = c.u64().ok_or("truncated section table")?;
            let _addr = c.u64().ok_or("truncated section table")?;
            let offset = c.u64().ok_or("truncated section table")? as usize;
            let size = c.u64().ok_or("truncated section table")? as usize;
            let link = c.u32().ok_or("truncated section table")?;
            raw.push((name, sh_type, flags, offset, size, link));
        }
        let (_, _, _, stroff, strsize, _) = *raw.get(shstrndx).ok_or("bad shstrndx")?;
        let shstr = data.get(stroff..stroff + strsize).ok_or("bad shstrtab")?;
        let mut sections = Vec::with_capacity(shnum);
        for (name, sh_type, flags, offset, size, link) in raw {
            let name = cstr_at(shstr, name as usize).unwrap_or(b"");
            let data = if sh_type == SHT_NOBITS {
                &data[..0]
            } else {
                data.get(offset..offset.saturating_add(size)).unwrap_or(&data[..0])
            };
            sections.push(Section {
                name,
                sh_type,
                flags,
                data,
                link,
            });
        }
        Ok(Elf { sections })
    }

    /// Section contents by name; empty when absent. Compressed debug
    /// sections are refused: the reader works on the raw bytes.
    pub fn section(&self, name: &str) -> Result<&'static [u8], String> {
        for s in &self.sections {
            if s.name == name.as_bytes() {
                if s.flags & SHF_COMPRESSED != 0 {
                    return Err(format!(
                        "{name} is compressed (CONFIG_DEBUG_INFO_COMPRESSED); \
                         set VOCK_ADDR2LINE to an external addr2line"
                    ));
                }
                return Ok(s.data);
            }
        }
        Ok(&[])
    }

    /// (.symtab, its .strtab), empty when the file is stripped.
    pub fn symtab(&self) -> (&'static [u8], &'static [u8]) {
        for s in &self.sections {
            if s.sh_type == SHT_SYMTAB {
                let strtab = self
                    .sections
                    .get(s.link as usize)
                    .map(|t| t.data)
                    .unwrap_or(&[]);
                return (s.data, strtab);
            }
        }
        (&[], &[])
    }
}

/// Code symbols sorted by address, for PCs without DWARF function info.
pub struct SymTab {
    syms: Vec<(u64, &'static [u8])>,
}

const STT_NOTYPE: u8 = 0;
const STT_FUNC: u8 = 2;

impl SymTab {
    pub fn parse(symtab: &'static [u8], strtab: &'static [u8]) -> SymTab {
        let mut syms = Vec::with_capacity(symtab.len() / 24);
        for ent in symtab.chunks_exact(24) {
            let name = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]) as usize;
            let info = ent[4];
            let shndx = u16::from_le_bytes([ent[6], ent[7]]);
            let value = u64::from_le_bytes([
                ent[8], ent[9], ent[10], ent[11], ent[12], ent[13], ent[14], ent[15],
            ]);
            let size = u64::from_le_bytes([
                ent[16], ent[17], ent[18], ent[19], ent[20], ent[21], ent[22], ent[23],
            ]);
            let typ = info & 0xf;
            if shndx == 0 || value == 0 || (typ != STT_FUNC && typ != STT_NOTYPE) {
                continue;
            }
            let Some(n) = cstr_at(strtab, name) else { continue };
            // Assembler-local labels (.Ltmp, .LBB) and mapping symbols ($x,
            // $d) sit inside functions; addr2line names the function.
            if n.is_empty() || n.starts_with(b".L") || n.starts_with(b"$") {
                continue;
            }
            syms.push((value, typ, size, n));
        }
        // Stable: at one address a function symbol beats an untyped label,
        // a sized symbol beats a bare marker (irq_entries_start over
        // __irqentry_text_start), then the first in table order wins.
        syms.sort_by_key(|s| (s.0, s.1 != STT_FUNC, s.2 == 0));
        SymTab {
            syms: syms.into_iter().map(|(a, _, _, n)| (a, n)).collect(),
        }
    }

    /// The symbol at the greatest address <= pc.
    pub fn before(&self, pc: u64) -> Option<&'static [u8]> {
        let i = self.syms.partition_point(|s| s.0 <= pc);
        // Prefer the first of several symbols sharing that address.
        let j = i.checked_sub(1)?;
        let addr = self.syms[j].0;
        let first = self.syms[..j].iter().rposition(|s| s.0 != addr).map_or(0, |k| k + 1);
        Some(self.syms[first].1)
    }

    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.syms
            .iter()
            .find(|s| s.1 == name.as_bytes())
            .map(|s| s.0)
    }
}
