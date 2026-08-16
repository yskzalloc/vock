//! Native BTF parser (port of btf/btf.c), zero dependencies.
//!
//! Reads `/sys/kernel/btf/vmlinux` (raw BTF) or an ELF file with a `.BTF`
//! section directly and builds an in-memory type table indexed by type id
//! (id 0 == void).
#![allow(dead_code)]

// BTF type kinds.
pub const BTF_KIND_INT: u16 = 1;
pub const BTF_KIND_PTR: u16 = 2;
pub const BTF_KIND_ARRAY: u16 = 3;
pub const BTF_KIND_STRUCT: u16 = 4;
pub const BTF_KIND_UNION: u16 = 5;
pub const BTF_KIND_ENUM: u16 = 6;
pub const BTF_KIND_FWD: u16 = 7;
pub const BTF_KIND_TYPEDEF: u16 = 8;
pub const BTF_KIND_VOLATILE: u16 = 9;
pub const BTF_KIND_CONST: u16 = 10;
pub const BTF_KIND_RESTRICT: u16 = 11;
pub const BTF_KIND_FUNC: u16 = 12;
pub const BTF_KIND_FUNC_PROTO: u16 = 13;
pub const BTF_KIND_VAR: u16 = 14;
pub const BTF_KIND_DATASEC: u16 = 15;
pub const BTF_KIND_FLOAT: u16 = 16;
pub const BTF_KIND_ENUM64: u16 = 19;

const BTF_MAGIC: u16 = 0xEB9F;

pub struct BtfMember {
    pub name: String,
    pub type_id: u32,
    pub offset_bits: u32,
}

pub struct BtfEnumVal {
    pub name: String,
    pub val: i64,
}

pub struct BtfType {
    pub id: u32,
    pub kind: u16,
    pub name: String,
    pub size: u32,        // byte size for INT/STRUCT/UNION/ENUM
    pub ref_type_id: u32, // for PTR/TYPEDEF/CONST/VOLATILE/RESTRICT
    pub members: Vec<BtfMember>,
    pub enums: Vec<BtfEnumVal>,
    pub int_bits: u8,
    pub int_signed: u8,
    pub array_type_id: u32,
    pub array_nelems: u32,
}

impl BtfType {
    fn void() -> BtfType {
        BtfType {
            id: 0,
            kind: 0,
            name: String::new(),
            size: 0,
            ref_type_id: 0,
            members: Vec::new(),
            enums: Vec::new(),
            int_bits: 0,
            int_signed: 0,
            array_type_id: 0,
            array_nelems: 0,
        }
    }
}

pub struct Btf {
    pub types: Vec<BtfType>, // index == type id; [0] == void
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

fn btf_str(strs: &[u8], off: u32) -> String {
    let off = off as usize;
    if off >= strs.len() {
        return String::new();
    }
    let end = strs[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(strs.len());
    String::from_utf8_lossy(&strs[off..end]).into_owned()
}

/// Locate the `.BTF` section inside an ELF64 image. Returns (offset, size).
fn find_elf_btf(raw: &[u8]) -> Option<(usize, usize)> {
    // Elf64_Ehdr fields we need.
    let e_shoff = rd_u64(raw, 0x28)? as usize;
    let e_shentsize = rd_u16(raw, 0x3a)? as usize;
    let e_shnum = rd_u16(raw, 0x3c)? as usize;
    let e_shstrndx = rd_u16(raw, 0x3e)? as usize;
    if e_shentsize < 64 || e_shoff + e_shnum * e_shentsize > raw.len() {
        return None;
    }
    let shdr_at = |i: usize| e_shoff + i * e_shentsize;
    // section header string table
    let strtab_off = rd_u64(raw, shdr_at(e_shstrndx) + 0x18)? as usize;
    for i in 0..e_shnum {
        let base = shdr_at(i);
        let sh_name = rd_u32(raw, base)? as usize;
        let sh_offset = rd_u64(raw, base + 0x18)? as usize;
        let sh_size = rd_u64(raw, base + 0x20)? as usize;
        let name_ptr = strtab_off + sh_name;
        let name_end = raw[name_ptr..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| name_ptr + p)
            .unwrap_or(raw.len());
        if &raw[name_ptr..name_end] == b".BTF" {
            return Some((sh_offset, sh_size));
        }
    }
    None
}

impl Btf {
    pub fn open(path: &str) -> Option<Btf> {
        let raw = std::fs::read(path).ok()?;
        if raw.len() < 24 {
            return None;
        }

        // Extract the .BTF section if this is an ELF file.
        let (bstart, bsize) = if raw.len() > 64 && &raw[0..4] == b"\x7fELF" {
            find_elf_btf(&raw)?
        } else {
            (0, raw.len())
        };
        let btf_data = raw.get(bstart..bstart + bsize)?;
        if btf_data.len() < 24 || rd_u16(btf_data, 0)? != BTF_MAGIC {
            return None;
        }

        // BTF header.
        let hdr_len = rd_u32(btf_data, 4)? as usize;
        let type_off = rd_u32(btf_data, 8)? as usize;
        let type_len = rd_u32(btf_data, 12)? as usize;
        let str_off = rd_u32(btf_data, 16)? as usize;
        let str_len = rd_u32(btf_data, 20)? as usize;

        let base = hdr_len;
        let type_start = base + type_off;
        let type_end = type_start + type_len;
        let str_start = base + str_off;
        let strs = btf_data.get(str_start..str_start + str_len)?;
        let types_sec = btf_data.get(type_start..type_end)?;

        let mut types: Vec<BtfType> = Vec::new();
        types.push(BtfType::void());

        let mut p = 0usize;
        let mut id: u32 = 1;
        while p + 12 <= types_sec.len() {
            let name_off = rd_u32(types_sec, p)?;
            let info = rd_u32(types_sec, p + 4)?;
            let size_or_type = rd_u32(types_sec, p + 8)?;
            let kind = ((info >> 24) & 0x1f) as u16;
            let vlen = (info & 0xffff) as usize;
            let kflag = info >> 31;
            p += 12;

            let mut out = BtfType::void();
            out.id = id;
            out.kind = kind;
            out.name = btf_str(strs, name_off);

            match kind {
                BTF_KIND_INT => {
                    out.size = size_or_type;
                    let enc = rd_u32(types_sec, p)?;
                    out.int_bits = (enc & 0xff) as u8;
                    out.int_signed = ((enc >> 24) & 1) as u8;
                    p += 4;
                }
                BTF_KIND_PTR | BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST
                | BTF_KIND_RESTRICT | BTF_KIND_FWD => {
                    out.ref_type_id = size_or_type;
                }
                BTF_KIND_ARRAY => {
                    out.array_type_id = rd_u32(types_sec, p)?;
                    out.array_nelems = rd_u32(types_sec, p + 8)?;
                    p += 12;
                }
                BTF_KIND_STRUCT | BTF_KIND_UNION => {
                    out.size = size_or_type;
                    out.members.reserve(vlen);
                    for i in 0..vlen {
                        let mp = p + i * 12;
                        let m_name = rd_u32(types_sec, mp)?;
                        let m_type = rd_u32(types_sec, mp + 4)?;
                        let m_off = rd_u32(types_sec, mp + 8)?;
                        let offset_bits = if kflag != 0 { m_off & 0xffffff } else { m_off };
                        out.members.push(BtfMember {
                            name: btf_str(strs, m_name),
                            type_id: m_type,
                            offset_bits,
                        });
                    }
                    p += vlen * 12;
                }
                BTF_KIND_ENUM => {
                    out.size = size_or_type;
                    out.enums.reserve(vlen);
                    for i in 0..vlen {
                        let ep = p + i * 8;
                        let e_name = rd_u32(types_sec, ep)?;
                        let e_val = rd_u32(types_sec, ep + 4)? as i32 as i64;
                        out.enums.push(BtfEnumVal {
                            name: btf_str(strs, e_name),
                            val: e_val,
                        });
                    }
                    p += vlen * 8;
                }
                BTF_KIND_ENUM64 => {
                    out.size = size_or_type;
                    out.enums.reserve(vlen);
                    for i in 0..vlen {
                        let ep = p + i * 12;
                        let e_name = rd_u32(types_sec, ep)?;
                        let lo = rd_u32(types_sec, ep + 4)? as u64;
                        let hi = rd_u32(types_sec, ep + 8)? as u64;
                        out.enums.push(BtfEnumVal {
                            name: btf_str(strs, e_name),
                            val: ((hi << 32) | lo) as i64,
                        });
                    }
                    p += vlen * 12;
                }
                BTF_KIND_FUNC_PROTO => {
                    out.ref_type_id = size_or_type;
                    p += vlen * 8;
                }
                BTF_KIND_FUNC => {
                    out.ref_type_id = size_or_type;
                }
                BTF_KIND_VAR => {
                    out.ref_type_id = size_or_type;
                    p += 4;
                }
                BTF_KIND_DATASEC => {
                    out.size = size_or_type;
                    p += vlen * 12;
                }
                BTF_KIND_FLOAT => {
                    out.size = size_or_type;
                }
                _ => {}
            }

            types.push(out);
            id += 1;
        }

        Some(Btf { types })
    }

    pub fn type_count(&self) -> u32 {
        self.types.len() as u32
    }

    pub fn type_by_id(&self, id: u32) -> Option<&BtfType> {
        self.types.get(id as usize)
    }

    pub fn find_struct(&self, name: &str) -> Option<&BtfType> {
        self.types.iter().skip(1).find(|t| {
            (t.kind == BTF_KIND_STRUCT || t.kind == BTF_KIND_UNION) && t.name == name
        })
    }

    /// Resolve a type through const/volatile/typedef/restrict qualifiers.
    pub fn resolve<'a>(&'a self, mut t: &'a BtfType) -> &'a BtfType {
        while matches!(
            t.kind,
            BTF_KIND_CONST | BTF_KIND_VOLATILE | BTF_KIND_TYPEDEF | BTF_KIND_RESTRICT
        ) {
            match self.type_by_id(t.ref_type_id) {
                Some(next) => t = next,
                None => break,
            }
        }
        t
    }
}
