//! Type-aware struct mutation using BTF field layouts (port of btf/mutate.c).
//!
//! Mutates raw buffers field-by-field with type-appropriate strategies. Field
//! selection is weighted by past signal contribution.
#![allow(dead_code)]

use super::btf::{
    Btf, BtfType, BTF_KIND_ARRAY, BTF_KIND_ENUM, BTF_KIND_INT, BTF_KIND_PTR, BTF_KIND_STRUCT,
    BTF_KIND_UNION,
};
use super::rng::Rng;

const INT_BOUNDARIES: [u64; 18] = [
    0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
    0x10000, 0x7fffffff, 0x80000000, 0xffffffff,
    0x100000000, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
];

const PTR_VALUES: [u64; 7] = [
    0,                  // NULL
    0xdead,             // sentinel
    0x1000,             // page-aligned
    0xffff,             // misaligned
    0xffffffff,         // 32-bit overflow
    0x7fffffffe000,     // near stack
    0xffff888000000000, // kernel direct map
];

pub struct FieldWeight {
    pub hits: u32,
    pub tries: u32,
}

pub struct BtfMutator<'a> {
    pub btf: &'a Btf,
    pub root_id: u32,
    pub weights: Vec<FieldWeight>,
    pub nmembers: usize,
}

fn mask_bits(val: u64, bits: u32) -> u64 {
    if bits >= 64 {
        val
    } else {
        val & ((1u64 << bits) - 1)
    }
}

/// Copy the low `nbytes` of `val` (little-endian) into `field`, clamped to len.
fn write_int(field: &mut [u8], val: u64, nbytes: usize) {
    let n = nbytes.min(field.len()).min(8);
    let bytes = val.to_le_bytes();
    field[..n].copy_from_slice(&bytes[..n]);
}

fn read_int(field: &[u8], nbytes: usize) -> u64 {
    let n = nbytes.min(field.len()).min(8);
    let mut b = [0u8; 8];
    b[..n].copy_from_slice(&field[..n]);
    u64::from_le_bytes(b)
}

fn mutate_int_field(field: &mut [u8], bits: u32, is_signed: bool, rng: &mut Rng) {
    let bits = if bits == 0 { 8 } else { bits };
    let nbytes = ((bits + 7) / 8) as usize;
    let strategy = rng.below(100);
    if strategy < 40 {
        let mut val = INT_BOUNDARIES[rng.below(INT_BOUNDARIES.len() as i64) as usize];
        val = mask_bits(val, bits);
        if is_signed && rng.below(3) == 0 {
            val = mask_bits((val as i64).wrapping_neg() as u64, bits);
        }
        write_int(field, val, nbytes);
    } else if strategy < 60 {
        if nbytes > 0 {
            let byte_idx = rng.below(nbytes as i64) as usize;
            if byte_idx < field.len() {
                field[byte_idx] ^= 1 << (rng.below(8) as u32);
            }
        }
    } else if strategy < 80 {
        let mut val = read_int(field, nbytes);
        let delta = rng.below(35) as u64 + 1;
        val = if rng.rand() & 1 == 1 {
            val.wrapping_add(delta)
        } else {
            val.wrapping_sub(delta)
        };
        val = mask_bits(val, bits);
        write_int(field, val, nbytes);
    } else {
        let mut val = (rng.rand() << 32) | rng.rand();
        val = mask_bits(val, bits);
        write_int(field, val, nbytes);
    }
}

fn mutate_ptr_field(field: &mut [u8], rng: &mut Rng) {
    let strategy = rng.below(100);
    let val = if strategy < 60 {
        PTR_VALUES[rng.below(PTR_VALUES.len() as i64) as usize]
    } else if strategy < 80 {
        ((rng.rand() << 32) | rng.rand()) & !0xfffu64
    } else {
        (rng.rand() << 32) | rng.rand()
    };
    write_int(field, val, 8);
}

fn mutate_enum_field(field: &mut [u8], size: usize, enum_type: &BtfType, rng: &mut Rng) {
    let strategy = rng.below(100);
    if strategy < 70 && !enum_type.enums.is_empty() {
        let val = enum_type.enums[rng.below(enum_type.enums.len() as i64) as usize].val;
        write_int(field, val as u64, size);
    } else if strategy < 90 && !enum_type.enums.is_empty() {
        let mut val = enum_type.enums[rng.below(enum_type.enums.len() as i64) as usize].val;
        val += if rng.rand() & 1 == 1 { 1 } else { -1 };
        write_int(field, val as u64, size);
    } else {
        let mut val = (rng.rand() << 32) | rng.rand();
        if size < 8 && size > 0 {
            val &= (1u64 << (size * 8)) - 1;
        }
        write_int(field, val, size);
    }
}

fn mutate_array_field(field: &mut [u8], elem_size: usize, nelems: usize, rng: &mut Rng) {
    if nelems == 0 || elem_size == 0 {
        return;
    }
    let total = (elem_size * nelems).min(field.len());
    let strategy = rng.below(100);
    if strategy < 40 {
        let idx = rng.below(nelems as i64) as usize;
        let start = idx * elem_size;
        for i in 0..elem_size {
            if start + i < field.len() {
                field[start + i] ^= (rng.rand() & 0xff) as u8;
            }
        }
    } else if strategy < 70 {
        for b in field[..total].iter_mut() {
            *b = 0;
        }
    } else if strategy < 85 {
        for b in field[..total].iter_mut() {
            *b = 0xff;
        }
    } else {
        for b in field[..total].iter_mut() {
            *b = (rng.rand() & 0xff) as u8;
        }
    }
}

impl<'a> BtfMutator<'a> {
    pub fn init(btf: &'a Btf, struct_type_id: u32) -> BtfMutator<'a> {
        let nmembers = btf
            .type_by_id(struct_type_id)
            .map(|t| t.members.len())
            .unwrap_or(0);
        let mut weights = Vec::with_capacity(nmembers);
        for _ in 0..nmembers {
            weights.push(FieldWeight { hits: 0, tries: 0 });
        }
        BtfMutator {
            btf,
            root_id: struct_type_id,
            weights,
            nmembers,
        }
    }

    fn select_field(&self, rng: &mut Rng) -> usize {
        if self.nmembers == 0 {
            return 0;
        }
        let total: u32 = self.weights.iter().map(|w| w.hits + 1).sum();
        let r = (rng.rand() % total as u64) as u32;
        let mut acc = 0u32;
        for (i, w) in self.weights.iter().enumerate() {
            acc += w.hits + 1;
            if r < acc {
                return i;
            }
        }
        self.nmembers - 1
    }

    /// Mutate `buf` in place. Returns the index of the mutated field, or -1
    /// on error (mirrors the C return convention).
    pub fn mutate(&mut self, buf: &mut [u8], rng: &mut Rng) -> i32 {
        if self.nmembers == 0 {
            return -1;
        }
        let root = match self.btf.type_by_id(self.root_id) {
            Some(t) => t,
            None => return -1,
        };
        if buf.len() < root.size as usize {
            return -1;
        }

        let field_idx = self.select_field(rng);
        let member = &root.members[field_idx];
        let byte_off = (member.offset_bits / 8) as usize;
        if byte_off >= buf.len() {
            return -1;
        }

        let member_type_id = member.type_id;
        let ft = match self.btf.type_by_id(member_type_id) {
            Some(t) => self.btf.resolve(t),
            None => return field_idx as i32,
        };
        let (ft_kind, ft_int_bits, ft_int_signed, ft_size, ft_nelems) = (
            ft.kind,
            ft.int_bits as u32,
            ft.int_signed != 0,
            ft.size as usize,
            ft.array_nelems as usize,
        );

        self.weights[field_idx].tries += 1;

        match ft_kind {
            BTF_KIND_INT => {
                mutate_int_field(&mut buf[byte_off..], ft_int_bits, ft_int_signed, rng)
            }
            BTF_KIND_PTR => mutate_ptr_field(&mut buf[byte_off..], rng),
            BTF_KIND_ENUM => {
                // borrow ft again by id to satisfy the borrow checker
                let et = self.btf.type_by_id(member_type_id).unwrap();
                let et = self.btf.resolve(et);
                mutate_enum_field(&mut buf[byte_off..], ft_size, et, rng)
            }
            BTF_KIND_ARRAY => mutate_array_field(&mut buf[byte_off..], 1, ft_nelems, rng),
            BTF_KIND_STRUCT | BTF_KIND_UNION => {
                if ft_size > 0 {
                    let off = rng.below(ft_size as i64) as usize;
                    if byte_off + off < buf.len() {
                        buf[byte_off + off] ^= 1 << (rng.below(8) as u32);
                    }
                }
            }
            _ => {
                buf[byte_off] ^= 1 << (rng.below(8) as u32);
            }
        }

        field_idx as i32
    }

    /// Signal feedback: reward a field that produced new coverage.
    pub fn reward(&mut self, field_idx: i32) {
        if field_idx >= 0 && (field_idx as usize) < self.nmembers {
            self.weights[field_idx as usize].hits += 1;
        }
    }
}
