//! Base64 + zlib/DEFLATE decoding for syzkaller's compressed image blobs.
//!
//! A `syz_mount_image` reproducer carries its filesystem image inline as
//! `"$<base64>"`, where the payload is zlib-compressed
//! (`pkg/image/compression.go`: `zlib.NewWriter` + `base64.StdEncoding`). The
//! executor decompresses it with `puff_zlib_to_file` (`executor/common_linux.h`).
//!
//! This is a from-scratch RFC 1950/1951 decoder following puff's structure,
//! the same algorithm the executor uses, because vock deliberately carries no
//! dependency beyond `libc`.

#![allow(dead_code)]

// ─── base64 (RFC 4648 standard alphabet, with padding) ──────────────────────

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64. Whitespace is skipped; `=` ends the stream.
pub fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &c in s {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = b64_val(c)?;
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

// ─── DEFLATE (RFC 1951) ─────────────────────────────────────────────────────

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, buf: 0, cnt: 0 }
    }
    /// Read `n` bits LSB-first (n <= 16, so the u32 buffer cannot overflow).
    fn bits(&mut self, n: u32) -> Option<u32> {
        if n == 0 {
            return Some(0);
        }
        while self.cnt < n {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.buf |= u32::from(b) << self.cnt;
            self.cnt += 8;
        }
        let out = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.cnt -= n;
        Some(out)
    }
    fn align_byte(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }
}

/// Canonical Huffman table in puff's counts/symbols representation.
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

const MAX_BITS: usize = 15;

impl Huffman {
    fn new(lengths: &[u8]) -> Huffman {
        let mut counts = [0u16; MAX_BITS + 1];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // Starting offset of each code length's symbol run (puff's `offs`).
        let mut offs = [0u16; MAX_BITS + 2];
        for len in 1..MAX_BITS {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let slot = offs[l as usize] as usize;
                if slot < symbols.len() {
                    symbols[slot] = sym as u16;
                }
                offs[l as usize] += 1;
            }
        }
        Huffman { counts, symbols }
    }

    /// Decode one symbol (puff's `decode`): walk code lengths shortest-first.
    fn decode(&self, br: &mut BitReader) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= br.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return self.symbols.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn fixed_trees() -> (Huffman, Huffman) {
    let mut lit = [0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist = [5u8; 30];
    (Huffman::new(&lit), Huffman::new(&dist))
}

fn inflate_block(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
    limit: usize,
) -> Option<()> {
    loop {
        let sym = lit.decode(br)?;
        match sym {
            0..=255 => {
                if out.len() >= limit {
                    return None;
                }
                out.push(sym as u8);
            }
            256 => return Some(()),
            257..=285 => {
                let i = (sym - 257) as usize;
                let len = LEN_BASE[i] as usize + br.bits(u32::from(LEN_EXTRA[i]))? as usize;
                let dsym = dist.decode(br)? as usize;
                if dsym >= 30 {
                    return None;
                }
                let d = DIST_BASE[dsym] as usize + br.bits(u32::from(DIST_EXTRA[dsym]))? as usize;
                if d > out.len() || out.len() + len > limit {
                    return None;
                }
                let start = out.len() - d;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return None,
        }
    }
}

/// Raw DEFLATE stream → bytes. `limit` caps the output so a crafted stream
/// cannot exhaust memory.
pub fn inflate(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align_byte();
                // Stored: LEN, NLEN, then raw bytes.
                let len = br.bits(16)? as usize;
                let _nlen = br.bits(16)?;
                for _ in 0..len {
                    if out.len() >= limit {
                        return None;
                    }
                    out.push(br.bits(8)? as u8);
                }
            }
            1 => {
                let (lit, dist) = fixed_trees();
                inflate_block(&mut br, &mut out, &lit, &dist, limit)?;
            }
            2 => {
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl = [0u8; 19];
                for &o in ORDER.iter().take(hclen) {
                    cl[o] = br.bits(3)? as u8;
                }
                let cl_tree = Huffman::new(&cl);
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lengths.len() {
                    let sym = cl_tree.decode(&mut br)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return None;
                            }
                            let prev = lengths[i - 1];
                            let n = 3 + br.bits(2)? as usize;
                            for _ in 0..n {
                                if i >= lengths.len() {
                                    return None;
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let n = 3 + br.bits(3)? as usize;
                            i = (i + n).min(lengths.len());
                        }
                        18 => {
                            let n = 11 + br.bits(7)? as usize;
                            i = (i + n).min(lengths.len());
                        }
                        _ => return None,
                    }
                }
                let lit = Huffman::new(&lengths[..hlit]);
                let dist = Huffman::new(&lengths[hlit..]);
                inflate_block(&mut br, &mut out, &lit, &dist, limit)?;
            }
            _ => return None,
        }
        if last == 1 {
            return Some(out);
        }
    }
}

/// zlib stream (RFC 1950: 2-byte header, DEFLATE payload, adler32 trailer).
pub fn zlib_decompress(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let cmf = data[0];
    let flg = data[1];
    // CM must be 8 (deflate) and the header checksum must validate.
    if cmf & 0x0f != 8 || (u16::from(cmf) * 256 + u16::from(flg)) % 31 != 0 {
        return None;
    }
    // A preset dictionary (FDICT) is never produced by Go's zlib writer.
    if flg & 0x20 != 0 {
        return None;
    }
    inflate(&data[2..], limit)
}

/// Decode a syzkaller `"$<base64>"` compressed image blob.
pub fn decode_compressed_image(b64: &[u8], limit: usize) -> Option<Vec<u8>> {
    let raw = base64_decode(b64)?;
    zlib_decompress(&raw, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_vectors() {
        assert_eq!(base64_decode(b"").unwrap(), b"");
        assert_eq!(base64_decode(b"Zg==").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode(b"Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");
        // Whitespace is tolerated, invalid characters are rejected.
        assert_eq!(base64_decode(b"Zm9v\nYmFy").unwrap(), b"foobar");
        assert!(base64_decode(b"Zm9v!").is_none());
    }

    #[test]
    fn inflate_stored_block() {
        // BFINAL=1, BTYPE=00, then LEN=5 NLEN=~5, "hello".
        let mut d = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        d.extend_from_slice(b"hello");
        assert_eq!(inflate(&d, 1 << 20).unwrap(), b"hello");
    }

    #[test]
    fn zlib_rejects_bad_header() {
        assert!(zlib_decompress(&[0x00, 0x00], 1 << 20).is_none());
        assert!(zlib_decompress(&[], 1 << 20).is_none());
    }

    #[test]
    fn inflate_respects_output_limit() {
        let mut d = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        d.extend_from_slice(b"hello");
        assert!(inflate(&d, 2).is_none(), "must refuse to exceed the limit");
    }

    /// A real zlib stream produced by a standard compressor (dynamic Huffman
    /// blocks, back-references), the shape syzkaller actually emits.
    #[test]
    fn decodes_real_zlib_base64_blob() {
        const B64: &str = "eNpjYBgFIxmkVpSY6BaXFqQWJeXkJ2frZhZn6KYkliSOio+Kj4oPfnEGRiZmFlY2dg5OLm4eXj5+AUEhYRFRMXEJSSlpGVk5eQVFJWUVVTV1DU0tbR1dPX0DQyNjE1MzcwtLK2sbWzt7B0cnZxdXN3cPTy9vH18//4DAoOCQ0LDwiMio6JjYuPiExKTklNS09IzMrOyc3Lz8gsKi4pLSsvKKyqrqmtq6+obGpuaW1rb2js6u7p7evv4JEydNnjJ12vQZM2fNnjN33vwFCxctXrJ02fIVK1etXrN23foNGzdt3rJ12/YdO3ft3rN33/4DBw8dPnL02PETJ0+dPnP23PkLFy9dvnL12vUbN2/dvnP33v0HDx89fvL02fMXL1+9fvP23fsPHz99/vL12/cfP3/9/vP33/9R/4/6fyT7HwBIO2vO";
        let out = decode_compressed_image(B64.as_bytes(), 1 << 20).expect("decode failed");
        assert_eq!(out.len(), 2496);
        // Spot-check the structure: leading zeros, then the repeated marker.
        assert!(out[..512].iter().all(|&b| b == 0));
        assert_eq!(&out[512..536], b"ext4-superblock-ish-data");
        assert_eq!(out[out.len() - 1], 255);
        let sum: u64 = out.iter().map(|&b| b as u64).sum();
        assert_eq!(sum, 224160);
    }
}
