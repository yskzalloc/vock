//! Syzkaller program deserializer + execution arena.
//!
//! Port of the parts of syzkaller's `prog/encoding.go` (textual program
//! syntax), `prog/alloc.go` (arena allocation) and `executor/executor.cc`
//! (copyin/copyout of arguments and resources) that are needed to *replay* an
//! unmodified syzbot reproducer.
//!
//! # The `&(0x7f0000000000)` form
//!
//! Every real reproducer serialises pointer arguments as
//! `&(0x7f0000000011c0)=<inner>`. `0x7f0000000000` is a purely *textual* base
//! (`encodingAddrBase`, encoding.go:864): the parser subtracts it to get an
//! arena-relative offset, and the runtime adds the target's `DataOffset` back
//! (`Target.PhysicalAddr`, prog.go:211):
//!
//! ```text
//!   offset       = textual_addr - 0x7f0000000000
//!   runtime_addr = DataOffset   + offset          // 0x200000000000 on amd64
//! ```
//!
//! We keep that two-step model rather than mapping the arena at the textual
//! base, because `0x7f...` is exactly where Linux places shared libraries, a
//! `MAP_FIXED` there would unmap libc out from under us. `DataOffset` is
//! chosen by syzkaller to be free.
//!
//! The inner value is laid out into the arena immediately before the owning
//! call runs (syzkaller's "copyin"), and resource values produced by earlier
//! calls are substituted into later arguments ("copyout" → copyin).
//!
//! # Known limitation: integer widths inside compound values
//!
//! The textual syntax records field *values* but not field *widths*, those
//! live in the syscall descriptions (`sys/linux/*.txt`), which vock does not
//! carry. For a struct/array element we therefore fall back to a fixed width
//! (8 bytes, override with `VOCK_PROG_INT_WIDTH`). Byte-exact targets, string
//! literals, which is what most reproducers point at, are unaffected.

#![allow(dead_code)]

use std::collections::HashMap;

/// Textual base address used by the serialiser (`encodingAddrBase`).
pub const ENCODING_ADDR_BASE: u64 = 0x7f00_0000_0000;
/// Where the data arena actually lives at runtime (`Target.DataOffset`,
/// sys/targets/targets.go:786, amd64/arm64 64-bit default).
pub const DATA_OFFSET: u64 = 0x2000_0000_0000;
/// Size of the arena syzkaller reserves (`NumPages * PageSize`, 16 MiB).
pub const ARENA_SIZE: usize = 16 << 20;
/// Allocation granule of the bitmap allocator (`memAllocGranule`).
pub const GRANULE: usize = 64;
/// Sentinel for `&AUTO`, replaced with a real offset by [`note_fixed`].
pub const AUTO_ADDR: u64 = u64::MAX;
/// Cap on nesting depth so a malformed `{{{{…` line cannot blow the stack.
const MAX_DEPTH: u32 = 64;
/// Width of a resource-typed field (`<rN=>`). Nearly every syzkaller resource
/// is an `fd`, i.e. a C `int`, so a produced field occupies 4 bytes, this is
/// what puts `pipe`'s second fd at offset 4 rather than 8.
const RES_WIDTH: usize = 4;
/// Upper bound on a decompressed filesystem image, so a crafted blob cannot
/// exhaust memory.
pub const MAX_IMAGE: usize = 128 << 20;
/// Maximum arguments a call may carry (`kMaxArgs`, executor.cc:74). Pseudo-
/// syscalls such as syz_mount_image take more than the six a syscall can.
pub const MAX_ARGS: usize = 9;

/// Default width for an integer that appears inside a compound value.
fn int_width() -> usize {
    match std::env::var("VOCK_PROG_INT_WIDTH").ok().and_then(|v| v.parse::<usize>().ok()) {
        Some(w @ (1 | 2 | 4 | 8)) => w,
        _ => 8,
    }
}

/// Arena offset → live address.
#[inline]
pub fn physical_addr(offset: u64) -> u64 {
    DATA_OFFSET.wrapping_add(offset)
}

// ─── AST ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum Arg {
    /// A plain integer constant.
    Int(u64),
    /// `rN[/div][+add]`, the value produced by call `N` (resource copyin).
    Res { idx: usize, div: u64, add: u64 },
    /// `&(0xADDR)=inner` or `&(0xADDR/0xSIZE)=nil`. `addr` is arena-relative.
    Ptr { addr: u64, inner: Option<Box<Arg>> },
    /// A byte blob: `"68656c6c6f"` (hex) or `'hello'` (ascii).
    Data(Vec<u8>),
    /// `{a, b, c}`
    Struct(Vec<Arg>),
    /// `[a, b, c]`
    Array(Vec<Arg>),
    /// `@name=arg`, a union; only the selected option is serialised.
    Union(Box<Arg>),
    /// A `csum[inet]` field, computed over the enclosing buffer at copyin.
    Csum,
    /// `<rN=>inner`, the field is *produced* by this call: after it returns,
    /// the bytes at this location fill resource slot `N` (executor.cc's
    /// `copyout_call_results` memory read-back). This is how `pipe` and
    /// `socketpair` hand their fds to later calls.
    Out { slot: usize, inner: Box<Arg> },
    /// `nil` / `AUTO` / a flag name with no numeric value.
    Nil,
}

/// A resource value to be read back out of the arena after a call returns.
#[derive(Clone, Copy, Debug)]
pub struct Copyout {
    pub slot: usize,
    /// Arena-relative offset of the field.
    pub off: u64,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct Call {
    /// Full textual name including any `$variant` suffix.
    pub name: String,
    /// Base syscall name with the `$variant` suffix stripped.
    pub base: String,
    /// Resolved syscall number, or `None` for a pseudo-syscall.
    pub nr: Option<i64>,
    pub args: Vec<Arg>,
    /// Index of the resource slot this call's return value fills (`rN =`).
    pub res: Option<usize>,
    /// `(fail_nth: N)` call property, per-call fault injection.
    pub fail_nth: Option<i32>,
    /// `(async)` call property, run without waiting for completion.
    pub is_async: bool,
}

impl Call {
    pub fn is_pseudo(&self) -> bool {
        self.base.starts_with("syz_")
    }
}

#[derive(Clone, Debug, Default)]
pub struct Prog {
    pub calls: Vec<Call>,
}

// ─── parser ─────────────────────────────────────────────────────────────────

struct P<'a> {
    s: &'a [u8],
    i: usize,
    depth: u32,
}

impl<'a> P<'a> {
    fn new(s: &'a str) -> P<'a> {
        P { s: s.as_bytes(), i: 0, depth: 0 }
    }
    fn peek(&self) -> u8 {
        if self.i < self.s.len() {
            self.s[self.i]
        } else {
            0
        }
    }
    fn eat_ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> bool {
        self.eat_ws();
        if self.peek() == c {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn done(&self) -> bool {
        self.i >= self.s.len()
    }
    fn starts_with(&self, pat: &[u8]) -> bool {
        self.s[self.i.min(self.s.len())..].starts_with(pat)
    }

    /// Parse a comma-separated argument list terminated by `close` (0 = EOF).
    fn list(&mut self, close: u8) -> Vec<Arg> {
        let mut out = Vec::new();
        loop {
            self.eat_ws();
            if self.done() {
                break;
            }
            if self.peek() == close {
                self.i += 1;
                break;
            }
            let before = self.i;
            out.push(self.arg());
            self.eat_ws();
            if self.peek() == b',' {
                self.i += 1;
            } else if self.peek() == close {
                self.i += 1;
                break;
            } else if self.i == before {
                // No progress and no separator, bail rather than spin.
                self.i += 1;
            }
        }
        out
    }

    fn arg(&mut self) -> Arg {
        self.eat_ws();
        // Bail out of pathologically nested input rather than recursing until
        // the stack overflows.
        if self.depth >= MAX_DEPTH {
            while !self.done() && !is_sep(self.peek()) {
                self.i += 1;
            }
            return Arg::Nil;
        }
        self.depth += 1;
        let a = self.arg_inner();
        self.depth -= 1;
        a
    }

    fn arg_inner(&mut self) -> Arg {
        // An inline result label `<r5=>arg` marks a field the call *produces*.
        if self.peek() == b'<' {
            let save = self.i;
            self.i += 1;
            let lbl = self.until(b'>');
            if let Some(name) = lbl.strip_suffix('=') {
                let slot = name.trim().strip_prefix('r').and_then(|n| n.parse::<usize>().ok());
                let inner = self.arg();
                return match slot {
                    Some(slot) => Arg::Out { slot, inner: Box::new(inner) },
                    None => inner,
                };
            }
            self.i = save;
        }
        match self.peek() {
            b'&' => self.ptr(),
            b'{' => {
                self.i += 1;
                Arg::Struct(self.list(b'}'))
            }
            b'[' => {
                self.i += 1;
                Arg::Array(self.list(b']'))
            }
            b'@' => {
                // @name=arg  |  @name
                self.i += 1;
                while !self.done() && self.peek() != b'=' && !is_sep(self.peek()) {
                    self.i += 1;
                }
                if self.eat(b'=') {
                    Arg::Union(Box::new(self.arg()))
                } else {
                    Arg::Nil
                }
            }
            b'"' => {
                self.i += 1;
                let raw = self.until(b'"');
                let d = decode_hex_bytes(&raw);
                self.opt_size_suffix();
                Arg::Data(d)
            }
            b'\'' => {
                self.i += 1;
                let raw = self.until(b'\'');
                let d = unescape(&raw);
                self.opt_size_suffix();
                Arg::Data(d)
            }
            _ => self.word(),
        }
    }

    /// A string literal may carry an explicit buffer size: `"..."/0x20`.
    fn opt_size_suffix(&mut self) {
        if self.peek() == b'/' {
            self.i += 1;
            while !self.done() && !is_sep(self.peek()) {
                self.i += 1;
            }
        }
    }

    /// `&(0xADDR)=inner`, `&(0xADDR/0xSIZE)=nil`, `&(0xADDR)`.
    fn ptr(&mut self) -> Arg {
        self.i += 1; // '&'
        let mut addr = 0u64;
        if self.starts_with(b"AUTO") {
            self.i += 4;
            addr = AUTO_ADDR;
        } else if self.eat(b'(') {
            let body = self.until(b')');
            // Strip an optional `/0xSIZE` VMA length suffix.
            let head = body.split('/').next().unwrap_or("").trim().to_string();
            // Textual address → arena-relative offset.
            addr = parse_int(&head).unwrap_or(ENCODING_ADDR_BASE).wrapping_sub(ENCODING_ADDR_BASE);
        }
        if self.eat(b'=') {
            self.eat_ws();
            // `&(...)=ANY=[...]`, squashed pointer; parse what follows.
            if self.starts_with(b"ANY=") {
                self.i += 4;
            }
            if self.starts_with(b"nil") {
                self.i += 3;
                return Arg::Ptr { addr, inner: None };
            }
            let inner = self.arg();
            return Arg::Ptr { addr, inner: Some(Box::new(inner)) };
        }
        Arg::Ptr { addr, inner: None }
    }

    fn until(&mut self, close: u8) -> String {
        let start = self.i;
        while !self.done() && self.peek() != close {
            // Honour backslash escapes so `\'` does not end the literal.
            if self.peek() == b'\\' && self.i + 1 < self.s.len() {
                self.i += 2;
                continue;
            }
            self.i += 1;
        }
        let out = String::from_utf8_lossy(&self.s[start..self.i.min(self.s.len())]).into_owned();
        if !self.done() {
            self.i += 1; // consume close
        }
        out
    }

    /// A bare token: integer, `rN[/div][+add]`, `nil`, `AUTO`, flag names.
    fn word(&mut self) -> Arg {
        self.eat_ws();
        let start = self.i;
        while !self.done() && !is_sep(self.peek()) {
            self.i += 1;
        }
        let w = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        let w = w.trim();
        if w.is_empty() {
            if !self.done() {
                self.i += 1;
            }
            return Arg::Nil;
        }
        if w == "nil" || w == "AUTO" {
            return Arg::Nil;
        }
        if w.starts_with("csum") {
            return Arg::Csum;
        }
        if let Some(r) = parse_res_ref(w) {
            return r;
        }
        match parse_int(w) {
            Some(v) => Arg::Int(v),
            // Flag/const names have no numeric value without the descriptions.
            None => Arg::Nil,
        }
    }
}

/// `r0`, `r0/0x10`, `r0+0x5`, `r0/0x10+0x5` (encoding.go:553-583).
fn parse_res_ref(w: &str) -> Option<Arg> {
    let rest = w.strip_prefix('r')?;
    let (num, mut tail) = split_digits(rest);
    if num.is_empty() {
        return None;
    }
    let idx: usize = num.parse().ok()?;
    let mut div = 0u64;
    let mut add = 0u64;
    if let Some(t) = tail.strip_prefix('/') {
        let (d, r) = split_int_token(t);
        div = parse_int(d).unwrap_or(0);
        tail = r;
    }
    if let Some(t) = tail.strip_prefix('+') {
        let (a, r) = split_int_token(t);
        add = parse_int(a).unwrap_or(0);
        tail = r;
    }
    if !tail.is_empty() {
        return None;
    }
    Some(Arg::Res { idx, div, add })
}

fn split_digits(s: &str) -> (&str, &str) {
    let n = s.bytes().take_while(|c| c.is_ascii_digit()).count();
    s.split_at(n)
}

fn split_int_token(s: &str) -> (&str, &str) {
    let n = s
        .bytes()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == b'x' || *c == b'X')
        .count();
    s.split_at(n)
}

fn is_sep(c: u8) -> bool {
    matches!(c, b',' | b')' | b'}' | b']' | b'=' | b' ' | b'\t' | 0)
}

fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Some(neg) = s.strip_prefix('-') {
        return neg.parse::<i64>().ok().map(|v| (-v) as u64);
    }
    // Go's base-0 parse treats a leading 0 as octal.
    if s.len() > 1 && s.starts_with('0') && s.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
        return u64::from_str_radix(&s[1..], 8).ok();
    }
    s.parse::<u64>().ok()
}

/// `"6162"` → `[0x61, 0x62]`. Non-hex content falls back to escaped bytes,
/// which matches how syzkaller writes `$`-prefixed compressed blobs.
fn decode_hex_bytes(s: &str) -> Vec<u8> {
    // `"$<base64>"` is a zlib-compressed image blob (serializeCompressedData,
    // encoding.go:917). Decompress it so syz_mount_image gets real bytes.
    if let Some(b64) = s.strip_prefix('$') {
        return crate::inflate::decode_compressed_image(b64.as_bytes(), MAX_IMAGE)
            .unwrap_or_default();
    }
    let all_hex = !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit());
    if all_hex {
        return (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect();
    }
    unescape(s)
}

fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'n' => { out.push(b'\n'); i += 2 }
                b't' => { out.push(b'\t'); i += 2 }
                b'r' => { out.push(b'\r'); i += 2 }
                b'a' => { out.push(0x07); i += 2 }
                b'b' => { out.push(0x08); i += 2 }
                b'f' => { out.push(0x0c); i += 2 }
                b'v' => { out.push(0x0b); i += 2 }
                b'\\' => { out.push(b'\\'); i += 2 }
                b'\'' => { out.push(b'\''); i += 2 }
                b'"' => { out.push(b'"'); i += 2 }
                // Decode from the byte slice, not `&s[..]`: a `\x` followed by
                // a multi-byte character would split it and panic on a
                // non-char-boundary slice.
                b'x' if i + 3 < b.len() => {
                    let hi = (b[i + 2] as char).to_digit(16);
                    let lo = (b[i + 3] as char).to_digit(16);
                    match (hi, lo) {
                        (Some(h), Some(l)) => {
                            out.push((h * 16 + l) as u8);
                            i += 4;
                        }
                        _ => {
                            out.push(b'x');
                            i += 2;
                        }
                    }
                }
                c => { out.push(c); i += 2 }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Parse the optional `(fail_nth: 3, async)` call-property block.
fn parse_props(s: &str, call: &mut Call) {
    for part in s.split(',') {
        let p = part.trim();
        if p == "async" {
            call.is_async = true;
        } else if let Some(v) = p.strip_prefix("fail_nth:") {
            call.fail_nth = parse_int(v.trim()).map(|v| v as i32);
        }
    }
}

/// Parse one statement: `[rN = ]name(args)[ (props)][ # comment]`.
pub fn parse_call(line: &str) -> Option<Call> {
    let mut line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Strip a trailing comment that is outside any string literal.
    if let Some(pos) = comment_pos(line) {
        line = line[..pos].trim();
    }
    let paren = line.find('(')?;
    // `rN = call(...)`, the `=` must precede the opening paren.
    let (res, rest) = match line[..paren].find('=') {
        Some(eq) => {
            let lhs = line[..eq].trim();
            let idx = lhs.strip_prefix('r').and_then(|n| n.parse::<usize>().ok());
            (idx, line[eq + 1..].trim())
        }
        None => (None, line),
    };
    let paren = rest.find('(')?;
    let name = rest[..paren].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let close = matching_paren(rest, paren)?;
    let mut p = P::new(&rest[paren + 1..close]);
    let args = p.list(0);

    let base = name.split('$').next().unwrap_or(&name).to_string();
    let nr = crate::syscall::syscall_nr(&base);
    let mut call = Call { name, base, nr, args, res, fail_nth: None, is_async: false };

    // Anything after the call's closing paren may be a call-property block.
    let tail = rest[close + 1..].trim();
    if let Some(open) = tail.find('(') {
        if let Some(end) = tail.rfind(')') {
            if end > open {
                parse_props(&tail[open + 1..end], &mut call);
            }
        }
    }
    Some(call)
}

/// Index of the `)` matching the `(` at `open`, ignoring string literals.
fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut quote = 0u8;
    let mut i = open;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
        } else {
            match c {
                b'"' | b'\'' => quote = c,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Position of a `#` that starts a comment (not inside a string literal).
fn comment_pos(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut quote = 0u8;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
        } else if c == b'"' || c == b'\'' {
            quote = c;
        } else if c == b'#' {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn parse_prog(text: &str) -> Prog {
    let mut calls = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(c) = parse_call(l) {
            calls.push(c);
        }
    }
    Prog { calls }
}

pub fn parse_file(path: &str) -> std::io::Result<Prog> {
    Ok(parse_prog(&std::fs::read_to_string(path)?))
}

/// True if the program uses syzkaller's `&(0x7f...)` memory-layout form and so
/// needs the arena.
pub fn needs_arena(text: &str) -> bool {
    text.contains("&(0x") || text.contains("&AUTO")
}

// ─── the arena ──────────────────────────────────────────────────────────────

/// The data arena, mapped at `DATA_OFFSET`, plus the 64-byte-granule bitmap
/// allocator syzkaller uses to place `AUTO` objects around fixed ones.
pub struct Arena {
    base: *mut u8,
    len: usize,
    used: Vec<u64>,
    /// Sorted addresses of fixed objects, used to clip over-wide writes.
    fixed: Vec<u64>,
}

impl Arena {
    /// Reserve the data arena (syzkaller's `MakeDataMmap` preamble).
    pub fn map() -> Option<Arena> {
        let p = unsafe {
            libc::mmap(
                DATA_OFFSET as *mut libc::c_void,
                ARENA_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return None;
        }
        Some(Arena {
            base: p as *mut u8,
            len: ARENA_SIZE,
            used: vec![0; ARENA_SIZE / GRANULE / 64 + 1],
            fixed: Vec::new(),
        })
    }

    /// Zero the arena between programs so one pass cannot see the last one's
    /// bytes.
    pub fn reset(&mut self) {
        unsafe { std::ptr::write_bytes(self.base, 0, self.len) };
        for w in self.used.iter_mut() {
            *w = 0;
        }
    }

    fn in_range(&self, off: u64, size: usize) -> bool {
        off.saturating_add(size as u64) <= self.len as u64
    }

    /// Mark `[off, off+size)` as occupied (`memAlloc.noteAlloc`).
    pub fn note_alloc(&mut self, off: u64, size: usize) {
        if !self.in_range(off, size) {
            return;
        }
        let first = off as usize / GRANULE;
        let last = (off as usize + size).div_ceil(GRANULE);
        for g in first..last {
            self.used[g / 64] |= 1 << (g % 64);
        }
    }

    /// First-fit allocation on the granule bitmap (`memAlloc.alloc`).
    pub fn alloc(&mut self, size: usize) -> u64 {
        let need = size.div_ceil(GRANULE).max(1);
        let total = self.len / GRANULE;
        let mut start = 0usize;
        while start + need <= total {
            let mut ok = true;
            for g in start..start + need {
                if self.used[g / 64] & (1 << (g % 64)) != 0 {
                    ok = false;
                    start = g + 1;
                    break;
                }
            }
            if ok {
                let off = (start * GRANULE) as u64;
                self.note_alloc(off, size);
                return off;
            }
        }
        0
    }

    /// Copy `bytes` to arena offset `off`.
    ///
    /// The write is clipped at the next object's address. Because integer
    /// widths are not recoverable from the textual form (see the module
    /// header), an over-wide guess would otherwise blit over the neighbouring
    /// object, reproducers routinely place objects only 0x20/0x40 apart.
    /// Clipping keeps a bad width guess local to its own object.
    fn write(&self, off: u64, bytes: &[u8]) {
        let mut len = bytes.len();
        if let Some(&next) = self.fixed.iter().find(|&&f| f > off) {
            len = len.min((next - off) as usize);
        }
        if len == 0 || !self.in_range(off, len) {
            return;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.add(off as usize), len);
        }
    }

    /// Read back `size` bytes at `off` as a little-endian integer (copyout).
    pub fn read_scalar(&self, off: u64, size: usize) -> Option<u64> {
        let size = size.clamp(1, 8);
        if !self.in_range(off, size) {
            return None;
        }
        let mut buf = [0u8; 8];
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(off as usize), buf.as_mut_ptr(), size);
        }
        Some(u64::from_le_bytes(buf))
    }

    /// Record the sorted set of fixed object addresses used to clip writes.
    fn set_fixed(&mut self, mut addrs: Vec<u64>) {
        addrs.sort_unstable();
        addrs.dedup();
        self.fixed = addrs;
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.len) };
    }
}

// ─── checksums (executor/common.h:452-480) ─────────────────────────────────

/// Internet checksum: sum of little-endian 16-bit words, end-around carry,
/// one's complement, byte-for-byte syzkaller's `csum_inet_*`.
pub fn csum_inet(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u32::from(u16::from_le_bytes([data[i], data[i + 1]]));
        // Fold as we go: upstream folds inside csum_inet_update, and without
        // it a buffer over ~128 KiB overflows the u32 accumulator.
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        i += 2;
    }
    if i < data.len() {
        acc += u32::from(data[i]);
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Pack `value` into `word` at bits `[offset, offset+length)`, the runtime
/// half of syzkaller's bitfield encoding (`copyin_int`, executor.cc:1642).
/// `offset` is counted from the low bit on a little-endian host.
pub fn bitfield_pack(word: u64, value: u64, offset: u64, length: u64) -> u64 {
    if length == 0 || length >= 64 {
        return value;
    }
    let mask = ((1u64 << length) - 1) << offset;
    (word & !mask) | ((value << offset) & mask)
}

// ─── copyin / copyout ───────────────────────────────────────────────────────

/// Execution state: the resource slots filled by earlier calls.
pub struct Ctx {
    pub res: HashMap<usize, u64>,
}

impl Ctx {
    pub fn new() -> Ctx {
        Ctx { res: HashMap::new() }
    }
    /// `read_result` (executor.cc:1788): divide first, then add. An
    /// unfulfilled resource falls back to the descriptions' default, which for
    /// the fd-like resources in reproducers is `(u64)-1`.
    fn resolve(&self, idx: usize, div: u64, add: u64) -> u64 {
        match self.res.get(&idx) {
            Some(&v) => {
                let v = if div != 0 { v / div } else { v };
                v.wrapping_add(add)
            }
            None => u64::MAX,
        }
    }
    /// Record a call's return value in slot `idx` (copyout).
    pub fn set(&mut self, idx: usize, val: u64) {
        self.res.insert(idx, val);
    }
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

/// Flatten a value to its in-memory byte image.
fn encode(arg: &Arg, ctx: &Ctx, w: usize) -> Vec<u8> {
    match arg {
        Arg::Int(v) => v.to_le_bytes()[..w].to_vec(),
        Arg::Res { idx, div, add } => ctx.resolve(*idx, *div, *add).to_le_bytes()[..w].to_vec(),
        Arg::Nil => vec![0u8; w],
        Arg::Csum => vec![0u8; 2],
        Arg::Data(d) => d.clone(),
        Arg::Union(inner) => encode(inner, ctx, w),
        // A produced resource field occupies RES_WIDTH bytes regardless of the
        // generic integer-width guess.
        Arg::Out { inner, .. } => {
            let mut b = encode(inner, ctx, RES_WIDTH);
            b.resize(RES_WIDTH, 0);
            b
        }
        Arg::Struct(fs) | Arg::Array(fs) => {
            let mut out = Vec::new();
            for f in fs {
                out.extend_from_slice(&encode(f, ctx, w));
            }
            out
        }
        // A nested pointer contributes its runtime address.
        Arg::Ptr { addr, .. } => physical_addr(*addr).to_le_bytes().to_vec(),
    }
}

/// Byte length `encode` will produce for `arg`.
fn encoded_len(arg: &Arg, w: usize) -> usize {
    match arg {
        Arg::Data(d) => d.len(),
        Arg::Csum => 2,
        Arg::Ptr { .. } => 8,
        Arg::Out { .. } => RES_WIDTH,
        Arg::Union(i) => encoded_len(i, w),
        Arg::Struct(fs) | Arg::Array(fs) => fs.iter().map(|f| encoded_len(f, w)).sum(),
        _ => w,
    }
}

/// Record every `<rN=>` field's offset within `arg`, so the executor can read
/// the produced resource back out of the arena after the call.
fn collect_copyouts(arg: &Arg, base: u64, w: usize, out: &mut Vec<Copyout>) {
    match arg {
        Arg::Out { slot, inner } => {
            out.push(Copyout { slot: *slot, off: base, size: RES_WIDTH });
            collect_copyouts(inner, base, w, out);
        }
        Arg::Struct(fs) | Arg::Array(fs) => {
            let mut off = base;
            for f in fs {
                collect_copyouts(f, off, w, out);
                off += encoded_len(f, w) as u64;
            }
        }
        Arg::Union(i) => collect_copyouts(i, base, w, out),
        _ => {}
    }
}

/// Recursively lay out any pointer targets of `arg` into the arena (copyin),
/// then return the scalar the syscall should receive.
fn copyin(arena: &Arena, arg: &Arg, ctx: &Ctx) -> u64 {
    let w = int_width();
    match arg {
        Arg::Int(v) => *v,
        Arg::Res { idx, div, add } => ctx.resolve(*idx, *div, *add),
        Arg::Nil | Arg::Csum => 0,
        // A compound passed by value has no meaningful scalar form.
        Arg::Data(_) | Arg::Struct(_) | Arg::Array(_) => 0,
        Arg::Union(inner) | Arg::Out { inner, .. } => copyin(arena, inner, ctx),
        Arg::Ptr { addr, inner } => {
            if let Some(inner) = inner {
                // Lay out nested pointers first so their addresses are live.
                lay_out_nested(arena, inner, ctx);
                let mut bytes = encode(inner, ctx, w);
                fix_csums(&mut bytes, inner, w);
                arena.write(*addr, &bytes);
            }
            physical_addr(*addr)
        }
    }
}

fn lay_out_nested(arena: &Arena, arg: &Arg, ctx: &Ctx) {
    match arg {
        Arg::Ptr { .. } => {
            copyin(arena, arg, ctx);
        }
        Arg::Struct(fs) | Arg::Array(fs) => {
            for f in fs {
                lay_out_nested(arena, f, ctx);
            }
        }
        Arg::Union(inner) | Arg::Out { inner, .. } => lay_out_nested(arena, inner, ctx),
        _ => {}
    }
}

/// Replace `Arg::Csum` placeholders with the inet checksum of the surrounding
/// buffer. syzkaller computes checksums after the rest of the object is laid
/// out, and zeroes the field first.
fn fix_csums(bytes: &mut [u8], arg: &Arg, w: usize) {
    let Some(off) = csum_offset(arg, 0, w) else { return };
    if off + 2 > bytes.len() {
        return;
    }
    bytes[off] = 0;
    bytes[off + 1] = 0;
    let sum = csum_inet(bytes);
    bytes[off..off + 2].copy_from_slice(&sum.to_le_bytes());
}

fn csum_offset(arg: &Arg, base: usize, w: usize) -> Option<usize> {
    match arg {
        Arg::Csum => Some(base),
        Arg::Struct(fs) | Arg::Array(fs) => {
            let mut off = base;
            for f in fs {
                if let Some(p) = csum_offset(f, off, w) {
                    return Some(p);
                }
                off += encoded_len(f, w);
            }
            None
        }
        Arg::Union(i) | Arg::Out { inner: i, .. } => csum_offset(i, base, w),
        _ => None,
    }
}

/// Reserve the arena slots every fixed (textually addressed) pointer occupies,
/// mirroring `analyze()`'s `noteAlloc` pass so later allocations don't overlap.
pub fn note_fixed(arena: &mut Arena, prog: &mut Prog) {
    let w = int_width();
    let mut addrs: Vec<u64> = Vec::new();

    // Pass 1: reserve every textually-addressed object.
    fn note(arena: &mut Arena, arg: &Arg, w: usize, addrs: &mut Vec<u64>) {
        if let Arg::Ptr { addr, inner } = arg {
            if let Some(inner) = inner {
                arena.note_alloc(*addr, encoded_len(inner, w).max(1));
                addrs.push(*addr);
                note(arena, inner, w, addrs);
            }
        }
        match arg {
            Arg::Struct(fs) | Arg::Array(fs) => {
                for f in fs {
                    note(arena, f, w, addrs);
                }
            }
            Arg::Union(i) | Arg::Out { inner: i, .. } => note(arena, i, w, addrs),
            _ => {}
        }
    }
    for c in &prog.calls {
        for a in &c.args {
            note(arena, a, w, &mut addrs);
        }
    }

    // Pass 2: give every `&AUTO` pointer a real slot around the fixed ones,
    // instead of leaving them all aliased at offset 0.
    fn assign(arena: &mut Arena, arg: &mut Arg, w: usize, addrs: &mut Vec<u64>) {
        if let Arg::Ptr { addr, inner } = arg {
            if let Some(inner) = inner {
                if *addr == AUTO_ADDR {
                    let off = arena.alloc(encoded_len(inner, w).max(1));
                    *addr = off;
                    addrs.push(off);
                }
                assign(arena, inner, w, addrs);
            } else if *addr == AUTO_ADDR {
                *addr = arena.alloc(GRANULE);
            }
        }
        match arg {
            Arg::Struct(fs) | Arg::Array(fs) => {
                for f in fs {
                    assign(arena, f, w, addrs);
                }
            }
            Arg::Union(i) | Arg::Out { inner: i, .. } => assign(arena, i, w, addrs),
            _ => {}
        }
    }
    for c in prog.calls.iter_mut() {
        for a in c.args.iter_mut() {
            assign(arena, a, w, &mut addrs);
        }
    }
    arena.set_fixed(addrs);
}

/// Everything a call needs to run: its scalar arguments plus the resource
/// fields to read back out of the arena afterwards.
pub struct Prepared {
    /// Materialised scalars. Only the first six can reach `syscall()`; a
    /// pseudo-syscall may consume more.
    pub args: [i64; MAX_ARGS],
    pub copyouts: Vec<Copyout>,
}

/// Materialise a call's arguments.
pub fn prepare_args(arena: &Arena, call: &Call, ctx: &Ctx) -> Prepared {
    let w = int_width();
    let mut args = [0i64; MAX_ARGS];
    let mut copyouts = Vec::new();
    for (i, a) in call.args.iter().take(MAX_ARGS).enumerate() {
        args[i] = copyin(arena, a, ctx) as i64;
        // `<rN=>` fields live inside a pointer target; record where.
        if let Arg::Ptr { addr, inner: Some(inner) } = a {
            collect_copyouts(inner, *addr, w, &mut copyouts);
        }
    }
    Prepared { args, copyouts }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pointer_with_hex_data() {
        let c = parse_call(r#"write(0xffffffffffffff9c, &(0x7f0000000000)="6869", 0x2)"#).unwrap();
        assert_eq!(c.base, "write");
        assert_eq!(c.args.len(), 3);
        match &c.args[1] {
            Arg::Ptr { addr, inner: Some(b) } => {
                assert_eq!(*addr, 0, "textual base must become offset 0");
                match &**b {
                    Arg::Data(d) => assert_eq!(d, b"hi"),
                    other => panic!("expected data, got {other:?}"),
                }
            }
            other => panic!("expected ptr, got {other:?}"),
        }
    }

    #[test]
    fn pointer_offset_and_physical_addr() {
        let c = parse_call("foo(&(0x7f0000001000)=\"00\")").unwrap();
        match &c.args[0] {
            Arg::Ptr { addr, .. } => {
                assert_eq!(*addr, 0x1000);
                assert_eq!(physical_addr(*addr), DATA_OFFSET + 0x1000);
            }
            other => panic!("expected ptr, got {other:?}"),
        }
    }

    #[test]
    fn parses_resource_binding_and_use() {
        let p = parse_prog("r0 = socket$inet(0x2, 0x1, 0x0)\nclose(r0)\n");
        assert_eq!(p.calls.len(), 2);
        assert_eq!(p.calls[0].res, Some(0));
        assert_eq!(p.calls[0].base, "socket");
        match p.calls[1].args[0] {
            Arg::Res { idx: 0, div: 0, add: 0 } => {}
            ref other => panic!("expected r0, got {other:?}"),
        }
    }

    #[test]
    fn parses_resource_div_add() {
        let c = parse_call("foo(r3/0x10+0x5)").unwrap();
        match c.args[0] {
            Arg::Res { idx: 3, div: 0x10, add: 0x5 } => {}
            ref other => panic!("expected r3/0x10+0x5, got {other:?}"),
        }
    }

    #[test]
    fn resource_resolve_divides_then_adds() {
        let mut ctx = Ctx::new();
        ctx.set(0, 0x100);
        assert_eq!(ctx.resolve(0, 0x10, 0x5), 0x15);
        assert_eq!(ctx.resolve(0, 0, 0x5), 0x105);
        assert_eq!(ctx.resolve(9, 0, 0), u64::MAX);
    }

    #[test]
    fn parses_vma_and_nil() {
        let c = parse_call("mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)").unwrap();
        match &c.args[0] {
            Arg::Ptr { addr, inner: None } => assert_eq!(*addr, 0),
            other => panic!("expected nil ptr, got {other:?}"),
        }
    }

    #[test]
    fn parses_nested_struct_and_array() {
        let c = parse_call("foo(&(0x7f0000000000)={0x1, [0x2, 0x3]})").unwrap();
        match &c.args[0] {
            Arg::Ptr { inner: Some(b), .. } => match &**b {
                Arg::Struct(fs) => {
                    assert_eq!(fs.len(), 2);
                    assert!(matches!(fs[1], Arg::Array(_)));
                }
                other => panic!("expected struct, got {other:?}"),
            },
            other => panic!("expected ptr, got {other:?}"),
        }
    }

    #[test]
    fn ascii_string_literal_with_escape() {
        let c = parse_call(r"open(&(0x7f0000000000)='./file0\x00', 0x0, 0x0)").unwrap();
        match &c.args[0] {
            Arg::Ptr { inner: Some(b), .. } => match &**b {
                Arg::Data(d) => assert_eq!(d.as_slice(), b"./file0\x00"),
                other => panic!("expected data, got {other:?}"),
            },
            other => panic!("expected ptr, got {other:?}"),
        }
    }

    #[test]
    fn union_selects_inner() {
        let c = parse_call("foo(&(0x7f0000000000)=@newtcp={0x1})").unwrap();
        assert!(matches!(&c.args[0], Arg::Ptr { inner: Some(_), .. }));
    }

    #[test]
    fn call_props_parsed() {
        let c = parse_call("foo(0x0) (fail_nth: 3)").unwrap();
        assert_eq!(c.fail_nth, Some(3));
        let c = parse_call("bar(0x0) (async)").unwrap();
        assert!(c.is_async);
    }

    #[test]
    fn comment_and_paren_in_string_do_not_confuse_parser() {
        let c = parse_call(r#"foo(&(0x7f0000000000)='a)b#c') # trailing"#).unwrap();
        match &c.args[0] {
            Arg::Ptr { inner: Some(b), .. } => match &**b {
                Arg::Data(d) => assert_eq!(d.as_slice(), b"a)b#c"),
                other => panic!("expected data, got {other:?}"),
            },
            other => panic!("expected ptr, got {other:?}"),
        }
    }

    #[test]
    fn csum_inet_matches_syzkaller_semantics() {
        // Little-endian 16-bit words, end-around carry, one's complement.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(csum_inet(&data), 0x0d22);
        // A buffer that sums to zero complements to 0xffff.
        assert_eq!(csum_inet(&[0x00, 0x00]), 0xffff);
    }

    #[test]
    fn bitfield_packs_in_place() {
        assert_eq!(bitfield_pack(0, 0b101, 2, 3), 0b10100);
        assert_eq!(bitfield_pack(u64::MAX, 0, 0, 8), 0xffff_ffff_ffff_ff00);
    }

    #[test]
    fn multibyte_and_truncated_escapes_do_not_panic() {
        // A `\x` whose two following bytes are part of a multi-byte character
        // must not be sliced as a &str.
        for line in [
            r"foo(&(0x7f0000000000)='\xé')",
            r"foo(&(0x7f0000000000)='\x')",
            r"foo(&(0x7f0000000000)='\xz9')",
            r"foo(&(0x7f0000000000)='trailing\')",
            "foo(&(0x7f0000000000)='日本語')",
        ] {
            let _ = parse_call(line);
        }
    }

    #[test]
    fn malformed_input_terminates() {
        // Unbalanced brackets and stray separators must not hang the parser.
        for line in [
            "foo({{{{{{",
            "foo([[[[[[",
            "foo(&(0x7f0000000000)={0x1,",
            "foo(,,,,,,,,)",
            "foo(@@@@)",
            "foo(&&&&)",
            "r0 = ",
            "foo(",
        ] {
            let _ = parse_call(line);
        }
    }

    #[test]
    fn inline_copyout_labels_are_recorded() {
        // pipe()/socketpair() produce their fds in memory, not as a return
        // value; without this the whole rest of the program gets -1 fds.
        let c = parse_call(
            "pipe(&(0x7f0000000000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})",
        )
        .unwrap();
        let mut cos = Vec::new();
        if let Arg::Ptr { addr, inner: Some(inner) } = &c.args[0] {
            collect_copyouts(inner, *addr, 8, &mut cos);
        }
        assert_eq!(cos.len(), 2, "both fds must be recorded: {cos:?}");
        assert_eq!(cos[0].slot, 0);
        assert_eq!(cos[0].off, 0);
        assert_eq!(cos[1].slot, 1);
        assert_eq!(cos[1].off, 4, "second fd sits one int after the first");
    }

    #[test]
    fn auto_pointers_get_distinct_addresses() {
        let mut prog = parse_prog(
            "foo(&AUTO=\"0011223344556677\")\nbar(&AUTO=\"8899aabbccddeeff\")\n",
        );
        // Both start life as the AUTO sentinel.
        assert!(matches!(prog.calls[0].args[0], Arg::Ptr { addr: AUTO_ADDR, .. }));
        let Some(mut arena) = Arena::map() else { return };
        note_fixed(&mut arena, &mut prog);
        let (a, b) = match (&prog.calls[0].args[0], &prog.calls[1].args[0]) {
            (Arg::Ptr { addr: a, .. }, Arg::Ptr { addr: b, .. }) => (*a, *b),
            _ => panic!("expected pointers"),
        };
        assert_ne!(a, AUTO_ADDR);
        assert_ne!(b, AUTO_ADDR);
        assert_ne!(a, b, "AUTO objects must not alias each other");
    }

    #[test]
    fn write_is_clipped_at_the_next_object() {
        // A struct of five ints guesses 40 bytes, but the next object sits at
        // offset 0x20, the write must stop there rather than destroy it.
        let mut prog = parse_prog(
            "foo(&(0x7f0000000000)={0x1,0x1,0x1,0x1,0x1}, &(0x7f0000000020)=\"abababababababab\")\n",
        );
        let Some(mut arena) = Arena::map() else { return };
        note_fixed(&mut arena, &mut prog);
        let ctx = Ctx::new();
        let _ = prepare_args(&arena, &prog.calls[0], &ctx);
        // The second object's first byte must still be 0xab, not clobbered.
        assert_eq!(
            arena.read_scalar(0x20, 1),
            Some(0xab),
            "neighbouring object was overwritten by the over-wide struct"
        );
    }

    #[test]
    fn needs_arena_detects_real_repro() {
        assert!(needs_arena("write(0x1, &(0x7f0000000000)=\"00\", 0x1)"));
        assert!(!needs_arena("syz_usb_connect(0x3, 0x1)"));
    }

    #[test]
    fn pseudo_detected_and_variant_stripped() {
        let c = parse_call("r0 = syz_open_dev$char(0xc, 0x4, 0x1)").unwrap();
        assert!(c.is_pseudo());
        assert_eq!(c.base, "syz_open_dev");
        assert_eq!(c.res, Some(0));
    }

    #[test]
    fn compressed_image_blob_is_inflated_into_the_arena() {
        // A real syz_mount_image line: the image arrives as "$<base64>" of a
        // zlib stream and must reach the arena as raw bytes.
        let line = format!(
            "syz_mount_image$vfat(&(0x7f0000000000)='vfat\\x00', &(0x7f0000000100)='./file0\\x00', 0x0, 0x0, 0x0, 0x{:x}, &(0x7f0000001000)=\"${}\")",
            219, "eNp7bTMhNzutWC8tsYSBDsDNMcTQTEFBIXQV7SEAgbA4Qg=="
        );
        let c = parse_call(&line).expect("parse");
        assert_eq!(c.base, "syz_mount_image");
        assert_eq!(c.args.len(), 7, "7-arg ABI, beyond the 6 a syscall takes");
        // The image argument decoded to the original bytes.
        match &c.args[6] {
            Arg::Ptr { inner: Some(b), .. } => match &**b {
                Arg::Data(d) => {
                    assert_eq!(d.len(), 219);
                    assert_eq!(&d[3..11], b"mkfs.fat");
                }
                other => panic!("expected inflated data, got {other:?}"),
            },
            other => panic!("expected ptr, got {other:?}"),
        }
        // And it survives copyin into the arena.
        let Some(mut arena) = Arena::map() else { return };
        let mut prog = Prog { calls: vec![c] };
        note_fixed(&mut arena, &mut prog);
        let p = prepare_args(&arena, &prog.calls[0], &Ctx::new());
        assert_eq!(p.args[5], 219, "size argument");
        assert_eq!(arena.read_scalar(0x1000 + 3, 1), Some(b'm' as u64));
    }
}
