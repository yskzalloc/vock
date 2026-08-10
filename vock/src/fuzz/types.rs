//! BTF-based type binding (port of syzlang/types.c).
//!
//! Auto-resolves syscall args to BTF structs by parsing a trace.syz file and
//! matching ioctl cmd size encodings / sockopt lengths against BTF struct
//! sizes (and searching enums for the cmd value).
#![allow(dead_code)]

use super::btf::{Btf, BtfType, BTF_KIND_ENUM, BTF_KIND_STRUCT, BTF_KIND_UNION};

// ioctl cmd encoding (asm-generic/ioctl.h).
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_DIRBITS: u32 = 2;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

fn ioc_size(nr: u64) -> u32 {
    ((nr >> IOC_SIZESHIFT) as u32) & ((1 << IOC_SIZEBITS) - 1)
}
fn ioc_dir(nr: u64) -> u32 {
    ((nr >> IOC_DIRSHIFT) as u32) & ((1 << IOC_DIRBITS) - 1)
}

pub struct TypeBinding {
    pub line: i32,
    pub syscall_nr: i64,
    pub syscall_name: &'static str,
    pub cmd: u64,
    pub arg_index: i32,
    pub btf_type_id: u32,
    pub arg_size: u32,
    pub struct_name: String,
}

pub struct TypeMap {
    pub bindings: Vec<TypeBinding>,
}

impl TypeMap {
    fn new() -> TypeMap {
        TypeMap {
            bindings: Vec::new(),
        }
    }
}

fn find_struct_by_size<'a>(btf: &'a Btf, size: u32) -> Option<&'a BtfType> {
    if size == 0 {
        return None;
    }
    btf.types.iter().skip(1).find(|t| {
        (t.kind == BTF_KIND_STRUCT || t.kind == BTF_KIND_UNION)
            && t.size == size
            && !t.name.is_empty()
    })
}

fn find_enum_name_for_val(btf: &Btf, val: u64) -> Option<&str> {
    for t in btf.types.iter().skip(1) {
        if t.kind != BTF_KIND_ENUM {
            continue;
        }
        for e in &t.enums {
            if e.val as u64 == val {
                return Some(&e.name);
            }
        }
    }
    None
}

/// Parse a C-style unsigned integer (strtoul base 0): 0x hex, 0 octal, or
/// decimal. Returns (value, bytes_consumed).
fn parse_uint(s: &[u8]) -> (u64, usize) {
    let (radix, start) = if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        (16u32, 2usize)
    } else if !s.is_empty() && s[0] == b'0' {
        (8u32, 0usize)
    } else {
        (10u32, 0usize)
    };
    let mut i = start;
    let mut val: u64 = 0;
    let mut any = false;
    while i < s.len() {
        let c = s[i] as char;
        let d = match c.to_digit(radix) {
            Some(d) => d,
            None => break,
        };
        val = val.wrapping_mul(radix as u64).wrapping_add(d as u64);
        any = true;
        i += 1;
    }
    if !any {
        // Leading "0" with no more digits still consumed one char in octal.
        if radix == 8 && start == 0 && !s.is_empty() && s[0] == b'0' {
            return (0, 1);
        }
        return (0, 0);
    }
    (val, i)
}

/// Parse "syscall_name(arg0, arg1, ...) = ret". Returns (name, args).
fn parse_trace_line(line: &str) -> Option<(String, Vec<u64>)> {
    let line = line.trim_start();
    let paren = line.find('(')?;
    let name = line[..paren].to_string();
    let bytes = line.as_bytes();
    let mut p = paren + 1;
    let mut args: Vec<u64> = Vec::new();
    while p < bytes.len() && bytes[p] != b')' && args.len() < 6 {
        while p < bytes.len() && (bytes[p] as char).is_whitespace() {
            p += 1;
        }
        if p >= bytes.len() || bytes[p] == b')' {
            break;
        }
        let rest = &bytes[p..];
        let (val, consumed) = parse_uint(rest);
        if consumed == 0 {
            // Non-numeric token, e.g. AT_FDCWD.
            if rest.len() >= 8 && &rest[..8] == b"AT_FDCWD" {
                args.push((-100i64) as u64);
                p += 8;
            } else {
                // Skip to next ',' or ')'.
                let mut q = p;
                while q < bytes.len() && bytes[q] != b',' && bytes[q] != b')' {
                    q += 1;
                }
                args.push(0);
                p = q;
            }
        } else {
            args.push(val);
            p += consumed;
        }
        while p < bytes.len() && (bytes[p] as char).is_whitespace() {
            p += 1;
        }
        if p < bytes.len() && bytes[p] == b',' {
            p += 1;
        }
    }
    Some((name, args))
}

/// Resolve type bindings from a trace file + BTF. Returns the number of
/// bindings found, or -1 on error.
pub fn resolve(btf: &Btf, trace_path: &str, out: &mut TypeMap) -> i32 {
    let data = match std::fs::read_to_string(trace_path) {
        Ok(d) => d,
        Err(_) => return -1,
    };
    out.bindings.clear();

    for (idx, line) in data.lines().enumerate() {
        let lineno = (idx + 1) as i32;
        let (name, args) = match parse_trace_line(line) {
            Some(v) => v,
            None => continue,
        };

        // ioctl: arg0=fd, arg1=cmd, arg2=arg_ptr
        if name == "ioctl" && args.len() >= 3 {
            let cmd = args[1];
            let size = ioc_size(cmd);
            let dir = ioc_dir(cmd);
            if size > 0 && (dir & (IOC_WRITE | IOC_READ)) != 0 {
                // Enum lookup is heuristic-only in C (find_struct_by_cmd_name
                // always returns NULL); fall back to size matching.
                let _ = find_enum_name_for_val(btf, cmd);
                if let Some(st) = find_struct_by_size(btf, size) {
                    out.bindings.push(TypeBinding {
                        line: lineno,
                        syscall_nr: 16, // __NR_ioctl
                        syscall_name: "ioctl",
                        cmd,
                        arg_index: 2,
                        btf_type_id: st.id,
                        arg_size: st.size,
                        struct_name: st.name.clone(),
                    });
                }
            }
        }

        // setsockopt: arg0=fd, arg1=level, arg2=optname, arg3=optval, arg4=optlen
        if name == "setsockopt" && args.len() >= 5 {
            let optlen = args[4] as u32;
            if optlen > 0 && optlen <= 4096 {
                if let Some(st) = find_struct_by_size(btf, optlen) {
                    out.bindings.push(TypeBinding {
                        line: lineno,
                        syscall_nr: 54, // __NR_setsockopt
                        syscall_name: "setsockopt",
                        cmd: (args[1] << 16) | args[2],
                        arg_index: 3,
                        btf_type_id: st.id,
                        arg_size: st.size,
                        struct_name: st.name.clone(),
                    });
                }
            }
        }
    }

    out.bindings.len() as i32
}
