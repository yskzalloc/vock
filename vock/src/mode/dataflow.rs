//! kcov-dataflow coverage mode (`--mode dataflow`).
//!
//! KCOV answers *which* kernel code a program reached; kcov-dataflow answers
//! *with what*: `/sys/kernel/debug/kcov_dataflow` records, per traced task,
//! every instrumented function's arguments at entry (struct pointer
//! arguments expanded field by field from the compiler's debug info) and
//! its return value, in execution order. The kernel side is
//! `kernel/kcov_dataflow.c` with the clang `-fsanitize-coverage=trace-args`
//! and `trace-ret` passes (`CONFIG_KCOV_DATAFLOW_ARGS` / `_RET`); see
//! `Documentation/dev-tools/kcov-dataflow.rst` in that tree and DATAFLOW.md
//! here.
//!
//! Collection needs no LD_PRELOAD shim: a dataflow session is a property
//! of the task, not of the process image, and it survives `execve`. So the
//! parent opens the device, sizes the buffer (`KCOV_DF_INIT_TRACK`) and
//! forks; the child enables the session on the inherited fd
//! (`KCOV_DF_ENABLE`) and execs the target, which then runs entirely under
//! the session; when it exits the kernel tears the session down and the
//! parent maps the buffer and decodes it. With `--remote-handle H` a
//! second buffer is published for handle `H`, so kernel code that brackets
//! its work with `kcov_df_remote_start(H)` / `kcov_df_remote_stop()` (a
//! kworker running on the target's behalf) lands in `dataflow-remote.log`.
//!
//! Buffer layout (all u64 words, `include/uapi/linux/kcov_dataflow.h`):
//! `area[0]` is the number of record words that follow; each record is a
//! header word (bits 0-23 sequence, 28-31 type, 32-47 nvals, 48-55 size,
//! 56-63 argument index), the PC of the instrumented function with the
//! KASLR offset removed (like mainline KCOV), the traced pointer (or the
//! comparison type for CMP records), then `nvals` value words.
//!
//! Artifacts: `dataflow.log` (one record per line, machine format),
//! `dataflow.txt` (the symbolized call tree), `dataflow.html` (the same
//! tree as a page), `dataflow-remote.log` when a remote handle was given,
//! and `kerncov.log` holding the function PCs in sequence, which the normal
//! report turns into `coverage.html` / `srccov.log` like every other engine.

use crate::report;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

pub const DEVICE: &str = "/sys/kernel/debug/kcov_dataflow";
const DEVICE_C: &[u8] = b"/sys/kernel/debug/kcov_dataflow\0";

// ioctls from include/uapi/linux/kcov_dataflow.h ('d' == 0x64):
//   KCOV_DF_INIT_TRACK     _IOR('d', 1, unsigned long)
//   KCOV_DF_ENABLE         _IO('d', 100)
//   KCOV_DF_DISABLE        _IO('d', 101)
//   KCOV_DF_REMOTE_ENABLE  _IOW('d', 102, __u64)   (pointer to the handle)
//   KCOV_DF_REMOTE_DISABLE _IO('d', 103)
const KCOV_DF_INIT_TRACK: libc::c_ulong = 0x8008_6401;
const KCOV_DF_ENABLE: libc::c_ulong = 0x6464;
#[allow(dead_code)]
const KCOV_DF_DISABLE: libc::c_ulong = 0x6465;
const KCOV_DF_REMOTE_ENABLE: libc::c_ulong = 0x4008_6466;
const KCOV_DF_REMOTE_DISABLE: libc::c_ulong = 0x6467;

/// Buffer size in u64 words. The session records from the child's first
/// instrumented instruction (dynamic loader onward) until the buffer fills,
/// and the kernel buffer is linear, not a ring: once full, later records --
/// the ones the workload cares about -- are dropped. So the default is
/// generous, 8M words = 64 MiB (a record costs 3 words plus one per value;
/// a full `vfs-write` run under INSTRUMENT_ALL over a 9p share measured
/// ~5.2M words). `VOCK_DATAFLOW_WORDS` overrides it; the kernel caps the
/// buffer at 128 MiB (16M words). A run that reports "buffer full" needs a
/// larger buffer or a smaller target.
const DEFAULT_WORDS: usize = 8 << 20;
const MAX_WORDS: usize = (128 << 20) / 8;

const HDR_WORDS: usize = 3;
const TYPE_CMP: u8 = 0xC;
const TYPE_ENTRY: u8 = 0xE;
const TYPE_RET: u8 = 0xF;
/// Value word the kernel writes when the traced pointer or a field could
/// not be read.
pub const MAGIC_BAD: u64 = 0xBADA_DD85;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Entry,
    Ret,
    Cmp,
}

/// One decoded record. `pc` is the KASLR-canonical (link-time) address of
/// the instrumented function, as the kernel wrote it.
#[derive(Clone, Debug)]
pub struct Record {
    pub kind: Kind,
    pub seq: u32,
    pub pc: u64,
    /// ENTRY/RET: the traced pointer; CMP: the comparison type word.
    pub ptr: u64,
    pub arg_idx: u8,
    pub size: u8,
    pub vals: Vec<u64>,
}

/// Decode a buffer (`words[0]` = number of record words after it). A word
/// that does not parse as a record header, a record that would run past
/// the counted words, or one with no value word resyncs one word at a time,
/// mirroring the kernel selftests' parser.
pub fn parse_records(words: &[u64]) -> Vec<Record> {
    let mut out = Vec::new();
    if words.is_empty() {
        return out;
    }
    let total = words[0] as usize;
    let end = (1 + total).min(words.len());
    let mut pos = 1usize;
    while pos + HDR_WORDS <= end {
        let hdr = words[pos];
        let kind = match ((hdr >> 28) & 0xF) as u8 {
            TYPE_ENTRY => Kind::Entry,
            TYPE_RET => Kind::Ret,
            TYPE_CMP => Kind::Cmp,
            _ => {
                pos += 1;
                continue;
            }
        };
        let nvals = ((hdr >> 32) & 0xFFFF) as usize;
        if nvals == 0 || pos + HDR_WORDS + nvals > end {
            pos += 1;
            continue;
        }
        let pc = words[pos + 1];
        if pc == 0 {
            pos += 1;
            continue;
        }
        out.push(Record {
            kind,
            seq: (hdr & 0x00FF_FFFF) as u32,
            pc,
            ptr: words[pos + 2],
            arg_idx: ((hdr >> 56) & 0xFF) as u8,
            size: ((hdr >> 48) & 0xFF) as u8,
            vals: words[pos + HDR_WORDS..pos + HDR_WORDS + nvals].to_vec(),
        });
        pos += HDR_WORDS + nvals;
    }
    out
}

fn perror(msg: &str) {
    eprintln!("{msg}: {}", std::io::Error::last_os_error());
}

/// One kcov_dataflow fd with its buffer sized; mapped only when read.
struct Buffer {
    fd: libc::c_int,
    words: usize,
}

impl Buffer {
    fn open(words: usize) -> Option<Buffer> {
        let fd = unsafe {
            libc::open(
                DEVICE_C.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            eprintln!("dataflow: open {DEVICE}: {e}");
            match e.raw_os_error() {
                Some(libc::ENOENT) => eprintln!(
                    "  the kernel needs CONFIG_KCOV_DATAFLOW_ARGS=y / CONFIG_KCOV_DATAFLOW_RET=y \
                     (built with the kcov-dataflow clang) and debugfs mounted"
                ),
                Some(libc::EACCES) | Some(libc::EPERM) => eprintln!("  run vock as root"),
                _ => {}
            }
            return None;
        }
        if unsafe { libc::ioctl(fd, KCOV_DF_INIT_TRACK, words as libc::c_ulong) } != 0 {
            perror("dataflow: KCOV_DF_INIT_TRACK");
            unsafe { libc::close(fd) };
            return None;
        }
        Some(Buffer { fd, words })
    }

    /// Copy the buffer out through a fresh mapping. The kernel keeps the
    /// area alive as long as this fd is open, so this is valid after the
    /// traced task has exited and its session was torn down.
    fn read(&self) -> Option<Vec<u64>> {
        let len = self.words * std::mem::size_of::<u64>();
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            perror("dataflow: mmap");
            return None;
        }
        let words = unsafe { std::slice::from_raw_parts(p as *const u64, self.words) }.to_vec();
        unsafe { libc::munmap(p, len) };
        Some(words)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn buffer_words() -> usize {
    std::env::var("VOCK_DATAFLOW_WORDS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|w| w.clamp(2, MAX_WORDS))
        .unwrap_or(DEFAULT_WORDS)
}

// ─── KASLR ───────────────────────────────────────────────────────────────────

/// `_text` of the running kernel from /proc/kallsyms (needs root or
/// kptr_restrict=0), 0 when hidden.
fn runtime_text() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/kallsyms") else { return 0 };
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(addr), Some(_), Some(name), module) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if name == "_text" && module.is_none() {
            return u64::from_str_radix(addr, 16).unwrap_or(0);
        }
    }
    0
}

/// Link-time `_text`: from the vmlinux symbol table when there is one,
/// else the architecture's default (x86_64 `__START_KERNEL`, arm64
/// `KIMAGE_VADDR`).
fn linktime_text(vmlinux: Option<&str>) -> u64 {
    if let Some(v) = vmlinux {
        if std::path::Path::new(v).is_file() {
            if let Some(a) = report::resolve::symbol_address(v, "_text") {
                return a;
            }
        }
    }
    if cfg!(target_arch = "x86_64") {
        0xffff_ffff_8100_0000
    } else if cfg!(target_arch = "aarch64") {
        0xffff_8000_8000_0000
    } else {
        0
    }
}

/// The offset the kernel subtracted from every recorded PC: runtime `_text`
/// minus link-time `_text`. Added back for the per-boot logs and kallsyms
/// lookups; DWARF symbolization uses the canonical PCs directly.
fn kaslr_offset(vmlinux: Option<&str>) -> u64 {
    let run = runtime_text();
    let link = linktime_text(vmlinux);
    if run == 0 || link == 0 {
        if run == 0 {
            eprintln!(
                "dataflow: _text not in /proc/kallsyms (kptr_restrict?); logs keep link-time PCs"
            );
        }
        return 0;
    }
    let off = run.wrapping_sub(link);
    if off & 0x1f_ffff != 0 {
        eprintln!(
            "dataflow: warning: KASLR offset 0x{off:x} is not 2 MiB aligned (vmlinux from \
             another build?)"
        );
    }
    off
}

// ─── symbolization ───────────────────────────────────────────────────────────

/// What is known about one instrumented function.
#[derive(Clone, Default)]
struct Sym {
    func: String,
    /// `file:line`, kernel-relative, or empty.
    loc: String,
}

/// Resolve every distinct PC: DWARF (in-process, link-time addresses need
/// no KASLR handling) with a vmlinux, else kallsyms with the per-boot PCs.
fn symbolize(
    pcs: &[u64],
    vmlinux: Option<&str>,
    kernel_src: &str,
    off: u64,
) -> HashMap<u64, Sym> {
    let mut m = HashMap::with_capacity(pcs.len());
    if let Some(v) = vmlinux {
        let res = report::resolve::symbolize(v, pcs);
        for (&pc, (func, loc)) in pcs.iter().zip(res.iter()) {
            let mut s = Sym::default();
            if func != "??" && !func.is_empty() {
                s.func = report::resolve::canonical_function(func).to_string();
            }
            if !loc.starts_with("??") {
                if let Some(colon) = loc.rfind(':') {
                    let line = loc[colon + 1..].split_whitespace().next().unwrap_or("0");
                    if line != "0" && line != "?" {
                        s.loc = format!(
                            "{}:{}",
                            report::resolve::rel_kernel_path(&loc[..colon], kernel_src),
                            line
                        );
                    }
                }
            }
            m.insert(pc, s);
        }
    } else {
        let strs: Vec<String> = pcs
            .iter()
            .map(|&pc| format!("0x{:x}", pc.wrapping_add(off)))
            .collect();
        let res = report::btf::resolve_pcs(&strs, "/proc/kallsyms");
        for (&pc, (_, name)) in pcs.iter().zip(res.iter()) {
            m.insert(
                pc,
                Sym {
                    func: name.clone().unwrap_or_default(),
                    loc: String::new(),
                },
            );
        }
    }
    m
}

fn fmt_val(v: u64) -> String {
    if v == MAGIC_BAD {
        "FAULT".to_string()
    } else {
        format!("0x{v:x}")
    }
}

fn fmt_vals(vals: &[u64]) -> String {
    if vals.len() == 1 {
        fmt_val(vals[0])
    } else {
        format!(
            "{{{}}}",
            vals.iter().map(|&v| fmt_val(v)).collect::<Vec<_>>().join(", ")
        )
    }
}

fn func_name(pc: u64, syms: &HashMap<u64, Sym>) -> String {
    match syms.get(&pc) {
        Some(s) if !s.func.is_empty() => s.func.clone(),
        _ => format!("0x{pc:x}"),
    }
}

/// Render records as an indented call tree, one line per call:
/// `<file:line>   <indent>[<ret> = ]<func>(<args>)`. Consecutive ENTRY
/// records of one PC are that call's arguments (ordered by index, the
/// pass emits dead-argument traces last); a RET closes the innermost open
/// call with that PC, popping calls that returned without a record (void,
/// or not instrumented at exit) on the way.
fn render_tree(records: &[Record], syms: &HashMap<u64, Sym>) -> Vec<String> {
    let width = records
        .iter()
        .filter_map(|r| syms.get(&r.pc))
        .map(|s| s.loc.len())
        .max()
        .unwrap_or(0)
        .max(10);
    let loc_of = |pc: u64| -> String {
        let l = syms.get(&pc).map(|s| s.loc.as_str()).unwrap_or("");
        format!("{l:>width$}")
    };
    let mut lines = Vec::new();
    // (pc, args string)
    let mut stack: Vec<(u64, String)> = Vec::new();
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        match r.kind {
            Kind::Cmp => {
                i += 1;
            }
            Kind::Entry => {
                let pc = r.pc;
                let mut args: Vec<(u8, String)> = Vec::new();
                while i < records.len() && records[i].kind == Kind::Entry && records[i].pc == pc {
                    args.push((records[i].arg_idx, fmt_vals(&records[i].vals)));
                    i += 1;
                }
                args.sort_by_key(|(idx, _)| *idx);
                let s = args.into_iter().map(|(_, a)| a).collect::<Vec<_>>().join(", ");
                stack.push((pc, s));
            }
            Kind::Ret => {
                // Calls that never reported a return: close them first.
                while stack.last().map(|(pc, _)| *pc != r.pc).unwrap_or(false) {
                    let (pc, args) = stack.pop().unwrap();
                    let indent = "  ".repeat(stack.len());
                    lines.push(format!(
                        "{}   {indent}{}({args})",
                        loc_of(pc),
                        func_name(pc, syms)
                    ));
                }
                let ret = if r.size == 0 {
                    String::new()
                } else {
                    format!("{} = ", fmt_vals(&r.vals))
                };
                match stack.pop() {
                    Some((pc, args)) => {
                        let indent = "  ".repeat(stack.len());
                        lines.push(format!(
                            "{}   {indent}{ret}{}({args})",
                            loc_of(pc),
                            func_name(pc, syms)
                        ));
                    }
                    None => {
                        lines.push(format!(
                            "{}   {ret}{}()",
                            loc_of(r.pc),
                            func_name(r.pc, syms)
                        ));
                    }
                }
                i += 1;
            }
        }
    }
    while let Some((pc, args)) = stack.pop() {
        let indent = "  ".repeat(stack.len());
        lines.push(format!(
            "{}   {indent}{}({args})",
            loc_of(pc),
            func_name(pc, syms)
        ));
    }
    lines
}

/// Machine-format log: one record per line, first token the per-boot PC so
/// the file is also valid `vock report --log` input.
fn write_log(path: &str, records: &[Record], off: u64) {
    let Ok(f) = std::fs::File::create(path) else {
        perror(&format!("dataflow: create {path}"));
        return;
    };
    let mut w = std::io::BufWriter::new(f);
    for r in records {
        let vals = r
            .vals
            .iter()
            .map(|v| format!("0x{v:x}"))
            .collect::<Vec<_>>()
            .join(",");
        let _ = match r.kind {
            Kind::Entry => writeln!(
                w,
                "0x{:x} ENTRY seq={} arg={} size={} ptr=0x{:x} vals={vals}",
                r.pc.wrapping_add(off),
                r.seq,
                r.arg_idx,
                r.size,
                r.ptr
            ),
            Kind::Ret => writeln!(
                w,
                "0x{:x} RET seq={} size={} ptr=0x{:x} vals={vals}",
                r.pc.wrapping_add(off),
                r.seq,
                r.size,
                r.ptr
            ),
            Kind::Cmp => writeln!(
                w,
                "0x{:x} CMP seq={} type=0x{:x} vals={vals}",
                r.pc.wrapping_add(off),
                r.seq,
                r.ptr
            ),
        };
    }
    let _ = w.flush();
}

/// The function PCs in sequence, the input of the ordinary coverage report.
fn write_kerncov(path: &str, records: &[Record], off: u64) {
    let Ok(f) = std::fs::File::create(path) else {
        perror(&format!("dataflow: create {path}"));
        return;
    };
    let mut w = std::io::BufWriter::new(f);
    for r in records {
        if r.kind != Kind::Cmp {
            let _ = writeln!(w, "0x{:x}", r.pc.wrapping_add(off));
        }
    }
    let _ = w.flush();
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn write_html(path: &str, title: &str, lines: &[String], summary: &str) {
    let Ok(f) = std::fs::File::create(path) else {
        perror(&format!("dataflow: create {path}"));
        return;
    };
    let mut w = std::io::BufWriter::new(f);
    let _ = write!(
        w,
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{}</title>\n\
         <style>body{{font-family:sans-serif;margin:1em 2em}}pre{{font-family:monospace;\
         font-size:12px;line-height:1.35}}h1{{font-size:1.3em}}.s{{color:#555}}</style>\n\
         </head><body>\n<h1>{}</h1>\n<p class=\"s\">{}</p>\n<pre>",
        esc(title),
        esc(title),
        esc(summary)
    );
    for l in lines {
        let _ = writeln!(w, "{}", esc(l));
    }
    let _ = write!(w, "</pre>\n</body></html>\n");
    let _ = w.flush();
}

/// Per-function record counts, most recorded first.
fn per_function(records: &[Record], syms: &HashMap<u64, Sym>) -> Vec<(String, usize, usize)> {
    let mut m: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
    for r in records {
        let e = m.entry(r.pc).or_default();
        match r.kind {
            Kind::Entry => e.0 += 1,
            Kind::Ret => e.1 += 1,
            Kind::Cmp => {}
        }
    }
    let mut v: Vec<(String, usize, usize)> = m
        .into_iter()
        .map(|(pc, (e, r))| (func_name(pc, syms), e, r))
        .collect();
    v.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)).then(a.0.cmp(&b.0)));
    v
}

fn ctx(v: i32) -> i32 {
    if v >= 0 {
        v
    } else {
        3
    }
}

/// Trace `cmd` under a kcov_dataflow session and write the artifacts.
/// Returns the target's exit status.
#[allow(clippy::too_many_arguments)]
pub fn run(
    cmd: &[String],
    kernel_src: Option<&str>,
    vmlinux: Option<&str>,
    filter: Option<&str>,
    btf: bool,
    ctx_after: i32,
    ctx_before: i32,
    ordered: bool,
    remote_handle: Option<u64>,
) -> i32 {
    let words = buffer_words();
    let vm_path = report::vmlinux_path(kernel_src, vmlinux);
    let have_vmlinux = !btf && std::path::Path::new(&vm_path).is_file();
    if have_vmlinux && std::env::var_os("VOCK_NO_PREWARM").is_none() {
        report::resolve::prewarm(&vm_path);
    }

    report::timing::mark("dataflow: start");
    let Some(local) = Buffer::open(words) else {
        return 1;
    };
    let remote = match remote_handle {
        Some(h) => {
            let Some(b) = Buffer::open(words) else {
                return 1;
            };
            let handle: u64 = h;
            if unsafe { libc::ioctl(b.fd, KCOV_DF_REMOTE_ENABLE, &handle as *const u64) } != 0 {
                perror(&format!("dataflow: KCOV_DF_REMOTE_ENABLE(0x{h:x})"));
                eprintln!(
                    "  the handle must be a kcov_remote_handle() value that is not already \
                     published"
                );
                return 1;
            }
            eprintln!("dataflow: remote buffer published for handle 0x{h:x}");
            Some(b)
        }
        None => None,
    };

    report::timing::mark("dataflow: fork target");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: the session belongs to this task from here on, through
        // execve and until exit; the fd itself is close-on-exec.
        if unsafe { libc::ioctl(local.fd, KCOV_DF_ENABLE, 0) } != 0 {
            perror("dataflow: KCOV_DF_ENABLE");
            unsafe { libc::_exit(125) };
        }
        crate::exec::execvp(cmd);
        eprintln!("target: execvp failed");
        unsafe { libc::_exit(127) };
    } else if pid < 0 {
        perror("target: fork failed");
        return 1;
    }

    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        perror("target: waitpid failed");
        return 1;
    }
    report::timing::mark("dataflow: target exited");
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 125 {
        eprintln!("dataflow: the target could not enable its session");
        return 1;
    }

    // Local: the exiting task tore its session down; the words are final.
    let Some(local_words) = local.read() else {
        return 1;
    };
    let mut records = parse_records(&local_words);
    let local_total = local_words[0];
    drop(local);

    let mut remote_records = Vec::new();
    if let Some(b) = remote.as_ref() {
        unsafe { libc::ioctl(b.fd, KCOV_DF_REMOTE_DISABLE, 0) };
        if let Some(w) = b.read() {
            remote_records = parse_records(&w);
        }
    }
    drop(remote);
    report::timing::mark("dataflow: buffers decoded");

    let off = kaslr_offset(if have_vmlinux { Some(&vm_path) } else { None });
    let kernel_src_abs = kernel_src
        .map(|k| {
            std::fs::canonicalize(k)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| k.to_string())
        })
        .unwrap_or_default();

    write_log("dataflow.log", &records, off);
    if remote_handle.is_some() {
        write_log("dataflow-remote.log", &remote_records, off);
    }
    records.append(&mut remote_records);
    write_kerncov("kerncov.log", &records, off);

    let mut pcs: Vec<u64> = records.iter().map(|r| r.pc).collect();
    pcs.sort_unstable();
    pcs.dedup();
    let syms = symbolize(
        &pcs,
        if have_vmlinux { Some(&vm_path) } else { None },
        &kernel_src_abs,
        off,
    );
    report::timing::mark("dataflow: symbolized");

    let entries = records.iter().filter(|r| r.kind == Kind::Entry).count();
    let rets = records.iter().filter(|r| r.kind == Kind::Ret).count();
    let cmps = records.iter().filter(|r| r.kind == Kind::Cmp).count();
    let mut tree = render_tree(&records, &syms);
    if let Some(kw) = filter {
        tree.retain(|l| l.contains(kw));
    }
    let summary = format!(
        "{} records ({entries} ENTRY, {rets} RET, {cmps} CMP) in {} functions; \
         buffer {} of {} words used; kaslr offset 0x{off:x}",
        records.len(),
        pcs.len(),
        local_total,
        words
    );

    {
        let mut out = String::new();
        out.push_str("# vock --mode dataflow: ");
        out.push_str(&cmd.join(" "));
        out.push('\n');
        out.push_str(&format!("# {summary}\n"));
        out.push_str(
            "# <file:line>   [<return> = ]<function>(<arg0>, <arg1>, ...); {a, b} is an \
             expanded struct, FAULT an unreadable field\n",
        );
        for l in &tree {
            out.push_str(l);
            out.push('\n');
        }
        if let Err(e) = std::fs::write("dataflow.txt", out) {
            eprintln!("dataflow: write dataflow.txt: {e}");
        }
    }
    write_html(
        "dataflow.html",
        &format!("vock dataflow: {}", cmd.join(" ")),
        &tree,
        &summary,
    );

    // Terminal: the numbers, the busiest functions, the head of the tree.
    println!("[vock] dataflow: {summary}");
    if local_total as usize + 1 >= words {
        println!(
            "[vock] dataflow: buffer full, later records were dropped; raise VOCK_DATAFLOW_WORDS"
        );
    }
    let top = per_function(&records, &syms);
    if !top.is_empty() {
        println!("  most recorded functions (entries / returns):");
        for (name, e, r) in top.iter().take(8) {
            let n: String = name.chars().take(70).collect();
            println!("    {e:6} / {r:<6} {n}");
        }
    }
    if !tree.is_empty() {
        println!("  call tree (first lines; dataflow.txt has all {}):", tree.len());
        for l in tree.iter().take(24) {
            let t: String = l.chars().take(120).collect();
            println!("    {t}");
        }
    }
    println!(
        "[vock] dataflow.log, dataflow.txt, dataflow.html written; kerncov.log holds the \
         function PCs"
    );
    report::timing::mark("dataflow: artifacts written");

    // The ordinary coverage report over the function PCs, so the source
    // excerpts, srccov twin and coverage.html come out like every engine.
    let opts = report::Options {
        kernel_src: kernel_src.map(String::from),
        vmlinux: vmlinux.map(String::from),
        log: "kerncov.log".to_string(),
        filter: filter.map(String::from),
        quiet: false,
        ctx_after: ctx(ctx_after),
        ctx_before: ctx(ctx_before),
        output: "coverage.html".to_string(),
        btf,
        ordered,
        parts: Vec::new(),
    };
    report::run(&opts);

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(kind: u8, nvals: u64, size: u64, arg: u64, seq: u64) -> u64 {
        seq | ((kind as u64) << 28) | (nvals << 32) | (size << 48) | (arg << 56)
    }

    #[test]
    fn ioctl_numbers_match_uapi() {
        // _IOR('d', 1, unsigned long) / _IO('d', 100..103) / _IOW('d', 102, __u64)
        assert_eq!(KCOV_DF_INIT_TRACK, (2 << 30) | (8 << 16) | (0x64 << 8) | 1);
        assert_eq!(KCOV_DF_ENABLE, (0x64 << 8) | 100);
        assert_eq!(KCOV_DF_DISABLE, (0x64 << 8) | 101);
        assert_eq!(KCOV_DF_REMOTE_ENABLE, (1 << 30) | (8 << 16) | (0x64 << 8) | 102);
        assert_eq!(KCOV_DF_REMOTE_DISABLE, (0x64 << 8) | 103);
    }

    #[test]
    fn parses_entry_struct_ret_and_skips_cmp_garbage() {
        let pc = 0xffff_ffff_8123_4560u64;
        let mut w = vec![0u64];
        // ENTRY arg0, 4-field struct
        w.extend([hdr(TYPE_ENTRY, 4, 8, 0, 1), pc, 0xdead, 1, 2, 3, MAGIC_BAD]);
        // ENTRY arg1 scalar
        w.extend([hdr(TYPE_ENTRY, 1, 8, 1, 2), pc, 0xbeef, 0x100]);
        // CMP
        w.extend([hdr(TYPE_CMP, 2, 0, 0, 3), pc + 8, 3, 7, 9]);
        // garbage word, then RET
        w.push(0x1234);
        w.extend([hdr(TYPE_RET, 1, 4, 0, 4), pc, 0, 0xffff_fff2]);
        w[0] = (w.len() - 1) as u64;
        let recs = parse_records(&w);
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[0].kind, Kind::Entry);
        assert_eq!(recs[0].vals, vec![1, 2, 3, MAGIC_BAD]);
        assert_eq!(recs[0].arg_idx, 0);
        assert_eq!(recs[1].vals, vec![0x100]);
        assert_eq!(recs[1].arg_idx, 1);
        assert_eq!(recs[2].kind, Kind::Cmp);
        assert_eq!(recs[3].kind, Kind::Ret);
        assert_eq!(recs[3].size, 4);
        assert_eq!(recs[3].seq, 4);
    }

    #[test]
    fn tree_orders_args_and_closes_calls() {
        let f = 0x1000u64;
        let g = 0x2000u64;
        let rec = |kind, seq, pc, arg_idx, size, vals: Vec<u64>| Record {
            kind,
            seq,
            pc,
            ptr: 0,
            arg_idx,
            size,
            vals,
        };
        let recs = vec![
            rec(Kind::Entry, 1, f, 1, 8, vec![0x22]),
            rec(Kind::Entry, 2, f, 0, 8, vec![0x11, 0x33]),
            rec(Kind::Entry, 3, g, 0, 4, vec![7]),
            rec(Kind::Ret, 4, f, 0, 8, vec![0x55]),
        ];
        let mut syms = HashMap::new();
        syms.insert(f, Sym { func: "f".into(), loc: "fs/a.c:10".into() });
        syms.insert(g, Sym { func: "g".into(), loc: String::new() });
        let lines = render_tree(&recs, &syms);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("  g(0x7)"), "{}", lines[0]);
        assert!(lines[1].ends_with("0x55 = f({0x11, 0x33}, 0x22)"), "{}", lines[1]);
        assert!(lines[1].contains("fs/a.c:10"));
    }
}
