//! High-value pseudo-syscalls (`syz_*`) for arena-based programs.
//!
//! Port of the parts of syzkaller's `executor/common_linux.h` that reproducers
//! most often depend on. These complement the USB raw-gadget interpreter in
//! [`crate::pseudo_syscalls`]: that module drives its own inline-hex program
//! form, whereas everything here takes arguments that have already been
//! materialised into the data arena by [`crate::prog_decode`], so a pointer
//! argument is a real, dereferenceable address.
//!
//! Anything not implemented returns `-ENOSYS` rather than silently succeeding,
//! so a reproducer that needs it fails visibly instead of "passing" wrongly.

#![allow(dead_code)]

use crate::prog_decode::{Arena, Call, Ctx, ARENA_SIZE, DATA_OFFSET};

/// True when `addr` points inside the data arena and so may be dereferenced.
fn in_arena(addr: i64) -> bool {
    let a = addr as u64;
    a >= DATA_OFFSET && a < DATA_OFFSET + ARENA_SIZE as u64
}

/// Read a NUL-terminated string from the arena.
fn cstr(addr: i64) -> Option<String> {
    if !in_arena(addr) {
        return None;
    }
    let max = (DATA_OFFSET + ARENA_SIZE as u64 - addr as u64) as usize;
    let p = addr as *const u8;
    let mut n = 0usize;
    while n < max.min(4096) {
        if unsafe { *p.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(p, n) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn ok(fd: libc::c_int) -> (i64, i32) {
    if fd < 0 {
        (-1, unsafe { *libc::__errno_location() })
    } else {
        (fd as i64, 0)
    }
}

fn enosys() -> (i64, i32) {
    (-1, libc::ENOSYS)
}

fn open_path(path: &str, flags: libc::c_int) -> (i64, i32) {
    let Ok(c) = std::ffi::CString::new(path) else {
        return (-1, libc::EINVAL);
    };
    ok(unsafe { libc::open(c.as_ptr(), flags) })
}

/// `syz_open_dev(dev, id, id2)` (common_linux.h:2833). Two forms: when `dev`
/// is the char/block marker 0xc/0xb it names `/dev/char/<major>:<minor>`,
/// otherwise it is a path in which each `#` is replaced by one digit of `id`.
/// `id2` carries the open flags.
fn syz_open_dev(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    if args[0] == 0xc || args[0] == 0xb {
        let kind = if args[0] == 0xc { "char" } else { "block" };
        return open_path(
            &format!("/dev/{kind}/{}:{}", args[1], args[2]),
            libc::O_RDWR | libc::O_NONBLOCK,
        );
    }
    let Some(path) = cstr(args[0]) else {
        return (-1, libc::EFAULT);
    };
    // Upstream substitutes a single digit per '#', not the whole number.
    let mut id = args[1];
    let path: String = path
        .chars()
        .map(|c| {
            if c == '#' {
                let d = char::from_digit((id % 10) as u32, 10).unwrap_or('0');
                id /= 10;
                d
            } else {
                c
            }
        })
        .collect();
    // O_CREAT is masked off upstream so a reproducer cannot create the node.
    let flags = (args[2] as libc::c_int) & !libc::O_CREAT;
    let flags = if flags == 0 { libc::O_RDWR | libc::O_NONBLOCK } else { flags };
    open_path(&path, flags)
}

/// `syz_open_procfs(pid, file)` (common_linux.h:2863): 0 → `/proc/self`,
/// -1 → `/proc/thread-self`, otherwise `/proc/self/task/<tid>`. Upstream tries
/// O_RDWR then falls back to O_RDONLY, which most procfs files require.
fn syz_open_procfs(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let Some(file) = cstr(args[1]) else {
        return (-1, libc::EFAULT);
    };
    let base = match args[0] {
        0 => "/proc/self".to_string(),
        -1 => "/proc/thread-self".to_string(),
        tid => format!("/proc/self/task/{tid}"),
    };
    let path = format!("{base}/{file}");
    let r = open_path(&path, libc::O_RDWR);
    if r.0 < 0 {
        return open_path(&path, libc::O_RDONLY);
    }
    r
}

/// `syz_open_pts(fd, flags)` — allocate a pty slave for the master `fd`.
fn syz_open_pts(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let master = args[0] as libc::c_int;
    let mut idx: libc::c_int = 0;
    // TIOCGPTN
    if unsafe { libc::ioctl(master, 0x8004_5430, &mut idx) } < 0 {
        return (-1, unsafe { *libc::__errno_location() });
    }
    open_path(&format!("/dev/pts/{idx}"), args[1] as libc::c_int)
}

/// `syz_init_net_socket(domain, type, proto)` — a socket in the init network
/// namespace. Entering that namespace needs privilege; without it we fall back
/// to a socket in the current namespace, which is what the reproducer would
/// otherwise have created anyway.
fn syz_init_net_socket(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let (d, t, p) = (args[0] as libc::c_int, args[1] as libc::c_int, args[2] as libc::c_int);
    let netns = unsafe {
        libc::open(b"/proc/1/ns/net\0".as_ptr() as *const libc::c_char, libc::O_RDONLY)
    };
    if netns < 0 {
        return ok(unsafe { libc::socket(d, t, p) });
    }
    let old = unsafe {
        libc::open(b"/proc/self/ns/net\0".as_ptr() as *const libc::c_char, libc::O_RDONLY)
    };
    let entered = unsafe { libc::setns(netns, libc::CLONE_NEWNET) } == 0;
    let fd = unsafe { libc::socket(d, t, p) };
    let err = unsafe { *libc::__errno_location() };
    if entered && old >= 0 {
        unsafe { libc::setns(old, libc::CLONE_NEWNET) };
    }
    unsafe {
        libc::close(netns);
        if old >= 0 {
            libc::close(old);
        }
        *libc::__errno_location() = err;
    }
    ok(fd)
}

/// `syz_create_resource(val)` — syzkaller's identity resource constructor.
fn syz_create_resource(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    (args[0], 0)
}

/// `syz_memcpy_off(dst, off, src, src_off, n)` — copy within the arena.
fn syz_memcpy_off(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let dst = args[0].wrapping_add(args[1]);
    let src = args[2].wrapping_add(args[3]);
    let n = args[4].max(0) as usize;
    if n == 0 {
        return (0, 0);
    }
    if !in_arena(dst) || !in_arena(src) || n > ARENA_SIZE {
        return (-1, libc::EFAULT);
    }
    // Check the last byte too, not just the start of each region.
    if !in_arena(dst.wrapping_add(n as i64 - 1)) || !in_arena(src.wrapping_add(n as i64 - 1)) {
        return (-1, libc::EFAULT);
    }
    unsafe { std::ptr::copy(src as *const u8, dst as *mut u8, n) };
    (0, 0)
}

/// `syz_genetlink_get_family_id(name, fd)` — resolve a generic netlink family
/// name to its numeric id via `CTRL_CMD_GETFAMILY`.
fn syz_genetlink_get_family_id(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    const NETLINK_GENERIC: libc::c_int = 16;
    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;

    let Some(name) = cstr(args[0]) else {
        return (-1, libc::EFAULT);
    };
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
    if fd < 0 {
        return (-1, unsafe { *libc::__errno_location() });
    }

    // nlmsghdr(16) + genlmsghdr(4) + nlattr(4) + name
    let namelen = name.len() + 1;
    let attrlen = 4 + namelen;
    let total = 16 + 4 + attrlen;
    let mut buf = vec![0u8; (total + 3) & !3];
    buf[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    buf[6..8].copy_from_slice(&1u16.to_ne_bytes()); // NLM_F_REQUEST
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    buf[16] = CTRL_CMD_GETFAMILY;
    buf[17] = 1; // version
    buf[20..22].copy_from_slice(&(attrlen as u16).to_ne_bytes());
    buf[22..24].copy_from_slice(&CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
    buf[24..24 + name.len()].copy_from_slice(name.as_bytes());

    let sent = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if sent < 0 {
        let e = unsafe { *libc::__errno_location() };
        unsafe { libc::close(fd) };
        return (-1, e);
    }
    let mut rsp = vec![0u8; 4096];
    let n = unsafe { libc::read(fd, rsp.as_mut_ptr() as *mut libc::c_void, rsp.len()) };
    unsafe { libc::close(fd) };
    if n < 20 {
        return (-1, libc::EINVAL);
    }
    // Walk the attributes following nlmsghdr + genlmsghdr.
    let n = n as usize;
    let mut off = 20usize;
    while off + 4 <= n {
        let alen = u16::from_ne_bytes([rsp[off], rsp[off + 1]]) as usize;
        let atype = u16::from_ne_bytes([rsp[off + 2], rsp[off + 3]]);
        if alen < 4 || off + alen > n {
            break;
        }
        if atype == CTRL_ATTR_FAMILY_ID && alen >= 6 {
            let id = u16::from_ne_bytes([rsp[off + 4], rsp[off + 5]]);
            return (id as i64, 0);
        }
        off += (alen + 3) & !3;
    }
    (-1, libc::ENOENT)
}

/// `syz_io_uring_setup(entries, params, ...)` — create a ring. The submission
/// and completion helpers need the mapped rings, which a reproducer normally
/// obtains through follow-up `mmap` calls in the program itself.
fn syz_io_uring_setup(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    const SYS_IO_URING_SETUP: i64 = 425;
    let entries = args[0];
    let params = args[1];
    if !in_arena(params) {
        return (-1, libc::EFAULT);
    }
    unsafe {
        *libc::__errno_location() = 0;
        let fd = libc::syscall(SYS_IO_URING_SETUP, entries, params);
        if fd < 0 {
            return (-1, *libc::__errno_location());
        }
        (fd, 0)
    }
}

/// `syz_emit_ethernet(len, packet, ...)` — inject a frame into the tap device
/// the reproducer's network setup created.
fn syz_emit_ethernet(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let len = args[0].max(0) as usize;
    let buf = args[1];
    // Validate the end of the frame as well as its start.
    if !in_arena(buf) || len == 0 || len > 64 << 10 || !in_arena(buf.wrapping_add(len as i64 - 1)) {
        return (-1, libc::EFAULT);
    }
    let fd = unsafe {
        libc::open(b"/dev/net/tun\0".as_ptr() as *const libc::c_char, libc::O_RDWR)
    };
    if fd < 0 {
        return (-1, unsafe { *libc::__errno_location() });
    }
    // struct ifreq { char name[16]; short flags; ... }
    let mut ifr = [0u8; 40];
    ifr[..7].copy_from_slice(b"syz_tun");
    // IFF_TAP | IFF_NO_PI
    ifr[16..18].copy_from_slice(&0x1002u16.to_ne_bytes());
    // TUNSETIFF
    if unsafe { libc::ioctl(fd, 0x4004_54ca, ifr.as_mut_ptr()) } < 0 {
        let e = unsafe { *libc::__errno_location() };
        unsafe { libc::close(fd) };
        return (-1, e);
    }
    let n = unsafe { libc::write(fd, buf as *const libc::c_void, len) };
    let e = unsafe { *libc::__errno_location() };
    unsafe { libc::close(fd) };
    if n < 0 {
        (-1, e)
    } else {
        (n as i64, 0)
    }
}

/// Read `len` bytes out of the arena.
fn arena_slice(addr: i64, len: usize) -> Option<&'static [u8]> {
    if len == 0 || !in_arena(addr) || !in_arena(addr.wrapping_add(len as i64 - 1)) {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
}

/// Write an image to a temporary file and attach it to a free loop device.
/// Returns the device path and its open fd; the caller closes the fd.
fn attach_loop(img: &[u8]) -> Option<(String, libc::c_int)> {
    const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
    const LOOP_SET_FD: libc::c_ulong = 0x4C00;

    let path = format!("/tmp/vock-img-{}", unsafe { libc::getpid() });
    std::fs::write(&path, img).ok()?;
    let ctl = unsafe {
        libc::open(b"/dev/loop-control\0".as_ptr() as *const libc::c_char, libc::O_RDWR)
    };
    if ctl < 0 {
        return None;
    }
    let idx = unsafe { libc::ioctl(ctl, LOOP_CTL_GET_FREE) };
    unsafe { libc::close(ctl) };
    if idx < 0 {
        return None;
    }
    let loop_path = format!("/dev/loop{idx}");
    let lc = std::ffi::CString::new(loop_path.clone()).ok()?;
    let lfd = unsafe { libc::open(lc.as_ptr(), libc::O_RDWR) };
    if lfd < 0 {
        return None;
    }
    let ic = std::ffi::CString::new(path).ok()?;
    let ifd = unsafe { libc::open(ic.as_ptr(), libc::O_RDWR) };
    if ifd < 0 {
        unsafe { libc::close(lfd) };
        return None;
    }
    let r = unsafe { libc::ioctl(lfd, LOOP_SET_FD, ifd as libc::c_ulong) };
    unsafe { libc::close(ifd) };
    if r < 0 {
        unsafe { libc::close(lfd) };
        return None;
    }
    Some((loop_path, lfd))
}

/// Detach a loop device (`reset_loop_device`, common_linux.h:3443). Without
/// this a --repeat run burns one /dev/loopN per iteration until none are left.
fn detach_loop(lfd: libc::c_int) {
    const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
    unsafe {
        libc::ioctl(lfd, LOOP_CLR_FD);
        libc::close(lfd);
    }
    let path = format!("/tmp/vock-img-{}", unsafe { libc::getpid() });
    let _ = std::fs::remove_file(path);
}

/// `syz_mount_image(fs, dir, flags, opts, chdir, size, img)` —
/// common_linux.h:3523. `img` points at the decompressed image (the parser has
/// already inflated the `"$<base64>"` blob) and `size` is its length.
fn syz_mount_image(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    let (Some(fs), Some(dir)) = (cstr(args[0]), cstr(args[1])) else {
        return (-1, libc::EFAULT);
    };
    let size = args[5].max(0) as usize;
    let Some(img) = arena_slice(args[6], size.min(crate::prog_decode::MAX_IMAGE)) else {
        return (-1, libc::EINVAL);
    };
    let Some((loop_path, lfd)) = attach_loop(img) else {
        return (-1, libc::ENODEV);
    };
    let _ = std::fs::create_dir_all(&dir);
    let (Ok(src), Ok(tgt), Ok(fstype)) = (
        std::ffi::CString::new(loop_path),
        std::ffi::CString::new(dir.clone()),
        std::ffi::CString::new(fs),
    ) else {
        detach_loop(lfd);
        return (-1, libc::EINVAL);
    };
    let opts = cstr(args[3]).unwrap_or_default();
    let copts = std::ffi::CString::new(opts).unwrap_or_default();
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            args[2] as libc::c_ulong,
            copts.as_ptr() as *const libc::c_void,
        )
    };
    let e = unsafe { *libc::__errno_location() };
    if r < 0 {
        detach_loop(lfd);
        return (-1, e);
    }
    // chdir into the mount point when the reproducer asked for it.
    if args[4] != 0 {
        if let Ok(c) = std::ffi::CString::new(dir) {
            unsafe { libc::chdir(c.as_ptr()) };
        }
    }
    // The loop fd stays open for the lifetime of the mount; closing it here
    // would not detach the device while it is in use.
    unsafe { libc::close(lfd) };
    (0, 0)
}

/// `syz_read_part_table(size, img)` — force a partition-table re-scan of an
/// image attached to a loop device (common_linux.h).
fn syz_read_part_table(args: &[i64; crate::prog_decode::MAX_ARGS]) -> (i64, i32) {
    const BLKRRPART: libc::c_ulong = 0x125F;
    let size = args[0].max(0) as usize;
    let Some(img) = arena_slice(args[1], size.min(crate::prog_decode::MAX_IMAGE)) else {
        return (-1, libc::EINVAL);
    };
    let Some((_, lfd)) = attach_loop(img) else {
        return (-1, libc::ENODEV);
    };
    let r = unsafe { libc::ioctl(lfd, BLKRRPART) };
    let e = unsafe { *libc::__errno_location() };
    detach_loop(lfd);
    if r < 0 {
        (-1, e)
    } else {
        (0, 0)
    }
}

/// Dispatch a `syz_*` call whose arguments are already materialised.
pub fn dispatch(call: &Call, args: &[i64; crate::prog_decode::MAX_ARGS], _arena: &Arena, _ctx: &Ctx) -> (i64, i32) {
    match call.base.as_str() {
        "syz_open_dev" => syz_open_dev(args),
        "syz_open_procfs" => syz_open_procfs(args),
        "syz_open_pts" => syz_open_pts(args),
        "syz_init_net_socket" => syz_init_net_socket(args),
        "syz_create_resource" => syz_create_resource(args),
        "syz_memcpy_off" => syz_memcpy_off(args),
        "syz_genetlink_get_family_id" => syz_genetlink_get_family_id(args),
        "syz_io_uring_setup" => syz_io_uring_setup(args),
        "syz_emit_ethernet" => syz_emit_ethernet(args),
        "syz_mount_image" => syz_mount_image(args),
        "syz_read_part_table" => syz_read_part_table(args),
        _ => enosys(),
    }
}

/// Names this module can execute — used to report what a program needs.
pub const SUPPORTED: &[&str] = &[
    "syz_open_dev",
    "syz_open_procfs",
    "syz_open_pts",
    "syz_init_net_socket",
    "syz_create_resource",
    "syz_memcpy_off",
    "syz_genetlink_get_family_id",
    "syz_io_uring_setup",
    "syz_emit_ethernet",
    "syz_mount_image",
    "syz_read_part_table",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_pseudo_is_enosys_not_success() {
        let c = crate::prog_decode::parse_call("syz_kvm_setup_cpu$x86(0x0)").unwrap();
        let arena = Arena::map();
        // The arena may be unavailable in a restricted test sandbox; the
        // dispatch decision does not depend on it.
        let ctx = Ctx::new();
        if let Some(a) = arena {
            let (ret, errno) = dispatch(&c, &[0; crate::prog_decode::MAX_ARGS], &a, &ctx);
            assert_eq!(ret, -1);
            assert_eq!(errno, libc::ENOSYS);
        }
    }

    #[test]
    fn create_resource_is_identity() {
        let c = crate::prog_decode::parse_call("syz_create_resource(0x2a)").unwrap();
        let ctx = Ctx::new();
        if let Some(a) = Arena::map() {
            let mut args = [0i64; crate::prog_decode::MAX_ARGS];
            args[0] = 0x2a;
            assert_eq!(dispatch(&c, &args, &a, &ctx), (0x2a, 0));
        }
    }

    #[test]
    fn out_of_arena_pointer_is_efault() {
        let c = crate::prog_decode::parse_call("syz_open_dev(0x0, 0x0, 0x0)").unwrap();
        let ctx = Ctx::new();
        if let Some(a) = Arena::map() {
            let (ret, errno) = dispatch(&c, &[0; crate::prog_decode::MAX_ARGS], &a, &ctx);
            assert_eq!(ret, -1);
            assert_eq!(errno, libc::EFAULT);
        }
    }
}
