//! syzkaller pseudo-syscall layer (`syz_usb_*`, `syz_open_dev`).
//!
//! Faithful Rust port of syzkaller's `executor/common_usb_linux.h` +
//! `executor/common_usb.h`. It drives the Linux **Raw Gadget** interface
//! (`/dev/raw-gadget`) together with `dummy_hcd`/`dummy_udc` to emulate a USB
//! device entirely from userspace, which is exactly how syzkaller reproduces
//! USB-subsystem bugs (USB audio / MIDI, HID, printers, …).
//!
//! Only the pieces needed to drive a bug reproducer are ported:
//!   * `syz_usb_connect(speed, dev)`    — enumerate an emulated device
//!   * `syz_usb_control_io(fd)`         — service one ep0 control request
//!   * `syz_usb_disconnect(fd)`         — tear the device down (`close`)
//!   * `syz_open_dev(path, id, id2)`    — open `/dev/…#…` with `#` → id
//!
//! The response-descriptor arguments of `syz_usb_connect`/`syz_usb_control_io`
//! (`conn_descs`, `descs`, `resps`) are not modelled: for GET_DESCRIPTOR the
//! device/config bytes come straight from the connect blob and everything else
//! falls back to syzkaller's built-in default string/qualifier responses, which
//! is what an enumeration needs to reach a driver's `probe`.
//!
//! This is the executor side of `vock execprog`; see [`crate::execprog`] for
//! the (rN = …) program parser that calls into here.
#![allow(dead_code)]

use std::collections::HashMap;

// ─── Raw Gadget UAPI (linux/usb/raw_gadget.h) ────────────────────────────────

// _IOC encoding (asm-generic/ioctl.h) — same on x86_64 and arm64.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS; // 8
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS; // 16
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS; // 30
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    (((dir << IOC_DIRSHIFT)
        | (ty << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as u32) as libc::c_ulong
}

const U: u32 = b'U' as u32;
// struct sizes as the kernel computes them for the ioctl numbers.
const SZ_INIT: u32 = 257; // usb_raw_init: driver[128]+device[128]+speed
const SZ_EVENT: u32 = 8; // usb_raw_event: type+length (+ flex data[])
const SZ_EP_IO: u32 = 8; // usb_raw_ep_io: ep+flags+length (+ flex data[])
const SZ_EP_DESC: u32 = 9; // usb_endpoint_descriptor (packed, audio-extended)
const SZ_U32: u32 = 4;

const USB_RAW_IOCTL_INIT: libc::c_ulong = ioc(IOC_WRITE, U, 0, SZ_INIT);
const USB_RAW_IOCTL_RUN: libc::c_ulong = ioc(IOC_NONE, U, 1, 0);
const USB_RAW_IOCTL_EVENT_FETCH: libc::c_ulong = ioc(IOC_READ, U, 2, SZ_EVENT);
const USB_RAW_IOCTL_EP0_WRITE: libc::c_ulong = ioc(IOC_WRITE, U, 3, SZ_EP_IO);
const USB_RAW_IOCTL_EP0_READ: libc::c_ulong = ioc(IOC_READ | IOC_WRITE, U, 4, SZ_EP_IO);
const USB_RAW_IOCTL_EP_ENABLE: libc::c_ulong = ioc(IOC_WRITE, U, 5, SZ_EP_DESC);
const USB_RAW_IOCTL_EP_DISABLE: libc::c_ulong = ioc(IOC_WRITE, U, 6, SZ_U32);
const USB_RAW_IOCTL_CONFIGURE: libc::c_ulong = ioc(IOC_NONE, U, 9, 0);
const USB_RAW_IOCTL_VBUS_DRAW: libc::c_ulong = ioc(IOC_WRITE, U, 10, SZ_U32);
const USB_RAW_IOCTL_EP0_STALL: libc::c_ulong = ioc(IOC_NONE, U, 12, 0);

const USB_RAW_EVENT_CONNECT: u32 = 1;
const USB_RAW_EVENT_CONTROL: u32 = 2;

// ─── USB ch9 constants (linux/usb/ch9.h) ─────────────────────────────────────
const USB_DIR_IN: u8 = 0x80;
const USB_TYPE_MASK: u8 = 0x60;
const USB_TYPE_STANDARD: u8 = 0x00;

const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
const USB_REQ_SET_CONFIGURATION: u8 = 0x09;
const USB_REQ_SET_INTERFACE: u8 = 0x0b;

const USB_DT_DEVICE: u8 = 0x01;
const USB_DT_CONFIG: u8 = 0x02;
const USB_DT_STRING: u8 = 0x03;
const USB_DT_INTERFACE: u8 = 0x04;
const USB_DT_ENDPOINT: u8 = 0x05;
const USB_DT_DEVICE_QUALIFIER: u8 = 0x06;
const USB_DT_BOS: u8 = 0x0f;

const USB_MAX_PACKET_SIZE: usize = 4096;

// syzkaller's built-in fallback descriptors.
const DEFAULT_LANG_ID: [u8; 4] = [4, USB_DT_STRING, 0x09, 0x04]; // English (US)
const DEFAULT_STRING: [u8; 8] = [8, USB_DT_STRING, b's', 0, b'y', 0, b'z', 0]; // "syz"

// ─── control request (usb_ctrlrequest, 8 bytes, little-endian on the wire) ───
#[derive(Clone, Copy, Default)]
struct CtrlRequest {
    b_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
}

impl CtrlRequest {
    fn parse(d: &[u8]) -> CtrlRequest {
        CtrlRequest {
            b_request_type: d[0],
            b_request: d[1],
            w_value: u16::from_le_bytes([d[2], d[3]]),
            w_index: u16::from_le_bytes([d[4], d[5]]),
            w_length: u16::from_le_bytes([d[6], d[7]]),
        }
    }
    fn dir_in(&self) -> bool {
        self.b_request_type & USB_DIR_IN != 0
    }
}

// ─── parsed device index (port of struct usb_device_index) ───────────────────
struct EpIndex {
    desc: [u8; 9], // usb_endpoint_descriptor bytes
    handle: i32,   // raw-gadget endpoint handle (-1 = disabled)
}

struct IfaceIndex {
    b_interface_number: u8,
    b_alternate_setting: u8,
    eps: Vec<EpIndex>,
}

struct DeviceIndex {
    dev: Vec<u8>,      // device descriptor bytes (18)
    config: Vec<u8>,   // config descriptor + trailing bytes
    b_max_power: u8,
    ifaces: Vec<IfaceIndex>,
    iface_cur: i32,
}

/// Port of `parse_usb_descriptor()`: split the connect blob into the device and
/// config descriptors and index every interface/endpoint (needed by
/// `set_interface`).
fn parse_usb_descriptor(buf: &[u8]) -> Option<DeviceIndex> {
    const DEV_LEN: usize = 18; // sizeof(usb_device_descriptor)
    const CFG_LEN: usize = 9; // sizeof(usb_config_descriptor)
    if buf.len() < DEV_LEN + CFG_LEN {
        return None;
    }
    let mut idx = DeviceIndex {
        dev: buf[..DEV_LEN].to_vec(),
        config: buf[DEV_LEN..].to_vec(),
        b_max_power: buf[DEV_LEN + 8], // config.bMaxPower
        ifaces: Vec::new(),
        iface_cur: -1,
    };

    let mut off = 0usize;
    while off + 1 < buf.len() {
        let desc_len = buf[off] as usize;
        let desc_type = buf[off + 1];
        if desc_len <= 2 || off + desc_len > buf.len() {
            break;
        }
        if desc_type == USB_DT_INTERFACE && desc_len >= 9 {
            idx.ifaces.push(IfaceIndex {
                b_interface_number: buf[off + 2],
                b_alternate_setting: buf[off + 3],
                eps: Vec::new(),
            });
        }
        if desc_type == USB_DT_ENDPOINT && !idx.ifaces.is_empty() {
            let iface = idx.ifaces.last_mut().unwrap();
            let mut ep = [0u8; 9];
            let n = desc_len.min(9);
            ep[..n].copy_from_slice(&buf[off..off + n]);
            iface.eps.push(EpIndex { desc: ep, handle: -1 });
        }
        off += desc_len;
    }
    Some(idx)
}

// ─── raw-gadget ioctl wrappers ───────────────────────────────────────────────
unsafe fn ioctl_ptr(fd: i32, req: libc::c_ulong, arg: *mut libc::c_void) -> i32 {
    libc::ioctl(fd, req, arg) as i32
}

fn usb_raw_open() -> i32 {
    let path = c"/dev/raw-gadget";
    unsafe { libc::open(path.as_ptr(), libc::O_RDWR) }
}

fn usb_raw_init(fd: i32, speed: u8, device: &str) -> i32 {
    // struct usb_raw_init { u8 driver_name[128]; u8 device_name[128]; u8 speed; }
    let mut arg = [0u8; 257];
    let driver = b"dummy_udc";
    arg[..driver.len()].copy_from_slice(driver);
    let dev = device.as_bytes();
    let n = dev.len().min(127);
    arg[128..128 + n].copy_from_slice(&dev[..n]);
    arg[256] = speed;
    unsafe { ioctl_ptr(fd, USB_RAW_IOCTL_INIT, arg.as_mut_ptr() as *mut _) }
}

fn usb_raw_run(fd: i32) -> i32 {
    unsafe { libc::ioctl(fd, USB_RAW_IOCTL_RUN, 0) as i32 }
}

fn usb_raw_configure(fd: i32) -> i32 {
    unsafe { libc::ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) as i32 }
}

fn usb_raw_vbus_draw(fd: i32, power: u32) -> i32 {
    unsafe { libc::ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power as libc::c_ulong) as i32 }
}

fn usb_raw_ep0_stall(fd: i32) -> i32 {
    unsafe { libc::ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0) as i32 }
}

fn usb_raw_ep_enable(fd: i32, desc: &[u8; 9]) -> i32 {
    unsafe { ioctl_ptr(fd, USB_RAW_IOCTL_EP_ENABLE, desc.as_ptr() as *mut _) }
}

fn usb_raw_ep_disable(fd: i32, handle: i32) -> i32 {
    let mut h = handle as u32;
    unsafe { ioctl_ptr(fd, USB_RAW_IOCTL_EP_DISABLE, &mut h as *mut u32 as *mut _) }
}

/// Blocking `USB_RAW_IOCTL_EVENT_FETCH`. Returns (type, ctrl-bytes) or None.
fn usb_raw_event_fetch(fd: i32) -> Option<(u32, [u8; 8])> {
    // struct usb_raw_event { u32 type; u32 length; u8 data[]; }
    let mut buf = [0u8; 8 + 64];
    // length = capacity of the data area.
    buf[4..8].copy_from_slice(&64u32.to_le_bytes());
    let rv = unsafe { ioctl_ptr(fd, USB_RAW_IOCTL_EVENT_FETCH, buf.as_mut_ptr() as *mut _) };
    if rv < 0 {
        return None;
    }
    let ty = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let mut ctrl = [0u8; 8];
    ctrl.copy_from_slice(&buf[8..16]);
    Some((ty, ctrl))
}

/// ep0 write (IN) or read (OUT). `data` is the payload for IN; for OUT it is
/// the number of bytes to drain. Returns the ioctl result.
fn usb_raw_ep0_io(fd: i32, write: bool, data: &[u8]) -> i32 {
    // struct usb_raw_ep_io { u16 ep; u16 flags; u32 length; u8 data[]; }
    let len = data.len().min(USB_MAX_PACKET_SIZE);
    let mut buf = vec![0u8; 8 + len];
    // ep = 0, flags = 0 already zero.
    buf[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    buf[8..8 + len].copy_from_slice(&data[..len]);
    let req = if write {
        USB_RAW_IOCTL_EP0_WRITE
    } else {
        USB_RAW_IOCTL_EP0_READ
    };
    unsafe { ioctl_ptr(fd, req, buf.as_mut_ptr() as *mut _) }
}

// ─── connect-response lookup (port of common_usb.h) ──────────────────────────
/// Port of `lookup_connect_response_in()` for the standard GET_DESCRIPTOR
/// requests. `conn_descs` (BOS/qualifier/custom strings) is not modelled, so
/// those fall back to syzkaller's defaults / synthesized qualifier.
fn lookup_connect_response_in(idx: &DeviceIndex, ctrl: &CtrlRequest) -> Option<Vec<u8>> {
    if ctrl.b_request_type & USB_TYPE_MASK != USB_TYPE_STANDARD {
        return None;
    }
    if ctrl.b_request != USB_REQ_GET_DESCRIPTOR {
        return None;
    }
    let desc_type = (ctrl.w_value >> 8) as u8;
    let str_idx = (ctrl.w_value & 0xff) as u8;
    match desc_type {
        USB_DT_DEVICE => Some(idx.dev.clone()),
        USB_DT_CONFIG => Some(idx.config.clone()),
        USB_DT_STRING => {
            if str_idx == 0 {
                Some(DEFAULT_LANG_ID.to_vec())
            } else {
                Some(DEFAULT_STRING.to_vec())
            }
        }
        USB_DT_DEVICE_QUALIFIER => {
            // Synthesize a qualifier from the device descriptor (as syzkaller
            // does when conn_descs->qual is absent).
            if idx.dev.len() < 18 {
                return None;
            }
            let mut q = [0u8; 10];
            q[0] = 10; // bLength
            q[1] = USB_DT_DEVICE_QUALIFIER;
            q[2] = idx.dev[2]; // bcdUSB lo
            q[3] = idx.dev[3]; // bcdUSB hi
            q[4] = idx.dev[4]; // bDeviceClass
            q[5] = idx.dev[5]; // bDeviceSubClass
            q[6] = idx.dev[6]; // bDeviceProtocol
            q[7] = idx.dev[7]; // bMaxPacketSize0
            q[8] = idx.dev[17]; // bNumConfigurations
            q[9] = 0; // bRESERVED
            Some(q.to_vec())
        }
        USB_DT_BOS => None, // no BOS supplied → stall (host proceeds without it)
        _ => None,
    }
}

// ─── device state ────────────────────────────────────────────────────────────
pub struct UsbDevice {
    pub fd: i32,
    index: DeviceIndex,
}

/// Enable the endpoints of interface index `n`, disabling the previous one —
/// port of `set_interface()`. Failures are non-fatal (as in syzkaller).
fn set_interface(fd: i32, index: &mut DeviceIndex, n: i32) {
    if index.iface_cur >= 0 && (index.iface_cur as usize) < index.ifaces.len() {
        for ep in &index.ifaces[index.iface_cur as usize].eps {
            if ep.handle >= 0 {
                usb_raw_ep_disable(fd, ep.handle);
            }
        }
    }
    if n >= 0 && (n as usize) < index.ifaces.len() {
        let eps_len = index.ifaces[n as usize].eps.len();
        for i in 0..eps_len {
            let desc = index.ifaces[n as usize].eps[i].desc;
            let rv = usb_raw_ep_enable(fd, &desc);
            if rv >= 0 {
                index.ifaces[n as usize].eps[i].handle = rv;
            }
        }
        index.iface_cur = n;
    }
}

/// Port of `configure_device()`: vbus_draw + configure + select interface 0.
fn configure_device(fd: i32, index: &mut DeviceIndex) -> i32 {
    let rv = usb_raw_vbus_draw(fd, index.b_max_power as u32);
    if rv < 0 {
        return rv;
    }
    let rv = usb_raw_configure(fd);
    if rv < 0 {
        return rv;
    }
    set_interface(fd, index, 0);
    0
}

/// `syz_usb_connect(speed, dev)` — port of `syz_usb_connect_impl` with the
/// generic OUT-response lookup. `dev` is the full connect blob (device
/// descriptor + config descriptor + class/endpoint descriptors). `procid`
/// selects the `dummy_udc.<procid>` instance. Returns the raw-gadget fd, or
/// negative on failure.
pub fn syz_usb_connect(speed: u8, dev: &[u8], procid: u64) -> Result<UsbDevice, i32> {
    let mut index = match parse_usb_descriptor(dev) {
        Some(i) => i,
        None => return Err(-1),
    };

    let fd = usb_raw_open();
    if fd < 0 {
        return Err(fd);
    }

    // Prefer this worker's own UDC; fall back to instance 0 if it is absent
    // (dummy_hcd defaults to a single dummy_udc.0).
    let mut rv = usb_raw_init(fd, speed, &format!("dummy_udc.{procid}"));
    if rv < 0 && procid != 0 {
        rv = usb_raw_init(fd, speed, "dummy_udc.0");
    }
    if rv < 0 {
        unsafe { libc::close(fd) };
        return Err(rv);
    }

    rv = usb_raw_run(fd);
    if rv < 0 {
        unsafe { libc::close(fd) };
        return Err(rv);
    }

    let mut done = false;
    while !done {
        let (ty, ctrl_bytes) = match usb_raw_event_fetch(fd) {
            Some(e) => e,
            None => {
                unsafe { libc::close(fd) };
                return Err(-1);
            }
        };
        if ty != USB_RAW_EVENT_CONTROL {
            let _ = USB_RAW_EVENT_CONNECT; // (connect/reset/suspend: ignored)
            continue;
        }
        let ctrl = CtrlRequest::parse(&ctrl_bytes);

        let response_data: Option<Vec<u8>>;
        if ctrl.dir_in() {
            match lookup_connect_response_in(&index, &ctrl) {
                Some(d) => response_data = Some(d),
                None => {
                    usb_raw_ep0_stall(fd);
                    continue;
                }
            }
        } else {
            // OUT: only SET_CONFIGURATION is known (generic lookup); it ends
            // enumeration. Everything else stalls.
            if ctrl.b_request_type & USB_TYPE_MASK == USB_TYPE_STANDARD
                && ctrl.b_request == USB_REQ_SET_CONFIGURATION
            {
                done = true;
            } else {
                usb_raw_ep0_stall(fd);
                continue;
            }
            response_data = None;
        }

        if ctrl.b_request_type & USB_TYPE_MASK == USB_TYPE_STANDARD
            && ctrl.b_request == USB_REQ_SET_CONFIGURATION
        {
            let rv = configure_device(fd, &mut index);
            if rv < 0 {
                unsafe { libc::close(fd) };
                return Err(rv);
            }
        }

        // Clamp the response to wLength, as syzkaller does.
        let mut resp = response_data.unwrap_or_default();
        if resp.len() > ctrl.w_length as usize {
            resp.truncate(ctrl.w_length as usize);
        }
        let rv = usb_raw_ep0_io(fd, ctrl.dir_in(), &resp);
        if rv < 0 {
            unsafe { libc::close(fd) };
            return Err(rv);
        }
    }

    sleep_ms(200);
    Ok(UsbDevice { fd, index })
}

/// `syz_usb_control_io(fd)` — service one ep0 control request during the
/// driver's `probe`. Port of `syz_usb_control_io` with no descriptor/response
/// tables: IN requests are answered with zeros, SET_INTERFACE switches the
/// altsetting, other OUT requests are acked. Blocks in EVENT_FETCH until a
/// request arrives (guarded by the per-program alarm in `run_program`).
pub fn syz_usb_control_io(dev: &mut UsbDevice) -> i32 {
    let fd = dev.fd;
    let (ty, ctrl_bytes) = match usb_raw_event_fetch(fd) {
        Some(e) => e,
        None => return -1,
    };
    if ty != USB_RAW_EVENT_CONTROL {
        return -1;
    }
    let ctrl = CtrlRequest::parse(&ctrl_bytes);

    let mut response_length = ctrl.w_length as usize;
    if ctrl.dir_in() && ctrl.w_length != 0 {
        // No descriptor table: answer with zeros (host reads whatever it asked).
    } else {
        // OUT / zero-length IN. Handle SET_INTERFACE altset switching.
        if ctrl.b_request_type & USB_TYPE_MASK == USB_TYPE_STANDARD
            || ctrl.b_request == USB_REQ_SET_INTERFACE
        {
            let iface_num = ctrl.w_index as u8;
            let alt_set = ctrl.w_value as u8;
            if let Some(i) = lookup_interface(&dev.index, iface_num, alt_set) {
                set_interface(fd, &mut dev.index, i as i32);
            }
        }
        response_length = ctrl.w_length as usize;
    }
    if ctrl.dir_in() && ctrl.w_length == 0 {
        response_length = USB_MAX_PACKET_SIZE;
    }
    response_length = response_length.min(USB_MAX_PACKET_SIZE);

    let data = vec![0u8; response_length];
    let rv = usb_raw_ep0_io(fd, ctrl.dir_in() && ctrl.w_length != 0, &data);
    if rv < 0 {
        return rv;
    }
    sleep_ms(200);
    0
}

fn lookup_interface(index: &DeviceIndex, num: u8, alt: u8) -> Option<usize> {
    index
        .ifaces
        .iter()
        .position(|f| f.b_interface_number == num && f.b_alternate_setting == alt)
}

/// `syz_usb_disconnect(fd)` — port of `syz_usb_disconnect`: close the fd, which
/// unbinds the gadget and triggers the driver's `disconnect` (the teardown path
/// where the UAF lives).
pub fn syz_usb_disconnect(dev: &UsbDevice) -> i32 {
    let rv = unsafe { libc::close(dev.fd) };
    sleep_ms(200);
    rv
}

/// `syz_open_dev(path, id, id2)` — port of `syz_open_dev`: substitute the two
/// `#` placeholders in `path` with `id`/`id2` and `open(O_RDWR)`.
pub fn syz_open_dev(path: &str, id: u64, id2: u64) -> i32 {
    let mut out = String::with_capacity(path.len() + 8);
    let mut seen = 0;
    for ch in path.chars() {
        if ch == '#' {
            let v = if seen == 0 { id } else { id2 };
            out.push_str(&v.to_string());
            seen += 1;
        } else {
            out.push(ch);
        }
    }
    let c = match std::ffi::CString::new(out) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c.as_ptr(), libc::O_RDWR) }
}

fn sleep_ms(ms: u64) {
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

// ─── program interpreter ─────────────────────────────────────────────────────
//
// vock serializes a pseudo-syscall reproducer in a simplified, self-describing
// syzlang-like form (the full syz-executor memory layout — `&(0x7f00…)` pointer
// args and packed struct literals — is not modelled). One statement per line:
//
//   r0 = syz_usb_connect(0x0, <hex-descriptor-blob>)
//   syz_usb_control_io(r0)
//   syz_usb_disconnect(r0)
//   r1 = syz_open_dev('/dev/snd/midiC#D#', 0x0, 0x0)
//
// `rN =` binds a resource (a fd/handle) reused by later statements. Plain
// syscalls (immediate integer args) may be interleaved and are replayed raw.

enum Op {
    Connect {
        res: Option<String>,
        speed: u8,
        dev: Vec<u8>,
    },
    ControlIo {
        fd: String,
    },
    Disconnect {
        fd: String,
    },
    OpenDev {
        res: Option<String>,
        path: String,
        id: u64,
        id2: u64,
    },
    Raw {
        nr: i64,
        args: [i64; 6],
    },
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Split `a, b, c` at top level (our format has no nested parens/brackets).
fn split_args(s: &str) -> Vec<String> {
    s.split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect()
}

fn parse_line(line: &str) -> Option<Op> {
    let line = line.trim();
    // Optional "rN = " resource binding.
    let (res, rest) = match line.split_once('=') {
        Some((lhs, rhs)) if lhs.trim().starts_with('r') && !lhs.contains('(') => {
            (Some(lhs.trim().to_string()), rhs.trim())
        }
        _ => (None, line),
    };
    let paren = rest.find('(')?;
    let name = rest[..paren].trim();
    let close = rest.rfind(')')?;
    let inner = &rest[paren + 1..close];
    let args = split_args(inner);

    match name {
        "syz_usb_connect" | "syz_usb_connect$printer" | "syz_usb_connect$hid"
        | "syz_usb_connect$cdc_ecm" | "syz_usb_connect$uac1" | "syz_usb_connect$midi" => {
            // (speed, dev-blob[, conn_descs])  — conn_descs is ignored.
            let speed = parse_u64(args.first()?)? as u8;
            let dev = decode_hex(args.get(1)?)?;
            Some(Op::Connect { res, speed, dev })
        }
        "syz_usb_control_io" | "syz_usb_control_io$printer" | "syz_usb_control_io$hid"
        | "syz_usb_control_io$midi" => Some(Op::ControlIo {
            fd: args.first()?.to_string(),
        }),
        "syz_usb_disconnect" => Some(Op::Disconnect {
            fd: args.first()?.to_string(),
        }),
        n if n.starts_with("syz_open_dev") => {
            let path = args.first()?.trim_matches(['\'', '"']).to_string();
            let id = args.get(1).and_then(|a| parse_u64(a)).unwrap_or(0);
            let id2 = args.get(2).and_then(|a| parse_u64(a)).unwrap_or(0);
            Some(Op::OpenDev { res, path, id, id2 })
        }
        _ => {
            // Fall back to a plain syscall replay (immediate args only).
            let nr = crate::syscall::syscall_nr(name)? as i64;
            let mut a = [0i64; 6];
            for (i, slot) in a.iter_mut().enumerate() {
                match args.get(i).and_then(|x| parse_u64(x)) {
                    Some(v) => *slot = v as i64,
                    None => break,
                }
            }
            Some(Op::Raw { nr, args: a })
        }
    }
}

fn parse_program(path: &str) -> Option<Vec<Op>> {
    let body = std::fs::read_to_string(path).ok()?;
    let mut ops = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(op) = parse_line(l) {
            ops.push(op);
        }
    }
    if ops.is_empty() {
        None
    } else {
        Some(ops)
    }
}

/// True if the program at `path` uses any pseudo-syscall (`syz_*`), i.e. it
/// must go through this interpreter rather than the plain execprog replay.
pub fn program_has_pseudo(path: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(body) => body
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .any(|l| l.contains("syz_")),
        Err(_) => false,
    }
}

extern "C" fn on_alarm(_sig: libc::c_int) {}

/// Install a SIGALRM handler *without* SA_RESTART so a blocking EVENT_FETCH
/// ioctl is interrupted (EINTR) rather than restarted.
fn install_alarm_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as usize;
        sa.sa_flags = 0; // no SA_RESTART
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }
}

/// Per-program watchdog: enumeration + probe servicing should take well under a
/// second; cap it so a wedged EVENT_FETCH cannot stall the repeat loop.
const PROG_TIMEOUT_SECS: u32 = 8;

/// Execute one pass of the program with a fresh resource store.
fn run_once(ops: &[Op], procid: u64) {
    let mut usb: HashMap<String, UsbDevice> = HashMap::new();
    let mut fds: HashMap<String, i32> = HashMap::new();

    unsafe { libc::alarm(PROG_TIMEOUT_SECS) };
    for op in ops {
        match op {
            Op::Connect { res, speed, dev } => {
                if let Ok(d) = syz_usb_connect(*speed, dev, procid) {
                    if let Some(r) = res {
                        usb.insert(r.clone(), d);
                    } else {
                        // Unbound device: keep it alive under a private key so
                        // it is torn down at the end of the pass.
                        usb.insert(format!("__anon{}", usb.len()), d);
                    }
                }
            }
            Op::ControlIo { fd } => {
                if let Some(d) = usb.get_mut(fd) {
                    syz_usb_control_io(d);
                }
            }
            Op::Disconnect { fd } => {
                if let Some(d) = usb.remove(fd) {
                    syz_usb_disconnect(&d);
                }
            }
            Op::OpenDev { res, path, id, id2 } => {
                let fd = syz_open_dev(path, *id, *id2);
                if fd >= 0 {
                    if let Some(r) = res {
                        fds.insert(r.clone(), fd);
                    }
                }
            }
            Op::Raw { nr, args } => unsafe {
                libc::syscall(*nr, args[0], args[1], args[2], args[3], args[4], args[5]);
            },
        }
    }
    unsafe { libc::alarm(0) };

    // Tear down anything the program left open, freeing the UDC / fds for the
    // next iteration.
    for (_, d) in usb.drain() {
        unsafe { libc::close(d.fd) };
    }
    for (_, fd) in fds.drain() {
        unsafe { libc::close(fd) };
    }
}

/// Run a pseudo-syscall program file like `syz-execprog`: `procs` workers, each
/// replaying the program `repeat` times (0 = until killed). Returns 0 on
/// success, non-zero if the program could not be parsed.
pub fn run_file(path: &str, repeat: i32, procs: i32) -> i32 {
    let ops = match parse_program(path) {
        Some(o) => o,
        None => {
            eprintln!("[execprog] no runnable statements in {path}");
            return 1;
        }
    };
    eprintln!("[execprog] {} pseudo-syscall statements from {path}", ops.len());
    eprintln!("[execprog] repeat={repeat}, procs={procs} (raw-gadget / dummy_udc)");
    install_alarm_handler();

    let worker = |id: u64| {
        let mut i = 0i32;
        while repeat == 0 || i < repeat {
            run_once(&ops, id);
            if (i + 1) % 100 == 0 {
                eprintln!("[execprog:{id}] executed {} programs", i + 1);
            }
            i += 1;
        }
    };

    if procs <= 1 {
        worker(0);
    } else {
        let mut pids = Vec::new();
        for w in 0..procs {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                worker(w as u64);
                unsafe { libc::_exit(0) };
            }
            pids.push(pid);
        }
        for pid in pids {
            if pid > 0 {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
            }
        }
    }
    0
}
