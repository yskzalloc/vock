//! Target programs the selftests trace, decoupled from the harness so that
//! `vock selftest --help` can print each test's equivalent raw command and a
//! user can replay any test by hand, e.g.:
//!
//! ```text
//! vng --rw -- vock --mode kcov --vmlinux ./vmlinux --kernel-src . /bin/ls /tmp
//! ```
//!
//! The Test 3 crypto workload is implemented here in Rust over AF_ALG —
//! `vock selftest target crypto-setup` / `crypto-decrypt` — instead of a
//! kcapi-enc shell pipeline. The traced decrypt is a single process making
//! AF_ALG syscalls, and the staged files live in the working directory (the
//! kernel tree, which vng shares with the host), so the harness can verify
//! everything from the host without stdout markers.

use std::path::Path;

/// Test 1 workload: create a unique file. `touch` drives the vfs write path
/// end to end (openat with O_CREAT, inode allocation, utimensat), so the
/// harness can assert that inode/write related functions really appear in
/// the resolved coverage.
pub const KCOV_TARGET: &str = "/bin/touch \"/tmp/$(date +%s).txt\"";

/// Test 2 workload: plain syscall traffic through vfs paths.
pub const COVERAGE_TARGET: &str = "/bin/ls /tmp";

/// Test 3 traced target: this same vock binary running the AF_ALG decrypt.
pub const CRYPTO_TARGET_ARGS: &[&str] = &["selftest", "target", "crypto-decrypt"];

/// Test 4 sample reproducer (KASAN UAF in `snd_usb_midi_v2_free`), relative
/// to the vock directory.
pub const KASAN_SAMPLE: &str = "selftest/samples/midi_uaf.syz";

/// `--syscall sud` prologue: SUD dispatch needs `mmap_min_addr` relaxed
/// before the target runs.
pub const SUD_SETUP: &str = "echo 0 > /proc/sys/vm/mmap_min_addr 2>/dev/null; ";

// ─── Test 3 crypto workload (AF_ALG xts(aes)) ───────────────────────────────

/// Staged in the working directory — the kernel tree — so both the guest and
/// the host see them. Prefixed to avoid clobbering anything in a real tree.
pub const BLOCK_IMG: &str = "vock-block.img";
pub const BLOCK_ENC: &str = "vock-block.enc";
pub const BLOCK_DEC: &str = "vock-block.dec";
pub const KEY_FILE: &str = "vock-key.bin";

const DATA_LEN: usize = 64 * 1024;
const KEY: &[u8; 64] = b"ThisIsA64ByteSecretKeyForAES256XTSModeWhichRequires512BitsOfData";
const IV: [u8; 16] = [0; 16];

/// Every file the crypto test stages or produces, for cleanup.
pub const CRYPTO_FILES: &[&str] = &[BLOCK_IMG, BLOCK_ENC, BLOCK_DEC, KEY_FILE];

/// Test 5 traced target: this vock binary driving the Rust misc-device
/// sample from userspace.
pub const RUST_TARGET_ARGS: &[&str] = &["selftest", "target", "rust-touch"];

/// The Rust sample's device node (samples/rust/rust_misc_device.rs).
pub const RUST_MISC_DEV: &str = "/dev/rust-misc-device";

// ioctls from the sample's doc block: _IO/_IOR/_IOW('|', ...).
const RUST_MISC_DEV_HELLO: libc::c_ulong = 0x7c80;
const RUST_MISC_DEV_GET_VALUE: libc::c_ulong = 0x8004_7c81;
const RUST_MISC_DEV_SET_VALUE: libc::c_ulong = 0x4004_7c82;

/// Exercise the Rust misc device end to end, write path first: write()
/// lands in the sample's write_iter, read() in read_iter, and the three
/// ioctls in its ioctl handler — all Rust kernel code reached from
/// userspace in this single traced task.
pub fn rust_touch() -> Result<(), String> {
    let path = std::ffi::CString::new(RUST_MISC_DEV).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "open {RUST_MISC_DEV}: {} (CONFIG_SAMPLE_RUST_MISC_DEVICE=y?)",
            std::io::Error::last_os_error()
        ));
    }
    let ok = unsafe {
        let msg = b"vock rust write path";
        let w = libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len());
        let mut buf = [0u8; 64];
        let r = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        let hello = libc::ioctl(fd, RUST_MISC_DEV_HELLO, 0usize);
        let mut value: libc::c_int = 42;
        let set = libc::ioctl(fd, RUST_MISC_DEV_SET_VALUE, &value as *const libc::c_int);
        let get = libc::ioctl(fd, RUST_MISC_DEV_GET_VALUE, &mut value as *mut libc::c_int);
        libc::close(fd);
        // write_iter is the aspect under test; the rest is best-effort.
        println!(
            "rust-touch: write={w} read={r} hello={hello} set={set} get={get} value={value}"
        );
        w > 0
    };
    if ok {
        Ok(())
    } else {
        Err("write() into the Rust misc device failed".into())
    }
}

/// Dispatcher for `vock selftest target <name>` — the in-VM halves of the
/// selftest workloads.
pub fn run_target(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("crypto-setup") => match crypto_setup(Path::new(".")) {
            Ok(()) => {
                println!("crypto-setup: {DATA_LEN} bytes encrypted → {BLOCK_ENC}");
                0
            }
            Err(e) => {
                eprintln!("crypto-setup: {e}");
                1
            }
        },
        Some("rust-touch") => match rust_touch() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("rust-touch: {e}");
                1
            }
        },
        Some("crypto-decrypt") => match crypto_decrypt(Path::new(".")) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("crypto-decrypt: {e}");
                1
            }
        },
        _ => {
            eprintln!("vock selftest target: expected crypto-setup | crypto-decrypt | rust-touch");
            2
        }
    }
}

/// Stage the workload in `dir`: random plaintext, key file, and the xts(aes)
/// ciphertext (encrypted via AF_ALG). Any stale decrypt output is removed.
///
/// For reference, the kcapi-enc shell pipeline this replaces (it additionally
/// required kcapi-tools in the guest and CONFIG_CRYPTO_USER for the
/// NETLINK_CRYPTO cipher lookup):
///
/// ```text
/// dd if=/dev/urandom of=/tmp/block.img bs=64K count=64 2>/dev/null; \
/// printf '<64-byte key>' > /tmp/key.bin; \
/// kcapi-enc -c 'xts(aes)' -e -i /tmp/block.img -o /tmp/block.enc \
///     --iv 00000000000000000000000000000000 --keyfd 3 3</tmp/key.bin; \
/// printf '#!/bin/sh\nkcapi-enc -d -c "xts(aes)" -i /tmp/block.enc \
///     -o /tmp/block.dec --iv 00000000000000000000000000000000 \
///     --keyfd 3 3</tmp/key.bin\n' > /tmp/dec.sh; chmod +x /tmp/dec.sh
/// # traced target: /bin/sh /tmp/dec.sh; verified with cmp block.img block.dec
/// ```
pub fn crypto_setup(dir: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut plain = vec![0u8; DATA_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut plain))
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    std::fs::write(dir.join(BLOCK_IMG), &plain).map_err(|e| format!("write {BLOCK_IMG}: {e}"))?;
    std::fs::write(dir.join(KEY_FILE), KEY).map_err(|e| format!("write {KEY_FILE}: {e}"))?;
    let _ = std::fs::remove_file(dir.join(BLOCK_DEC));

    let enc = afalg_xts(true, KEY, &IV, &plain)?;
    std::fs::write(dir.join(BLOCK_ENC), &enc).map_err(|e| format!("write {BLOCK_ENC}: {e}"))?;
    Ok(())
}

/// The traced target: decrypt `BLOCK_ENC` with the staged key via AF_ALG and
/// write `BLOCK_DEC`. Single process, no children — every crypto syscall runs
/// in the task the KCOV shim instruments.
pub fn crypto_decrypt(dir: &Path) -> Result<(), String> {
    let key = std::fs::read(dir.join(KEY_FILE)).map_err(|e| format!("read {KEY_FILE}: {e}"))?;
    let enc = std::fs::read(dir.join(BLOCK_ENC)).map_err(|e| format!("read {BLOCK_ENC}: {e}"))?;
    let dec = afalg_xts(false, &key, &IV, &enc)?;
    std::fs::write(dir.join(BLOCK_DEC), &dec).map_err(|e| format!("write {BLOCK_DEC}: {e}"))?;
    Ok(())
}

/// Host-side verification: the decrypted output matches the original.
pub fn crypto_verify(dir: &Path) -> bool {
    match (
        std::fs::read(dir.join(BLOCK_IMG)),
        std::fs::read(dir.join(BLOCK_DEC)),
    ) {
        (Ok(a), Ok(b)) => !a.is_empty() && a == b,
        _ => false,
    }
}

/// One xts(aes) operation over AF_ALG: bind an skcipher socket, set the key,
/// then sendmsg the whole buffer with ALG_SET_OP/ALG_SET_IV ancillary data
/// and read the transformed result back.
fn afalg_xts(encrypt: bool, key: &[u8], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, String> {
    #[repr(C)]
    struct AfAlgIv {
        ivlen: u32,
        iv: [u8; 16],
    }

    unsafe {
        let tfm = libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0);
        if tfm < 0 {
            return Err(format!("socket(AF_ALG): {} (CONFIG_CRYPTO_USER_API_SKCIPHER?)",
                std::io::Error::last_os_error()));
        }
        let mut sa: libc::sockaddr_alg = std::mem::zeroed();
        sa.salg_family = libc::AF_ALG as u16;
        sa.salg_type[..b"skcipher".len()].copy_from_slice(b"skcipher");
        sa.salg_name[..b"xts(aes)".len()].copy_from_slice(b"xts(aes)");
        if libc::bind(
            tfm,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(tfm);
            return Err(format!("bind(xts(aes)): {e} (CONFIG_CRYPTO_XTS/CRYPTO_AES?)"));
        }
        if libc::setsockopt(
            tfm,
            libc::SOL_ALG,
            libc::ALG_SET_KEY,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(tfm);
            return Err(format!("ALG_SET_KEY: {e}"));
        }
        let op = libc::accept(tfm, std::ptr::null_mut(), std::ptr::null_mut());
        if op < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(tfm);
            return Err(format!("accept: {e}"));
        }

        // Ancillary data: ALG_SET_OP (u32) + ALG_SET_IV (af_alg_iv).
        let op_space = libc::CMSG_SPACE(4) as usize;
        let iv_space = libc::CMSG_SPACE(std::mem::size_of::<AfAlgIv>() as u32) as usize;
        let mut cbuf = vec![0u8; op_space + iv_space];
        let mut iovec = libc::iovec {
            iov_base: input.as_ptr() as *mut libc::c_void,
            iov_len: input.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len();

        let c1 = libc::CMSG_FIRSTHDR(&msg);
        (*c1).cmsg_level = libc::SOL_ALG;
        (*c1).cmsg_type = libc::ALG_SET_OP;
        (*c1).cmsg_len = libc::CMSG_LEN(4) as usize;
        let opval: u32 = if encrypt { libc::ALG_OP_ENCRYPT as u32 } else { libc::ALG_OP_DECRYPT as u32 };
        std::ptr::copy_nonoverlapping(&opval as *const u32 as *const u8, libc::CMSG_DATA(c1), 4);

        let c2 = libc::CMSG_NXTHDR(&msg, c1);
        (*c2).cmsg_level = libc::SOL_ALG;
        (*c2).cmsg_type = libc::ALG_SET_IV;
        (*c2).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<AfAlgIv>() as u32) as usize;
        let ivmsg = AfAlgIv { ivlen: 16, iv: *iv };
        std::ptr::copy_nonoverlapping(
            &ivmsg as *const AfAlgIv as *const u8,
            libc::CMSG_DATA(c2),
            std::mem::size_of::<AfAlgIv>(),
        );

        if libc::sendmsg(op, &msg, 0) != input.len() as isize {
            let e = std::io::Error::last_os_error();
            libc::close(op);
            libc::close(tfm);
            return Err(format!("sendmsg: {e}"));
        }

        let mut out = vec![0u8; input.len()];
        let mut got = 0usize;
        while got < out.len() {
            let n = libc::read(
                op,
                out[got..].as_mut_ptr() as *mut libc::c_void,
                out.len() - got,
            );
            if n <= 0 {
                let e = std::io::Error::last_os_error();
                libc::close(op);
                libc::close(tfm);
                return Err(format!("read: {e}"));
            }
            got += n as usize;
        }
        libc::close(op);
        libc::close(tfm);
        Ok(out)
    }
}

/// Reproducible raw command for one test, shared by `vock selftest --help`
/// and `vock selftest raw <n>` (which CI embeds in its job summary) so the
/// two can never drift apart. `vng` lines run from the kernel source tree;
/// `--on host` drops the `vng --rw --` prefix.
pub fn raw_command(test: &str) -> Option<String> {
    match test {
        "1" => Some(format!(
            "vng --rw -- vock --mode kcov --syzlang --syscall ptrace \\\n\
    --vmlinux ./vmlinux --kernel-src . {KCOV_TARGET}\n\
... repeated for --syscall sud/ebpf, with --btf instead of --vmlinux,\n\
and with --ordered / --filter fs   (sud runs need: {SUD_SETUP})"
        )),
        "2" => Some(format!(
            "vock --mode hw --syzlang --syscall ptrace \\\n\
    --vmlinux ./vmlinux --kernel-src . {COVERAGE_TARGET}\n\
... repeated for --syscall sud/ebpf; bare metal for Intel PT/CoreSight,\n\
AMD LBR also works via vng --rw --. The host ebpf run needs root, or\n\
as a normal user: sudo sysctl kernel.unprivileged_bpf_disabled=0,\n\
sudo setcap cap_bpf,cap_perfmon+ep <vock binary> (re-apply after every\n\
make/install, which rewrites the file), and\n\
sudo mount -o remount,mode=755,gid=$(id -g) /sys/kernel/tracing"
        )),
        "3" => Some(format!(
            "vock selftest target crypto-setup     # stage {BLOCK_IMG}/{BLOCK_ENC}/{KEY_FILE}\n\
vng --rw -- vock --mode kcov --filter crypto --vmlinux ./vmlinux --kernel-src . \\\n\
    vock selftest target crypto-decrypt\n\
# both halves are AF_ALG xts(aes) in vock itself — no kcapi-enc, no shell"
        )),
        "4" => Some(format!(
            "vng --rw -- vock execprog -repeat=0 -procs=4 {KASAN_SAMPLE}"
        )),
        "5" => Some(format!(
            "vng --rw -- vock --mode kcov --vmlinux ./vmlinux --kernel-src . \\\n\
    vock selftest target rust-touch\n\
# the target write()s/read()s/ioctl()s {RUST_MISC_DEV} (built-in Rust\n\
# sample); needs CONFIG_RUST=y and a kernel Rust toolchain (make rustavailable)"
        )),
        _ => None,
    }
}

/// The "equivalent raw commands" section of `vock selftest --help`, composed
/// from [`raw_command`] so help and `vock selftest raw` stay identical.
pub fn help_raw_commands() -> String {
    let mut s = String::from(
        "equivalent raw commands (run from the kernel source tree; each test first\n\
configures + builds the kernel via `vng --force --configitem ... --build`;\n\
`vock` is whichever binary you run — ./vock.bin in a build tree works too):\n",
    );
    for t in ["1", "2", "3", "4", "5"] {
        let block = raw_command(t).unwrap_or_default();
        let mut lines = block.lines();
        if let Some(first) = lines.next() {
            s.push_str(&format!("  {t}  {first}\n"));
        }
        for l in lines {
            s.push_str(&format!("     {l}\n"));
        }
    }
    s
}
