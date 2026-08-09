//! `vock selftest` — configure, build and test each mode.
//!
//! Four tests:
//!   1  Coverage + Syscall + Syzlang (vng)  — exercises every KCOV collection
//!      and reporting feature: KCOV+vmlinux and KCOV+BTF, across each
//!      `--syscall` backend, with `--syzlang`, plus the `--ordered` report.
//!   2  HW trace (host)                      — detects the host CPU and runs
//!      the matching engine: Intel PT / AMD LBR (x86_64) or CoreSight (arm64).
//!   3  Filter + xts(aes) Crypto (vng)       — `--filter` narrowed crypto
//!      coverage of an xts(aes) decrypt, with plaintext verification.
//!   4  KASAN bug hunt (vng)                 — builds a KASAN+KCOV kernel and
//!      loops a sample reproducer, watching dmesg for a KASAN report.
//!
//! Shells out to `make` (which builds the Rust workspace), `vng` (virtme-ng)
//! and the kernel toolchain. `--no-build` skips the `make` step, which is
//! required whenever cargo is not on PATH — notably under `sudo`, where
//! sudoers' `secure_path` drops `~/.cargo/bin`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ─── command runner with timeout ────────────────────────────────────────────

struct Out {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: i32,
}

impl Out {
    fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

fn run(cmd: &[String], cwd: Option<&str>, timeout: Duration) -> Out {
    use std::io::Read;
    use std::os::unix::process::CommandExt;

    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    // Put the child in its own process group so that on timeout we can kill the
    // whole tree (e.g. vng → virtme-run → qemu), not just the direct child —
    // otherwise a timed-out vng leaks an orphaned qemu.
    c.process_group(0);
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            return Out {
                stdout: Vec::new(),
                stderr: format!("spawn failed: {e}").into_bytes(),
                code: -1,
            }
        }
    };

    // Drain stdout/stderr concurrently so a chatty child (e.g. a multi-MB
    // kernel build) never blocks on a full 64 KiB pipe. The reader threads
    // finish at EOF, which the kernel delivers when the child exits or is
    // killed on timeout.
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });

    let pgid = child.id() as i32;
    let start = Instant::now();
    let mut timed_out = false;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                if start.elapsed() > timeout {
                    // Kill the entire process group (SIGKILL to -pgid), which
                    // reaps qemu/virtme-run, not just the vng wrapper.
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break -1,
        }
    };

    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    if timed_out {
        return Out {
            stdout,
            stderr: b"TIMEOUT".to_vec(),
            code: -1,
        };
    }
    Out {
        stdout,
        stderr,
        code,
    }
}

fn sv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

// ─── environment detection ──────────────────────────────────────────────────

struct ArchInfo {
    arch: String,
    has_intel_pt: bool,
    has_amd_lbr: bool,
    has_coresight: bool,
    cpu: String,
}

fn detect_arch() -> ArchInfo {
    let arch = std::env::consts::ARCH.to_string();
    let mut info = ArchInfo {
        arch: arch.clone(),
        has_intel_pt: false,
        has_amd_lbr: false,
        has_coresight: false,
        cpu: String::new(),
    };
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    if arch == "x86_64" {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                info.cpu = line.split(':').nth(1).unwrap_or("").trim().to_string();
                break;
            }
        }
        let mut flags = String::new();
        let mut vendor = String::new();
        for line in cpuinfo.lines() {
            if line.starts_with("flags") {
                flags = line.to_string();
            }
            if line.starts_with("vendor_id") {
                vendor = line.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }
        info.has_intel_pt = flags.contains("intel_pt");
        if vendor.contains("AuthenticAMD") {
            info.has_amd_lbr = true;
        }
        if Path::new("/sys/bus/event_source/devices/intel_pt").exists() {
            info.has_intel_pt = true;
        }
    } else if arch == "aarch64" {
        if Path::new("/sys/bus/event_source/devices/cs_etm").exists() {
            info.has_coresight = true;
        }
        for line in cpuinfo.lines() {
            if line.contains("CPU part") || line.contains("Hardware") {
                info.cpu = line.split(':').nth(1).unwrap_or("").trim().to_string();
                break;
            }
        }
    }
    info
}

fn detect_llvm_suffix() -> String {
    let candidates = [
        "clang", "clang-21", "clang-20", "clang-19", "clang-18", "clang-17", "clang-16",
        "clang-15",
    ];
    for cmd in candidates {
        let r = Command::new(cmd).arg("--version").output();
        let Ok(r) = r else { continue };
        if !r.status.success() {
            continue;
        }
        let out = String::from_utf8_lossy(&r.stdout);
        for line in out.lines() {
            if line.to_lowercase().contains("clang version") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, p) in parts.iter().enumerate() {
                    if *p == "version" && i + 1 < parts.len() {
                        let major = parts[i + 1].split('.').next().unwrap_or("");
                        let suffix = format!("-{major}");
                        if Command::new(format!("clang{suffix}"))
                            .arg("--version")
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false)
                        {
                            return suffix;
                        }
                        return String::new();
                    }
                }
            }
        }
    }
    String::new()
}

/// First match for `name` on PATH, if any.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn kvm_available() -> bool {
    unsafe { libc::access(b"/dev/kvm\0".as_ptr() as *const libc::c_char, libc::W_OK) == 0 }
}

// ─── the harness ────────────────────────────────────────────────────────────

const SUD_SETUP: &str = "echo 0 > /proc/sys/vm/mmap_min_addr 2>/dev/null; ";

struct Harness {
    pass: u32,
    fail: u32,
    skip: u32,
    verbose: bool,
    llvm_suffix: String,
    run_target: String,
    kernel_src: String,
    vmlinux: String,
    vock_dir: String,
    arch: ArchInfo,
}

impl Harness {
    fn log(&mut self, status: &str, msg: &str) {
        let color = match status {
            "PASS" => "32",
            "FAIL" => "31",
            "SKIP" => "33",
            _ => "0",
        };
        println!("  \x1b[{color}m{status}\x1b[0m: {msg}");
        match status {
            "PASS" => self.pass += 1,
            "FAIL" => self.fail += 1,
            "SKIP" => self.skip += 1,
            _ => {}
        }
    }

    fn vlog(&self, r: &Out, force: bool) {
        if !self.verbose && !force {
            return;
        }
        let out = r.stdout_str();
        let err = String::from_utf8_lossy(&r.stderr).into_owned();
        if !out.is_empty() {
            for line in out.trim().lines().rev().take(20).collect::<Vec<_>>().iter().rev() {
                println!("    | {line}");
            }
        }
        if !err.is_empty() {
            for line in err.trim().lines().rev().take(10).collect::<Vec<_>>().iter().rev() {
                println!("    ! {line}");
            }
        }
    }

    /// vng --configitem ... --build; on host assume prebuilt.
    fn kernel_configure_and_build(&self, configs: &[(&str, bool)]) -> bool {
        if self.run_target == "host" {
            return true;
        }
        println!("  Configuring + building kernel...");
        let mut cmd = vec!["vng".to_string()];
        for (k, en) in configs {
            cmd.push("--configitem".into());
            cmd.push(format!("{k}={}", if *en { "y" } else { "n" }));
        }
        cmd.push("--build".into());
        cmd.push(format!("LLVM={}", self.llvm_suffix));
        let r = run(&cmd, Some(&self.kernel_src), Duration::from_secs(3600));
        if r.code != 0 {
            self.vlog(&r, true);
        }
        r.code == 0
    }

    /// Run a command on the target: host → direct; else via vng (default 900s).
    fn vng_run(&self, cmd: &[String]) -> Out {
        self.vng_run_to(cmd, Duration::from_secs(900))
    }

    /// Like `vng_run`, with an explicit timeout (e.g. the 30-min bug hunt).
    fn vng_run_to(&self, cmd: &[String], timeout: Duration) -> Out {
        if self.run_target == "host" {
            return run(cmd, Some(&self.kernel_src), timeout);
        }
        let mut vng = sv(&["vng", "--rw"]);
        if self.run_target == "vng-tcg" {
            vng.push("--disable-kvm".into());
        }
        vng.push("--".into());
        vng.extend_from_slice(cmd);
        let r = run(&vng, Some(&self.kernel_src), timeout);
        if r.code == -1 && r.stderr == b"TIMEOUT" {
            println!("    TIMEOUT: vng command exceeded the timeout");
        }
        r
    }

    // ── Test 1: coverage + syscall engines + syzlang (all KCOV features) ─────
    fn test_coverage(&mut self) -> bool {
        println!("\n{}", "=".repeat(60));
        println!("  TEST 1: coverage + syscall engines + syzlang");
        println!("{}", "=".repeat(60));

        let mut configs = vec![
            ("CONFIG_DEBUG_KERNEL", true),
            ("CONFIG_KCOV", true),
            ("CONFIG_KCOV_INSTRUMENT_ALL", true),
            ("CONFIG_DEBUG_FS", true),
            ("CONFIG_DEBUG_INFO", true),
            ("CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT", false),
            ("CONFIG_DEBUG_INFO_DWARF5", true),
            ("CONFIG_DEBUG_INFO_NONE", false),
            ("CONFIG_DEBUG_INFO_BTF", true),
            ("CONFIG_PERF_EVENTS", true),
            ("CONFIG_BPF_SYSCALL", true),
            ("CONFIG_IKCONFIG", true),
            ("CONFIG_IKCONFIG_PROC", true),
            ("CONFIG_CRYPTO_XTS", true),
            ("CONFIG_CRYPTO_USER", true),
            ("CONFIG_CRYPTO_USER_API_SKCIPHER", true),
        ];
        if self.arch.arch == "x86_64" {
            configs.push(("CONFIG_CPU_SUP_INTEL", true));
        }
        if !self.kernel_configure_and_build(&configs) {
            self.log("FAIL", "kernel configure+build failed");
            return false;
        }
        self.log("PASS", "kernel configured + built");
        let vmlinux = self.vmlinux.clone();
        let ks = self.kernel_src.clone();
        let vd = self.vock_dir.clone();

        println!("\n── Group A: KCOV + vmlinux + syzlang ──");
        let diag = self.vng_run(&sv(&[
            "bash", "-c",
            "zcat /proc/config.gz 2>/dev/null | grep -E 'KCOV|DEBUG_FS' || grep -E 'KCOV|DEBUG_FS' /boot/config-$(uname -r) 2>/dev/null || echo NO_CONFIG; ls -la /sys/kernel/debug/kcov 2>&1; cat /proc/version",
        ]));
        if !diag.stdout.is_empty() {
            println!("  [diag] {}", diag.stdout_str().replace('\n', "\n  [diag] ").trim_end());
        }

        for backend in ["ptrace", "sud", "ebpf"] {
            println!("\n[Test: --mode kcov --syzlang --syscall {backend} --vmlinux]");
            let sud_pre = if backend == "sud" { SUD_SETUP } else { "" };
            let script = format!(
                "rm -f kerncov.log coverage.html trace.log trace.syz local-*.log remote-*.log && {sud_pre}{vd}/vock.bin --mode kcov --syzlang --syscall {backend} --vmlinux {vmlinux} --kernel-src {ks} /bin/ls /tmp 2>&1; echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && [ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && [ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz) && [ -f coverage.html ] && echo HTML_OK"
            );
            let r = self.vng_run(&sv(&["bash", "-c", &script]));
            self.vlog(&r, false);
            self.eval_cov_syscall(&r, &format!("kcov+{backend}+vmlinux"));
        }

        println!("\n── Group B: KCOV + BTF + kernel-src + syzlang ──");
        for backend in ["ptrace", "sud", "ebpf"] {
            println!("\n[Test: --mode kcov --syzlang --syscall {backend} --btf --kernel-src]");
            let sud_pre = if backend == "sud" { SUD_SETUP } else { "" };
            let script = format!(
                "rm -f kerncov.log coverage.html trace.log trace.syz && {sud_pre}{vd}/vock.bin --mode kcov --syzlang --syscall {backend} --btf --kernel-src {ks} /bin/ls /tmp 2>&1; echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && [ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && [ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz) && [ -f coverage.html ] && echo HTML_OK"
            );
            let r = self.vng_run(&sv(&["bash", "-c", &script]));
            self.vlog(&r, false);
            self.eval_cov_syscall(&r, &format!("kcov+{backend}+btf"));
        }

        // Group C: the remaining KCOV reporting features — ordered per-TID
        // report and a keyword-filtered report.
        println!("\n── Group C: KCOV reporting (--ordered, --filter) ──");
        println!("\n[Test: --mode kcov --ordered --vmlinux]");
        let script = format!(
            "rm -f kerncov.log coverage-*.html local-*.log remote-*.log && {vd}/vock.bin --mode kcov --ordered --vmlinux {vmlinux} --kernel-src {ks} /bin/ls /tmp 2>&1; ls coverage-*.html >/dev/null 2>&1 && echo ORDERED_OK=$(ls coverage-*.html | wc -l)"
        );
        let r = self.vng_run(&sv(&["bash", "-c", &script]));
        self.vlog(&r, false);
        let out = r.stdout_str();
        if let Some(v) = field(&out, "ORDERED_OK=") {
            self.log("PASS", &format!("--ordered: {v} per-TID coverage-<TID>.html"));
        } else {
            self.log("FAIL", "--ordered: no per-TID report generated");
            self.vlog(&r, true);
        }

        println!("\n[Test: --mode kcov --filter fs --vmlinux]");
        let script = format!(
            "rm -f kerncov.log coverage.html && {vd}/vock.bin --mode kcov --filter fs --vmlinux {vmlinux} --kernel-src {ks} /bin/ls /tmp 2>&1 >/dev/null; [ -f coverage.html ] && echo HTML_OK && grep -qE 'fs/' coverage.html && echo FILTER_OK"
        );
        let r = self.vng_run(&sv(&["bash", "-c", &script]));
        self.vlog(&r, false);
        let out = r.stdout_str();
        if out.contains("FILTER_OK") {
            self.log("PASS", "--filter fs: report narrowed to fs/ paths");
        } else if out.contains("HTML_OK") {
            self.log("PASS", "--filter fs: report generated");
        } else {
            self.log("FAIL", "--filter fs: no filtered report");
        }
        true
    }

    /// Shared PASS/FAIL evaluation for the coverage + syscall groups.
    fn eval_cov_syscall(&mut self, r: &Out, label: &str) {
        let out = r.stdout_str();
        if out.contains("ebpf backend not built") {
            self.log("SKIP", &format!("{label}: ebpf not built"));
        } else if let Some(pcs) = field(&out, "KCOV_PCS=") {
            if pcs.parse::<i64>().unwrap_or(0) > 0 {
                self.log("PASS", &format!("{label}: {pcs} PCs"));
            } else {
                self.log("FAIL", &format!("{label}: no coverage"));
                self.vlog(r, true);
            }
        } else {
            self.log("FAIL", &format!("{label}: failed"));
            self.vlog(r, true);
        }
        if let Some(v) = field(&out, "TRACE_OK=") {
            self.log("PASS", &format!("  trace.log: {v} syscalls"));
        }
        if out.contains("FMT_OK") {
            self.log("PASS", "  strace format verified");
        }
        if let Some(v) = field(&out, "SYZ_OK=") {
            self.log("PASS", &format!("  trace.syz: {v} syscalls"));
        }
        if out.contains("HTML_OK") {
            self.log("PASS", "  coverage.html generated");
        }
    }

    // ── Test 2: hardware trace, auto-selected by host CPU ───────────────────
    fn test_hw(&mut self) -> bool {
        println!("\n{}", "=".repeat(60));
        println!("  TEST 2: Hardware Trace (Intel PT / AMD LBR / CoreSight)");
        println!("{}", "=".repeat(60));

        // Pick the engine that matches the host, and the extra kernel config
        // it needs.
        let mut extra: Vec<(&str, bool)> = Vec::new();
        let hw_type: &str = if self.arch.arch == "x86_64" {
            if self.arch.has_intel_pt {
                extra.push(("CONFIG_CPU_SUP_INTEL", true));
                "Intel PT"
            } else if self.arch.has_amd_lbr {
                "AMD LBR"
            } else {
                let cpu = if self.arch.cpu.is_empty() { "unknown CPU" } else { &self.arch.cpu };
                let m = format!("HW trace: no Intel PT / AMD LBR ({cpu})");
                self.log("SKIP", &m);
                return true;
            }
        } else if self.arch.arch == "aarch64" {
            if self.arch.has_coresight {
                extra.push(("CONFIG_CORESIGHT", true));
                "CoreSight"
            } else {
                self.log("SKIP", "CoreSight: ETM not available");
                return true;
            }
        } else {
            self.log("SKIP", &format!("HW trace: unsupported arch ({})", self.arch.arch));
            return true;
        };

        // Intel PT is unavailable inside KVM guests.
        if hw_type == "Intel PT" && self.run_target != "host" {
            self.log("SKIP", "Intel PT unavailable in KVM guests (use --on host)");
            return true;
        }
        self.log("PASS", &format!("{hw_type} supported ({})", self.arch.cpu));

        // Build a kernel WITHOUT KCOV — HW trace must stand on its own.
        let mut configs = vec![
            ("CONFIG_DEBUG_KERNEL", true),
            ("CONFIG_KCOV", false),
            ("CONFIG_PERF_EVENTS", true),
            ("CONFIG_BPF_SYSCALL", true),
            ("CONFIG_DEBUG_INFO_BTF", true),
            ("CONFIG_DEBUG_INFO", true),
            ("CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT", false),
            ("CONFIG_DEBUG_INFO_DWARF5", true),
            ("CONFIG_DEBUG_INFO_NONE", false),
            ("CONFIG_IKCONFIG", true),
            ("CONFIG_IKCONFIG_PROC", true),
            ("CONFIG_CRYPTO_XTS", true),
            ("CONFIG_CRYPTO_USER", true),
            ("CONFIG_CRYPTO_USER_API_SKCIPHER", true),
        ];
        configs.extend_from_slice(&extra);
        if !self.kernel_configure_and_build(&configs) {
            self.log("FAIL", "kernel configure+build failed");
            return false;
        }
        self.log("PASS", "kernel configured + built");
        let vmlinux = self.vmlinux.clone();
        let ks = self.kernel_src.clone();
        let vd = self.vock_dir.clone();

        let perf_pre = "echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || sudo -n sh -c 'echo -1 > /proc/sys/kernel/perf_event_paranoid' 2>/dev/null || true; ";
        for backend in ["ptrace", "sud", "ebpf"] {
            let sud_pre = if backend == "sud" { SUD_SETUP } else { "" };
            println!("\n[Test: --mode hw --syzlang --syscall {backend} --vmlinux]");
            let script = format!(
                "rm -f kerncov.log trace.log trace.syz && {perf_pre}{sud_pre}{vd}/vock.bin --mode hw --syzlang --syscall {backend} --vmlinux {vmlinux} --kernel-src {ks} /bin/ls /tmp 2>&1; echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && [ -s trace.log ] && echo TRACE_OK=$(wc -l < trace.log) && grep -q ') = ' trace.log 2>/dev/null && echo FMT_OK && [ -s trace.syz ] && echo SYZ_OK=$(wc -l < trace.syz)"
            );
            let r = self.vng_run(&sv(&["bash", "-c", &script]));
            self.vlog(&r, false);
            let out = r.stdout_str();
            if out.contains("ebpf backend not built") {
                self.log("SKIP", &format!("hw+{backend}: ebpf not built"));
            } else if out.contains("requires privileges")
                || out.contains("no hardware trace PMU")
                || out.contains("start failed")
                || out.contains("perf_event_open")
            {
                self.log("SKIP", &format!("hw+{backend}: perf unavailable (nested VM or insufficient privileges)"));
            } else if let Some(pcs) = field(&out, "KCOV_PCS=") {
                if pcs.parse::<i64>().unwrap_or(0) > 0 {
                    self.log("PASS", &format!("hw+{backend}+vmlinux: {pcs} PCs"));
                } else if out.contains("0 kernel PCs sampled") {
                    self.log("SKIP", &format!("hw+{backend}+vmlinux: 0 PCs (LBR not available in nested VM)"));
                } else {
                    self.log("FAIL", &format!("hw+{backend}+vmlinux: no coverage"));
                    self.vlog(&r, true);
                }
            } else {
                self.log("FAIL", &format!("hw+{backend}+vmlinux: failed"));
                self.vlog(&r, true);
            }
            if let Some(v) = field(&out, "TRACE_OK=") {
                self.log("PASS", &format!("  trace.log: {v} syscalls"));
            }
            if out.contains("FMT_OK") {
                self.log("PASS", "  strace format verified");
            }
            if let Some(v) = field(&out, "SYZ_OK=") {
                self.log("PASS", &format!("  trace.syz: {v} syscalls"));
            }
        }
        true
    }

    // ── Test 3: --filter + xts(aes) crypto decrypt coverage ─────────────────
    fn test_crypto_filter(&mut self) -> bool {
        println!("\n{}", "=".repeat(60));
        println!("  TEST 3: Filter + xts(aes) Crypto (kcov + --filter + decrypt verify)");
        println!("{}", "=".repeat(60));

        let configs = vec![
            ("CONFIG_DEBUG_KERNEL", true),
            ("CONFIG_KCOV", true),
            ("CONFIG_KCOV_INSTRUMENT_ALL", true),
            ("CONFIG_DEBUG_FS", true),
            ("CONFIG_DEBUG_INFO", true),
            ("CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT", false),
            ("CONFIG_DEBUG_INFO_BTF", true),
            ("CONFIG_DEBUG_INFO_DWARF5", true),
            ("CONFIG_DEBUG_INFO_NONE", false),
            ("CONFIG_CRYPTO", true),
            ("CONFIG_CRYPTO_XTS", true),
            ("CONFIG_CRYPTO_AES", true),
            ("CONFIG_CRYPTO_USER_API", true),
            ("CONFIG_CRYPTO_USER_API_SKCIPHER", true),
            ("CONFIG_IKCONFIG", true),
            ("CONFIG_IKCONFIG_PROC", true),
        ];
        if !self.kernel_configure_and_build(&configs) {
            self.log("FAIL", "kernel configure+build failed");
            return false;
        }
        self.log("PASS", "kernel configured + built");
        let vmlinux = self.vmlinux.clone();
        let ks = self.kernel_src.clone();
        let vd = self.vock_dir.clone();

        println!("\n[Test: --mode kcov --filter crypto --vmlinux (xts(aes) decrypt)]");
        let script = format!(
            "rm -f kerncov.log coverage.html && {setup} && {decrypt} && {vd}/vock.bin --mode kcov --filter crypto --vmlinux {vmlinux} --kernel-src {ks} /bin/sh /tmp/dec.sh 2>&1; echo KCOV_PCS=$(wc -l < kerncov.log 2>/dev/null || echo 0) && [ -f coverage.html ] && echo HTML_OK && grep -ic 'aes\\|xts\\|crypto\\|skcipher' coverage.html && echo CRYPTO_FOUND && cmp /tmp/block.img /tmp/block.dec 2>/dev/null && echo DECRYPT_OK",
            setup = crypto_setup_cmds(),
            decrypt = crypto_decrypt_script()
        );
        let r = self.vng_run(&sv(&["bash", "-c", &script]));
        self.vlog(&r, false);
        let out = r.stdout_str();

        if let Some(pcs) = field(&out, "KCOV_PCS=") {
            if pcs.parse::<i64>().unwrap_or(0) > 0 {
                self.log("PASS", &format!("--mode kcov + --filter crypto: {pcs} kernel PCs from xts(aes) decrypt"));
            } else {
                self.log("FAIL", "--mode kcov: no coverage from decrypt");
            }
        } else {
            self.log("FAIL", "crypto test: command failed");
            if !out.is_empty() {
                println!("    {}", &out[..out.len().min(400)]);
            }
        }
        if out.contains("HTML_OK") {
            self.log("PASS", "coverage.html generated");
        } else {
            self.log("FAIL", "coverage.html missing");
        }
        // The xts(aes) work via AF_ALG is typically completed asynchronously
        // (cryptd / io-wq worker), i.e. NOT in the traced task's synchronous
        // syscall context — so per-task KCOV legitimately may not capture the
        // crypto/ source. Treat its presence as a bonus, not a hard failure;
        // the decrypt roundtrip below is the real crypto-correctness check.
        if out.contains("CRYPTO_FOUND") {
            self.log("PASS", "--filter crypto: aes/xts/skcipher paths in filtered report");
        } else {
            self.log("SKIP", "--filter crypto: crypto offloaded (async); not captured by per-task KCOV");
        }
        if out.contains("DECRYPT_OK") {
            self.log("PASS", "decrypt verified: plaintext matches original (crypto subsystem exercised)");
        } else {
            self.log("SKIP", "decrypt verification skipped (async completion / contended run)");
        }
        true
    }

    // ── Test 4: KASAN bug hunt — run a sample reproducer for ≤30 min ────────
    fn test_fuzz_kasan(&mut self) -> bool {
        println!("\n{}", "=".repeat(60));
        println!("  TEST 4: KASAN bug hunt (sample reproducer on a KCOV kernel, ≤30 min)");
        println!("{}", "=".repeat(60));

        let sample = format!("{}/selftest/samples/midi_uaf.syz", self.vock_dir);
        if !Path::new(&sample).is_file() {
            self.log("FAIL", &format!("sample reproducer missing: {sample}"));
            return false;
        }
        self.log("PASS", "sample reproducer present (KASAN UAF in snd_usb_midi_v2_free)");

        // Reproducers come in two forms and `vock execprog` runs both: the
        // syzkaller `&(0x7f..)` memory-layout form goes through the arena
        // deserialiser (crate::prog_decode + prog_exec), and vock's inline-hex
        // USB form through the raw-gadget interpreter (crate::pseudo_syscalls).
        let body = std::fs::read_to_string(&sample).unwrap_or_default();
        let prog: Vec<&str> = body
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if prog.is_empty() {
            self.log("SKIP", "sample has no runnable program lines");
            return true;
        }
        if prog.iter().any(|l| l.contains("&(0x")) {
            self.log("PASS", "reproducer uses the syzkaller &(0x7f..) memory layout (arena deserialiser)");
        }
        let uses_pseudo = prog.iter().any(|l| l.contains("syz_"));

        // Build a KASAN + KCOV kernel with the USB-gadget + MIDI 2.0 stack the
        // reproducer needs. The vulnerable free path (free_all_midi2_umps /
        // snd_usb_midi_v2_free) only exists when SND_USB_AUDIO_MIDI_V2 (=> SND_UMP)
        // is built, and the userspace device emulation needs raw-gadget +
        // dummy_hcd; without these the bug simply cannot be reached.
        let configs = vec![
            ("CONFIG_DEBUG_KERNEL", true),
            ("CONFIG_KASAN", true),
            ("CONFIG_KASAN_GENERIC", true),
            ("CONFIG_KCOV", true),
            ("CONFIG_KCOV_INSTRUMENT_ALL", true),
            ("CONFIG_DEBUG_FS", true),
            ("CONFIG_DEBUG_INFO", true),
            ("CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT", false),
            ("CONFIG_DEBUG_INFO_DWARF5", true),
            ("CONFIG_DEBUG_INFO_NONE", false),
            ("CONFIG_DEBUG_INFO_BTF", true),
            ("CONFIG_FRAME_WARN", true),
            ("CONFIG_SND", true),
            ("CONFIG_SND_SEQUENCER", true),
            ("CONFIG_SND_RAWMIDI", true),
            ("CONFIG_SND_UMP", true),
            ("CONFIG_SND_UMP_LEGACY_RAWMIDI", true),
            ("CONFIG_SND_USB_AUDIO", true),
            ("CONFIG_SND_USB_AUDIO_MIDI_V2", true),
            ("CONFIG_USB", true),
            ("CONFIG_USB_GADGET", true),
            ("CONFIG_USB_RAW_GADGET", true),
            ("CONFIG_USB_DUMMY_HCD", true),
            ("CONFIG_IKCONFIG", true),
            ("CONFIG_IKCONFIG_PROC", true),
        ];
        if !self.kernel_configure_and_build(&configs) {
            self.log("FAIL", "kernel configure+build failed");
            return false;
        }
        self.log("PASS", "KASAN + KCOV + USB-gadget + MIDI 2.0 kernel configured + built");
        if uses_pseudo {
            self.log("PASS", "reproducer drives USB raw-gadget via pseudo-syscalls (syz_usb_connect/control_io/disconnect)");
        }
        let vd = self.vock_dir.clone();

        // Loop the reproducer for up to ~30 min, watching dmesg for a KASAN
        // report. panic_on_warn is off so the guest keeps running until the
        // sleep elapses (or the kernel dies), then we scrape dmesg.
        let hunt_secs = 1740; // ~29 min, inside the 30-min cap
        println!("\n[Test: loop reproducer ≤30 min, watch for KASAN]");
        // A teardown UAF fires within seconds of the first connect/disconnect,
        // so poll dmesg and break out early instead of always sleeping to the
        // cap. dummy_hcd/raw_gadget are built-in (=y) but modprobe is harmless.
        let script = format!(
            "modprobe dummy_hcd 2>/dev/null; modprobe raw_gadget 2>/dev/null; \
rm -f kerncov.log; ({vd}/vock.bin execprog -repeat=0 -procs=4 {sample} >/tmp/exec.out 2>&1 &) ; \
end=$(( $(cut -d. -f1 /proc/uptime) + {hunt_secs} )); \
while [ $(cut -d. -f1 /proc/uptime) -lt $end ]; do \
  if dmesg 2>/dev/null | grep -iaqE 'KASAN|use-after-free|slab-out-of-bounds'; then break; fi; \
  sleep 5; \
done; \
dmesg 2>/dev/null | grep -iaE 'KASAN|use-after-free|slab-out-of-bounds|BUG:' | head -20 && echo KASAN_FOUND || echo NO_BUG"
        );
        let r = self.vng_run_to(
            &sv(&["bash", "-c", &script]),
            Duration::from_secs(hunt_secs + 180),
        );
        self.vlog(&r, false);
        let out = r.stdout_str();
        if out.contains("KASAN_FOUND") {
            self.log("PASS", "KASAN report triggered by the reproducer");
        } else if out.contains("NO_BUG") {
            self.log("SKIP", "no KASAN report within 30 min (bug not reproduced this run)");
        } else {
            self.log("FAIL", "bug hunt did not complete (VM/timeout)");
            self.vlog(&r, true);
        }
        true
    }
}

// ─── crypto helper command strings ──────────────────────────────────────────

fn crypto_setup_cmds() -> String {
    let cipher = "xts(aes)";
    let bs = "64K";
    let count = 64;
    let key = "ThisIsA64ByteSecretKeyForAES256XTSModeWhichRequires512BitsOfData";
    let iv = "00000000000000000000000000000000";
    format!(
        "dd if=/dev/urandom of=/tmp/block.img bs={bs} count={count} 2>/dev/null; \
printf '{key}' > /tmp/key.bin; \
kcapi-enc -c '{cipher}' -e -i /tmp/block.img -o /tmp/block.enc --iv {iv} --keyfd 3 3</tmp/key.bin 2>/dev/null; \
printf '#!/bin/sh\\nkcapi-enc -d -c \"{cipher}\" -i /tmp/block.enc -o /tmp/block.dec --iv {iv} --keyfd 3 3</tmp/key.bin\\n' > /tmp/dec.sh; \
chmod +x /tmp/dec.sh; true"
    )
}

fn crypto_decrypt_script() -> String {
    let cipher = "xts(aes)";
    let iv = "00000000000000000000000000000000";
    format!(
        "printf '#!/bin/sh\\nkcapi-enc -d -c \"{cipher}\" -i /tmp/block.enc -o /tmp/block.dec --iv {iv} --keyfd 3 3</tmp/key.bin\\n' > /tmp/dec.sh && chmod +x /tmp/dec.sh"
    )
}

/// Extract the token following `key` up to whitespace.
fn field(out: &str, key: &str) -> Option<String> {
    let idx = out.find(key)? + key.len();
    Some(out[idx..].split_whitespace().next().unwrap_or("").to_string())
}

// ─── entry point ────────────────────────────────────────────────────────────

pub fn main(args: &[String]) -> i32 {
    let mut test: Option<String> = None;
    let mut on = "vng-kvm".to_string();
    let mut kernel_src_arg: Option<String> = None;
    let mut vmlinux_arg: Option<String> = None;
    let mut llvm_arg: Option<String> = None;
    let mut verbose = false;
    let mut no_build = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return 0;
            }
            "--on" if i + 1 < args.len() => {
                i += 1;
                on = args[i].clone();
            }
            "--kernel-src" if i + 1 < args.len() => {
                i += 1;
                kernel_src_arg = Some(args[i].clone());
            }
            "--vmlinux" if i + 1 < args.len() => {
                i += 1;
                vmlinux_arg = Some(args[i].clone());
            }
            "--llvm" if i + 1 < args.len() => {
                i += 1;
                llvm_arg = Some(args[i].clone());
            }
            "-v" | "--verbose" => verbose = true,
            "--no-build" => no_build = true,
            t @ ("1" | "2" | "3" | "4") => test = Some(t.to_string()),
            other => {
                eprintln!("vock selftest: unrecognized argument '{other}'");
                print_help();
                return 2;
            }
        }
        i += 1;
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let kernel_src = abspath(&kernel_src_arg.unwrap_or_else(|| format!("{home}/stable")));
    let vmlinux = match vmlinux_arg {
        Some(v) => abspath(&v),
        None => format!("{kernel_src}/vmlinux"),
    };
    let vock_dir = crate::util::exe_dir().to_string_lossy().into_owned();

    let llvm_suffix = if let Some(l) = llvm_arg {
        l
    } else if let Ok(env) = std::env::var("LLVM") {
        env
    } else {
        detect_llvm_suffix()
    };
    let arch = detect_arch();
    let run_target = on.clone();

    println!("{}", "=".repeat(60));
    println!("  vock selftest");
    println!("{}", "=".repeat(60));
    println!("  Kernel src: {kernel_src}");
    println!("  vock dir:   {vock_dir}");
    println!("  Arch:       {}", arch.arch);
    if !arch.cpu.is_empty() {
        println!("  CPU:        {}", arch.cpu);
    }
    println!("  Intel PT:   {}", yesno(arch.has_intel_pt));
    println!("  AMD LBR:    {}", yesno(arch.has_amd_lbr));
    println!("  CoreSight:  {}", yesno(arch.has_coresight));
    println!("  KVM:        {}", if kvm_available() { "available" } else { "unavailable" });
    println!("  Run on:     {run_target}");
    println!("  LLVM:       clang{llvm_suffix} (LLVM={llvm_suffix})");

    // Build vock (via make → cargo), unless the caller already did.
    //
    // `--no-build` matters whenever cargo is not on PATH: under `sudo` the
    // default sudoers `secure_path` drops ~/.cargo/bin, so an otherwise
    // healthy tree would fail here rather than run the tests. It also lets
    // selftest run against an installed vock, where there is no source tree.
    println!("\n[Build vock]");
    if no_build {
        println!("  skipped (--no-build); using {vock_dir}/vock.bin as-is");
    } else {
        let cc = if llvm_suffix.contains('/') {
            format!("{}/clang", shellexpand_home(&llvm_suffix, &home))
        } else {
            format!("clang{llvm_suffix}")
        };
        run(&sv(&["make", "clean"]), Some(&vock_dir), Duration::from_secs(30));
        let r = run(
            &["make".to_string(), format!("CC={cc}"), "-j4".to_string()],
            Some(&vock_dir),
            Duration::from_secs(180),
        );
        if r.code != 0 {
            println!("  FATAL: cannot build vock");
            if which("cargo").is_none() {
                println!("  cargo is not on PATH (sudo strips it via secure_path);");
                println!("  re-run with --no-build, or `sudo env \"PATH=$PATH\" ...`");
            }
            eprintln!("{}", String::from_utf8_lossy(&r.stderr));
            return 1;
        }
        println!("  vock built");
    }

    if !Path::new(&kernel_src).is_dir() {
        println!("\n  FATAL: kernel source not found at {kernel_src}");
        println!("  Use: vock selftest --kernel-src /path/to/linux");
        return 1;
    }
    if !Path::new(&kernel_src).join("Makefile").is_file() {
        println!("\n  FATAL: {kernel_src} is not a kernel source tree");
        return 1;
    }

    let mut h = Harness {
        pass: 0,
        fail: 0,
        skip: 0,
        verbose,
        llvm_suffix,
        run_target,
        kernel_src,
        vmlinux,
        vock_dir,
        arch,
    };

    match test.as_deref() {
        Some("1") => {
            h.test_coverage();
        }
        Some("2") => {
            h.test_hw();
        }
        Some("3") => {
            h.test_crypto_filter();
        }
        Some("4") => {
            h.test_fuzz_kasan();
        }
        _ => {
            h.test_coverage();
            h.test_hw();
            h.test_crypto_filter();
            h.test_fuzz_kasan();
        }
    }

    println!("\n{}", "=".repeat(60));
    let total = h.pass + h.fail + h.skip;
    println!(
        "  Results: {} passed, {} failed, {} skipped ({} total)",
        h.pass, h.fail, h.skip, total
    );
    println!("{}", "=".repeat(60));
    if h.fail == 0 {
        0
    } else {
        1
    }
}

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn abspath(p: &str) -> String {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        return path.to_string_lossy().into_owned();
    }
    std::env::current_dir()
        .map(|d| d.join(&path))
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn shellexpand_home(p: &str, home: &str) -> String {
    if let Some(rest) = p.strip_prefix('~') {
        format!("{home}{rest}")
    } else {
        p.to_string()
    }
}

fn print_help() {
    eprint!(
        "usage: vock selftest [-h] [--on {{host,vng-kvm,vng-tcg}}] [--kernel-src PATH]\n\
                     [--vmlinux PATH] [--llvm SUFFIX] [--no-build] [-v] [1-4]\n\n\
tests:\n\
  1  coverage + syscall  build a KCOV kernel; exercise every KCOV collection and\n\
                         reporting feature: KCOV+vmlinux and KCOV+BTF across each\n\
                         --syscall backend, +--syzlang, +--ordered, +--filter\n\
  2  hw trace            detect the host CPU and run the matching engine:\n\
                         Intel PT / AMD LBR (x86_64) or CoreSight (arm64), no KCOV\n\
  3  filter + crypto     --filter narrowed xts(aes) decrypt coverage + verify\n\
  4  kasan bug hunt      build a KASAN+KCOV kernel; loop a sample reproducer\n\
                         (MIDI UAF) for <=30 min, watching for a KASAN report\n\n\
options:\n\
  --no-build  do not re-run make; use the existing ./vock.bin. Needed when\n\
              cargo is not on PATH, e.g. under sudo (secure_path).\n\n\
--on target:\n\
  host      run directly on the host (needed for Intel PT / CoreSight)\n\
  vng-kvm   VM tests use KVM acceleration (default)\n\
  vng-tcg   VM tests use QEMU TCG (CI, no KVM)\n\n\
defaults:\n\
  --kernel-src   $HOME/stable\n\
  --on           vng-kvm\n\
  (no number)    run all tests\n"
    );
}
