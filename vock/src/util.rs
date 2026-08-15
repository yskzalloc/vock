//! Small process/filesystem helpers used across modules.

use std::path::{Path, PathBuf};

/// Directory containing the running `vock` executable (mirrors the C
/// `readlink("/proc/self/exe")` + `dirname`). Used to locate `mode/kcov.so`,
/// and previously `output.py` / `selftest/run.py`.
pub fn exe_dir() -> PathBuf {
    std::fs::read_link("/proc/self/exe")
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Locate the `kcov.so` LD_PRELOAD shim.
///
/// The same binary has to work from a build tree and from a packaged install,
/// so the shim is looked up in order:
///
/// 1. `$VOCK_KCOV_SO` — explicit override, for unusual layouts and testing.
/// 2. `<exe dir>/mode/kcov.so` — the build tree and any relocatable unpack.
/// 3. The FHS locations a distribution package uses. `/usr/bin/vock` must not
///    look for `/usr/bin/mode/kcov.so`.
///
/// Returns the first existing candidate, falling back to the build-tree path
/// so the error message names something meaningful.
pub fn kcov_preload_path() -> PathBuf {
    if let Ok(p) = std::env::var("VOCK_KCOV_SO") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let build_tree = exe_dir().join("mode").join("kcov.so");
    if build_tree.exists() {
        return build_tree;
    }
    // PREFIX-relative install (`make install PREFIX=...`): the shim lands in
    // <prefix>/lib/vock/kcov.so next to <prefix>/bin/vock, wherever the
    // prefix is (e.g. ~/.local), so probe relative to the binary.
    let prefix_lib = exe_dir().join("..").join("lib").join("vock").join("kcov.so");
    if prefix_lib.exists() {
        return prefix_lib;
    }
    for c in kcov_preload_system_paths() {
        if c.exists() {
            return c;
        }
    }
    build_tree
}

/// The FHS locations [`kcov_preload_path`] searches after the build tree.
/// The Debian package installs to the first of these.
pub fn kcov_preload_system_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(triple) = option_env!("VOCK_MULTIARCH") {
        v.push(PathBuf::from(format!("/usr/lib/{triple}/vock/kcov.so")));
    }
    v.push(PathBuf::from("/usr/lib/vock/kcov.so"));
    v.push(PathBuf::from("/usr/libexec/vock/kcov.so"));
    v.push(PathBuf::from("/usr/local/lib/vock/kcov.so"));
    v
}

/// Copy a file byte-for-byte, silently doing nothing on error (matches the
/// best-effort semantics of the C `vock_copy_file`).
pub fn copy_file(src: &str, dst: &str) {
    if let Ok(data) = std::fs::read(src) {
        let _ = std::fs::write(dst, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Debian package installs the shim to /usr/lib/vock/kcov.so, so that
    /// path must stay in the compiled-in search list — otherwise an installed
    /// vock cannot find its own preload shim.
    #[test]
    fn packaged_shim_path_is_searched() {
        let paths = kcov_preload_system_paths();
        assert!(
            paths.iter().any(|p| p == std::path::Path::new("/usr/lib/vock/kcov.so")),
            "packaging installs to /usr/lib/vock/kcov.so; search list was {paths:?}"
        );
    }

    #[test]
    fn explicit_override_wins() {
        // Safe here: the test binary is single-threaded for this variable and
        // no other test reads it.
        std::env::set_var("VOCK_KCOV_SO", "/nonexistent/custom.so");
        assert_eq!(kcov_preload_path(), std::path::Path::new("/nonexistent/custom.so"));
        std::env::remove_var("VOCK_KCOV_SO");
    }
}
