//! `execvp` from a `&[String]` command vector. Returns only on failure.

use std::ffi::CString;

pub fn execvp(cmd: &[String]) {
    if cmd.is_empty() {
        return;
    }
    let cargs: Vec<CString> = cmd
        .iter()
        .filter_map(|s| CString::new(s.as_bytes()).ok())
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
}
