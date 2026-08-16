//! Live FD tracking (port of fuzz/state.c), syzkaller analysis.go state.
#![allow(dead_code)]

use super::rng::Rng;

pub const MAX_FDS: usize = 256;

pub struct FdState {
    pub fds: Vec<i32>,
}

impl FdState {
    pub fn new() -> FdState {
        FdState { fds: Vec::new() }
    }

    pub fn nfds(&self) -> usize {
        self.fds.len()
    }

    /// Track fd-producing syscalls and `close`. `ret` is the syscall result,
    /// `args` its arguments.
    pub fn track(&mut self, nr: i64, args: &[i64; 6], ret: i64) {
        if ret >= 0 && (ret as usize) < MAX_FDS {
            match nr {
                // open, openat, socket, accept, dup, accept4, epoll_create,
                // openat2, pidfd_open, ...
                2 | 257 | 41 | 43 | 32 | 288 | 22 | 437 | 434 => {
                    if self.fds.len() < MAX_FDS {
                        self.fds.push(ret as i32);
                    }
                }
                _ => {}
            }
        }
        // Track close(fd).
        if nr == 3 && args[0] >= 0 && (args[0] as usize) < MAX_FDS {
            if let Some(idx) = self.fds.iter().position(|&f| f == args[0] as i32) {
                self.fds.swap_remove(idx);
            }
        }
    }

    /// Return a live fd, or the default 3 when none are tracked.
    pub fn get_valid(&self, rng: &mut Rng) -> i32 {
        if self.fds.is_empty() {
            return 3;
        }
        self.fds[rng.below(self.fds.len() as i64) as usize]
    }
}
