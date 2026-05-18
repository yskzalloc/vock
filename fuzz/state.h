#ifndef VOCK_FUZZ_STATE_H
#define VOCK_FUZZ_STATE_H

#define MAX_FDS 256

/* Live FD tracking — syzkaller analysis.go state struct */
struct fd_state {
	int fds[MAX_FDS];
	int nfds;
};

void fd_state_init(struct fd_state *s);
void fd_state_track(struct fd_state *s, long nr, long *args, long ret);
int  fd_state_get_valid(struct fd_state *s);

#endif
