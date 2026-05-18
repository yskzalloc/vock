#include "state.h"
#include <stdlib.h>

void fd_state_init(struct fd_state *s) { s->nfds = 0; }

void fd_state_track(struct fd_state *s, long nr, long *args, long ret)
{
	/* Track fd-producing syscalls */
	if (ret >= 0 && ret < MAX_FDS) {
		switch (nr) {
		case 2: case 257: case 41: case 43: case 32: case 288: case 22:
		case 437: case 434: /* openat2, pidfd_open */
			if (s->nfds < MAX_FDS) s->fds[s->nfds++] = (int)ret;
			break;
		}
	}
	/* Track close */
	if (nr == 3 && args[0] >= 0 && args[0] < MAX_FDS) {
		for (int i = 0; i < s->nfds; i++) {
			if (s->fds[i] == (int)args[0]) {
				s->fds[i] = s->fds[--s->nfds];
				break;
			}
		}
	}
}

int fd_state_get_valid(struct fd_state *s)
{
	if (s->nfds == 0) return 3;
	return s->fds[rand() % s->nfds];
}
