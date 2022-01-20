/* 
 *  rocks/sockopt.c
 *
 *  Sockets API implementation for setsockopt and getsockopt.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "log.h"

int
rs_setsockopt(int s, int level, int optname,
	      const void *optval, socklen_t optlen)
{
	if (level == SOL_SOCKET && optname == SO_KEEPALIVE) {
		rs_log("Ignoring app KEEPALIVE");
		return 0;
	}
	if (level == SOL_SOCKET && optname == SO_SNDBUF) {
		rs_log("Ignoring app SO_SNDBUF (%d)", *(unsigned long*)optval);
		return 0;
	}
	if (level == SOL_SOCKET && optname == SO_RCVBUF) {
		rs_log("Ignoring app SO_RCVBUF (%d)", *(unsigned long*)optval);
		return 0;
	}
	if (level == SOL_SOCKET && optname == SO_LINGER) {
		struct linger *lo = (struct linger *)optval;
		rs_log("Ignoring app LINGER { l_onoff = %d, l_linger = %d }",
		       lo->l_onoff, lo->l_linger);
		return 0;
	}
	return setsockopt(s, level, optname, optval, optlen);
}

int
rs_fcntl(int fd, int cmd, long arg)
{
	if (cmd == F_SETFL && (arg & O_NONBLOCK)) {
		rs_log("Not ignoring app NONBLOCK");
		fcntl(fd, cmd, O_NONBLOCK);
		return 0;
	} else if (cmd == F_DUPFD) {
		rs_log("SHIT! Ignoring app F_DUPFD");
		return 0;
	}
	return fcntl(fd, cmd, arg);
}

int
rs_ioctl(int fd, int cmd, long arg)
{
	return ioctl(fd, cmd, arg);
}
