/* 
 *  rocks/1of2.c
 *
 *  1 connection from 2 symmetric connection attempts.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
/*
  Each end simultaneously attempts to establish a new connection with
  its peer.  The problem is getting both ends to agree on one
  connection.  The protocol is as follows:

  Each end sends its peer the address of a socket on which it is
  listening for an incoming connection.  Then it performs a
  non-blocking connect to its peer's listening socket and polls this
  active socket and the passive listening socket, waiting for an
  connection to be established.

  The remaining behavior depends on whether the role of the end in the
  original connection was CLIENT or SERVER.

  SERVERs send an ack byte on the first established connection.  If
  two connections are ready at the same time (i.e., select returns
  them both being ready), then the server first tries the active one.

  CLIENTs wait for an ack byte on established connections.  If both
  are ready, they check the passive one before the active one.

  The first connection on which the read or write is successful is
  chosen as the connection; the other, if established, is closed.

  I am quite interested in making this protocol role independent.  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include "rs.h"
#include "log.h"

/* return -1 if A is a smaller time value than B,
           0 if they are equal, or
	   1 if A is a bigger time value than B. */
static int
tv_cmp(const struct timeval *a,	const struct timeval *b)
{
	if (a->tv_sec < b->tv_sec)
		return -1;
	if (a->tv_sec > b->tv_sec)
		return 1;
	if (a->tv_usec < b->tv_usec)
		return -1;
	if (a->tv_usec > b->tv_usec)
		return 1;
	return 0;
}

static int
timeout_expired(struct timeval *tout)
{
	struct timeval tv;
	int rv;
	rv = gettimeofday(&tv, NULL);
	assert(!rv);
	return tv_cmp(&tv, tout) >= 0;
}

/* IF *PASSIVEP or *ACTIVEP is non-negative, then
   it must a socket for an established connection */
static int
_1of2_client(int *passivep, int *activep)
{
	int pick = -1;
	char byte;
	int passive = *passivep;
	int active = *activep;
	int max;
	fd_set fds;
	struct timeval tv;

retry:
	rs_log("1of2: clients's pick: p=%d, a=%d", *passivep, *activep);
	max = 0;
	FD_ZERO(&fds);
	if (passive >= 0) {
		FD_SET(passive, &fds);
		max = MAX(max, passive);
	}
	if (active >= 0) {
		FD_SET(active, &fds);
		max = MAX(max, active);
	}
	tv.tv_sec = tv.tv_usec = 0;
	if (0 > select(max+1, &fds, NULL, NULL, &tv)) {
		if (EINTR == errno)
			goto retry;
		else {
			rs_log("1of2: client error");
			return -1;
		}
	}
	if (active >= 0 && FD_ISSET(active, &fds)) {
		if (0 >= rs_xread(active, &byte, sizeof(byte), 0)) {
			close(active);
			*activep = -1;
		} else {
			pick = active;
			close(passive);
		}
	} 
	if (pick < 0 && passive >= 0 && FD_ISSET(passive, &fds)) {
		if (0 >= rs_xread(passive, &byte, sizeof(byte), 0)) {
			close(passive);
			*passivep = -1;
		} else {
			pick = passive;
			close(active);
		}
	}
	rs_log("1of2: client picked %d", pick);
	return pick;
}

/* IF *PASSIVEP or *ACTIVEP is non-negative, then
   it must a socket for an established connection */
static int
_1of2_server(int *passivep, int *activep)
{
	int pick = -1;
	char byte;
	int passive = *passivep;
	int active = *activep;

	rs_log("1of2: server picking: p=%d, a=%d", *passivep, *activep);
	if (active >= 0) {
		if (0 > rs_xwrite(active, &byte, sizeof(byte))) {
			close(active);
			*activep = -1;
		} else {
			pick = active;
			close(passive);
		}
	} 
	if (pick < 0 && passive >= 0) {
		if (0 > rs_xwrite(passive, &byte, sizeof(byte))) {
			close(passive);
			*passivep = -1;
		} else {
			pick = passive;
			close(active);
		}
	}
	rs_log("1of2: server picked %d", pick);
	return pick;
}

/* Bind and return a new socket to ADDR */
static int
xbind(struct sockaddr_in *addr)
{
	int fd, rv;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > fd)
		return -1;
	if (0 > rs_reuseaddr(fd)) {
		close(fd);
		fd = -1;
	}
	rv = bind(fd, (struct sockaddr *) addr, sizeof(*addr));
	if (0 > rv) {
		close(fd);
		rs_log("1of2 bind failed (%s)", strerror(errno));
		return -1;
	}
	/* Non blocking avoids timing problem described in
	   Stevens, Network Programming 1, 15.6 */
	if (0 > rs_nonblock(fd, 1)) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Start listening on already bound socket FD */
static int
xlisten(int fd)
{
	int rv;
	rv = listen(fd, 1);
	if (0 > rv) {
		close(fd);
		fd = -1;
	}
	return fd;
}

/* Return a new socket making a non-blocking connect to ADDR */
static int
xconnect(struct sockaddr_in *addr)
{
	int fd, rv;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > fd)
		return -1;
	if (0 > rs_nonblock(fd, 1)) {
		close(fd);
		fd = -1;
	}
	rv = connect(fd, (struct sockaddr *) addr, sizeof(*addr));
	if (0 > rv && EINPROGRESS != errno) {
		close(fd);
		fd = -1;
	}
	return fd;
}

static int
self_connected(int sd)
{
	int rv;
	struct sockaddr_in locl, peer;
	socklen_t len;

	len = sizeof(locl);
	rv = getsockname(sd, (struct sockaddr *) &locl, &len);
	if (0 > rv)
		return -1;
	rv = getpeername(sd, (struct sockaddr *) &peer, &len);
	if (0 > rv)
		return -1;
	return (locl.sin_addr.s_addr == peer.sin_addr.s_addr
		&& locl.sin_port == peer.sin_port);
}

/*  LOCL: local address on which we listen for incoming
          connections
    PEER: peer's listening address
    LS:   if non-negative, TCP socket bound to LOCL (not listening)
    LIM:  maximum time to spend connection attempt; NULL for no timeout
    ROLE: RS_ROLE_CLIENT or RS_ROLE_SERVER
    Return fd of new connection or -1 on if timeout expires.
*/
int
rs_1of2(struct sockaddr_in *locl, struct sockaddr_in *peer, 
	int ls, struct timeval *lim, rs_role role)
{
	int rv, len;
	int ss;               /* connected passive socket, obtained from ls */
	int ns, cs;           /* active sockets; 
				 ns is attempting to connect,
                                 cs is connected */
	int pick;             /* Selected connection descriptor */ 
	struct sockaddr_in addr;

	cs = ss = ns = -1;
	pick = -1;

	if (ls >= 0)
		ls = xlisten(ls);
	while (pick < 0) {
		fd_set rfds, wfds;
		struct timeval tv;
		int max;

		if (lim && timeout_expired(lim)) {
			/* timeout */
			close(ls);
			close(ss);
			close(ns);
			return -1;
		}

		if (0 > ss && 0 > ls) {
			ls = xbind(locl);
			if (ls >= 0)
				ls = xlisten(ls);
		}
		if (0 > cs && 0 > ns)
			ns = xconnect(peer);

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		max = 0;

		/* for clients or servers: poll for established connections */
		if (0 > cs && ns >= 0) {
			FD_SET(ns, &wfds);
			FD_SET(ns, &rfds);
			max = MAX(max, ns);
		}
		if (0 > ss && ls >= 0) {
			FD_SET(ls, &rfds);
			max = MAX(max, ls);
		}

		/* for clients: poll for data on connected sockets */
		if (cs >= 0 && RS_ROLE_CLIENT == role) {
			FD_SET(cs, &rfds);
			max = MAX(max, cs);
		}
		if (ss >= 0 && RS_ROLE_CLIENT == role) {
			FD_SET(ss, &rfds);
			max = MAX(max, ss);
		}

		/* imprecise - we could exceed
		   reconnect timeout by the granularity
		   of this timeout; but the reconnect
		   timeout is usually on order of hours */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		rv = select(1+max, &rfds, &wfds, NULL, &tv);
		if (0 > rv && EINTR == errno)
			continue;   /* interrupt */
		if (0 == rv) {
			/* timeout */
			/* retry connect; maybe we have a new IP address */
			if (0 > cs && ns >= 0) {
				close(ns);
				ns = -1;
			}
			continue;
		}
		if (0 > rv) {
			rs_log("select failure in 1of2");
			assert(0);
		}

		len = sizeof(addr);
		/* check for newly established connections */
		if (0 > ss && ls >= 0 && FD_ISSET(ls, &rfds)) {
			ss = accept(ls, (struct sockaddr *) &addr, &len);
			if (ss >= 0 && RS_ROLE_SERVER == role)
				pick = _1of2_server(&ss, &cs);
			continue;
		}
		if (0 > cs && ns >= 0
		    && (FD_ISSET(ns, &wfds) || FD_ISSET(ns, &rfds))) {
			if (0 > getpeername(ns, (struct sockaddr *) &addr,
					    &len)) {
				close(ns);
				ns = -1; /* connect failed */
			} else if (self_connected(ns)) {
				close(ns);
				ns = -1;
			} else {
				cs = ns;
				ns = -1;
				if (RS_ROLE_SERVER == role)
					pick = _1of2_server(&ss, &cs);
			}
		}

		/* One of CS or SS is ready for reading */
		if (RS_ROLE_CLIENT == role && (ss >= 0 || cs >= 0))
			pick = _1of2_client(&ss, &cs);

	}
	close(ls);
	if (pick >= 0)
		rs_nonblock(pick, 0);
	return pick;
}
