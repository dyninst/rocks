/* 
 *  rocks/util.c
 *
 *  Common utility functions.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h> /* uname */ 

#include "log.h"
#include "rs.h"

int
rs_xwrite(int sd, void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nsent = 0;
	ssize_t rv;
	
	while (nsent < len) {
		rv = write(sd, p, len - nsent);
		if (0 > rv && (errno == EINTR || errno == EAGAIN))
			continue;
		if (0 > rv)
			return -1;
		nsent += rv;
		p += rv;
	}
	return nsent;
}

/* c = a-b */
static
void tv_diff(const struct timeval *a,
	     const struct timeval *b,
	     struct timeval *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;
	c->tv_usec = a->tv_usec - b->tv_usec;
	if (c->tv_usec < 0) {
		c->tv_sec -= 1;
		c->tv_usec += 1000000;
	}
}

int
rs_waitread(int sd, unsigned long ms)
{
	struct timeval start, tv, tv2, cur;
	fd_set fds;
	int rv;

	tv.tv_sec = ms / 1000;
	tv.tv_usec = 1000 * (ms % 1000);

	/* select on Linux does not return the remaining time on
	   error, so we manually track it. */
	gettimeofday(&start, NULL);
	memcpy(&tv2, &tv, sizeof(tv2));
retry:
	FD_ZERO(&fds);
	FD_SET(sd, &fds);
	rv = select(sd+1, &fds, NULL, NULL, &tv);
	if (rv > 0)
		return 0;  /* sd is ready */
	if (rv == 0)
		return -1; /* timeout */
	if (rv < 0 && errno != EINTR)
		return -1; /* error */

	/* We were interrupted.  Retry for remaining time. */
	gettimeofday(&cur, NULL);
	tv_diff(&cur, &start, &tv);
	tv_diff(&tv2, &tv, &tv);
	if (tv.tv_sec < 0 || (0 == tv.tv_sec && 0 == tv.tv_usec))
		return -1; /* timeout */
	goto retry;
}

/* Perform a blocking read of SD until LEN bytes are read into BUF.
   If MS is non-zero, return after MS milliseconds, no matter how much
   has been read.  Return -1 on this timeout or other error. */
int
rs_xread(int sd, void *buf, size_t len, unsigned long ms)
{
	char *p = (char *)buf;
	size_t nrecv = 0;
	ssize_t rv;
	int flags;
	int ret;
	
	flags = fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
	assert(len > 0);
	ret = -1;
	while (nrecv < len) {
		if (ms && 0 > rs_waitread(sd, ms))
			goto out; /* timeout */
		rv = read(sd, p, len - nrecv);
		if (0 > rv && EINTR == errno)
			continue;
		if (0 > rv)
			goto out;
		if (rv == 0) {
			ret = 0; /* closed */
			goto out;
		}
		nrecv += rv;
		p += rv;
	}
	ret = nrecv;
out:
	fcntl(sd, F_SETFL, flags);
	return ret;
}

int
rs_reset_on_close(int sd, int onoff)
{
	struct linger l;
	static int version = 0;

	/* Linux 2.2 does not support reset-on-close.  But if we try
	   to set it, we will put the socket in linger-on-close mode
	   at maximum timeout.
	   FIXME: This is not a good version check. */
	if (!version) {
		int rv;
		struct utsname uts;
		rv = uname(&uts);
		assert(!rv);
		if (!strncmp(uts.release, "2.4", 3)) {
			version = 24;
		} else {
			version = -1;
		}
	}
	if (24 != version)
		return 0;
	l.l_onoff = onoff;
	l.l_linger = 0;
	if (0 > setsockopt(sd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)))
		return -1;
	return 0;
}

int
rs_reuseaddr(int sd)
{
	int optval = 1;

	if (0 > setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
			   &optval, sizeof(optval)))
		return -1;
	return 0;
}

int
rs_nodelay(int sd, int optval)
{
	if (0 > setsockopt(sd, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval)))
		return -1;
	return 0;
}

int
rs_nonblock(int sd, int on)
{
	int flags;
	flags = fcntl(sd, F_GETFL, 0);
	if (0 > flags)
		return -1;
	if (on)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK; 
	return fcntl(sd, F_SETFL, flags);
}

int
rs_settcpbuf(int sd, int type, int size)
{
	if (type != SO_SNDBUF && type != SO_RCVBUF) {
		errno = EINVAL;
		return -1;
	}
	if (0 > setsockopt(sd, SOL_SOCKET, type, &size, sizeof(size))) {
		rs_log("Warning: can't set %s to %d bytes failed: %s",
		       type == SO_SNDBUF ? "SO_SNDBUF" : "SO_RCVBUF",
		       size, strerror(errno));
		return -1;
	}
	return 0;
}

char *
rs_ipstr(struct sockaddr_in *sa)
{
	static char buf[128];
	struct servent *servent;

	static char addr[32];
	static char serv[32];

	strcpy(addr, inet_ntoa(sa->sin_addr));
	servent = getservbyport(sa->sin_port, "tcp");
	if (servent) {
		strcpy(serv, servent->s_name);
		sprintf(buf, "%s:%s", addr, serv);
	}
	else
		sprintf(buf, "%s:%d", addr, ntohs(sa->sin_port));
	return buf;
}

static const char xtoa[] = { '0', '1', '2', '3',
			     '4', '5', '6', '7',
			     '8', '9', 'a', 'b',
			     'c', 'd', 'e', 'f' };

/* BUF must be at least 58 bytes long */
static void
data_to_str(const char *data, int len, char *buf)
{
	int i;
	char *p = buf;
	char *q = buf + 39;
	const char *r = data;
	
	*q++ = ' ';
	*q++ = ' ';
	for (i = 0; i < 16 && i < len; i++) {
		if (i > 0 && (i % 2) == 0)
			*p++ = ' ';
		*p++ = xtoa[(*r >> 4) & 0xf];
		*p++ = xtoa[*r & 0xf];
		*q++ = (isprint(*r) ? *r : '.');
		r++;
	}

	for (; i < 16; i++) {
		if (i > 0 && (i % 2) == 0)
			*p++ = ' ';
		*p++ = '0';
		*p++ = '0';
		*q++ = '.';
	}
	*q = '\0';
}

void
rs_logbytes(char *bytes, int len)
{
	char buf[64];
	while (len > 0) {
		int nb = MIN(len, 16);
		data_to_str(bytes, nb, buf);
		rs_log("%s", buf);
		bytes += nb;
		len -= nb;
	}
}


int
rs_rocklist_insert(rocklist_t *head, rs_t rs)
{
	rocklist_t rl = (rocklist_t) malloc(sizeof(struct rocklist));
	if (!rl)
		return -1;
	rl->rs = rs;
	rl->next = *head;
	*head = rl;
	return 0;
}

int
rs_rocklist_remove(rocklist_t *head, rs_t rs)
{
	rocklist_t p, q;

	p = *head;
	if (!p)
		return -1; /* Not found */

	/* List head */
	if (p->rs == rs) {
		*head = p->next;
		free(p);
		return 0;
	}

	/* Rest of list */
	q = p;
	p = q->next;
	while (p) {
		if (p->rs == rs) {
			q->next = p->next;
			free(p);
			return 0;
		}
		q = p;
		p = q->next;
	}
	return -1; /* Not found */
}

rs_t
rs_rocklist_findsa(rocklist_t head, struct sockaddr_in *sa)
{
	rocklist_t p = head;
	while (p) {
		struct sockaddr_in *ta;
		ta = &p->rs->sa_peer;
		if (ta->sin_addr.s_addr == sa->sin_addr.s_addr
		    && ta->sin_port == sa->sin_port)
			return p->rs;
		p = p->next;
	}
	return NULL;
}

void
rs_rocklist_free(rocklist_t *head)
{
	rocklist_t p = *head;
	if (p)
		rs_rocklist_free(&p->next);
	*head = NULL;
}

void
rs_kill9_and_wait(pid_t pid)
{
	int olderrno;
	sigset_t mask, old;

	olderrno = errno;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (0 > sigprocmask(SIG_BLOCK, &mask, &old))
		goto out;
	if (0 == kill(pid, SIGKILL) && 0 > waitpid(pid, NULL, 0))
		goto out;
	sigprocmask(SIG_SETMASK, &old, NULL);
out:
	errno = olderrno;
}

#if 0
static int
parse_addr(const char *s, struct in_addr *addr)
{
	struct hostent* h;
	h = gethostbyname(s);
	if (!h)
		return -1;
	*addr = *((struct in_addr *) h->h_addr); /* network order */
	return 0;
}

static int
parse_port(const char *s, short *port)
{
	char *p;
	struct servent *se;
	unsigned long l;

	se = getservbyname(s, "tcp");
	if (se) {
		*port = se->s_port;
		return 0;
	}
	l = strtoul(s, &p, 10);
	if (*p != '\0')
		return -1;
	*port = (short) htons(l);
	return 0;
}

static int
parse_ip(const char *s, struct sockaddr_in *addr)
{
	char *buf = NULL;
	char *p;
	int ret = -1;

	buf = strdup(s);
	if (!buf) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;
	addr->sin_port = htons(0);
	if ((p = strchr(buf, ':'))) {
		/* HOST:PORT */
		*p++ = '\0';
		if (0 > parse_addr(buf, &addr->sin_addr))
			goto out;
		if (0 > parse_port(p, &addr->sin_port))
			goto out;
	} else if ((p = strchr(buf, '.'))) {
		/* HOST */
		if (0 > parse_addr(buf, &addr->sin_addr))
			goto out;
	} else {
		/* PORT or HOST? */
		if (0 > parse_port(buf, &addr->sin_port)
		    && 0 > parse_addr(buf, &addr->sin_addr))
			goto out;
	}
	ret = 0;
out:
	free(buf);
	return ret;
}
#endif
