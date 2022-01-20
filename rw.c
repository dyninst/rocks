/* 
 *  rocks/rw.c
 *
 *  Sockets API implementation for I/O calls.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>  /* strerror */
#include <sys/types.h>
#include <sys/socket.h>

#include "ring.h"
#include "rs.h"
#include "log.h"

int
rs_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rv;
	rs_t rs;
	int unsup_flags = 0;      /* unsupported flags */

	unsup_flags |= MSG_OOB;      /* FIXME: Change to "supported flags" */
	assert(!(flags & unsup_flags));

	if (len == 0)
		return 0;	/* see Linux read(2) */

	rserrno = 0;
	rs = rs_lookup(fd);
	if (! rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (rs->edpspill) {
		int n = rs_ring_nbytes(rs->edpspill);
		assert(n > 0);
		rv = MIN(n, len);
		memcpy(buf, rs_ring_data(rs->edpspill), rv);
		if (rv == n) {
			rs_free_ring(rs->edpspill);
			rs->edpspill = NULL;
		} else
			rs_pop_ring(rs->edpspill, rv);
		return rv;
	}

	if (rs->clospill) {
		int n = rs_ring_nbytes(rs->clospill);
		if (!n) {
			/* closed */
			rs_free_ring(rs->clospill);
			rs->edpspill = NULL;
			return 0;
		}
		rv = MIN(n, len);
		memcpy(buf, rs_ring_data(rs->clospill), rv);
		rs_pop_ring(rs->clospill, rv);
		return rv;
	}

	if (rs->state == RS_EDP) {
		edp_result_t isrock;
		rv = rs_iopsrv(rs, buf, len, &isrock);
		if (0 > rv)
			return -1;
		switch (isrock) {
		case EDP_NOTROCK:
			return rv;
			break;
		case EDP_PROBE:
			return 0; /* hand EOF to application */
			break;
		case EDP_ROCK:
			/* fall through - read again */
			break;
		default:
			assert(0);
		}
	}

	if (rs->state == RS_SUSPENDED)
		rs_wait_reconnect(rs);
retry:
	rv = recv(fd, buf, len, flags);

	if (0 < rv) {
		/* Normal data transfer */
		if (!(flags & MSG_PEEK))
			rs->rcvseq += rv;
		return rv;
	}
	if (0 == rv) {
		rs_log("rock <%p> eof", rs);
		return 0;
	}
	/* Error */
	switch (errno) {
	case EINTR:
		goto retry;
		break;
	case EAGAIN:
		/* FIXME: Nonblocking I/O currently unsupported */
		return -1;
		assert(0);
		break;
	case EINVAL:
	case EIO:
		/* These shouldn't happen */
		assert(0);
		break;
	case EFAULT:
		/* Caller's error */
		rserrno = errno;
		return -1;
	case EBADF:
	default:
		/* The connection went away */
		rs_log("read failed (%s) -> begin reconnect",
		       strerror(errno));
		rs_reconnect(rs, RS_BLOCK);
		goto retry;
		break;
	}
	assert(0);
	return -1;
}

int
rs_read(int fd, void *buf, size_t len)
{
	return rs_recv(fd, buf, len, 0);
}

int
rs_write(int fd, const void *buf, size_t len)
{
	size_t tosend;          /* bytes to pass to real write call */
	ssize_t rv;             /* return value from write */
	char *p = (char *)buf;  /* ptr to next byte to send */
	rs_t rs;	
	int e;

	if (len == 0)
		/* On Linux, a write of 0 bytes returns 0, on both
		   regular files and sockets. */
		return 0;

	rs = rs_lookup(fd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	} else if (rs->state == RS_SUSPENDED) {
		rs_wait_reconnect(rs);
	} else if (rs->state == RS_EDP) {
		/* send application data while server
		   is waiting for edp to complete */
		assert(RS_ROLE_SERVER == rs->role);
		return write(fd, buf, len);
	} else if (rs->state != RS_ESTABLISHED) {
		/* FIXME: Better values */
		rserrno = EINVAL;
		errno = EINVAL;
		return -1;
	}
	tosend = MIN(rs->maxsnd, len);
retry:
	rv = write(fd, p, tosend);

	if (0 < rv) {
		/* Normal data transfer */
		if (rs_opt_flight)
			rs_push_ring(rs->ring, p, rv);
		rs->sndseq += rv;
		return rv;
	}

	if (0 == rv) {
		/* FIXME: Why would this happen? */
		assert(0);
		return -1;
	}

	e = errno;
	switch (e) {
	case EINTR:
		goto retry;
		break;
	case EAGAIN:
		/* Although nonblocking I/O is unsupported, we can
		   draw EAGAIN on linux while blocking */
		goto retry;
		break;
	case ENOSPC:
	case EIO:
		/* These shouldn't happen */
		assert(0);
		break;
	case EFAULT:
		/* Caller's error */
		rserrno = errno;
		return -1;
		break;
	case EBADF:
	case EINVAL:  /* Linux can do this if you remove the nic */
	default:
		/* The connection went away */
		/* FIXME: Handle interoperability here */
		rs_log("write failed (%s) -> begin reconnect",
		       strerror(errno));
		rs_reconnect(rs, RS_BLOCK);
		goto retry;
		break;
	}
	assert(0);
	return -1;
}

int
rs_send(int sd, const void *buf, size_t len, int flags)
{
	int unsup_flags = 0;      /* unsupported flags */
	unsup_flags |= MSG_OOB;
	unsup_flags |= MSG_DONTROUTE;
	return rs_write(sd, buf, len);
}

#define MAXUDP (64*1024)
static char udpsndbuf[MAXUDP];

int
rs_recvfrom(int sd, void *buf, size_t ilen, int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	rs_t rs;
	int torecv, rv;
	int len, nlen;
	char *p;

	if (ilen == 0)
		return 0;

	rs = rs_lookup(sd);
	if (! rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (rs->type == SOCK_STREAM)
		return rs_recv(sd, buf, ilen, flags);
	if (rs->state == RS_NOTCONNECTED) {
		if (0 > rs_listen(sd, 1)) {
			rs_log("recvfrom: cannot setup listener");
			return -1;
		}
		rs->booger = rs_accept(sd, from, fromlen);
		rs->state = RS_ESTABLISHED;
		if (0 > rs->booger) {
			rs_log("recvfrom: cannot accept from listener");
			return -1;
		}
	}

	torecv = sizeof(nlen);
	p = (char *)&nlen;
	while (torecv > 0) {
		rv = rs_recv(rs->booger, p, torecv, flags);
		if (0 > rv)
			return -1;
		torecv -= rv;
		p += rv;
	}
	len = ntohl(nlen);

	/* FIXME: To be more general, consume and discard extra bytes
	   if receiver won't have them. */
	assert(ilen >= len);
	torecv = len;
	p = buf;
	while (torecv > 0) {
		rv = rs_recv(rs->booger, p, torecv, flags);
		if (0 > rv)
			return -1;
		torecv -= rv;
		p += rv;
	}
	return len;
}

int
rs_sendto(int sd, const void *buf, size_t len, int flags,
	  const struct sockaddr *to, socklen_t tolen)
{
	rs_t rs;
	int tosend, rv;
	int nlen;
	char *p;

	if (len == 0)
		return 0;
	rs = rs_lookup(sd);
	if (! rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (rs->type == SOCK_STREAM)
		return rs_send(sd, buf, len, flags);
	if (rs->state == RS_NOTCONNECTED) {
		if (0 > rs_connect(sd, to, tolen))
			return -1;
		rs->booger = sd;
	}

	nlen = htonl(len);
#if 0
	tosend = sizeof(nlen);
	p = (char *)&nlen;
	while (tosend > 0) {
		rv = rs_write(rs->booger, p, tosend);
		if (0 > rv)
			return -1;
		tosend -= rv;
		p += rv;
	}
#else
	memcpy(udpsndbuf, &nlen, sizeof(nlen));
	memcpy(udpsndbuf+sizeof(nlen), buf, len);
#endif
	tosend = len + sizeof(nlen);
	p = (char *)udpsndbuf;
	while (tosend > 0) {
		/* FIXME: Call send? */
		rv = rs_write(rs->booger, p, tosend);
		if (0 > rv)
			return -1;
		tosend -= rv;
		p += rv;
	}

	return len;
}

ssize_t
rs_readv(int sd, const struct iovec *iov, int iovcnt)
{
	int i;
	int rv;
	int n;

	n = 0;
	for (i = 0; i < iovcnt; i++) {
		rv = rs_read(sd, iov[i].iov_base, iov[i].iov_len);
		if (0 > rv)
			return rv;
		n += rv;
		if (rv < iov[i].iov_len)
			break;
	}
	return n;
}

ssize_t
rs_writev(int sd, const struct iovec *iov, int iovcnt)
{
	int i;
	int rv;
	int n;

	n = 0;
	for (i = 0; i < iovcnt; i++) {
		rv = rs_write(sd, iov[i].iov_base, iov[i].iov_len);
		if (0 > rv)
			return rv;
		n += rv;
		if (rv < iov[i].iov_len)
			break;
	}
	return n;
}

int
rs_recvmsg(int sd, struct msghdr *msg, int flags)
{
	assert(0);
	return 0;
}

int
rs_sendmsg(int sd, const struct msghdr *msg, int flags)
{
	assert(0);
	return 0;
}
