/* 
 *  rocks/select.c
 *
 *  Sockets API implementation for select.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/poll.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "rs.h"
#include "log.h"

static void
choose(int fd, const fd_set *set,
       int *rsn, int *sysn, fd_set *rs_set, fd_set *sys_set)
{
	/* FIXME: I never understand what this does when I look at it.
	   Improve the variable names. */
	rs_t rs;
	assert(FD_ISSET(fd, set));

	rs = rs_lookup(fd);
	if (rs && RS_SUSPENDED == rs->state) {
		FD_SET(fd, rs_set);
		if (fd > *rsn)
			*rsn = fd;
	} else {
		FD_SET(fd, sys_set);
		if (fd > *sysn)
			*sysn = fd;
	}
}

/* NN is largest fd set in O, plus 1.  N is same wrt S.  If FD is set
   in S or O, then upon return it is set in S, and N is the largest fd
   set in S, plus 1. */
static void
merge_fdset(int *n, fd_set *s, int nn, const fd_set *o)
{
	int i;
	int max;
	
	max = *n;
	for (i = 0; i < nn; i++)
		if (FD_ISSET(i, o)) {
			FD_SET(i, s);
			if (i+1 > max)
				max = i+1;
		}
	*n = max;
}

/* Assumes native context.  Returns 0 if we found and recovered a bad
   rock among FDS. */
int
rs_recover_bad_rocks(int n, fd_set *fds)
{
	int i;
	rs_t rs;
	fd_set t;
	struct timeval tv;
	int rv;
	int ret;

	ret = -1;
	for (i = 0; i < n; i++) {
		rs = rs_lookup(i);
		if (!rs)
			continue;
		FD_ZERO(&t);
		FD_SET(i, &t);
		tv.tv_sec = tv.tv_usec = 0;
		rv = select(i+1, &t, NULL, NULL, &tv);
		if (0 > rv && errno == EBADF) {
			rs_log("select badfd -> begin reconnect");
			rs_reconnect(rs, RS_NOBLOCK);
			ret = 0;
		} else if (0 > rv)
			assert(0); /* Unexpected */
	}
	return ret;
}

static void
check_spilled(int n, fd_set *rset, int *nspilled, fd_set *spilled)
{
	int i;
	for (i = 0; i < n; i++) {
		rs_t x = rs_lookup(i);
		if (x && FD_ISSET(i, rset) && (x->edpspill || x->clospill)) {
			FD_SET(i, spilled);
			*nspilled = i+1;
		}
	}
}

/* Test the fds in RP up to NN for rocks that have just
   failed.  Remove them from RP and return the number removed. */
static int
checkrocks(int nn, fd_set *rp)
{
	int i;
	rs_t rs;
	int n = 0;
	
	for (i = 0; i < nn; i++)
		if (FD_ISSET(i, rp)
		    && (rs = rs_lookup(i))
		    && rs->state == RS_ESTABLISHED) {
			struct sockaddr_in addr;
			socklen_t len = sizeof(addr);
			if (0 > getpeername(i, (struct sockaddr *)&addr,
					    &len)) {
				rs_reconnect(rs, RS_NOBLOCK);
				FD_CLR(i, rp);
				n++;
			}
		}
	return n;
}


int
rs_select(int n, fd_set *rs, fd_set *ws, fd_set *es, struct timeval *tv)
{
	int rv;
	int i, rsn, sysn, nn;
	fd_set rsrs, rsws, rses;      /* suspended rs descriptors */
	fd_set spilled;               /* rocks with a non-empty spill ring */
	int nspilled;         	      /* max fd set in spilled plus 1 */
	fd_set sysrs, sysws, syses;   /* descriptors for kernel to test */
	fd_set args[3], *rp, *wp, *ep;
	int caller_fdsn;

	/* Don't waste time if caller just wants timing */
	if (n == 0 || (!rs && !ws && !es))
		return select(n, rs, ws, es, tv);

	nspilled = 0;
	FD_ZERO(&spilled);
	if (rs)
		check_spilled(n, rs, &nspilled, &spilled);

retry:
	rsn = sysn = 0;
	FD_ZERO(&rsrs);
	FD_ZERO(&rsws);
	FD_ZERO(&rses);
	FD_ZERO(&sysrs);
	FD_ZERO(&sysws);
	FD_ZERO(&syses);

	/* Separate suspended rs descriptors */
	for (i = 0; i < n; i++) {
		if (rs && FD_ISSET(i, rs))
			choose(i, rs, &rsn, &sysn, &rsrs, &sysrs);
		if (ws && FD_ISSET(i, ws))
			choose(i, ws, &rsn, &sysn, &rsws, &sysws);
		if (es && FD_ISSET(i, es))
			choose(i, es, &rsn, &sysn, &rses, &syses);
	}		
	/* FIXME: Non portable select semantics: on Linux, interrupted
           select returns the time not slept. */
	if (sysn > 0) {
		rp = &args[0];
		wp = &args[1];
		ep = &args[2];
		memcpy(rp, &sysrs, sizeof(fd_set));
		memcpy(wp, &sysws, sizeof(fd_set));
		memcpy(ep, &syses, sizeof(fd_set));
		nn = sysn + 1;
	} else {
		rp = wp = ep = NULL;
		nn = 0;
	}
	rv = select(nn, rp, wp, ep, tv);
	if (0 > rv && errno == EINTR)
		goto retry;
	/* Bad descriptors can arise following a checkpoint restart */
	if (0 > rv && errno == EBADF) {
		int m = 0;
		fd_set s;
		rs_log("Select came back with bad fds"); 
		FD_ZERO(&s);
		if (rp)
			merge_fdset(&m, &s, nn, rp);
		if (wp)
			merge_fdset(&m, &s, nn, wp);
		if (ep)
			merge_fdset(&m, &s, nn, ep);
		if (!rs_recover_bad_rocks(m, &s))
			goto retry;
		/* Otherwise, the bad fd is the application's problem */
	}
	if (rv >= 0 && rp && nspilled > 0)
		merge_fdset(&n, rp, nspilled, &spilled);
	if (rv > 0 && rp) {
		/* check for newly failed rocks */
		rv -= checkrocks(nn, rp);
		if (!rv)
			goto retry;
	}

	/* Copy results to caller.  Since not every caller passes in a
	   whole fd_set, do a minimal copy. */
	caller_fdsn = n / 8;
	if (n % 8)
		++caller_fdsn;
	if (rs && rp)
		memcpy(rs, rp, caller_fdsn);
	if (ws && wp)
		memcpy(ws, wp, caller_fdsn);
	if (es && ep)
		memcpy(es, ep, caller_fdsn);
	return rv;
}

int
rs_poll(struct pollfd *ufds, unsigned int nfds, int timeout)
{
	assert(0);
	return 0;
}

