/* 
 *  rocks/iop.c
 *
 *  Interoperability of rocks with ordinary sockets.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

#include "rs.h"
#include "log.h"

#define ROCKIDLEN 16
static char rockid[ROCKIDLEN] = "IROCKYOUROCKMAN";

/* return 1 if peer is enhanced; return 0 if not or if there was an error */
static int
client_probe(rs_t rs)
{
	char buf[ROCKIDLEN];
	int rv;
	ring_t ring;
	fd_set fds;
	struct timeval tv;
	int ret = 0;
	int n;

	shutdown(rs->sd, 1);

	ring = rs_new_ring(ROCKIDLEN);
	if (!ring)
		return 0;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(rs->sd, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = 500000;
		n = select(rs->sd+1, &fds, NULL, NULL, &tv);
		if (0 > n && errno == EINTR)
			continue;
		if (0 > n) {
			rs_log("edp: rock <%p> client probe error", rs);
			break;
		}
		if (0 == n) {
			rs_log("edp: rock <%p> client probe timeout", rs);
			break;
		}
		rv = read(rs->sd, buf, sizeof(buf));
		if (0 > rv && errno == EINTR)
			continue;
		if (!rv || (0 > rv && errno == ECONNRESET)) {
			/* server closed or reset connection */
			char *p = rs_ring_data(ring);
			int n = rs_ring_nbytes(ring);
			if (n < ROCKIDLEN)
				break;
			p += n - ROCKIDLEN;
			if (!strncmp(p, rockid, ROCKIDLEN))
				ret = 1;
			break;
		}
		rs_push_ring(ring, buf, rv);
	}
	close(rs->sd);
	rs_free_ring(ring);
	return ret;
}

static unsigned long
room(ring_t ring)
{
	return rs_ring_size(ring) - rs_ring_nbytes(ring);
}

static ring_t
double_ring(ring_t ring)
{
	ring_t r;
	unsigned long sz;
	sz = 2 * rs_ring_size(ring);
	r = rs_new_ring(sz);
	if (!r)
		return NULL;
	rs_push_ring(r, rs_ring_data(ring), rs_ring_nbytes(ring));
	rs_free_ring(ring);
	return r;
}

static int
scan_for_rockid(rs_t rs)
{
	ring_t spill, stage;
	char buf[ROCKIDLEN];
	int rv, over;

	stage = rs_new_ring(ROCKIDLEN);
	spill = rs_new_ring(2048); /* FIXME: 2048 is arbitrary */
	if (!stage || !spill)
		goto err;

	while (1) {
		rv = read(rs->sd, buf, sizeof(buf));
		if (0 > rv && errno != EINTR)
			goto err;
		if (0 == rv)
			goto err;

		/* if stage does not have room for the new data,
		   move the difference from stage to the spill */
		over = rv - room(stage);
		if (over > 0 && over > room(spill))
			if (!(spill = double_ring(spill)))
				goto err;
		if (over > 0) {
			rs_push_ring(spill, rs_ring_data(stage), over);
			rs_pop_ring(stage, over);
		}
			
		/* stage buf */
		rs_push_ring(stage, buf, rv);

		/* check for announcement */
		if (rs_ring_nbytes(stage) == ROCKIDLEN
		    && !strncmp(rs_ring_data(stage), rockid, ROCKIDLEN))
			break; /* found it */
	}
	rs_free_ring(stage);
	if (rs_ring_nbytes(spill) > 0)
		rs->edpspill = spill;
	else
		rs_free_ring(spill);
	return 0;
err:
	if (stage)
		rs_free_ring(stage);
	if (spill)
		rs_free_ring(spill);
	return -1;
}

/* returns:
      -1 error - no connection
       0 peer is not a rock
       1 peer is a rock
*/
int
rs_iop_connect(rs_t rs)
{
	int td;
	int isrock;

	isrock = client_probe(rs);  /* closes rs->sd */
#if 0
	if (isrock)
		rs_log("edp: rock <%p> peer is a rock", rs);
	else
		rs_log("edp: rock <%p> peer is not a rock", rs);
#endif
	td = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > td) {
		rserrno = errno;
		return -1;
	}
	if (td != rs->sd) {
		if (0 > dup2(td, rs->sd)) {
			rserrno = errno;
			return -1;
		}
		close(td);
	}

	/* reconnect */
	if (0 > connect(rs->sd, (struct sockaddr *)&rs->sa_peer,
			sizeof(struct sockaddr_in))) {
		rserrno = errno;
		return -1;
	}
	if (!isrock)
		return 0;

	/* send the announcement */
	if (0 > rs_xwrite(rs->sd, rockid, ROCKIDLEN))
		return -1;

	/* buffer and scan for the reply */
	if (0 > scan_for_rockid(rs))
		return -1;
	return isrock;
}

int
rs_iopsrv(rs_t rs, char *z, int len, edp_result_t *result)
{
	int l;
	int rv;
	char buf[ROCKIDLEN];

	/* any which way, we're not coming back here */
	rs->state = RS_NOTCONNECTED;
	*result = EDP_NOTROCK;

	l = MIN(len, ROCKIDLEN);
	rv = read(rs->sd, buf, l);
	if (0 > rv)
		return -1;
	if (0 == rv) {
		*result = EDP_PROBE;
		if (0 > rs_xwrite(rs->sd, rockid, ROCKIDLEN))
			return -1;
		rs->state = RS_EDP; /* FIXME: good idea? */
		return 0;
	}

	if (!strncmp(rockid, buf, rv)) {
		if (rv != ROCKIDLEN) {
			/* get the rest */ 
			rv = rs_xread(rs->sd, &buf[rv], ROCKIDLEN-rv, 0);
			if (0 >= rv)
				return -1;
			if (strncmp(rockid, buf, ROCKIDLEN))
				/* FIXME: we should tolerate this */
				return -1;
		}
		*result = EDP_ROCK;
		if (0 > rs_xwrite(rs->sd, rockid, ROCKIDLEN))
			return -1;
		if (0 > rs_init_connection(rs))
			return -1;
		return 0;
	}
	rs_fallback(rs);
	memcpy(z, buf, rv);
	return rv;
}
