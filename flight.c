/* 
 *  rocks/flight.c
 *
 *  In-flight buffering and recovery.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rs.h"
#include "ring.h"
#include "log.h"

/* FIXME: eliminate this by fixing the assumption
   of fixed size in inflight_limits */
static void
fix_inflight_size(int sd)
{
	static const unsigned len = 32*1024;
	if (0 > setsockopt(sd, SOL_SOCKET, SO_SNDBUF,
			   (void*) &len, sizeof(len)))
		assert(0);
	if (0 > setsockopt(sd, SOL_SOCKET, SO_RCVBUF,
			   (void*) &len, sizeof(len)))
		assert(0);
}

/* Find the upper limits on the amount of in-flight data in the send
   and receive directions on socket SD, and store them in MAXSND and
   MAXRCV.  A call to this must be synchronized with another call by
   the peer.  Return 0 on success, -1 on failure. */
int
rs_inflight_limits(int sd, unsigned *maxsnd, unsigned *maxrcv)
{
	size_t optlen;
	int ret;
	unsigned peer_snd, peer_rcv;
	unsigned locl_snd, locl_rcv;
	unsigned x;

	fix_inflight_size(sd);

	/* Determine our buffer sizes */
	optlen = sizeof(locl_snd);
	if (0 > getsockopt(sd, SOL_SOCKET, SO_SNDBUF,
			   (void*) &locl_snd, &optlen)) {
		return -1;
	}
	optlen = sizeof(locl_rcv);
	if (0 > getsockopt(sd, SOL_SOCKET, SO_RCVBUF,
			   (void*) &locl_rcv, &optlen)) {
		return -1;
	}

	/* Tell peer our buffer sizes */
	x = htonl(locl_snd);
	ret = rs_xwrite(sd, &x, sizeof(x));
	if (0 > ret) {
		return -1;
	}
	x = htonl(locl_rcv);
	ret = rs_xwrite(sd, &x, sizeof(x));
	if (0 > ret) {
		return -1;
	}

	/* Read buffer sizes of peer */
	ret = rs_xread(sd, &peer_snd, sizeof(peer_snd), 0);
	if (0 > ret) {
		return -1;
	}
	ret = rs_xread(sd, &peer_rcv, sizeof(peer_rcv), 0);
	if (0 > ret) {
		return -1;
	}
	*maxsnd = locl_snd + ntohl(peer_rcv);
	*maxrcv = locl_rcv + ntohl(peer_snd);
	return 0;
}

int rs_inflight_recover(int sd, ring_t ring,
			unsigned long rcvseq, unsigned long sndseq,
			unsigned *maxsnd, unsigned *maxrcv)
{
	unsigned long rseq;  /* peer's recv sequence number */
	unsigned long nbytes;
	unsigned new_maxsnd, new_maxrcv;

	/* Exchange sequence numbers */
	rcvseq = htonl(rcvseq);
	if (0 > rs_xwrite(sd, &rcvseq, sizeof(rcvseq)))
		return -1;
	if (0 > rs_xread(sd, &rseq, sizeof(rseq), 0))
		return -1;
	rseq = ntohl(rseq);

	/* Discard bytes the receiver has consumed */
	rs_set_ring_seq(ring, rseq);

	/* Get new buffer sizes (which currently must be the same) */
	if (0 > rs_inflight_limits(sd, &new_maxsnd, &new_maxrcv))
		return -1;
	assert(new_maxsnd == *maxsnd);
	assert(new_maxrcv == *maxrcv);

	nbytes = rs_ring_nbytes(ring);
	if (!nbytes)
		return 0; /* Nothing to resend */

	/* This write may block as the data is transferred to peer,
	   but it should be bounded, as we know there's enough room in
	   our combined TCP buffers to hold it all. */
	assert(nbytes <= *maxsnd); /* Otherwise write might block
				      indefinitely. */
	if (0 > rs_xwrite(sd, rs_ring_data(ring), nbytes))
		return -1;
	return 0;
}
