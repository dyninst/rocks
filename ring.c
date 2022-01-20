/* 
 *  rocks/ring.c
 *
 *  A ring buffer.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* TODO:
   Use unsigned long.
   Name routines consistently 
*/

#include "ring.h"
#include "log.h"
#include "rs.h" /* rs_xwrite, rs_xread */

#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

struct _ring{
	char *buf;       /* ring buffer */
	unsigned size;   /* capacity of ring */
	unsigned nbytes; /* number of bytes in the ring */
	char *hd;        /* pointer to next byte to be removed */
	unsigned seq;    /* sequence number of hd byte */
};

ring_t
rs_new_ring(unsigned size)
{
	ring_t ring;
	ring = malloc(sizeof(struct _ring));
	if (! ring)
		return NULL;

	ring->buf = malloc(size);
	if (! ring->buf) {
		free(ring);
		return NULL;
	}
	ring->size = size;
	ring->nbytes = 0;
	ring->hd = ring->buf;
	ring->seq = 0;
	return ring;
}

int
rs_ring_save(ring_t ring, int fd)
{
	if (0 > rs_xwrite(fd, ring, sizeof(*ring)))
		return -1;
	if (0 > rs_xwrite(fd, ring->buf, ring->size))
		return -1;
	return 0;
}

ring_t
rs_ring_restore(int fd)
{
	char *buf;
	struct _ring r;
	ring_t ring;
	if (0 > rs_xread(fd, &r, sizeof(r), 0))
		return NULL;
	ring = rs_new_ring(r.size);
	if (!ring)
		return NULL;
	buf = ring->buf;
	*ring = r;
	ring->buf = buf;
	ring->hd = buf + (r.hd - r.buf);
	if (0 > rs_xread(fd, ring->buf, ring->size, 0))
		return NULL;
	return ring;
}

void
rs_free_ring(ring_t ring)
{
	if (!ring)
		return;
	if (ring->buf)
		free(ring->buf);
	free(ring);
}

/* FIXME: Must this be so complicated? */
void
rs_push_ring(ring_t ring, void *p, unsigned nbytes)
{
	unsigned hd, tl;         /* ring offsets */
	unsigned chunk1, chunk2; /* chunk sizes */
	int nonempty;            /* data in the ring when we started? */
	unsigned x;

	if (nbytes == 0)
		return;
	if (nbytes > ring->size) {
		p += nbytes - ring->size;
		nbytes = ring->size;
	}
	nonempty = ring->nbytes;
	hd = ring->hd - ring->buf;
	tl = (hd + ring->nbytes) % ring->size;
	chunk1 = MIN(ring->size - tl, nbytes); /* from tl to end of buffer */
	chunk2 = nbytes - chunk1;     /* from start of buffer to last byte */

	/* Append data after the tail, wrapping to start of buffer if
           necessary. */
	memcpy(ring->buf + tl, p, chunk1);
	if (chunk2)
		memcpy(ring->buf, p + chunk1, chunk2);
	
	ring->nbytes = MIN(ring->size, ring->nbytes + nbytes);

	/* Handle wrap past the head */
	x = (tl + nbytes) % ring->size; /* pointer to end of new data */
	if (hd == tl && nonempty) {
		/* Full buffer */
		ring->hd = ring->buf + ((hd + nbytes) % ring->size);
		ring->seq += nbytes;
	} else if (hd < tl && x > hd && x < tl) {
		ring->hd = ring->buf + ((x + 1) % ring->size);
		ring->seq += x - hd;
	} else if (hd > tl && (x > hd || x < tl)) {
		ring->hd = ring->buf + ((x + 1) % ring->size);
		if (x > hd)
			ring->seq += x - hd;
		else
			ring->seq += ring->size - (hd - x);
	}
}

/* Advance hd until its sequence number is equal to NEWSEQ. */
void
rs_set_ring_seq(ring_t ring, unsigned newseq)
{
	unsigned hd;
	unsigned x;
	if (ring->seq == newseq)
		return;
	assert(newseq >= ring->seq);
	assert(newseq <= ring->seq + ring->nbytes);
	x = newseq - ring->seq;
	hd = ring->hd - ring->buf;
	hd = (hd + x) % ring->size;
	ring->hd = ring->buf + hd;
	ring->seq = newseq;
	ring->nbytes -= x;
}

void
rs_pop_ring(ring_t ring, unsigned n)
{
	rs_set_ring_seq(ring, n+ring->seq);
}

unsigned
rs_ring_size(ring_t ring)
{
	return ring->size;
}

unsigned
rs_ring_nbytes(ring_t ring)
{
	return ring->nbytes;
}

unsigned
rs_ring_seq(ring_t ring)
{
	return ring->seq;
}

void *
rs_ring_data(ring_t ring)
{
	if (! rs_ring_grow(ring, 0))
		return NULL;
	/* grow rotates bytes to beginning of data */
	return ring->buf;
}

void *
rs_ring_grow(ring_t ring, unsigned growth)
{
	char *p;
	unsigned len;

	p = malloc(ring->size + growth);
	if (! p)
		return NULL;

	len = ring->size - (ring->hd - ring->buf);
	memcpy(p, ring->hd, len);
	memcpy(p + len, ring->buf, ring->size - len);

	free(ring->buf);
	ring->hd = ring->buf = p;
	ring->size += growth;

	return ring->buf;
}
