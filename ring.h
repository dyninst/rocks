/* 
 *  rocks/ring.h
 *
 *  A ring buffer.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#ifndef _RING_H_
#define _RING_H_

typedef struct _ring * ring_t;

void rs_free_ring(ring_t ring);
ring_t rs_new_ring(unsigned size);
void rs_push_ring(ring_t ring, void *p, unsigned nbytes);
unsigned rs_ring_size(ring_t ring);
unsigned rs_ring_nbytes(ring_t ring);
unsigned rs_ring_seq(ring_t ring);
void * rs_ring_data(ring_t ring);
void rs_pop_ring(ring_t ring, unsigned n);
void rs_set_ring_seq(ring_t ring, unsigned newseq);
int rs_ring_save(ring_t ring, int fd);
ring_t rs_ring_restore(int fd);

/* Increase the capacity of RING by GROWTH bytes. */
void * rs_ring_grow(ring_t ring, unsigned growth);

#endif
