/* 
 *  rocks/flight.h
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#ifndef _FLIGHT_H_
#define _FLIGHT_H_

#include "ring.h"

int rs_inflight_recover(int sd, ring_t ring,
			unsigned long rcvseq, unsigned long sndseq,
			unsigned *maxsnd, unsigned *maxrcv);
int rs_inflight_limits(int cd, unsigned *maxsnd, unsigned *maxrcv);
#endif
