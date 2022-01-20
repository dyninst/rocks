/* 
 *  rocks/options.c
 *
 *  Reliable sockets options.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include "rs.h"

/* User-visible options */
int rs_opt_log = 0;	   /* logging */
int rs_opt_auth = 1;       /* authentication */
int rs_opt_interop = 1;    /* interoperability */
int rs_opt_hb = 1;	   /* heartbeat */
int rs_opt_flight = 1;     /* in-flight data buffer */
int rs_opt_udp = 0;	   /* UDP support */
int rs_opt_localhost = 0;  /* localhost reconnection */

/* Heartbeat */
int rs_opt_alarm_period = 1;        /* seconds */
int rs_opt_max_alarm_misses = 15;

/* Authentication */
int rs_opt_auth_timeout = 1000;     /* milliseconds */

/* Reconnection */
int rs_opt_rec_max_timeouts = 5;    /* Max timeouts during reconnection
				       before refreshing sockets. */

/* Checkpoint library support */
char *rs_opt_ckptpath = NULL;       /* Path to checkpoint library,
				       if one is present. */
