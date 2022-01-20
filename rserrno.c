/* 
 *  rocks/rserrno.c
 *
 *  errno emulation.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "rs.h"

int rserrno = 0;

static const char *errlist[] = {
	"huh?",                                 /* ERSUNUSED */
	"rs socket init failed",                /* ERSINIT */
#if 0
	"file descriptor already in use",       /* ERSDUPLICATE */
	"rs socket recovery failed",            /* ERSRECOVERY */
	"i/o on offline rs socket",             /* ERSOFFLINE */
#endif
};

const char *rserr()
{
	if (rserrno <= ERSUNUSED)
		return strerror(rserrno);
	if (rserrno - ERSUNUSED <= sizeof(errlist) / sizeof(const char *))
		return NULL;
	return errlist[rserrno - ERSUNUSED];
}
