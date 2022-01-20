/* 
 *  rocks/fork.c
 *
 *  Fork handler
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "rs.h"
#include "log.h"

static int
post_fork_child()
{
	rs_pid = getpid();
	if (!rs_opt_hb)
		return 0; /* nothing to do if there is no hb */
	if (0 > rs_init_heartbeat()) {
		rs_log("fork child cannot initialize heartbeat");
		return -1;
	}
	return 0;
}

static int
post_fork_parent(pid_t child)
{
	rs_log("fork -> [%d]", child);
	return 0;
}

/* FIXME: What should happen to suspended rocks across fork? */
pid_t
rs_fork()
{
	pid_t rv;
	sigset_t set;
	int i;

	/* avoid races with shm garbage collector in hb alarm handler */
	rs_stop_heartbeat(&set);

	for (i = 0; i < RS_MAXFD; i++) {
		rs_t rs;
		rs = rs_lookup(i);
		if (!rs)
			continue;

		/* share shareworthy rocks that are not already shared */
		if (rs->state != RS_NOTCONNECTED && rs->state != RS_EDP) {
			if (!rs_rock_is_shared(rs)) {
				if (0 > rs_shm_create(rs)) {
					rs_log("fork cannot share rock");
					goto out;
				}
			}
			rs_shm_lock(rs->shm);
			rs->shm->refcnt++;
			rs_shm_unlock(rs->shm);
		}
	}

	rv = fork();
	if (!rv)
		post_fork_child();
	else
		post_fork_parent(rv);
out:
	rs_resume_heartbeat(&set);
	return rv;
}

pid_t
rs_vfork()
{
	return rs_fork();
}
