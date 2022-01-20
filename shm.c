/* 
 *  rocks/shm.c
 *
 *  Routines for managing rocks shared memory.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "rs.h"
#include "log.h"

static int
init_shm_lock(shm_t shm)
{
	char tmp[] = "/tmp/rocksXXXXXX";
	shm->lfd = mkstemp(tmp);
	if (0 > shm->lfd) {
		rs_log("cannot create lockfile");
		return -1;
	}
	if (0 > unlink(tmp)) {
		rs_log("cannot unlink lockfile");
		return -1;
	}
	return 0;
}

static int
fini_shm_lock(shm_t shm)
{
	close(shm->lfd);
	return 0;
}

static int
do_lock(int fd, int type)
{
	struct flock lk;
retry:
	lk.l_type = type;
	lk.l_start = 0;
	lk.l_whence = SEEK_SET;
	lk.l_len = 1;
	if (0 > fcntl(fd, F_SETLKW, &lk)) {
		if (EINTR == errno)
			goto retry;
		else {
			rs_log("fcntl set lock failed: %s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

void
rs_shm_lock(shm_t shm)
{
	assert(shm);
	if (0 > do_lock(shm->lfd, F_WRLCK))
		assert(0);
}

void
rs_shm_unlock(shm_t shm)
{
	assert(shm);
	if (0 > do_lock(shm->lfd, F_UNLCK))
		assert(0);
}

int
rs_rock_is_shared(rs_t rs)
{
	return rs->shm != NULL;
}

int
rs_shm_has_one_owner(rs_t rs)
{
	struct shmid_ds buf;
	assert(rs->shm);
	if (0 > shmctl(rs->shmid, IPC_STAT, &buf))
		assert(0);
	return buf.shm_nattch == 1;
}

int
rs_shm_attach(rs_t rs)
{
	rs->shm = shmat(rs->shmid, 0, 0);
	if ((void *) -1 == rs->shm) {
		rs_log("shmat failed!");
		return -1;
	}
	return 0;
}

int
rs_shm_create(rs_t rs)
{
	int rv;

	rs_log("<%d:%p> shm create", rs->sd, rs);
	rs->shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT|SHM_R|SHM_W);
	if (-1 == rs->shmid) {
		rs_log("shmget failed!");
		return -1;
	}
	rv = rs_shm_attach(rs);
	if (0 > rv)
		return -1;
	if (0 > init_shm_lock(rs->shm)) {
		rs_log("cannot initialize shm lock");
		return -1;
	}

	/* mark for deletion now so that it automatically goes away
           with last detach */
	rv = shmctl(rs->shmid, IPC_RMID, NULL);
	if (0 > rv) {
		rs_log("shmctl failed!");
		return -1;
	}

	if (rs_opt_hb)
		rs_hb_init_shm(rs);
	rs->shm->refcnt = rs->refcnt;
	return 0;
}

/* Because we mark for deletion in shm_create, unreferenced shared
   memory will be destroyed automatically. */
void
rs_shm_detach(rs_t rs)
{
	rs_log("<%d:%p> shm detach", rs->sd, rs);
	assert(rs->shm);
	rs->refcnt = rs->shm->refcnt;
	fini_shm_lock(rs->shm);
	shmdt(rs->shm);
	rs->shm = NULL;
}
