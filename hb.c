/* 
 *  rocks/hb.c
 *
 *  The heartbeat connection failure detection mechanism.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "rs.h"
#include "log.h"

struct hb {
	int period;		  /* Beat period (multiple of alarm period) */
	int count;		  /* Beats that have occurred within period */
	int limit;		  /* Missed beats limit */
	int missed;		  /* Current number of missed beats */
	int s;   		  /* Connection to peer hb socket (plain) */
	struct sockaddr_in addr;  /* Address of peer's hb socket */
	rs_t rs;		  /* Pointer to owning rock */
	int lshm;		  /* Last count seen in shm */
	int ushm;		  /* Beats in which shm has not changed */
};

/* These are NULL unless there is a HB for the descriptor. */
static hb_t hbs[RS_MAXFD];

hb_t
rs_new_heartbeat(rs_t rs)
{
	hb_t hb;
	hb = (hb_t) malloc(sizeof(struct hb));
	if (!hb)
		return NULL;
	hb->limit = rs_opt_max_alarm_misses;
	hb->period = 1;
	hb->count = 0;
	hb->missed = 0;
	hb->s = -1;
	hb->rs = rs;
	hb->lshm = 0;
	hb->ushm = 0;
	return hb;
}

int
rs_hb_save(hb_t hb, int fd)
{
	if (0 > rs_xwrite(fd, hb, sizeof(*hb)))
		return -1;
	return 0;
}

hb_t
rs_hb_restore(rs_t rs, int fd)
{
	struct hb h;
	hb_t hb;

	if (0 > rs_xread(fd, &h, sizeof(h), 0))
		return NULL;
	hb = rs_new_heartbeat(NULL);
	if (!hb)
		return NULL;
	*hb = h;
	rs->hb = hb;
	hb->rs = rs;
	hbs[hb->s] = hb;
	return hb;
}

void
rs_free_heartbeat(hb_t hb)
{
	rs_mode_native();
	close(hb->s);
	rs_mode_pop();
	free(hb);
}

static hb_t
hb_lookup(int s)
{
	if (s >= RS_MAXFD || s < 0)
		return NULL;
	return hbs[s];
}

/* ROCK is established data connection descriptor.
   HB is allocated, initialized HB structure.
   Establish HB connection and update HB accordingly.
   ROLE is used to decide ties. */
int
rs_hb_establish(int rock, hb_t hb, rs_role role)
{
	int rv, len, sd;
	struct sockaddr_in laddr;

	rs_mode_native();

	/* Bind a new listening socket with IP address of ROCK */
	len = sizeof(laddr);
	if (0 > getsockname(rock, (struct sockaddr *)&laddr, &len))
		goto out;
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (0 > sd)
		goto out;
	len = sizeof(laddr);
	laddr.sin_port = htons(0);
	rv = bind(sd, (struct sockaddr *) &laddr, sizeof(laddr));
	if (0 > rv)
		goto out;

	/* Exchange socket addresses with peer - network order */
	len = sizeof(laddr);
	if (0 > getsockname(sd, (struct sockaddr *)&laddr, &len))
		goto out;
	if (0 >= rs_xwrite(rock, &laddr, sizeof(laddr)))
		goto out;
	if (0 >= rs_xread(rock, &hb->addr, sizeof(hb->addr), 0))
		goto out;
	hb->s = sd;
	hbs[sd] = hb;
	rs_mode_pop();
	rs_log("return from hb est l=%s", rs_ipstr(&laddr));
	rs_log("return from hb est p=%s", rs_ipstr(&hb->addr));
	return 0;
out:
	close(sd);
	rs_mode_pop();
	rs_log("Cannot establish heartbeat connection for <%p>.", hb->rs);
	return -1;
}

int
rs_hb_cancel(hb_t hb)
{
	if (hb->s >= 0) {
		hbs[hb->s] = NULL;
		close(hb->s);
		rs_log("<%d:%p> canceled hb", hb->rs->sd, hb->rs);
	}
	hb->s = -1;
	hb->count = 0;
	hb->missed = 0;
	return 0;
}

void
rs_hb_init_shm(rs_t rs)
{
	rs->shm->hb_owner = getpid();
	rs->shm->hb_count = 0;
	rs->hb->lshm = 0;
	rs->hb->ushm = 0;
}

static pid_t
hb_owner(hb_t hb)
{
	if (!rs_rock_is_shared(hb->rs))
		return getpid();
	else
		return hb->rs->shm->hb_owner;
}

static int
hb_ping_owner(hb_t hb)
{
	if (hb->lshm == hb->rs->shm->hb_count) {
		hb->ushm++;
		if (hb->ushm > 2)
			return 0;
		else
			return 1;
	}
	hb->lshm = hb->rs->shm->hb_count;
	hb->ushm = 0;
	return 1;
}

static int
hb_takeover(hb_t hb)
{
	rs_shm_lock(hb->rs->shm);
	hb->rs->shm->hb_owner = getpid();
	hb->rs->shm->hb_count++; /* notifies others that hb is okay */
	rs_log("new owner of HB for <%d:%p>", hb->rs->sd, hb->rs);
	rs_shm_unlock(hb->rs->shm);
	return 0;
}

/* Return 0 if sent hb okay.  Return -1 if the connection went away. */
static int
send_hb(hb_t hb)
{
	int rv, e;
retry:
	rv = sendto(hb->s, "x", 1, 0,
		    (struct sockaddr *)&hb->addr, sizeof(hb->addr));
	if (rv == 1)
		return 0;
	assert(rv != 0);
	e = errno;
	switch(e) {
	case EINTR:
		goto retry;
		break;
	case EAGAIN:
	case ENOSPC:
	case EIO:
	case EFAULT:
		/* These shouldn't happen */
		assert(0);
		break;
	case EBADF:
	case EINVAL:  /* Linux can do this if you remove the nic */
	default:
 	        /* The connection went away */
		break;
	}
	return -1;
}


static void
chkrecv()
{
	fd_set fdr, fds, fdrx;
	int max, maxh, n, sd, rv;
	struct timeval tv;
	rs_t rs;
	hb_t hb;
	char x;
	pid_t mypid;

	mypid = getpid();
retry_select:
	FD_ZERO(&fdrx);
	FD_ZERO(&fds);
	max = rs_fdset(&fds);
	maxh = 0;
	for (sd = 0; sd < max; sd++)
		if (FD_ISSET(sd, &fds)) {
			int x;
			rs_t rs = rs_lookup(sd);
			assert(rs);
			if (mypid != hb_owner(rs->hb))
				continue;
			if (RS_SUSPENDED == rs->state)
				x = rs->sd; /* reconnect notification */
			else
				x = rs->hb->s; /* hb */
			FD_SET(x, &fdrx);
			if (x > maxh)
				maxh = x;
		}
	maxh++;
	memcpy(&fdr, &fdrx, sizeof(fdrx));
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	n = select(maxh, &fdr, NULL, NULL, &tv);
	if (0 > n) {
		if (errno == EBADF)
			rs_recover_bad_rocks(maxh, &fds);
		goto retry_select;
	}

	for (sd = 0; n > 0 && sd < maxh; sd++) {
		if (!FD_ISSET(sd, &fdr))
			continue;

		/* reconnection? */
		if ((rs = rs_lookup(sd))) {
			assert(rs->state == RS_SUSPENDED);
			rs_rec_complete(rs, RS_NOBLOCK);
			continue;
		}

		/* otherwise a heartbeat */
		hb = hb_lookup(sd);
		assert(hb);
		assert(hb->s == sd);
		rv = recv(hb->s, &x, 1, 0);
		if (0 > rv) {
			rs_log("rock <%d:%p> hb recv error (%s)",
			       hb->rs->sd, hb->rs,
			       strerror(errno));
			rs_reconnect(hb->rs, RS_NOBLOCK);
			continue;
		} else {
			hb->missed = 0;
			n--;
		}
	}
}

static void
handle_sigalrm(int sig)
{
	fd_set fdset;
	rs_t rs;
	int max;
	int sd;
	pid_t mypid;

	rs_mode_native();

	if (getpid() != rs_pid) {
		/* FIXME: assume we've restored a checkpoint;
		   restart the log. hopefully we will not need
		   any other updating.  once ckpt does files,
		   this can go. */
		rs_init_log();
		rs_log("process id changed from [%d]", rs_pid);
		rs_pid = getpid();
	}

	chkrecv();
	mypid = getpid();
	FD_ZERO(&fdset);
	max = rs_fdset(&fdset);
	for (sd = 0; sd < max; sd++) {
		if (!FD_ISSET(sd, &fdset))
			continue;
		rs = rs_lookup(sd);
		assert(rs);

		/* Update shared heartbeats; even for suspended rocks */
		if (rs_rock_is_shared(rs)) {
			if (mypid != hb_owner(rs->hb)) {
				if (!hb_ping_owner(rs->hb))
					hb_takeover(rs->hb);
				continue; /* non-owner does not touch hb */
			} else if (rs_shm_has_one_owner(rs))
				/* garbage collect */
				rs_shm_detach(rs);
			else
				rs->shm->hb_count++;
		}
		if (RS_EDP == rs->state || RS_SUSPENDED == rs->state)
			continue;

		/* Count beats toward this heartbeat's period */
		rs->hb->count++;
		if (rs->hb->count < rs->hb->period)
			continue;
		
		/* Period expired */
		rs->hb->count = 0;
		rs->hb->missed++;
		
		/* Send hb */
		if (0 > send_hb(rs->hb)) {
			rs_log("rock <%d:%p> hb send error (%s)", rs->sd, rs,
			       strerror(errno));
			rs_reconnect(rs, RS_NOBLOCK);
			continue;
		}
		
		/* Check missed hb */
		if (rs->hb->missed >= rs->hb->limit) {
			rs_log("reconnect for too many missed hbs");
			rs_reconnect(rs, RS_NOBLOCK);
		} else if (rs->hb->missed > 1)
			rs_log("<%d:%p> missed heartbeat (%d more)",
			       rs->sd, rs, rs->hb->limit - rs->hb->missed);
	}
	rs_mode_pop();
}

void 
rs_stop_heartbeat(sigset_t *oset)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigprocmask(SIG_BLOCK, &set, oset);
}

void
rs_resume_heartbeat(sigset_t *oset)
{
	sigprocmask(SIG_SETMASK, oset, NULL);
}

int
rs_init_heartbeat()
{
	struct sigaction sa;
	struct itimerval it;
	int ret = 0;

	sigfillset(&sa.sa_mask);
	sigdelset(&sa.sa_mask, SIGTERM);
	sigdelset(&sa.sa_mask, SIGINT);
	sa.sa_flags = SA_RESTART;
	sa.sa_restorer = 0;
	sa.sa_handler = handle_sigalrm;
	rs_rs_sigaction(SIGALRM, &sa);

	it.it_value.tv_sec = it.it_interval.tv_sec = rs_opt_alarm_period;
	it.it_value.tv_usec = it.it_interval.tv_usec = 0;
	rs_mode_native();
	ret = setitimer(ITIMER_REAL, &it, NULL);
	rs_mode_pop();
	return ret;
}

int
rs_setitimer(int which, const struct itimerval *value, struct itimerval *ov)
{
	return 0;
}
