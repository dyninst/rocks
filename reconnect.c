/* 
 *  rocks/reconnect.c
 *
 *  Reconnection.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rs.h"
#include "flight.h"
#include "log.h"

static void reconnect0(rs_t rs, block_t block);

/* c = a+b */
static void
tv_add(const struct timeval *a,
       const struct timeval *b,
       struct timeval *c)
{
	c->tv_sec = a->tv_sec + b->tv_sec;
	c->tv_usec = a->tv_usec + b->tv_usec;
	if (c->tv_usec >= 1000000) {
		c->tv_sec += 1;
		c->tv_usec -= 1000000;
	}
}

static void
set_timeout(rs_t rs)
{
	struct timeval tv;
	int rv;
	rv = gettimeofday(&tv, NULL);
	assert(!rv);
	tv_add(&tv, &rs->lim, &rs->tout);
	rs_log("reconnect timeout at %lu sec (cur %lu)",
	       rs->tout.tv_sec, tv.tv_sec);
}

/* Obtain a reconnection address and tell the other side about it */
int
rs_addr_exchange(rs_t rs)
{
	int len;

	/* bind up a fresh socket in any case */
	if (rs->rec_fd >= 0) {
		close(rs->rec_fd);
		rs->rec_fd = -1;
	}
	
	/* bind a server socket with IP address of the rock */
	rs->rec_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > rs->rec_fd)
		goto err;
	/* Non blocking avoids the timing problem described in
	   Stevens Network Programming V1 (2nd ed.), sec. 15.6 */
	if (0 > rs_nonblock(rs->rec_fd, 1))
		assert(0);
	if (0 > rs_reuseaddr(rs->rec_fd))
		assert(0);

	if (rs_opt_localhost) {
		/* always attempt to reconnect to the localhost
		   (this is process migration hack) */
		bzero(&rs->sa_rl, sizeof(rs->sa_rl));
		rs->sa_rl.sin_addr.s_addr = 0x0100007f;
	} else {
		len = sizeof(rs->sa_rl);
		if (0 > getsockname(rs->sd, (struct sockaddr *) &rs->sa_rl, &len))
			goto err;
	}

	rs->sa_rl.sin_port = htons(0);
	if (0 > bind(rs->rec_fd, (struct sockaddr *) &rs->sa_rl,
		     sizeof(rs->sa_rl)))
		goto err;
	len = sizeof(rs->sa_rl);
	if (0 > getsockname(rs->rec_fd, (struct sockaddr *) &rs->sa_rl, &len))
		goto err;
	/* we don't listen until reconnection */

	/* Exchange reconnection addresses with peer - network order */
	if (0 >= rs_xwrite(rs->sd, &rs->sa_rl, sizeof(rs->sa_rl)))
		goto err;
	if (0 >= rs_xread(rs->sd, &rs->sa_rp, sizeof(rs->sa_rp), 0))
		goto err;
	return 0;
err:
	rs->rec_fd = -1;	
	return -1;
}

static int
reconnect(rs_t rs)
{
	int fd, lfd;

	/* assume hb signals are already blocked */

	/* close everything except log,
	   link to parent, and current reconnection listener */
	lfd = rs_logfileno();
	for (fd = 0; fd < RS_MAXFD; fd++) {
		if (fd == lfd
		    || fd == rs->sd
		    || fd == rs->rec_fd)
			continue;
		close(fd);
	}
retry:
	/* establish connection with peer */
	if (rs_opt_localhost)
		fd = rs_1of2(&rs->sa_rl, &rs->sa_rp, -1, &rs->tout, rs->role);
	else
		fd = rs_1of2(&rs->sa_rl, &rs->sa_rp, rs->rec_fd, &rs->tout, rs->role);
	if (fd < 0)
		return -1; /* timeout */

	/* Authenticate */
#ifndef NO_AUTH
	if (rs_opt_auth) {
		int rv;
		rs_log("Reconnect: Authenticating");
		rv = rs_authenticate(rs->key, fd);
		if (0 >= rv) {
			rs_log("Authentication of incoming connection failed");
			close(fd);
			goto retry;
		}
	}
#endif
	return fd;
}

enum {
	REC_TIMEOUT, REC_OK
};

struct rec_msg {
	int fd;
	int stat;
};

/* send M over SD */
static int
send_rec_msg(int sd, struct rec_msg *m)
{
	struct cmsghdr *cmsg;
	struct msghdr msg;
	int buf[128];
	int len, rv;
	struct iovec iv;

	if (m->stat != REC_OK)
		/* no fd to pass */
		return rs_xwrite(sd, m, sizeof(*m));

	/* pass fd */
	assert(m->fd >= 0);
	bzero(&msg, sizeof(msg));
	len = CMSG_SPACE(sizeof(int));
	assert(len <= sizeof(buf));
	iv.iov_base = m;
	iv.iov_len = sizeof(*m);
	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = len;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = m->fd;
	msg.msg_controllen = cmsg->cmsg_len;
	rv = sendmsg(sd, &msg, 0);
	if (0 > rv)
		rs_log("sendmsg failed: %s (%d)", strerror(errno), errno);
	return rv;
}

/* receive a fd or error message from SD; return it or -1 on failure */
static int
recv_rec_msg(int sd, struct rec_msg *m)
{
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iv;
	int buf[128];
	int len;

	len = CMSG_SPACE(sizeof(int));
	assert(len <= sizeof(buf));
	bzero(&msg, sizeof(msg));
	iv.iov_base = m;
	iv.iov_len = sizeof(*m);
	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = len;
	if (0 > recvmsg(sd, &msg, 0))
		return -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		assert(m->stat != REC_OK);
		m->fd = -1;
		return 0;
	}
	assert(m->stat == REC_OK);
	assert(cmsg->cmsg_level == SOL_SOCKET);
	assert(cmsg->cmsg_type == SCM_RIGHTS);
	assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
	m->fd = *(int *)CMSG_DATA(cmsg);
	return 0;
}

/* Pass ROCK descriptor to parent (PPID) over FD, or notify parent of
   error if ROCK is negative. */
static void
notify(int rock, int fd, pid_t ppid)
{
	int rv;
	struct rec_msg rm;

	if (rock >= 0) {
		rm.fd = rock;
		rm.stat = REC_OK;
		rs_log("reconnection ok; notifying parent");
	} else {
		rm.fd = -1;
		rm.stat = REC_TIMEOUT;
		rs_log("reconnection timed out; notifying parent");
	}
	rv = send_rec_msg(fd, &rm);
	close(fd);
	if (0 > rv)
		rs_log("Unable to notify parent of reconnect status (1)\n");
}

int rs_rec_failed(rs_t rs)
{
	return 0;
}

void
rs_rec_complete(rs_t rs, block_t block)
{
	int rv;
	int len;
	sigset_t hbsigs;
	struct rec_msg m;

	rs_log("enter rec_complete");

	if (0 > recv_rec_msg(rs->sd, &m))
		goto failed;
	if (m.stat == REC_TIMEOUT) {
		rs_log("rock <%p> hung up", rs);
		rs->state = RS_HUNGUP;
		return;
	}
	assert(m.fd != rs->sd);
	if (0 > dup2(m.fd, rs->sd))
		goto failed;
	close(m.fd);

	/* Heartbeat must be established and beating before in-flight
	   recovery so that full fault detection is available during
	   in flight recovery. */
	if (rs_opt_hb)
		if (0 > rs_hb_establish(rs->sd, rs->hb, rs->role))
			goto failed;
	rs->state = RS_ESTABLISHED;
	rs_resume_heartbeat(&hbsigs);

	/* obtain and exchange new reconnection addresses */
	if (0 > rs_addr_exchange(rs))
		goto failed;

	/* Update addresses */
	len = sizeof(rs->sa_locl);
	if (0 > getsockname(rs->sd, (struct sockaddr *) &rs->sa_locl, &len))
		goto failed;
	len = sizeof(rs->sa_locl);
	if (0 > getpeername(rs->sd, (struct sockaddr *) &rs->sa_peer, &len))
		goto failed;

	rs_reset_on_close(rs->sd, 1);

	/* Finally recover in-flight data */
	if (rs_opt_flight) {
		rv = rs_inflight_recover(rs->sd, rs->ring,
					 rs->rcvseq, rs->sndseq,
					 &rs->maxsnd, &rs->maxrcv);
		if (0 > rv)
			goto failed;
	}
	rs_tty_print("reconnected %d", rs->sd);
	return;
failed:
	rs_log("reconnection completion failed");
	/* whatever the failure, try again */
	reconnect0(rs, block);
}

void
rs_wait_reconnect(rs_t rs)
{
	while (RS_SUSPENDED == rs->state)
		pause();
}

/* - FIXME: make it safe to migrate the child process, or not to;
            either way, the reconnect effort should proceed. 
   - assumes we are in native mode
*/ 


static void
reconnect0(rs_t rs, block_t block)
{
	pid_t pid;
	sigset_t hbsigs;
	sigset_t cur, old;
	int sv[2];

	assert(rs);

	/* suspend */
	sigemptyset(&cur);
	sigaddset(&cur, SIGCHLD);
	if (0 > sigprocmask(SIG_BLOCK, &cur, &old)) {
		rs_log("Cannot block SIGCHLD");
		assert(0);
	}
	rs_stop_heartbeat(&hbsigs);
	close(rs->sd);
	rs->state = RS_SUSPENDED;
	if (rs_opt_hb)
		rs_hb_cancel(rs->hb);
	if (0 > socketpair(PF_UNIX, SOCK_DGRAM, 0, sv)) {
		rs_log("Unable to create unix socketpair");
		assert(0);
		return;
	}

	pid = fork();
	if (0 > pid) {
		rs_log("reconnect unable to fork");
		assert(0);
		return;
	}
	if (!pid) {
		/* child - with signals still blocked */
		int ppid;
		int fd;

		ppid = getppid();
		/* fork again to reparent.  prevents application
		   from seeing an unexpected child process */
		pid = fork();
		if (0 > pid) {
			rs_log("reconnect unable to fork");
			exit(1);
		}
		if (pid)
			exit(0);

		rs_log("reconnection process started for %d", ppid);
		close(sv[0]);
		if (sv[1] != rs->sd) {
			dup2(sv[1], rs->sd);
			close(sv[1]);
		}
		pid = getpid();
		if (0 > rs_xwrite(rs->sd, &pid, sizeof(pid))) {
			rs_log("unable to initialize reconnection daemon");
			exit(1);
		}
		fd = reconnect(rs);
		notify(fd, rs->sd, ppid);
		exit(0);
	}

	/* parent */ 
	close(sv[1]);
	if (sv[0] != rs->sd) {
		dup2(sv[0], rs->sd); /* dup child pipe to rock socket fd */
		close(sv[0]);
	}
	rs_log("<%d:%p> socketpair was [%d,%d]", rs->sd, rs, sv[0], sv[1]);
	rs_log("<%d:%p> socketpair now [%d,x]", rs->sd, rs, rs->sd);
	if (0 > rs_xread(rs->sd, &rs->rec_pid, sizeof(rs->rec_pid), 0)) {
		rs_log("unable to initialize reconnection daemon");
		assert(0);
	}
	if (rs->rec_fd >= 0) {
		close(rs->rec_fd); /* child manages it now */
		rs->rec_fd = -1;
	}
	rs_resume_heartbeat(&hbsigs);
	if (0 > sigprocmask(SIG_SETMASK, &old, NULL)) {
		rs_log("Cannot unblock SIGCHLD");
		assert(0);
	}
	waitpid(pid, NULL, 0);

	if (block == RS_BLOCK)
		rs_wait_reconnect(rs);
}

static int
actuallyclosed(rs_t rs)
{
	int rv;
	char buf[1024];
	int flags;
	
	/* Perhaps the remote end closed the socket and
	   the application has not noticed. */
	flags = fcntl(rs->sd, F_GETFL);
	assert(flags != -1);
	rv = fcntl(rs->sd, F_SETFL, flags|O_NONBLOCK);
	assert(rv != -1);
	rv = read(rs->sd, buf, sizeof(buf));
	fcntl(rs->sd, F_SETFL, flags);
	if (0 > rv)
		return 0; /* nope, it failed */
	rs->clospill = rs_new_ring(rv);
	rs_push_ring(rs->clospill, buf, rv);
	rs_log("actually closed pushing %d bytes", rv);
	while (rv > 0) {
		rv = read(rs->sd, buf, sizeof(buf));
		if (0 > rv) {
			rs_free_ring(rs->clospill);
			return 0; /* failure */
		}
		rs_ring_grow(rs->clospill, rv);
		rs_push_ring(rs->clospill, buf, rv);
	}
	return 1;
}

void
relisten(rs_t rs)
{
	int sd = -1;
	struct sockaddr_in addr;

	/* try to restart a listening sockets in one
	   shot in the same process.  bound to break
	   someday; in that case, adapt the reconnect
	   daemon to listening. */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > sd)
		goto fail;
	if (sd != rs->sd) {
		if (0 > dup2(sd, rs->sd))
			goto fail;
		close(sd);
	}
	bzero(&addr, sizeof(addr));
	memcpy(&addr, &rs->sa_locl, sizeof(addr));
	if (0 > bind(rs->sd, (struct sockaddr *)&addr, sizeof(addr)))
		goto fail;
	if (0 > listen(rs->sd, rs->backlog))
		goto fail;
	rs_log("<%d:%p> relisten ok", rs->sd, rs);
	return;
fail:
	if (sd >= 0)
		close(sd);
	rs_log("<%d:%p> relisten failed", rs->sd, rs);
}

void
rs_reconnect(rs_t rs, block_t block)
{
	if (rs->role == RS_ROLE_LISTEN) {
		relisten(rs);
		return;
	}
	if (block == RS_NOBLOCK && actuallyclosed(rs)) {
		sigset_t hbsigs;
		/* If we got here along a blocking
		   path, the caller should have noticed
		   the close. */
		assert(block == RS_NOBLOCK);
		rs_stop_heartbeat(&hbsigs);
		if (rs_opt_hb)
			rs_hb_cancel(rs->hb);
		rs_resume_heartbeat(&hbsigs);
		rs->state = RS_NOTCONNECTED;
		return;
	}
	rs_tty_print("suspended %d", rs->sd);
	if (rs->cb && rs->cb->suspend)
		rs->cb->suspend(rs->sd);
	set_timeout(rs);
	reconnect0(rs, block);
}
