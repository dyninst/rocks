/* 
 *  rocks/rs.c
 *
 *  Sockets API implementation, except select, sockopt, and I/O.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>

#include "rs.h"
#include "flight.h"
#include "ring.h"
#include "log.h"

/* These are NULL unless there is a RS for the descriptor. */
static rs_t rocks[RS_MAXFD];
char *rs_roles[] = { "server", "client", "listening", "undefined" };

int rs_pid;

static void
env_options()
{
	if (getenv("RS_NOAUTH"))
		rs_opt_auth = 0;
	if (getenv("RS_NOLOG"))
		rs_opt_log = 0;
	if (getenv("RS_NOINTEROP"))
		rs_opt_interop = 0;
	if (getenv("RS_NOHB"))
		rs_opt_hb = 0;
	if (getenv("RS_NOFLIGHT"))
		rs_opt_flight = 0;
	rs_opt_ckptpath = getenv("RS_CKPTPATH");
	if (getenv("RS_LOCALHOST"))
		rs_opt_localhost = 1;
}

static void
close_shop()
{
	int i;
	for (i = 0; i < RS_MAXFD; i++)
		if (rocks[i] && rocks[i]->state == RS_ESTABLISHED)
			rs_close(rocks[i]->sd);
}


void
rs_init_log()
{
	char buf[32];
	if (!rs_opt_log)
		rs_startlog(NULL, RS_LOGNOLOG);
	else {
#if 1
#if 0
		/* FIXME: fork should open a new pid-based log */
		snprintf(buf, sizeof(buf), "/tmp/rocks.%d", getpid());
#else
		snprintf(buf, sizeof(buf), "/tmp/rocks");
#endif
		fprintf(stderr, "rocks logging to %s\n", buf);
		rs_startlog(buf, 0);
#else

		/* FIXME: Logging to stderr (or stdout)
		   breaks rockd, if not other programs.
		   I think the problem is the std* fd
		   becomes the connection fd.  Once the
		   connection failed, the std* fds are
		   invalid, and may get reused.  In the
		   rockd case, the fd is reused in the
		   reconnection daemon socketpair, and
		   subsequent logging messages are
		   confused for reconnection event
		   messages.*/
		assert(0);
  	        rs_startlog(NULL, 0); /* log to stderr */
#endif
	}
}

void
rs_init()
{
	rs_pid = getpid();
	env_options();
	rs_init_log();
	rs_init_signal();
	if (0 > rs_init_sys()) {
		fprintf(stderr, "Can't initialize reliable sockets\n");
		exit(1);
	}
	rs_log("*** Rocks loaded ***");

	if (rs_in_exec()) {
		/* FIXME: Necessary mode switch? */
		rs_mode_native();		
		rs_restore_exec();
		rs_mode_pop();
	}
	if (rs_opt_hb) {
		if (0 > rs_init_heartbeat()) {
			fprintf(stderr, "Can't initialize reliable sockets\n");
			exit(1);
		}
	}	  
	if (0 > atexit(close_shop)) {
		fprintf(stderr, "Can't initialize reliable sockets exit\n");
		exit(1);
	}
#ifndef NO_AUTH
	if (rs_opt_auth && 0 > rs_init_crypt()) {
		fprintf(stderr, "Can't initialize reliable sockets\n");
		exit(1);
	}
#endif
}

static rs_t
new_rs(int sd, int state, int type)
{
	rs_t rs;

	rserrno = 0;
	assert(!rocks[sd]); /* Not in use */

	rs = (rs_t) malloc(sizeof(struct rs_));
	if (!rs) {
		rserrno = ENOMEM;
		return NULL;
	}
	rs->sd = sd;
	rs->rec_fd = -1;
	rs->rec_pid = 0;
	rs->type = type;
	rs->state = state;
	rs->ring = NULL;
	rs->rcvseq = 0;
	rs->sndseq = 0;
	rs->maxrcv = 0;
	rs->maxsnd = 0;
	rs->role = RS_ROLE_UNDEF;
	rs->hb = NULL;
	rs->edpspill = NULL;
	rs->clospill = NULL;
	rs->booger = -1;
	rs->shmid = 0;
	rs->shm = NULL;
	rs->lim.tv_sec = 3*24*60*60; /* 3 days */
	rs->lim.tv_usec = 0;
	rs->tout.tv_sec = rs->tout.tv_usec = 0;
	rocks[sd] = rs;
	rs->refcnt = 1;
	rs->cb = NULL;
	return rs;
}

static void
free_rs(rs_t rs)
{
	if (!rs)
		return;
	if (rs->ring)
		rs_free_ring(rs->ring);
	if (rs->hb)
		rs_free_heartbeat(rs->hb);
	if (rs->edpspill)
		rs_free_ring(rs->edpspill);
	if (rs->clospill)
		rs_free_ring(rs->clospill);
	if (rs->rec_fd)
		close(rs->rec_fd);
	free(rs);
}

rs_t
rs_lookup(int fd)
{
	if (fd < 0)
		return NULL;
	if (fd >= RS_MAXFD)
		return NULL;
	return rocks[fd];
}

/* Sets in FDSET the descriptors for all established or suspended
   reliable sockets.  Returns the highest descriptor set plus 1, or 0
   if none are established. */
int
rs_fdset(fd_set *fdset)
{
	int d, max;
	rs_t rs;

	max = 0;
	for (d = 0; d < RS_MAXFD; d++)
		if ((rs = rs_lookup(d))
		    && rs->state != RS_NOTCONNECTED
		    && rs->state != RS_EDP) {
			/* FIXME: This is booger (UDP) code.  It keeps the
			   heartbeat handler from thinking this rock
			   has a heartbeat. */
			if (RS_ROLE_LISTEN == rs->role)
				continue;
			FD_SET(d, fdset);
			max = d+1;
		}
	return max;
}

void
rs_fallback(rs_t rs)
{
	rs_log("<%d:%p> fallback to ordinary socket", rs->sd, rs);
	rocks[rs->sd] = NULL;
	free_rs(rs);
}


/* do dup (NEW < 0) or dup2 (NEW >= 0) */
static int
do_dup(int old, int new)
{
	rs_t rs;
	rs = rs_lookup(old);
	if (!rs) {
		rserrno = EBADF;
		return -1;
	}
	if (new >= 0) {
		/* dup2 closes new if necessary */
		if (rs_lookup(new))
			rs_close(new);
		new = dup2(old, new);
	} else
		new = dup(old);
	if (0 > new)
		return -1;
	assert(!rocks[new]); /* if dup returns it, it should not be in use */
	rocks[new] = rs;

	if (rs_rock_is_shared(rs)) {
		rs_shm_lock(rs->shm);
		rs->shm->refcnt++;
		rs_shm_unlock(rs->shm);
	} else
		rs->refcnt++;
	return new;
}

int
rs_dup(int old)
{
	return do_dup(old, -1);
}

int
rs_dup2(int old, int new)
{
	return do_dup(old, new);
}

int
rs_close(int sd)
{
	rs_t rs;
	int cnt;

	rserrno = 0;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}

	/* duplicated descriptor */
	if (rs->shm) {
		rs_log("locking shm");
		rs_shm_lock(rs->shm);
		rs_log("shm locked");
		cnt = --rs->shm->refcnt;
		rs_shm_unlock(rs->shm);
	} else
		cnt = --rs->refcnt;
	if (cnt >= 1) {
		/* local close - don't kill the connection */
		rocks[sd] = NULL;
		close(sd);
		return 0;
	}

	if (rs->booger >= 0) {
		/* FIXME: Booger code; doesn't close listeners. */
		int b = rs->booger;
		rs->booger = -1;
		return rs_close(b);
	}
        rs->state = RS_NOTCONNECTED;
	if (rs->hb)
		rs_hb_cancel(rs->hb);
	rocks[sd] = NULL;
	if (rs_rock_is_shared(rs))
		rs_shm_detach(rs);
	rs_reset_on_close(sd, 0);
	close(sd);
	rs_log("<%d:%p> closed", sd, rs);
	free_rs(rs);
	return 0;
}

int
rs_shutdown(int sd, int how)
{
	if (how == 2)
		return rs_close(sd);
	assert(0);
	return 0;
}

int
rs_init_connection(rs_t rs)
{
	rs_log("<%d:%p> locl is %s", rs->sd, rs, rs_ipstr(&rs->sa_locl));
	rs_log("<%d:%p> peer is %s", rs->sd, rs, rs_ipstr(&rs->sa_peer));
	rs_log("<%d:%p> initing", rs->sd, rs);
	if (0 > rs_reuseaddr(rs->sd)) {
		rserrno = errno;
		return -1;
	}
	/* NO_DELAY reduces connect time. */
	if (0 > rs_nodelay(rs->sd, 1)) {
		rserrno = errno;
		return -1;
	}
#ifndef NO_AUTH
	/* Exchange session key */
	rs_log("<%d:%p> init pre auth", rs->sd, rs);
	if (rs_opt_auth) {
		rs->key = rs_key_exchange(rs->sd);
		if (!rs->key) {
			rs_log("Unable to establish key");
			rserrno = ERSINIT;
			return -1;
		}
	}
	rs_log("<%d:%p> init auth", rs->sd, rs);
#endif
	/* exchange reconnection addresses */
	if (0 > rs_addr_exchange(rs)) {
		rs_log("Unable to exchange reconnection address");
		rserrno = ERSINIT;
		return -1;
	}
	rs_log("<%d:%p> init aex", rs->sd, rs);

	if (rs_opt_flight) {
		if (0 > rs_inflight_limits(rs->sd, &rs->maxsnd, &rs->maxrcv)) {
			rserrno = ERSINIT;
			return -1;
		}
		rs->ring = rs_new_ring(rs->maxsnd);
		if (!rs->ring) {
			rserrno = ENOMEM;
			return -1;
		}
	} else {
		/* FIXME: Do something better than this. */
		/* See usage of maxsnd in rw.c */
		rs->maxsnd = 1000000;
	}
	rs_log("<%d:%p> init flight", rs->sd, rs);
	if (0 > rs_reset_on_close(rs->sd, 1)) {
		rserrno = ERSINIT;
		return -1;
	}
	if (rs_opt_hb) {
		rs->hb = rs_new_heartbeat(rs);
		if (!rs->hb) {
			rserrno = ENOMEM;
			free(rs);
			return -1;
		}
		if (0 > rs_hb_establish(rs->sd, rs->hb, rs->role)) {
			rserrno = ERSINIT;
			return -1;
		}
	}
	rs_log("<%d:%p> init hb", rs->sd, rs);
	/* FIXME: Restore application NO_DELAY state. */
	if (0 > rs_nodelay(rs->sd, 0)) {
		rserrno = errno;
		return -1;
	}
	rs->state = RS_ESTABLISHED;
	return 0;
}

int
rs_socket(int domain, int type, int protocol)
{
	int sd;
	rs_t rs;

	rserrno = 0;

	if (!rs_opt_udp && SOCK_DGRAM == type)
		return socket(domain, type, protocol);

	/* Always create a SOCK_STREAM, but store the requested type
	   in the rs so we can give it the behavior later. */
	sd = socket(domain, SOCK_STREAM, protocol);
	if (0 > sd) {
		rserrno = errno;
		return -1;
	}
	if (domain != AF_INET)
		/* Default to ordinary socket */
		return sd;
	if (0 > rs_reuseaddr(sd)) {
		rserrno = errno;
		return -1;
	}
	rs = new_rs(sd, RS_NOTCONNECTED, type);
	if (!rs)
		return -1;

	rs_log("<%d:%p> new rock", sd, rs);
	return sd;
}

int
rs_bind(int sd, const struct sockaddr *iaddr, socklen_t addrlen)
{
	struct sockaddr_in *addr;
	rs_t rs;
	int len;

	rserrno = 0;
	if (iaddr->sa_family != AF_INET) {
		rserrno = EPROTONOSUPPORT;
		return -1;
	}
	addr = (struct sockaddr_in *) iaddr;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (rs->state != RS_NOTCONNECTED) {
		rserrno = EISCONN;
		return -1;
	}
	if (0 > bind(sd, iaddr, addrlen)) {
		rserrno = errno;
		return -1;
	}
	len = sizeof(rs->sa_locl);
	if (0 > getsockname(rs->sd, (struct sockaddr *) &rs->sa_locl, &len)) {
		rserrno = errno;
		return -1;
	}
	return 0;
}

int
rs_listen(int sd, int backlog)
{
	rs_t rs;

	rserrno = 0;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (rs->state != RS_NOTCONNECTED) {
		rserrno = EISCONN;
		return -1;
	}
	if (0 > listen(sd, backlog)) {
		rserrno = errno;
		return -1;
	}
	if (0 > rs_reuseaddr(sd)) {
		rserrno = errno;
		return -1;
	}
	rs->role = RS_ROLE_LISTEN;
	rs->backlog = backlog;
	rs_log("<%d:%p> listening on %d", rs->sd, rs,
	       ntohs(rs->sa_locl.sin_port));
	return 0;
}

int
rs_accept(int srv_sd, struct sockaddr *iaddr, int *addrlen)
{
	socklen_t len;
	rs_t srv_rs, rs;
	int sd;
	struct sockaddr_in addr;

	rs_log("In rs_accept");
	rserrno = 0;
	srv_rs = rs_lookup(srv_sd);
	if (!srv_rs) {
		rserrno = EINVAL;
		rs_log("rs_accept error at lookup");
		return -1;
	}
rs_accept_retry:
	len = sizeof(addr);
	sd = accept(srv_sd, (struct sockaddr *)&addr, &len);
	if (0 > sd) {
		if (errno == EINTR)
			goto rs_accept_retry;
		rserrno = errno;
		rs_log("rs_accept error at accept %s", strerror(errno));
		return -1;
	}

	rs = new_rs(sd, RS_NOTCONNECTED, SOCK_STREAM);
	if (!rs)
		return -1;
	rs->role = RS_ROLE_SERVER;
	if (0 > rs_reuseaddr(sd)) {
		rserrno = errno;
		return -1;
	}
	memcpy(&rs->sa_locl, &srv_rs->sa_locl, sizeof(rs->sa_locl));
	memcpy(&rs->sa_peer, &addr, sizeof(rs->sa_peer));
	*addrlen = MIN(*addrlen, sizeof(addr));
	memcpy(iaddr, &addr, *addrlen);

	rs_log("<%d:%p> accept -> <%d:%p>", srv_rs->sd, srv_rs, rs->sd, rs);
	if (!rs_opt_interop) {
		if (0 > rs_init_connection(rs))
			return -1;
	} else
		/* don't init until we see some client proof of rockhood */
		rs->state = RS_EDP;

	return sd;
}

int
rs_connect(int sd, const struct sockaddr *iaddr, socklen_t peerlen)
{
	struct sockaddr_in *peer;
	socklen_t len;
	rs_t rs;

	rserrno = 0;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}
	if (iaddr->sa_family != AF_INET) {
		rserrno = EPROTONOSUPPORT;
		return -1;
	}
	peer = (struct sockaddr_in *) iaddr;
	if (rs->state != RS_NOTCONNECTED) {
		rserrno = EISCONN;
		return -1;
	}
	rs_log("<%d:%p> connecting to %s", rs->sd, rs, rs_ipstr(peer));
	if (0 > connect(sd, (struct sockaddr *)peer, peerlen)) {
		rserrno = errno;
		return -1;
	}
	len = sizeof(rs->sa_locl);
	if (0 > getsockname(rs->sd, (struct sockaddr *) &rs->sa_locl, &len)) {
		rserrno = errno;
		return -1;
	}
	memcpy(&rs->sa_peer, peer, sizeof(rs->sa_peer));
	rs->role = RS_ROLE_CLIENT;
	if (rs_opt_interop) {
		int isrock;
		rs_log("start client probe for <%d:%p>", rs->sd, rs);
		isrock = rs_iop_connect(rs);
		if (0 > isrock)
			return -1;
		rs_log("<%d:%p> connect to %s", rs->sd, rs,
		       isrock ? "rock" : "non-rock");
		if (!isrock) {
			rs_fallback(rs);
			return 0;
		} else
			return rs_init_connection(rs);
	} else {
		rs_log("<%d:%p> connect to presumed rock", rs->sd, rs);
		return rs_init_connection(rs);
	}
}

int
rs_getsockname(int sd, struct sockaddr *name, socklen_t *namelen)
{
	rs_t rs;

	rserrno = 0;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}
	memcpy(name, &rs->sa_locl, sizeof(rs->sa_locl));
	*namelen = sizeof(rs->sa_locl);
	return 0;
}

int
rs_getpeername(int sd, struct sockaddr *name, socklen_t *namelen)
{
	rs_t rs;

	rserrno = 0;
	rs = rs_lookup(sd);
	if (!rs) {
		rserrno = EINVAL;
		return -1;
	}

	rserrno = 0;
	memcpy(name, &rs->sa_peer, sizeof(rs->sa_peer));
	*namelen = sizeof(rs->sa_peer);
	return 0;
}

int 
rs_save(rs_t rs, int fd)
{
	rs_log("saving rock %d", rs->sd);
	if (0 > rs_xwrite(fd, rs, sizeof(*rs)))
		return -1;
	if (rs_opt_flight && 0 > rs_ring_save(rs->ring, fd))
		return -1;
	if (rs_opt_hb && 0 > rs_hb_save(rs->hb, fd))
		return -1;
#ifndef NO_AUTH
	if (rs_opt_auth && 0 > rs_key_save(rs->key, fd))
		return -1;
#endif
	return 0;
}

rs_t
rs_restore(int fd)
{
	struct rs_ r;
	rs_t rs;
	if (0 >= rs_xread(fd, &r, sizeof(r), 0))
		return NULL;
	rs = new_rs(r.sd, r.state, r.type);
	*rs = r;
	if (!rs)
		return NULL;
	if (rs_rock_is_shared(rs))
		if (0 > rs_shm_attach(rs)) {
			rs_log("Error restoring exec shm");
			return NULL;
		}
	if (rs_opt_flight) {
		rs->ring = rs_ring_restore(fd);
		if (!rs->ring) {
			rs_log("Error restoring exec rock ring");
			return NULL;
		}
	}
	if (rs_opt_hb) {
		rs->hb = rs_hb_restore(rs, fd);
		if (!rs->hb) {
			rs_log("Error restoring exec rock hb");
			return NULL;
		}
	}
#ifndef NO_AUTH
	if (rs_opt_auth) {
		rs->key = rs_key_restore(fd);
		if (!rs->key) {
			rs_log("Error restoring exec rock key");
			return NULL;
		}
	}
#endif
	return rs;
}

static void
exit_cleanup()
{
	rs_t rs;
	int fd;
	for (fd = 0; fd < RS_MAXFD; fd++) {
		rs = rs_lookup(fd);
		if (!rs)
			continue;
		if (rs->state == RS_SUSPENDED
		    && !rs_rock_is_shared(rs))
			kill(rs->rec_pid, SIGKILL);
	}
}

void
rs_exit(int status)
{
	exit_cleanup();
	exit(status);
}
