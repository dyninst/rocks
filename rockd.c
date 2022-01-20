/* 
 *  rocks/rockd.c
 *
 *  Reliable sockets port forwarder.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include "rs.h"

static struct in_addr
hostname_to_addr(char *hostname)
{
	struct hostent* h;
	struct in_addr addr;
	h = gethostbyname(hostname);
	if (!h) {
		fprintf(stderr, "gethostbyname error\n");
		exit(1);
	}
	addr = *((struct in_addr *) h->h_addr); /* network order */
	return addr;
}

static int
rxwrite(int sd, void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nsent = 0;
	ssize_t rv;
	
	while (nsent < len) {
		rv = rs_write(sd, p, len - nsent);
		if (0 > rv && (errno == EINTR || errno == EAGAIN))
			continue;
		if (0 > rv)
			return -1;
		nsent += rv;
		p += rv;
	}
	return nsent;
}

static int
xwrite(int sd, void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nsent = 0;
	ssize_t rv;
	
	while (nsent < len) {
		rv = write(sd, p, len - nsent);
		if (0 > rv && errno == EINTR)
			continue;
		if (0 > rv)
			return -1;
		nsent += rv;
		p += rv;
	}
	return nsent;
}

/* Port forward between rock and sock */
int pf(int rock, int sock)
{
	char buf[1024];
	int max, rv;
	fd_set r;
	int rockbytes = 0;
	int rockclose = 0;  /* Did rock close connection before sending data? */

	max = rock > sock ? rock : sock;
	while (1) {
		FD_ZERO(&r);
		FD_SET(rock, &r);
		FD_SET(sock, &r);
		rv = rs_select(max+1, &r, NULL, NULL, NULL);
		if (0 > rv && errno == EINTR)
			continue;
		if (0 > rv) {
			perror("select");
			close(sock);
			rs_close(rock);
			break;
		}
		if (FD_ISSET(sock, &r)) {
			rv = read(sock, buf, sizeof(buf));
			if (0 > rv && errno == EINTR)
				continue;
			if (0 > rv) {
				/* Aborted, done. */
				close(sock);
				rs_close(rock);
				break;
			}
			if (0 == rv) {
				/* Closed, done */
				close(sock);
				rs_close(rock);
				break;
			}
			if (0 > rxwrite(rock, buf, rv)) {
				/* Aborted, Done */
				close(sock);
				rs_close(rock);
				break;
			}
		}
		if (FD_ISSET(rock, &r)) {
			rv = rs_read(rock, buf, sizeof(buf));
			if (0 > rv && errno == EINTR)
				continue;
			if (0 > rv) {
				/* Aborted, done */
				close(sock);
				rs_close(rock);
				break;
			}
			if (0 == rv) {
				/* Closed, done */
				if (rockbytes == 0)
					rockclose = 1;
				close(sock);
				rs_close(rock);
				break;
			}
			rockbytes += rv;
			if (0 > xwrite(sock, buf, rv)) {
				/* Aborted, done */
				close(sock);
				rs_close(rock);
				break;
			}
		}
	}
	return rockclose;
}

int
getserv()
{
	int serv;
	struct sockaddr_in addr;
	int opt;

	serv = rs_socket(AF_INET, SOCK_STREAM, 0);
	if (0 > serv) {
		perror("socket");
		return -1;
	}
	opt = 1;
	if (0 > setsockopt(serv, SOL_SOCKET, SO_REUSEADDR,
			   &opt, sizeof(opt))) {
		perror("setsockopt");
		return -1;
	}
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(0);

	if (0 > rs_bind(serv, (struct sockaddr *)&addr, sizeof(addr))) {
		fprintf(stderr, "bind: %s\n", rserr());
		return -1;
	}
	if (0 > rs_listen(serv, 1)) {
		fprintf(stderr, "listen: %s\n", rserr());
		return -1;
	}

	return serv;
}

int
getcons(int serv, short oport, int *irock, int *isock)
{
	int rock, sock;
	struct sockaddr_in addr;
	socklen_t len;

	len = sizeof(addr);
	rock = rs_accept(serv, (struct sockaddr *)&addr, &len);
	if (0 > rock) {
		fprintf(stderr, "accept: %s\n", rserr());
		return -1;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > sock) {
		perror("socket");
		return -1;
	}
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = hostname_to_addr("localhost");
	addr.sin_port = htons(oport);
	if (0 > connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("connect");
		return -1;
	}
	*irock = rock;
	*isock = sock;
	return 0;
}

/* FIXME: Note that glibc on Linux defines a function called daemon
   that seems to do the same thing.  (See unistd.h) */
static int
mkdaemon()
{
	pid_t pid;

	pid = fork();
	if (0 > pid) {
		perror("fork");
		exit(1);
	}
	if (pid != 0)
		exit(0);

	setsid();
	/* FIXME: Should we fork again on SVR4? (Stevens APUE sec. 13.3) */
	/* FIXME: Close all open file descriptors (use sd) (Stevens APUE sec 2.5.7) */
	close(0);
	close(1);
	close(2);
	/* FIXME: Only go to /tmp to generate coredumps */
	chdir("/tmp");
	umask(0);
	return 0;
}

int
main(int argc, char *argv[])
{
	int rock, sock, serv;
	short oport;
	int c;
	int opt_daemon = 0;
	struct sockaddr_in addr;
	socklen_t len;

	opterr = 0;
	while (-1 != (c = getopt(argc, argv, "d")))
		switch (c) {
		case 'd':
			opt_daemon = 1;
			break;
		case '?':
			if (isprint(optopt))
				fprintf (stderr,
					 "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,
					 "Unknown option character `\\x%x'.\n",
					 optopt);
			return 1;
		default:
			assert(0);
		}

        if (0 > putenv("RS_NOINTEROP=1")) {
                fprintf(stderr, "Out of memory\n");
                exit(1);
        }
	rs_init();
	rs_mode_native(); /* set socket system calls to normal behavior */
	if (argc - optind != 1) {
		fprintf(stderr, "Usage: %s DESTPORT\n", argv[0]);
		exit(1);
	}
	oport = atoi(argv[optind]);
	serv = getserv();
	if (0 > serv)
		exit(1);
	len = sizeof(addr);
	if (0 > getsockname(serv, (struct sockaddr *)&addr, &len)) {
		perror("getsockname");
		exit(1);
	}
	fprintf(stdout, "%hu\n", ntohs(addr.sin_port));
	fflush(stdout);
	if (opt_daemon) {
		mkdaemon();
		rs_init_heartbeat();
	}
	
	if (0 > getcons(serv, oport, &rock, &sock))
		exit(1);
	rs_close(serv);
	pf(rock, sock);
	return 0;
}
