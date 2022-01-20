/* 
 *  rocks/exec.c
 *
 *  Exec handler
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "rs.h"
#include "log.h"

/* If non-negative, we are recovering from an exec call */
static int rs_execfd = -1;

int
rs_in_exec()
{
	char *s;
	if (rs_execfd == -1 && (s = getenv("RS_EXEC_FD"))) {
		rs_execfd = atoi(s);
		/* don't propagate this variable */
		unsetenv("RS_EXEC_FD");
	}
	return rs_execfd != -1;
}

static void
exec_daemon_sighandler(int sig)
{
	rs_log("exec daemon time out");
	exit(1);
}

/* Called in native syscall mode in new process.
   Feeds rock state to its parent, which has called exec, over FD.
   Currently preserves server and client (but not listener) sockets.
   Like everything else, does not handle duped sockets. */
static void
exec_daemon(int fd)
{
	int i;
	struct sigaction sa;
	struct itimerval it;
	pid_t pid;
	rs_t rs;

	/* fork (again) to reparent */
	pid = fork();
	if (0 > pid) {
		rs_log("exec daemon failed to start");
		exit(1);
	}
	if (pid) {
		rs_log("exec daemon is [%d]", pid);
		_exit(0); /* no atexit */
	}

	sigfillset(&sa.sa_mask);
	sigdelset(&sa.sa_mask, SIGTERM);
	sigdelset(&sa.sa_mask, SIGINT);
	sa.sa_restorer = 0;
	sa.sa_handler = exec_daemon_sighandler;
	rs_rs_sigaction(SIGALRM, &sa);
	it.it_value.tv_sec = 60;
	it.it_interval.tv_sec = 0;
	it.it_value.tv_usec = it.it_interval.tv_usec = 0;
	if (0 > setitimer(ITIMER_REAL, &it, NULL))
		rs_log("exec daemon failed to set timeout");

	for (i = 0; i < RS_MAXFD; i++) {
		if ((rs = rs_lookup(i)) && rs->state == RS_ESTABLISHED)
			if (0 > rs_save(rs, fd)) {
				rs_log("exec daemon failed to xfer state");
				_exit(1);  /* no atexit */
			}
	}
	close(fd);
	rs_log("exec daemon exiting");
	_exit(0); /* no atexit */
}

void
rs_restore_exec()
{
	rs_t rs;
	rs_log("restoring after exec");
	while ((rs = rs_restore(rs_execfd))) {
		rs_log("exec restored rock %d (now <%p>)", rs->sd, rs);
	}
	close(rs_execfd);
	rs_log("exec restore success");
}

extern char **environ;

static char **
extend_env(char *const envp[], char *buf)
{
	char **p;
	int len;
	int i;

	len = 0;
	p = (char **)envp;
	while (*p++)
		len++;
	p = (char **) malloc((len+2) * sizeof(char *));
	if (!p)
		return NULL;
	for (i = 0; i < len; i++)
		p[i] = envp[i];
	p[len] = buf;
	p[len+1] = NULL;
	return p;
}

int
rs_execve(const char *filename, char *const argv[], char *const envp[])
{
	char abuf[512], *ap;
	char *const *q;
	char buf[32];
	int p[2];
	pid_t pid;
	char **ep;
	sigset_t cur, old;
	struct itimerval it, oit;

	sigemptyset(&cur);
	sigaddset(&cur, SIGCHLD);
	if (0 > sigprocmask(SIG_BLOCK, &cur, &old)) {
		rs_log("Cannot block SIGCHLD");
		assert(0);
	}

	if (0 > pipe(p))
		return -1;
	pid = fork();
	if (0 > pid)
		return -1;
	if (0 == pid) {
		close(p[0]);
		exec_daemon(p[1]); /* does not return */
		assert(0);
	}
	ap = abuf;
	q = argv;
	while (*q && sizeof(abuf) > ap - &abuf[0]) {
		ap += snprintf(ap, sizeof(abuf) - (ap - &abuf[0]),
			       "%s ", *q);
		q++;
	}
	rs_log("exec(%s) -> handled by [%d]", abuf, pid);
	waitpid(pid, NULL, 0); /* no problem if we can't reap it;
				  someone else did for us */
	if (0 > sigprocmask(SIG_SETMASK, &old, NULL)) {
		rs_log("Cannot unblock SIGCHLD");
		assert(0);
	}

	close(p[1]);
	snprintf(buf, sizeof(buf), "RS_EXEC_FD=%d", p[0]);
	ep = extend_env(envp, buf);
	if (!ep) {
		rs_kill9_and_wait(pid);
		goto err;
	}
	/* cancel timer in execed process, lest we're not there to
	   handle it */
	it.it_value.tv_sec = it.it_interval.tv_sec = 0;
	it.it_value.tv_usec = it.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &it, &oit);
	execve(filename, argv, ep);
	setitimer(ITIMER_REAL, &oit, NULL);
	/* exec failed */
	free(ep); /* allocated by extend_env */
err:
	return -1;
	
}
