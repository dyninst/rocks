/* 
 *  rocks/signal.c
 *
 *  Signal setup and interposition.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "rs.h"
#include "log.h"

static sigset_t rs_handled;    /* signals used by rocks */
static sigset_t ap_handled;    /* signals used by application */
static struct sigaction rsh[NSIG];    /* signal action set by rocks */
static struct sigaction app[NSIG];    /* signal action set by application */
static struct sigaction def[NSIG];    /* default signal action */

static void
death(int sig)
{
	rs_log("suicide: signal %d", sig);
	assert(0);
}

static void
handle(int sig, siginfo_t *info, void *ctx)
{
	if (sigismember(&rs_handled, sig))
		rsh[sig].sa_sigaction(sig, info, ctx);
	if (sigismember(&ap_handled, sig)) {
		rs_log("passing signal %d to application handler", sig);
		rs_mode_push(RS_MODE_RS);
		if (app[sig].sa_flags & (SA_ONESHOT|SA_RESETHAND))
			sigdelset(&ap_handled, sig);
		app[sig].sa_sigaction(sig, info, ctx);
		rs_mode_pop();
		rs_log("returning from application signal %d handler", sig);
	}
	if (sig == SIGSEGV) {
		while (1)
			;
	}
}

/* for rocks handlers */
void
rs_rs_sigaction(int sig, const struct sigaction *sa)
{
	sigaddset(&rs_handled, sig);
	rsh[sig] = *sa;
}

int
rs_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact)
{
	int was;

	was = sigismember(&ap_handled, sig);
	if (oldact)
		*oldact = was ? app[sig] : def[sig];
	if (act) {
		if (act->sa_handler != SIG_DFL
		    && act->sa_handler != SIG_IGN
		    && sig != SIGALRM) {
			sigaddset(&ap_handled, sig);
			app[sig] = *act;
		}
		if (was && (act->sa_handler == SIG_DFL
			    || act->sa_handler == SIG_IGN))
			sigdelset(&ap_handled, sig);
	}
	return 0;
}

int
rs___libc_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact)
{
	return rs_sigaction(sig, act, oldact);
}

sighandler_t
rs_signal(int sig, sighandler_t handler)
{
	struct sigaction sa, old;
	sa.sa_handler = handler;
	sa.sa_flags = SA_ONESHOT|SA_NOMASK;
	rs_sigaction(sig, &sa, &old);
	return (old.sa_flags & SA_SIGINFO)
		? old.sa_handler : (sighandler_t) old.sa_sigaction;
}

int
rs_sigprocmask(int how, const sigset_t *iset, sigset_t *oldset)
{
	int i;
	sigset_t set;
	memcpy(&set, iset, sizeof(set));
	if (how == SIG_BLOCK || how == SIG_SETMASK)
		for (i = 1; i < NSIG; i++)
			if (sigismember(&rs_handled, i))
				sigdelset(&rs_handled, i);
	return sigprocmask(how, &set, oldset);
}

int
rs_sigsuspend(const sigset_t *mask)
{
	int i;
	sigset_t set;
	memcpy(&set, mask, sizeof(set));
	for (i = 1; i < NSIG; i++)
		if (sigismember(&rs_handled, i))
			sigdelset(&rs_handled, i);
	return sigsuspend(&set);
}

int
rs_sigaltstack(const stack_t *ss, stack_t *oss)
{
	assert(!oss);
	return 0;
}

unsigned int
rs_alarm(unsigned int t)
{
	/* We ignore application alarms;
	   FIXME handle application alarms */
	return 0;
}

void
rs_init_signal()
{
	int i;
	struct sigaction sa;

	sa.sa_flags = SA_RESTART|SA_SIGINFO;
	sa.sa_sigaction = handle;
	sigemptyset(&sa.sa_mask);

	for (i = 1; i < NSIG; i++) {
		if (i == SIGKILL
		    || i == SIGSTOP
		    || i == SIGINT
		    || i == SIGTERM)
			continue;
		if (0 > sigaction(i, &sa, &def[i]))
			assert(0);
	}
	
	sigemptyset(&rs_handled);
	sigemptyset(&ap_handled);

	sigfillset(&sa.sa_mask);
	sigdelset(&sa.sa_mask, SIGTERM);
	sigdelset(&sa.sa_mask, SIGINT);
	sa.sa_flags = SA_RESTART|SA_SIGINFO;
	sa.sa_restorer = 0;
	sa.sa_handler = death;
	rs_rs_sigaction(SIGPIPE, &sa);
	rs_rs_sigaction(SIGBUS, &sa);
}
