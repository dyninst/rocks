/* 
 *  rocks/sys.c
 *  
 *  System call redirection.
 *
 *  This file must be compiled with gcc.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <string.h>
#include "rs.h"
#include "log.h"

#include <features.h>		/* glibc version number */
/* glibc before 2.2 does not have this macro */
#ifndef __GLIBC_PREREQ
#define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
#endif

#define MODESTACK 1024
static rs_mode_t mode[MODESTACK] = { RS_MODE_NATIVE };
static rs_mode_t *mp = mode;

static int
isnative()
{
	return (*mp == RS_MODE_NATIVE);
}

void
rs_mode_push(rs_mode_t m)
{
	mp++;
	assert(mp - mode < MODESTACK);
	*mp = m;
}

void
rs_mode_native()
{
	rs_mode_push(RS_MODE_NATIVE);
}

void
rs_mode_pop()
{
	if (mp > mode)
		mp--;
}

static int
replaced_execve(const char *filename, char *const argv[], char *const envp[])
{
	int rv;
	if (isnative())
		return syscall(SYS_execve, filename, argv, envp);
	rs_mode_native();
	rv = rs_execve(filename, argv, envp);
	rs_mode_pop();
	return rv;
}

static int
replaced_vfork()
{
	int rv;
	if (isnative())
		return syscall(SYS_fork);
	rs_mode_native();
	rv = rs_fork();
	rs_mode_pop();
	return rv;
}

static void *libc;
int rs_init_sys()
{
	if (0 > replace_function("execve", replaced_execve)) {
		fprintf(stderr, "cannot replace functions\n");
		return -1;
	}
	if (0 > replace_function("__vfork", replaced_vfork)) {
		fprintf(stderr, "cannot replace functions\n");
		return -1;
	}

	if (rs_opt_ckptpath) {
		void *h;
		void (*r)(void (*)(void *), void *);

		h = dlopen(rs_opt_ckptpath, RTLD_LAZY);
		if (!h) {
			fprintf(stderr, "cannot find checkpoint library %s\n",
				rs_opt_ckptpath);
			return -1;
		}
		r = dlsym(h, "ckpt_on_ckpt");
		if (!r) {
			fprintf(stderr, "cannot find checkpoint symbol\n");
			return -1;
		}
		r(rs_mode_native, NULL);
		r = dlsym(h, "ckpt_on_restart");
		if (!r) {
			fprintf(stderr, "cannot find checkpoint symbol\n");
			return -1;
		}
		r(rs_mode_pop, NULL);
		dlclose(h);
	}
	rs_mode_push(RS_MODE_RS);
	return 0;
}


/* We need to pass something for the SIZE parameter of __builtin_apply.
   There doesn't seem to be any provision for determining this size,
   so we try to overestimate. */
#define MAXARGS 6

#define BYPASS(ret,func,params...)							\
ret func(params)									\
{											\
	static ret (*f)(params) = NULL;							\
	void *args, *result;								\
											\
        if (!libc) {									\
		libc = dlopen("libc.so.6", RTLD_LAZY);					\
		if (!libc) {								\
			fprintf(stderr, "librs: can't find my own libc\n%s\n",		\
				dlerror());						\
			exit(1);							\
		}									\
	}										\
	if (!f) {									\
		f = (ret(*)(params)) dlsym(libc, #func);				\
		if (!f) {								\
			fprintf(stderr,							\
				"librs: can't initialize syscall interface for %s\n",	\
                                #func);							\
				exit(1);						\
		}									\
	}										\
	args = __builtin_apply_args();							\
	if (isnative())									\
		result = __builtin_apply((void(*)()) f,					\
					 args, MAXARGS*sizeof(int));			\
	else {										\
		rs_mode_push(RS_MODE_NATIVE);						\
		result = __builtin_apply((void(*)()) rs_##func,				\
					 args, MAXARGS*sizeof(int));			\
		rs_mode_pop();								\
	}										\
	__builtin_return(result);							\
	assert(0);									\
}

#define BYPASSFD(ret,func,fd,params...)							\
ret func(params)									\
{											\
	static ret(*f)(params) = NULL;  						\
	void *args, *result;								\
											\
        if (!libc) {									\
		libc = dlopen("libc.so.6", RTLD_LAZY);					\
		if (!libc) {								\
			fprintf(stderr, "librs: can't find my own libc\n%s\n",		\
				dlerror());						\
			exit(1);							\
		}									\
	}										\
	if (!f) {									\
		f = (ret(*)(params)) dlsym(libc, #func);				\
		if (!f) {								\
			fprintf(stderr,							\
				"librs: can't initialize syscall interface for %s\n",	\
                                #func);							\
			exit(1);							\
		}									\
	}										\
	args = __builtin_apply_args();							\
	if (isnative() || !rs_lookup(fd))						\
		result = __builtin_apply((void(*)()) f,					\
					 args, MAXARGS*sizeof(int));			\
	else {										\
		rs_mode_push(RS_MODE_NATIVE);						\
		result = __builtin_apply((void(*)()) rs_##func,				\
					 args, MAXARGS*sizeof(int));			\
		rs_mode_pop();								\
	}										\
	__builtin_return(result);							\
	assert(0);									\
}

/* System calls bypassed only when the file descriptor argument is
   a reliable socket */
BYPASSFD(ssize_t, read, sd, int sd, void *buf, size_t count)
BYPASSFD(ssize_t, write, sd, int sd, const void *buf, size_t count)
BYPASSFD(int, bind, sd, int sd, const struct sockaddr *iaddr, socklen_t addrlen)
#if __GLIBC_PREREQ(2,2)
BYPASSFD(int, listen, sd, int sd, int backlog)
#else
BYPASSFD(int, listen, sd, int sd, unsigned int backlog)
#endif
BYPASSFD(int, accept, sd, int sd, struct sockaddr *addr, socklen_t *addrlen)
BYPASSFD(int, connect, sd, int sd, const struct sockaddr *iaddr, socklen_t addrlen)
BYPASSFD(int, close, sd, int sd);
BYPASSFD(int, getsockname, sd, int sd, struct sockaddr *addr, socklen_t *addrlen)
BYPASSFD(int, getpeername, sd, int sd, struct sockaddr *addr, socklen_t *addrlen)
BYPASSFD(int, recv, sd, int sd, void *buf, size_t len, int flags)
BYPASSFD(int, send, sd, int sd, const void *msg, size_t len, int flags)
BYPASSFD(int, shutdown, sd, int sd, int how)
BYPASSFD(int, recvfrom, sd, int sd, void *buf, size_t len, int flags,
	 struct sockaddr *from, socklen_t *fromlen)
BYPASSFD(int, sendto, sd, int sd, const void *msg, size_t len, int flags,
	 const struct sockaddr *to, socklen_t tolen)
BYPASSFD(ssize_t, readv, sd, int sd, const struct iovec *iov, int iovcnt)
BYPASSFD(ssize_t, writev, sd, int sd, const struct iovec *iov, int iovcnt)
BYPASSFD(int, recvmsg, sd, int sd, struct msghdr *msg, int flags)
BYPASSFD(int, sendmsg, sd, int sd, const struct msghdr *msg, int flags)
BYPASSFD(int, setsockopt, sd, int sd, int level, int optname,
	 const void *optval, socklen_t optlen)
BYPASSFD(int, fcntl, sd, int sd, int cmd, long arg)
BYPASSFD(int, ioctl, sd, int sd, int cmd, long arg)
BYPASSFD(int, dup, old, int old);
BYPASSFD(int, dup2, old, int old, int new);


/* System calls always bypassed */
BYPASS(pid_t, fork)
BYPASS(pid_t, vfork)
BYPASS(void, exit, int status);
BYPASS(int, socket, int domain, int type, int protocol)
BYPASS(int, select, int n, fd_set *rds, fd_set *wds, fd_set *eds,
       struct timeval *tv)
BYPASS(unsigned int, alarm, unsigned int t)
BYPASS(int, sigaction, int signum, const struct sigaction *act, struct sigaction *oldact)
BYPASS(int, __libc_sigaction, int signum, const struct sigaction *act, struct sigaction *oldact)
BYPASS(sighandler_t, signal, int signum, sighandler_t handler)
BYPASS(int, sigaltstack, const stack_t *ss, stack_t *oss)
#if 0
/* FIXME: What's with the coredumps that happen using rock when
   this is set? */
BYPASS(int, sigprocmask, int how, const sigset_t *set, sigset_t *oldset)
#endif
BYPASS(int, sigsuspend, const sigset_t *mask)
#if __GLIBC_PREREQ(2,2)
BYPASS(int, setitimer, __itimer_which_t which, const struct itimerval *value,
       struct itimerval *ovalue)
#else
BYPASS(int, setitimer, enum __itimer_which which, const struct itimerval *value,
       struct itimerval *ovalue)
#endif
