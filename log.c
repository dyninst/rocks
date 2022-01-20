#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h> 
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#include "log.h"

static FILE *logfp = NULL;
static int opt_nolog = 0;
static int opt_precise = 0;

int
rs_logfileno()
{
	if (!logfp)
		return -1;
	return fileno(logfp);
}

static
void tv_diff(const struct timeval *a,
	     const struct timeval *b,
	     struct timeval *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;
	c->tv_usec = a->tv_usec - b->tv_usec;
	if (c->tv_usec < 0) {
		c->tv_sec -= 1;
		c->tv_usec += 1000000;
	}
}

void
rs_log(char *fmt, ...)
{
	struct tm *tm;
	time_t timet;
	va_list args;
	static struct timeval tv, prev, c;

	if (opt_nolog)
		return;

	if (opt_precise) {
		gettimeofday(&tv, NULL);
		va_start(args, fmt);
		tv_diff(&tv, &prev, &c);
		fprintf(logfp, "[%d] %10ld.%06ld ",
			(int)getpid(), c.tv_sec, c.tv_usec);
		memcpy(&prev, &tv, sizeof(prev));
	} else {
		time(&timet);
		tm = localtime(&timet);
		va_start(args, fmt);
		fprintf(logfp, "[%d] %2d/%02d %2d:%02d:%02d ",
			(int)getpid(),
			tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	}
	vfprintf(logfp, fmt, args);
	fprintf(logfp, "\r\n");
	fflush(logfp);
	va_end(args);
}

void
rs_tty_print(char *fmt, ...)
{
	struct tm *tm;
	time_t timet;
	va_list args;

	if (!isatty(2))
		return;

	time(&timet);
	tm = localtime(&timet);
	va_start(args, fmt);
	fprintf(stderr, "[%d] %2d/%02d %2d:%02d:%02d ",
		getpid(),
		tm->tm_mon+1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\r\n");
	fflush(logfp);
	va_end(args);
}

int
rs_startlog(const char *logfilename, int flags)
{
	if (flags & RS_LOGNOLOG) {
		opt_nolog = 1;
		return 0;
	}
	if (!logfilename) {
		logfp = stderr;
		return 0;
	}
	if (flags & RS_LOGPRECISETIME)
		opt_precise = 1;
	logfp = fopen(logfilename, "a");
	if (!logfp) {
		logfp = stderr;
		rs_log("Can't open log %s", logfilename);
		return -1;
	} else if (flags & RS_LOGSTDERR
		   && fileno(logfp) != fileno(stderr)) {
		/* Redirect stderr to the log */
		/* FIXME: This is good for lazy server programmers,
                   bad for client users who rely on stderr. */
		int fd = fileno(stderr);
		close(fd);
		if (0 > dup2(fileno(logfp), fd))
			rs_log("stderr dup failed: stderr will be lost");
	}
	return 0;
}

void
rs_closelog()
{
	if (logfp)
		fclose(logfp);
}
