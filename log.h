/* 
 *  rocks/log.h
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#ifndef _LOG_H_
#define _LOG_H_

#define RS_LOGSTDERR        1
#define RS_LOGNOLOG         2
#define RS_LOGPRECISETIME   4
void rs_log(char *fmt, ...);
void rs_tty_print(char *fmt, ...);
int rs_startlog(const char *logfilename, int flags);
void rs_closelog();
int rs_logfileno();

#endif /* _LOG_H_ */
