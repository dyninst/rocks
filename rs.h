/* 
 *  rocks/rs.h
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */
#ifndef _RS_H_
#define _RS_H_

#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>

#include "ring.h"

extern int rserrno;
const char *rserr();
extern int rs_pid;   /* process id we think we are in; updated across forks */

#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

#define RS_MAXFD 1024 /* FIXME: Use the system limit */

/* Options */
extern int rs_opt_auth;
extern int rs_opt_interop;
extern int rs_opt_hb;
extern int rs_opt_log;
extern int rs_opt_flight;
extern int rs_opt_udp;
extern int rs_opt_alarm_period;
extern int rs_opt_max_alarm_misses;
extern int rs_opt_auth_timeout;
extern int rs_opt_rec_max_timeouts;
extern int rs_opt_localhost;
extern char *rs_opt_ckptpath;

#define ERSUNUSED       256    /* unused */
#define ERSINIT         257    /* rs socket init failed */

typedef struct rs_ * rs_t;

int rs_fork();
int rs_vfork();
void rs_exit(int status);
unsigned int rs_alarm(unsigned int);
int rs_socket(int domain, int type, int protocol);
int rs_bind(int sd, const struct sockaddr *iaddr, socklen_t addrlen);
int rs_listen(int sd, int backlog);
int rs_accept(int srv_sd, struct sockaddr *addr, int *addrlen);
int rs_connect(int sd, const struct sockaddr *iaddr, socklen_t addrlen);
int rs_close(int fd);
int rs_shutdown(int sd, int how);
int rs_read(int fd, void *buf, size_t len);
int rs_write(int fd, const void *buf, size_t len);
int rs_fdset(fd_set *);
int rs_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
int rs_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
int rs_recv(int sd, void *buf, size_t len, int flags);
int rs_send(int sd, const void *buf, size_t len, int flags);
int rs_recvfrom(int sd, void *buf, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen);
int rs_sendto(int sd, const void *msg, size_t len, int flags,
	      const struct sockaddr *to, socklen_t tolen);
ssize_t rs_readv(int sd, const struct iovec *iov, int iovcnt);
ssize_t rs_writev(int sd, const struct iovec *iov, int iovcnt);
int rs_recvmsg(int sd, struct msghdr *msg, int flags);
int rs_sendmsg(int sd, const struct msghdr *msg, int flags);
int rs_select(int n, fd_set *rs, fd_set *ws, fd_set *es,
	      struct timeval *tv);
int rs_dup(int old);
int rs_dup2(int old, int new);
int rs_recover_bad_rocks(int n, fd_set *fds);

/* Overloaded syscalls needed for our sanity, not for the sockets API */
typedef void (*sighandler_t)(int);
int rs_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact);
int rs___libc_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact);
sighandler_t rs_signal(int signum, sighandler_t handler);
int rs_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int rs_sigsuspend(const sigset_t *mask);
int rs_sigaltstack(const stack_t *ss, stack_t *oss);

/* util.c */
typedef struct rocklist *rocklist_t;
struct rocklist {
	rs_t rs;
	rocklist_t next;
};
int rs_xwrite(int sd, void *buf, size_t len);
int rs_xread(int sd, void *buf, size_t len, unsigned long ms);
int rs_reset_on_close(int sd, int onoff);
int rs_reuseaddr(int sd);
int rs_nodelay(int sd, int onoff);
int rs_settcpbuf(int sd, int type, int size);
int rs_nonblock(int sd, int on);
int rs_waitread(int sd, unsigned long ms);
void rs_logbytes(char *bytes, int len);
void rs_kill9_and_wait(pid_t pid);
int rs_rocklist_insert(rocklist_t *head, rs_t rs);
int rs_rocklist_remove(rocklist_t *head, rs_t rs);
rs_t rs_rocklist_findsa(rocklist_t head, struct sockaddr_in *sa);
void rs_rocklist_free(rocklist_t *head);

void rs_init();
int rs_init_sys();
void rs_init_signal();
void rs_rs_sigaction(int sig, const struct sigaction *sa);

int rs_setsockopt(int s, int level, int optname,
		  const void *optval, socklen_t optlen);
int rs_fcntl(int fd, int cmd, long arg);
int rs_ioctl(int fd, int cmd, long arg);
int rs_setitimer(int which, const struct itimerval *value,
		 struct itimerval *ovalue);

/* Internal library functions below? */

#ifndef NO_AUTH
/* Crypto implementation dependent declarations */
typedef struct rs_key *rs_key_t;
int rs_init_crypt();
void rs_key_free(rs_key_t key);
rs_key_t rs_key_exchange(int sock);
int rs_mutual_auth(rs_key_t key, int sock);
int rs_key_save(rs_key_t key, int fd);
rs_key_t rs_key_restore(int fd);

/* Common crypto functions */  
int rs_authenticate(rs_key_t key, int sock);
#else
typedef void *rs_key_t;
#endif /* NO_AUTH */

typedef struct hb * hb_t;
typedef enum { EDP_NOTROCK, EDP_PROBE, EDP_ROCK } edp_result_t;

typedef struct recstate recstate_t;
struct recstate {
	int sda, sdp;        /* active and passive socks */
	int sdn;             /* new incoming connection on sda */
	int sdc;             /* final connection */
	int sent;            /* Have we (if server) sent the byte? */
	int est;             /* Established connections bitset */
	int timeouts;	     /* Timeout counter  */
};

typedef enum { RS_NOTCONNECTED,
	       RS_ESTABLISHED,
	       RS_EDP,
	       RS_SUSPENDED,
	       RS_HUNGUP } rs_state;
typedef enum { RS_ROLE_SERVER, RS_ROLE_CLIENT, RS_ROLE_LISTEN, RS_ROLE_UNDEF } rs_role;
extern char *rs_roles[]; /* If you add a role, update rs_roles. */

typedef struct shm *shm_t;
typedef enum { RS_BLOCK, RS_NOBLOCK } block_t;

struct callbacks {
	void (*suspend)(int rock);
};

struct rs_ {
	rs_state state;
	int refcnt;		    /* reference count */
	int type;                   /* socket type */
	ring_t ring;                /* in flight buffer */
	unsigned rcvseq;            /* seq # of next byte to be passed to app */
	unsigned sndseq;            /* seq # of next byte to be passed to kernel */
	unsigned maxrcv;            /* TCP socket recv buffer size */
	unsigned maxsnd;            /* TCP socket send buffer size */
	int sd;                     /* socket descriptor */
	struct sockaddr_in sa_locl; /* current address of this endpoint */
	struct sockaddr_in sa_peer; /* current address of peer endpoint */
	struct sockaddr_in sa_rl;   /* local reconnection address */
	struct sockaddr_in sa_rp;   /* peer reconnection address */
	pid_t rec_pid;		    /* reconnection process */
	int rec_fd;                 /* socket to reconnection process */
	hb_t hb;                    /* heartbeat state */
	rs_key_t key;               /* authentication key */
	recstate_t rec;             /* reconnection state */
	struct timeval lim;         /* reconnection time limit */
	struct timeval tout;        /* current reconnection timeout alarm */
	rs_role role;		    /* role in connection */
	int backlog;		    /* backlog for listening sockets */
	ring_t edpspill;	    /* edp client recv buffer */
	ring_t clospill;	    /* close catcher */
	int booger;                 /* as the name implies, 
				       this needs to be cleaned up */
	int shmid;                  /* if shared rock, shm identifier */
	shm_t shm;                  /* if shared rock, shared state */
	struct callbacks *cb;
};

int rs_save(rs_t rs, int fd);
rs_t rs_restore(int fd);

/* shm.c */
struct shm {
	int lfd;                /* lock file descriptor */
	pid_t hb_owner;	        /* Process responsible for hbs */
	int hb_count;           /* Incremented each beat by owner */
	int refcnt;		/* reference count from rs_t */
};


int replace_function(char *from, void *to);

typedef enum { RS_MODE_RS, RS_MODE_NATIVE } rs_mode_t;
void rs_mode_push(rs_mode_t m);
void rs_mode_native();
void rs_mode_pop();

char *rs_ipstr(struct sockaddr_in *addr);

rs_t rs_lookup(int fd);
void rs_reconnect(rs_t rs, block_t block);
void rs_rec_complete(rs_t rs, block_t block);
int rs_addr_exchange(rs_t rs);
void rs_wait_reconnect(rs_t rs);

int rs_init_connection(rs_t rs);
void rs_init_log();

/* exec.c */
int rs_execve(const char *filename, char *const argv[], char *const envp[]);
int rs_in_exec();
void rs_restore_exec();

/* Heartbeat */
int rs_init_heartbeat();
void rs_stop_heartbeat(sigset_t *);
void rs_resume_heartbeat(sigset_t *);
hb_t rs_new_heartbeat();
void rs_free_heartbeat(hb_t hb);
int rs_hb_establish(int rock, hb_t hb, rs_role role);
int rs_hb_cancel(hb_t hb);
int rs_hb_save(hb_t hb, int fd);
hb_t rs_hb_restore(rs_t rs, int fd);
void rs_become_hb_owner(hb_t hb);
void rs_hb_init_shm(rs_t rs);

/* Interoperability */
void rs_free_iop(rs_t rs);
int rs_iopsrv(rs_t rs, char *z, int len, edp_result_t *result);
int rs_iop_connect(rs_t rs);
void rs_fallback(rs_t rs);

/* Interprocess rock sharing */
int rs_rock_is_shared(rs_t rs);
int rs_shm_has_one_owner(rs_t rs);
int rs_shm_create(rs_t rs);
int rs_shm_attach(rs_t rs);
void rs_shm_detach(rs_t rs);
void rs_shm_lock(shm_t shm);
void rs_shm_unlock(shm_t shm);

/* 1 of 2 connection establishment */
int rs_1of2(struct sockaddr_in *locl, struct sockaddr_in *peer, 
	    int ls, struct timeval *lim, rs_role role);

#endif /* _RS_H_ */

/* sockaddr.c */
int rs_xwrite_ipaddr(int fd, struct sockaddr_in *addr);
int rs_xread_ipaddr(int fd, struct sockaddr_in *addr);
