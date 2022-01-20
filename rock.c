/* 
 *  rocks/rock.c
 *
 *  Reliable sockets program launcher.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>

/* FIXME:
   Propagate option disabling variables to rockd. 
*/

/* Parameters.  Set by command line parsing or defaults(). */
static char *rockd_local_path = NULL;
static char *rockd_remote_path = "rockd";
static char *rockd_login = NULL;
static char *rocks_path = NULL;
static char *ckpt_path = NULL;
static char *version = "ROCK 2.2.4 (June 2002) for x86 Linux";

/* Switches. */
static int opt_verbose = 0;
static int opt_userockd = 0;
static int opt_log = 0;
static int opt_noauth = 0;
static int opt_nohb = 0;
static int opt_noflight = 0;
static int opt_nointerop = 0;
static int opt_uploadrockd = 0;
static int opt_ckpt = 0;
static int opt_localhost = 0;

/* Known services */
typedef struct service {
	char *cmd;                              /* User command name */
	unsigned short port;                    /* Default port */
	char * (*get_login)(int, char **);      /* Extract login from args */
	char * (*get_host)(int, char **);       /* Extract hostname from args */
	int (*get_port)(int, char **);          /* Extract port from args (default port override) */
	int (*set_port)(int *, char ***, int);  /* Add argument to set port */
} service_t;

/* SSH Service */
static char * get_login_ssh(int argc, char **argv);
static char * get_host_ssh(int argc, char **argv);
static int get_port_ssh(int argc, char **argv);
static int set_port_ssh(int *argc, char ***argv, int port);
service_t ssh_service = {
	"ssh", 22,
	get_login_ssh,
	get_host_ssh,
	get_port_ssh,
	set_port_ssh
};

/* SCP Service */
static char * get_login_scp(int argc, char **argv);
static char * get_host_scp(int argc, char **argv);
service_t scp_service = {
	"scp", 22,
	get_login_scp,
	get_host_scp,
	get_port_ssh,
	set_port_ssh
};

/* TELNET Service */
service_t telnet_service = {
	"telnet", 23,
};

static service_t *services[] = {
	&ssh_service,
	&scp_service,
/*	&telnet_service, */
	NULL
};

static service_t *
lookup_service(char *cmd)
{
	service_t **p;
	for (p = services; *p; p++)
		if (!strcmp((*p)->cmd, cmd))
			return *p;
	return NULL;
}

static char *
get_login_ssh(int argc, char **argv)
{
	int c;
	opterr = 0; /* Don't squeal on unrecognized args */
	optind = 0;
	while (EOF != (c = getopt(argc, argv, "+l:")))
		/* `+' means don't reorder argv */
		switch (c) {
		case 'l':
			return optarg;
			break;
		default:
			continue;
		}
	return NULL;
}

static char *
get_host_ssh(int argc, char **argv)
{
	int c;
	opterr = 0; /* Don't squeal on unrecognized args */
	optind = 0;
	while (EOF != (c = getopt(argc, argv, "+l:nAaXxi:tTvVPqfe:c:p:L:R:CNg462o:")))
		/* `+' means don't reorder argv */
		;
	if (optind < argc)
		return argv[optind];
	return NULL;
}

static int
get_port_ssh(int argc, char **argv)
{
	int c;
	opterr = 0; /* Don't squeal on unrecognized args */
	optind = 0;
	while (EOF != (c = getopt(argc, argv, "+p:")))
		/* `+' means don't reorder argv */
		switch (c) {
		case 'p':
			return atoi(optarg);
			break;
		default:
			continue;
		}
	return 0;
}

static int
set_port_ssh(int *ioargc, char ***ioargv, int port)
{
	static char portbuf[32];
	static char *minusp = "-p";
	int i, argc;
	char **argv, **newargv;

	argc = *ioargc;
	argv = *ioargv;
	if (get_port_ssh(argc, argv)) {
		fprintf(stderr, "rock: ssh to non-default ports currently unsupported.\n");
		return -1;
	}
	*ioargc += 2;
	newargv = *ioargv = (char**) malloc((argc+3) * sizeof(char *));
	if (!newargv) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}

	newargv[0] = argv[0];
	newargv[1] = minusp;
	sprintf(portbuf, "%hu", port);
	newargv[2] = portbuf;
	for (i = 1; i < argc; i++)
		newargv[i+2] = argv[i];
	newargv[argc+2] = '\0';
	return 0;
}

static char *
get_login_scp(int argc, char **argv)
{
	assert(0);
	return 0;
}

static char *
get_host_scp(int argc, char **argv)
{
	assert(0);
	return 0;
}

static int
scp_rockd(char *login, char *host, char *local_path, char *remote_path)
{
	/* Run the command:
                scp local_path [<login>@]<host>:<remote_path>
         */
	char buf[2048];
	int pid, stat, need;

	pid = fork();
	if (0 > pid) {
		perror("fork");
		return -1;
	}

	if (!pid) {
		/* Child */

		close(1);
		/* We need stderr for the scp password prompt */

		need = strlen(host) + strlen(remote_path) + 2;
		if (login)
			need += strlen(login) + 1;
		if (need > sizeof(buf)) {
			fprintf(stderr, "Arguments to scp too long\n");
			return -1;
		}
		if (login)
			snprintf(buf, sizeof(buf), "%s@%s:%s",
				 login, host, remote_path);
		else
			snprintf(buf, sizeof(buf), "%s:%s",
				 host, remote_path);

		if (opt_verbose) {
			fprintf(stderr,
				"About to run scp like this:\n\t");
			fprintf(stderr, "scp %s %s\n", local_path, buf);
		}
		execlp("scp", "scp", local_path, buf, 0);
		perror("exec");
		exit(1);
	}

	if (0 > waitpid(pid, &stat, 0)) {
		perror("waitpid");
		kill(pid, SIGKILL);
		return -1;
	}
	if (!WIFEXITED(stat) || WEXITSTATUS(stat)) {
		fprintf(stderr, "Remote scp failed.\n");
		kill(pid, SIGKILL);
		return -1;
	}
	return 0;
}

/* Start rockd on the remote host.  LOGIN may be NULL, in which case
   ssh chooses the login.  Return the port number on which rockd is
   listening for us, or -1 on error.  */
static int
spawn_rockd(char *login, char *host, char *rockd_path, int port)
{
	/* We run the command:
                ssh -l <login> <host> <rockd_path> -d <port>
         */
	char buf[2048];
	int fd[2];
	int pid;
	int stat;
	int oport;
	int rv;

	sprintf(buf, "%d", port);
	if (0 > pipe(fd)) {
		perror("pipe");
		return -1;
	}
	pid = fork();
	if (0 > pid) {
		perror("fork");
		return -1;
	}

	if (!pid) {
		/* Child */
		close(fd[0]);
		close(1);
		dup2(fd[1], 1);
		/* We need stderr for the ssh password prompt */
		if (login) {
			if (opt_verbose) {
				fprintf(stderr,
					"About to run rockd like this:\n\t");
				fprintf(stderr, "ssh -l %s %s %s -d %s\n",
					login, host, rockd_path, buf);
			}
			execlp("ssh", "ssh", "-l", login, host,
			       rockd_path, "-d", buf, 0);
		} else {
			if (opt_verbose) {
				fprintf(stderr,
					"About to run rockd like this:\n\t");
				fprintf(stderr, "ssh %s %s -d %s\n",
					host, rockd_path, buf);
			}
			execlp("ssh", "ssh", host,
			       rockd_path, "-d", buf, 0);
		}
		perror("exec(rock)");
		exit(1);
	}

	/* Parent */
	close(fd[1]);
	if (0 > waitpid(pid, &stat, 0)) {
		perror("waitpid");
		kill(pid, SIGKILL);
		return -1;
	}
	if (!WIFEXITED(stat)) {
		fprintf(stderr, "Remote rockd failed.\n");
		kill(pid, SIGKILL);
		return -1;
	}
	rv = read(fd[0], buf, sizeof(buf)-1);
	if (0 > rv) {
		fprintf(stderr, "Remote rockd failed.\n");
		return -1;
	}
	buf[rv] = '\0';
	if (1 != sscanf(buf, "%d", &oport) || oport <= 0) {
		if (rv > 0) {
			fprintf(stderr, "ssh error:\n");
			fprintf(stderr, buf);
		} else
			fprintf(stderr, "Remote rockd failed.\n");
		return -1;
	}
	close(fd[0]);
	return oport;
}

static char *
ldpreload()
{
	static char buf[1024];
	char *s = "LD_PRELOAD=";

	if (ckpt_path) {
		assert(strlen(ckpt_path)+strlen(rocks_path)+ 1
		       < (sizeof(buf) - strlen(s)));
		sprintf(buf, "%s%s %s", s, ckpt_path, rocks_path);
	} else {
		assert(strlen(rocks_path) + 1 < (sizeof(buf) - strlen(s)));
		sprintf(buf, "%s%s", s, rocks_path);
	}
	return buf;
}

static int
exec_cmd(int argc, char **argv)
{
	if (0 > putenv(ldpreload())) {
		fprintf(stderr, "Can't put rocks in environment\n");
		return -1;
	}
	execvp(argv[0], argv);
	fprintf(stderr, "[%d]exec %s: %s\n",
		getpid(), argv[0], strerror(errno));
	return -1;
}

static char *
find_lib(char *libname)
{
	char *home;
	char buf[1024];
	char *dir;
	
#ifdef ROCKS_LIB_PATH
	dir = ROCKS_LIB_PATH;
	assert(strlen(dir)+2 < sizeof(buf) - sizeof(libname));
	sprintf(buf, "%s/%s", dir, libname);
	if (!access(buf, R_OK|X_OK)) {
		return strdup(buf);
	}
#endif
	home = getenv("HOME");
	if (home) {
		assert(strlen(home)+6 < sizeof(buf) - sizeof(libname));
		sprintf(buf, "%s/lib/%s", home, libname);
		if (!access(buf, R_OK|X_OK))
			return strdup(buf);
	}
	/* Otherwise, maybe we'll get it in LD_LIBRARY_PATH */
	return strdup(libname);
}


/* Set up default parameters.  Must be called after doargs(). */
static void
defaults()
{
	char *user;
	if (!rockd_login) {
		user = getenv("USER");
		if (user)
			rockd_login = user;
		else {
			fprintf(stderr,
				"Warning: I can't find your username; ");
			fprintf(stderr,
				"I probably won't be able to start rockd.\n");
			rockd_login = "nobody";
		}
	}
	if (!rocks_path)
		rocks_path = find_lib("librocks.so");
	if (opt_ckpt && !ckpt_path)
		ckpt_path = find_lib("libckpt.so");
}

static void
usage()
{
	fprintf(stderr, "Usage: rock [switches] command\n");
	fprintf(stderr, " Switches:\n");
#if 0
	/* developer options */
        fprintf(stderr, "  -A             Disable authentication\n");
        fprintf(stderr, "  -I             Disable rock detection\n");
	fprintf(stderr, "  -H             Disable heartbeat\n");
	fprintf(stderr, "  -F             Disable in-flight buffers\n");
	fprintf(stderr, "  -W             Disable the whole works\n");
	fprintf(stderr, "  -x             Just start rockd\n");
        fprintf(stderr, "  -u <path>      Upload rockd from <path> on local host\n");
	fprintf(stderr, "  -f <path>      Use rockd at <path> on remote host\n");
#endif
	fprintf(stderr, "  -d [ <login> ] Start remote rockd\n"); 
	fprintf(stderr, "  -L             Log to /tmp/rocks\n");
	fprintf(stderr, "  -k             Enable checkpointing\n");
	fprintf(stderr, "  -l             Reconnect to the localhost\n");
        fprintf(stderr, "  -v             Be verbose\n");
        fprintf(stderr, "  -V             Print version number\n");
	fprintf(stderr, "  -h             Print this information\n");
}

/* Parse and handle options, stripping options and command (`rock') from
   IOARGC and IOARGV. */
static void
doargs(int *ioargc, char ***ioargv)
{
	int argc;
	char **argv;
	int c;
	int quit = 0;

	argc = *ioargc;
	argv = *ioargv;

	opterr = 0;
	optind = 0;
	/* `+' means don't reorder argv */
	while (EOF != (c = getopt(argc, argv, "+d::vVhLf:u:AIHFWkl")))
		switch (c) {
		case 'h':
			usage();
			quit = 1;
			break;
		case 'V':
			fprintf(stderr, "%s\n", version);
			quit = 1;
			break;
		case 'v':
			opt_verbose++;
			break;
		case 'd':
			if (optarg)
				rockd_login = optarg;
			opt_userockd++;
			break;
		case 'L':
			opt_log = 1;
			break;
		case 'A':
			opt_noauth++;
			break;
		case 'I':
			opt_nointerop++;
			break;
		case 'H':
			opt_nohb++;
			break;
		case 'F':
			opt_noflight++;
			break;
		case 'W':
			opt_noauth++;
			opt_nointerop++;
			opt_nohb++;
			opt_noflight++;
			break;
		case 'f':
			rockd_remote_path = optarg;
			break;
		case 'u':
			opt_uploadrockd++;
			rockd_local_path = optarg;
			break;
		case 'k':
			opt_ckpt++;
			break;
		case 'l':
			opt_localhost++;
			break;
		case '?':
			fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			exit(1);
			break;
		}
	if (quit)
		exit(0);
	argc -= optind;
	argv += optind;
	if (argc < 1) {
		usage();
		exit(1);
	}
	*ioargc = argc;
	*ioargv = argv;
}


int
main(int argc, char **argv)
{
	int port;
	char *cmd, *host, *login;
	service_t *sv;

	doargs(&argc, &argv);
	defaults();

	/* Add reliable socket options to environment. */
	if (!opt_log && (0 > putenv("RS_NOLOG=TRUE"))) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	if (opt_noauth && (0 > putenv("RS_NOAUTH=TRUE"))) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	if (opt_nointerop && (0 > putenv("RS_NOINTEROP=TRUE"))) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	if (opt_nohb && (0 > putenv("RS_NOHB=TRUE"))) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	if (opt_noflight && (0 > putenv("RS_NOFLIGHT=TRUE"))) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	if (opt_ckpt) {
		char buf[1024];
		sprintf(buf, "RS_CKPTPATH=%s", ckpt_path);
		if (0 > putenv(buf)) {
			fprintf(stderr, "Out of memory.\n");
			exit(1);
		}
	}
	if (opt_localhost) {
		char buf[1024];
		sprintf(buf, "RS_LOCALHOST=1");
		if (0 > putenv(buf)) {
			fprintf(stderr, "Out of memory.\n");
			exit(1);
		}
	}

	if (!opt_userockd)
		goto cmdonly;

	/* When using rockd, disable interoperability. */
	if (0 > putenv("RS_NOINTEROP=TRUE")) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}

	cmd = strrchr(argv[0], '/');
	if (cmd)
		cmd++;
	else
		cmd = argv[0];
	sv = lookup_service(cmd);
	if (!sv) {
		fprintf(stderr, "rock: Unrecognized service `%s'\n", cmd);
		exit(1);
	}
	host = sv->get_host(argc, argv);
	if (!host)
		fprintf(stderr, "rock: Cannot determine remote host from command line\n");
	if (!host)
		exit(1);
	login = sv->get_login(argc, argv);

	if (opt_uploadrockd) {
		fprintf(stderr, "[upload rockd] ");
		if (0 > scp_rockd(login, host, rockd_local_path, rockd_remote_path))
			exit(1);
	}

	fprintf(stderr, "[spawn rockd] ");
	port = spawn_rockd(login, host, rockd_remote_path, sv->port);
	if (0 > port)
		exit(1);
	if (opt_verbose && port > 0)
		fprintf(stderr, "Rockd listening on %s:%d\n", host, port);
	if (0 > set_port_ssh(&argc, &argv, port))
		exit(1);
cmdonly:
	if (opt_verbose) {
		int i;
		fprintf(stderr, "About to run your command like this:\n\t");
		for (i = 0; i < argc; i++)
			fprintf(stderr, " %s", argv[i]);
		fprintf(stderr, "\nUnder environment %s\n", ldpreload());
	}
	exec_cmd(argc, argv);
	exit(1);
}
