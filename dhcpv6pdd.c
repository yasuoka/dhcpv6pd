/*
 * Copyright (c) 2023 YASUOKA Masahiko <yasuoka@yasuoka.net>
 * Copyright (c) 2019 Internet Initiative Japan Inc.
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "dhcpv6.h"
#include "dhcpv6pdd.h"
#include "dhcpv6pdd_local.h"

#include "control.h"

static int	 noaction = 0, foreground = 0, debug = 0;
static char	 conffile[PATH_MAX];
static struct dhcpv6pdd_conf
		*curr_conf;
static bool	 terminated = false;
static struct imsgev
		 main_iev;

static pid_t	 start_child(const char *, int, char *[], int);
static void	 parent_dispatch_main(int, short, void *);
static void	 parent_dispatch_control(int, short, void *);
static void	 parent_on_signal(int, short, void *);
static int	 dhcpdv6_client_socket(void);

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dn][-f file]\n", __progname);
}

int
main(int argc, char *argv[])
{
	int		  ch, argc0, fds[2];
	char		**argv0;
	const char	 *conffile0 = DHCPV6PDD_CONF, *procname = NULL;
	struct imsgev	  control_iev;
	pid_t		  main_pid, control_pid;
	struct event	  evsigint, evsighup, evsigterm;

	argc0 = argc;
	argv0 = argv;

	while ((ch = getopt(argc, argv, "df:nP:")) != -1)
		switch (ch) {
		case 'd':
			foreground = 1;
			debug++;
		case 'D':
			foreground = 1;
			break;
		case 'f':
			conffile0 = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'P':
			procname = optarg;
			break;
		default:
			usage();
			exit(EX_USAGE);
		}

	argc -= optind;
	argv += optind;

	if ((realpath(conffile0, conffile)) == NULL && errno != ENOENT)
		err(EX_CONFIG, "%s", conffile0);
	curr_conf = parse_config(conffile);
	if (curr_conf == NULL)
		exit(EX_CONFIG);
	if (procname != NULL) {
		if (strcmp(procname, PROC_NAME_MAIN) == 0)
			dhcpv6pd_main();
		else if (strcmp(procname, PROC_NAME_CONTROL) == 0)
			control_main(DHCPV6PDD_SOCK);
		else
			err(EX_USAGE, "unknown proc: %s", procname);
		DHCPV6PD_ASSERT(0);	/* not reached here */
	}
	/*
	 * This is the "parent" process, which is priviledged
	 */

	if (noaction)
		exit(EXIT_SUCCESS);

	if (!foreground)
		daemon(0, 0);

	openlog(NULL, LOG_PID, LOG_DAEMON);

	if (unveil(argv0[0], "x") == -1)
		fatal("unveil");
//	if (pledge("stdio exec proc sendfd unveil", NULL) == -1)
//		fatal("pledge");
	/*
	 * Start "main" proccess and prepare the IPC with it
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, fds) == -1)
		fatal("socketpair");
	main_pid = start_child(PROC_NAME_MAIN, argc0, argv0, fds[1]);
	memset(&main_iev, 0, sizeof(main_iev));
	imsg_init(&main_iev.ibuf, fds[0]);
	main_iev.handler = parent_dispatch_main;

	/*
	 * Start "control" proccess and prepare the IPC with it
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, fds) == -1)
		err(EX_OSERR, "socketpair");
	control_pid = start_child(PROC_NAME_CONTROL, argc0, argv0, fds[1]);
	memset(&control_iev, 0, sizeof(control_iev));
	imsg_init(&control_iev.ibuf, fds[0]);
	control_iev.handler = parent_dispatch_control;

	if (unveil(argv0[0], "") == -1)
		fatal("unveil");
//	if (pledge("stdio sendfd", NULL) == -1)
//		fatal("pledge");

	event_init();

	signal(SIGPIPE, SIG_IGN);
	signal_set(&evsighup,  SIGHUP,  parent_on_signal, NULL);
	signal_set(&evsigterm, SIGTERM, parent_on_signal, NULL);
	signal_set(&evsigint,  SIGINT,  parent_on_signal, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsigint, NULL);

	/*
	 * Join "control" and "main"
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, fds) == -1)
		fatal("socketpair");
	if (imsg_compose_event(&main_iev, IMSG_PIPE_CONTROL, 0, 0, fds[0],
	    NULL, 0) == -1)
		fatal("imsg_compose_event(,IMSG_PIPE_CONTROL)");
	if (imsg_compose_event(&control_iev, IMSG_PIPE_MAIN, 0, 0, fds[1],
	    NULL, 0) == -1)
		fatal("imsg_compose_event(,IMSG_PIPE_MAIN)");

	imsg_event_add(&main_iev);
	imsg_event_add(&control_iev);

	imsg_compose_event(&main_iev, IMSG_CONFIG, 0, 0, -1, curr_conf,
	    sizeof(*curr_conf));

	int sock = dhcpdv6_client_socket();
	if (sock < 0)
		exit(EXIT_FAILURE);
	if (imsg_compose_event(&main_iev, IMSG_CLIENT_SOCK,
	    0, 0, sock, NULL, 0) == -1)
		fatal("imsg_compose_event() failed");
    {
	#include <net/if_dl.h>
	#include <ifaddrs.h>
	struct ifaddrs		*ifa0, *ifa;
	struct dhcpv6pdd_iface	 iface;
	struct sockaddr_dl	*sdl;

	getifaddrs(&ifa0);
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, "vmx0") == 0 &&
		    ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		/* XXX */
	} else {

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		strlcpy(iface.ifname, ifa->ifa_name, sizeof(iface.ifname));
		iface.ifidx = sdl->sdl_index;
		memcpy(iface.lladdr, LLADDR(sdl),
		    MINIMUM(sizeof(iface.lladdr), sdl->sdl_alen));
		if (imsg_compose_event(&main_iev, IMSG_NEW_INTERFACE,
		    0, 0, -1, &iface, sizeof(iface)) == -1)
			fatal("imsg_compose_event() failed");
	}
	freeifaddrs(ifa0);
    }
	event_loop(0);

	/* terminated */
	if (main_iev.ibuf.fd >= 0) {
		imsg_compose_event(&main_iev, IMSG_TERMINATE, 0, 0, -1,
		    NULL, 0);
		imsg_flush(&main_iev.ibuf);
		close(main_iev.ibuf.fd);
		main_iev.ibuf.fd = -1;
	}
	imsg_clear(&main_iev.ibuf);
	event_del(&main_iev.ev);

	if (control_iev.ibuf.fd >= 0) {
		imsg_compose_event(&control_iev, IMSG_TERMINATE, 0, 0, -1,
		    NULL, 0);
		imsg_flush(&control_iev.ibuf);
		close(control_iev.ibuf.fd);
		control_iev.ibuf.fd = -1;
	}
	imsg_clear(&control_iev.ibuf);
	event_del(&control_iev.ev);

	signal_del(&evsighup);
	signal_del(&evsigterm);
	signal_del(&evsigint);

	event_loop(0);

	/* make sure the child entered nirvana. */
	waitpid(main_pid, NULL, 0);
	waitpid(control_pid, NULL, 0);

	exit(terminated ? EXIT_SUCCESS : EXIT_FAILURE);
}

pid_t
start_child(const char *proc, int argc, char *argv[], int fd)
{
	pid_t	  pid;
	int	  i, nargc = 0;
	char	**nargv;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (fd != IMSG_PARENT_FILENO) {
		if (dup2(fd, IMSG_PARENT_FILENO) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	if ((nargv = calloc(argc + 3, sizeof(char *))) == NULL)
		fatal("calloc");

	nargv[nargc++] = argv[0];
	nargv[nargc++] = "-P";
	nargv[nargc++] = (char *)proc;
	for (i = 1; i < argc; i++)
		nargv[nargc++] = argv[i];
	nargv[nargc++] = NULL;

	execvp(nargv[0], nargv);
	fatal("execvp");
}

void
parent_dispatch_main(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	int		 n;

	if (ev & EV_READ) {
		if (((n = imsg_read(&iev->ibuf)) == -1 && errno != EAGAIN) ||
		    n == 0) {
			if (n == 0)
				dhcpv6pd_log(LOG_ERR,
				    "%s: connection closed", __func__);
			else
				dhcpv6pd_log(LOG_ERR,
				    "%s: imsg_read() failed: %m", __func__);
			goto fail;
		}
	}
	if ((ev & EV_WRITE) && iev->ibuf.w.queued) {
		if (msgbuf_write(&iev->ibuf.w) <= 0 && errno != EAGAIN)
			goto fail;
	}

	for (;;) {
		if ((n = imsg_get(&iev->ibuf, &imsg)) == -1)
			goto fail;

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		}
		imsg_free(&imsg);
	}

	imsg_event_add(iev);

	return;

 fail:
	close(iev->ibuf.fd);
	iev->ibuf.fd = -1;
	event_loopbreak();
}

void
parent_dispatch_control(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	int		 n;

	if (ev & EV_READ) {
		if (((n = imsg_read(&iev->ibuf)) == -1 && errno != EAGAIN) ||
		    n == 0) {
			if (n == 0)
				dhcpv6pd_log(LOG_ERR,
				    "%s: connection closed", __func__);
			else
				dhcpv6pd_log(LOG_ERR,
				    "%s: imsg_read() failed: %m", __func__);
			goto fail;
		}
	}
	if ((ev & EV_WRITE) && iev->ibuf.w.queued) {
		if (msgbuf_write(&iev->ibuf.w) <= 0 && errno != EAGAIN)
			goto fail;
	}

	for (;;) {
		if ((n = imsg_get(&iev->ibuf, &imsg)) == -1)
			goto fail;

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		}
		imsg_free(&imsg);
	}

	imsg_event_add(iev);

	return;

 fail:
	close(iev->ibuf.fd);
	iev->ibuf.fd = -1;
	event_loopbreak();
}

void
parent_on_signal(int sig, short ev, void *ctx)
{
	static struct dhcpv6pdd_conf *new_conf;
	switch (sig) {
	case SIGHUP:
		dhcpv6pd_log(LOG_INFO, "caught SIGHUP");
		if (conffile[0] != '\0') {
			parse_config(conffile);
			new_conf = parse_config(conffile);
			if (new_conf != NULL) {
				dhcpv6pd_log(LOG_INFO,
				    "Reload configuration failure");
			} else {
				dhcpv6pd_log(LOG_INFO,
				    "Reload configuration successfully");
				free(curr_conf);
				curr_conf = new_conf;
				imsg_compose_event(&main_iev, IMSG_CONFIG, 0,
				    0, -1, curr_conf, sizeof(*curr_conf));
			}
		}
		break;
	case SIGINT:
	case SIGTERM:
		dhcpv6pd_log(LOG_INFO,
		    "caught SIG%s", (sig == SIGINT)? "INT" : "TERM");
		terminated = true;
		event_loopbreak();
		break;
	}
}

int
dhcpdv6_client_socket(void)
{
	int			 sock = -1;
	struct sockaddr_in6	 sin6;

	if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		log_warn("socket()");
		goto on_error;
	}
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_port = htons(DHCPV6_CLIENT_PORT);
	if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) == -1) {
		log_warn("bind()");
		goto on_error;
	}

	return (sock);
on_error:
	if (sock >= 0)
		close(sock);
	return (-1);
}

/***********************************************************************
 * log
 ***********************************************************************/
void
dhcpv6pd_log(int priority, const char *format, ...)
{
	va_list	 ap;

	va_start(ap, format);
	if (noaction)
		vfprintf(stderr, format, ap);
	else
		vlog(priority, format, ap);
	va_end(ap);
	if (noaction)
		fputs("\n", stderr);
}

void
vlog(int priority, const char *format, va_list args)
{
	u_int		 i, fmtoff;
	int		 saved_errno;
	FILE		*fp = stderr;
	struct tm	 tm;
	time_t		 curr_time;
	const char	*pristr = NULL;
	char		 fmt[BUFSIZ];
	static struct {
		int		 prio;
		const char	*name;
	} prio_names[] = {
#define PRIO_NAME(_prio) { (_prio), (const char *)#_prio + 4 }
		PRIO_NAME(LOG_EMERG),
		PRIO_NAME(LOG_ALERT),
		PRIO_NAME(LOG_CRIT),
		PRIO_NAME(LOG_ERR),
		PRIO_NAME(LOG_WARNING),
		PRIO_NAME(LOG_NOTICE),
		PRIO_NAME(LOG_INFO),
		PRIO_NAME(LOG_DEBUG)
	};

	if (!foreground || !debug) {
		vsyslog(priority, format, args);
		return;
	}

	for (i = 0; i < nitems(prio_names); i++)
		if (prio_names[i].prio == priority) {
			pristr = prio_names[i].name;
			break;
		}
	DHCPV6PD_ASSERT(pristr != NULL);

	/* convert %m to error message */
	for (i = 0, fmtoff = 0; format[i] != '\0';) {
		if (fmtoff + 2 >= sizeof(fmt))
			break;
		if (format[i] == '%' && format[i + 1] == 'm') {
			saved_errno = errno;
			if (strerror_r(saved_errno, fmt + fmtoff,
			    sizeof(fmt) - fmtoff - 1) == 0) {
				errno = saved_errno;
				i += 2;
				fmtoff = strlen(fmt);
				continue;
			}
			errno = saved_errno;
		}
		fmt[fmtoff++] = format[i++];
	}
	fmt[fmtoff++] = '\n';
	fmt[fmtoff++] = '\0';

	time(&curr_time);
	localtime_r(&curr_time, &tm);
	fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d:%s: ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
	    tm.tm_min, tm.tm_sec, pristr);

	vfprintf(fp, fmt, args);
}

void
fatal(const char *msg)
{
	dhcpv6pd_log(LOG_CRIT, "%s: %s", msg, strerror(errno));
	abort();
}

void
fatalx(const char *msg)
{
	dhcpv6pd_log(LOG_CRIT, "%s", msg);
	abort();
}

void
log_warn(const char *fmt, ...)
{
	int	 saved_errno = errno;
	va_list	 ap;
	char	 fmt1[BUFSIZ];

	strlcpy(fmt1, fmt, sizeof(fmt1));
	strlcat(fmt1, ": ", sizeof(fmt1));
	strlcat(fmt1, strerror(saved_errno), sizeof(fmt1));

	va_start(ap, fmt);
	vlog(LOG_WARNING, fmt1, ap);
	va_end(ap);
}

void
log_warnx(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
log_debug(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

/***********************************************************************
 * imsg_event
 ***********************************************************************/
struct iovec;

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
	    pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);
	return (ret);
}

int
imsg_composev_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, struct iovec *iov, int niov)
{
	int	ret;

	if ((ret = imsg_composev(&iev->ibuf, type, peerid,
	    pid, fd, iov, niov)) != -1)
		imsg_event_add(iev);
	return (ret);
}
