/*	$OpenBSD: control.c,v 1.43 2017/01/08 23:04:42 krw Exp $ */

/*
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "dhcpv6pdd.h"
#include "dhcpv6pdd_local.h"
#include "control.h"

static TAILQ_HEAD(, ctl_conn) ctl_conns = TAILQ_HEAD_INITIALIZER(ctl_conns);

#define	CONTROL_BACKLOG	5

struct ctl_conn	*control_connbypid(pid_t);
void		 control_close(int);
void		 control_connfree(struct ctl_conn *);
void		 control_event_add(struct ctl_conn *);
void		 control_dispatch_parent(int, short, void *);
void		 control_dispatch_main(int fd, short ev, void *);

static struct imsgev	 main_iev, parent_iev;

struct {
	struct event	ev;
	struct event	evt;
	int		fd;
} control_state;

int
control_init(const char *path)
{
	struct sockaddr_un	 sun;
	int			 fd;
	mode_t			 old_umask;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1) {
		log_warn("control_init: socket");
		return (-1);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (unlink(path) == -1)
		if (errno != ENOENT) {
			log_warn("control_init: unlink %s", path);
			close(fd);
			return (-1);
		}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("control_init: bind: %s", path);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		log_warn("control_init: chmod");
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	control_state.fd = fd;

	return (0);
}

int
control_listen(void)
{

	if (listen(control_state.fd, CONTROL_BACKLOG) == -1) {
		log_warn("control_listen: listen");
		return (-1);
	}

	event_set(&control_state.ev, control_state.fd, EV_READ,
	    control_accept, NULL);
	event_add(&control_state.ev, NULL);
	evtimer_set(&control_state.evt, control_accept, NULL);

	return (0);
}

void
control_cleanup(void)
{
	struct ctl_conn	*c, *t;

	TAILQ_FOREACH_SAFE(c, &ctl_conns, entry, t) {
		TAILQ_REMOVE(&ctl_conns, c, entry);
		control_connfree(c);
	}
	event_del(&control_state.ev);
	event_del(&control_state.evt);
}

/* ARGSUSED */
void
control_accept(int listenfd, short event, void *bula)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct ctl_conn		*c;

	event_add(&control_state.ev, NULL);
	if ((event & EV_TIMEOUT))
		return;

	len = sizeof(sun);
	if ((connfd = accept4(listenfd, (struct sockaddr *)&sun, &len,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) == -1) {
		/*
		 * Pause accept if we are out of file descriptors, or
		 * libevent will haunt us here too.
		 */
		if (errno == ENFILE || errno == EMFILE) {
			struct timeval evtpause = { 1, 0 };

			event_del(&control_state.ev);
			evtimer_add(&control_state.evt, &evtpause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("control_accept: accept");
		return;
	}

	if ((c = calloc(1, sizeof(struct ctl_conn))) == NULL) {
		log_warn("control_accept");
		close(connfd);
		return;
	}

	imsg_init(&c->iev.ibuf, connfd);
	c->iev.handler = control_dispatch_imsg;
	c->iev.events = EV_READ;
	event_set(&c->iev.ev, c->iev.ibuf.fd, c->iev.events, c->iev.handler, c);
	event_add(&c->iev.ev, NULL);

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);
}

struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->iev.ibuf.fd == fd)
			break;
	}

	return (c);
}

struct ctl_conn *
control_connbypid(pid_t pid)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->iev.ibuf.pid == pid)
			break;
	}

	return (c);
}

void
control_close(int fd)
{
	struct ctl_conn	*c;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warn("control_close: fd %d: not found", fd);
		return;
	}
	control_connfree(c);
}

void
control_connfree(struct ctl_conn *c)
{
	msgbuf_clear(&c->iev.ibuf.w);
	TAILQ_REMOVE(&ctl_conns, c, entry);

	event_del(&c->iev.ev);
	close(c->iev.ibuf.fd);

	/* Some file descriptors are available again. */
	if (evtimer_pending(&control_state.evt, NULL)) {
		evtimer_del(&control_state.evt);
		event_add(&control_state.ev, NULL);
	}

	free(c);
}

/* ARGSUSED */
void
control_dispatch_imsg(int fd, short event, void *bula)
{
	struct ctl_conn	*c;
	struct imsg	 imsg;
	ssize_t		 n;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warn("control_dispatch_imsg: fd %d: not found", fd);
		return;
	}

	if (event & EV_READ) {
		if (((n = imsg_read(&c->iev.ibuf)) == -1 && errno != EAGAIN) ||
		    n == 0) {
			control_close(fd);
			return;
		}
	}
	if (event & EV_WRITE) {
		if (msgbuf_write(&c->iev.ibuf.w) <= 0 && errno != EAGAIN) {
			control_close(fd);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(&c->iev.ibuf, &imsg)) == -1) {
			control_close(fd);
			return;
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_PING:
			imsg_compose_event(&main_iev, IMSG_CTL_PING,
			    fd, -1, -1, NULL, 0);
			break;
		default:
			log_debug("control_dispatch_imsg: "
			    "error handling imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(&c->iev);
}

int
control_imsg_relay(struct imsg *imsg)
{
	struct ctl_conn	*c;

	if ((c = control_connbypid(imsg->hdr.pid)) == NULL)
		return (0);

	return (imsg_compose_event(&c->iev, imsg->hdr.type, 0, imsg->hdr.pid,
	    -1, imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE));
}

void
control_main(const char *control_path)
{
	struct passwd	*pw;

	setsid();
	openlog(NULL, LOG_PID, LOG_DAEMON);
	setproctitle(PROC_NAME_CONTROL);

	if (control_init(control_path) == -1)
		goto fail;
	/*
	 * Drop the privileges
	 */
	if ((pw = getpwnam(DHCPV6PDD_USER)) == NULL) {
		dhcpv6pd_log(LOG_ERR, "%s: gwpwnam: %m", __func__);
		goto fail;
	}

	tzset();	/* load /etc/localtime before going to jail */

	if (chroot(pw->pw_dir) == -1) {
		dhcpv6pd_log(LOG_ERR, "%s: chroot: %m", __func__);
		goto fail;
	}

	if (chdir("/") == -1) {
		dhcpv6pd_log(LOG_ERR, "%s: chdir(\"/\"): %m", __func__);
		goto fail;
	}
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
		dhcpv6pd_log(LOG_ERR, "%s: cannot drop privileges: %m", __func__);
		goto fail;
	}

	if (pledge("stdio unix cpath recvfd", NULL) == -1) {
		dhcpv6pd_log(LOG_ERR, "pledge: %m");
		goto fail;
	}

	memset(&parent_iev, 0, sizeof(parent_iev));
	imsg_init(&parent_iev.ibuf, IMSG_PARENT_FILENO);
	parent_iev.handler = control_dispatch_parent;

	memset(&main_iev, 0, sizeof(main_iev));
	main_iev.ibuf.fd = -1;

	event_init();

	signal(SIGPIPE, SIG_IGN);

	if (control_listen() == -1)
		goto fail;

	imsg_event_add(&parent_iev);

	event_loop(0);

	control_cleanup();

	if (parent_iev.ibuf.fd >= 0) {
		close(parent_iev.ibuf.fd);
		parent_iev.ibuf.fd = -1;
	}
	imsg_clear(&parent_iev.ibuf);
	event_del(&parent_iev.ev);

	if (main_iev.ibuf.fd >= 0) {
		close(main_iev.ibuf.fd);
		main_iev.ibuf.fd = -1;
	}
	imsg_clear(&main_iev.ibuf);
	event_del(&main_iev.ev);

	event_loop(0);

	exit(EXIT_SUCCESS);
 fail:
	exit(EXIT_FAILURE);
}

void
control_dispatch_parent(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	int		 n;

	if (ev & EV_READ) {
		if (((n = imsg_read(&iev->ibuf)) == -1 && errno != EAGAIN) ||
		    n == 0) {
			if (n == 0)
				dhcpv6pd_log(LOG_DEBUG,
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
		case IMSG_TERMINATE:
			event_loopbreak();
			break;
		case IMSG_PIPE_MAIN:
			DHCPV6PD_ASSERT(main_iev.ibuf.fd == -1);
			imsg_init(&main_iev.ibuf, imsg.fd);
			main_iev.handler = control_dispatch_main;
			imsg_event_add(&main_iev);
			break;
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
control_dispatch_main(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	int		 n;
	struct ctl_conn	*c;

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
		case IMSG_CTL_PONG:
			if ((c = control_connbyfd(imsg.hdr.peerid)) != NULL) {
				imsg_compose_event(&c->iev, imsg.hdr.type, 0,
				    -1, -1, imsg.data,
				    imsg.hdr.len - IMSG_HEADER_SIZE);
				imsg_event_add(&c->iev);
			}
			break;
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
