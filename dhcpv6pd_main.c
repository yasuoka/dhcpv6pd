/*
 * Copyright (c) 2019 Internet Initiative Japan Inc.
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

static void	 main_dispatch_parent(int, short, void *);
static void	 main_dispatch_control(int, short, void *);

static struct imsgev parent_iev, control_iev;

void
dhcpv6pd_main(void)
{
	struct passwd	*pw;

	setsid();
	openlog(NULL, LOG_PID, LOG_DAEMON);
	setproctitle(PROC_NAME_MAIN);

	dhcpv6pd_log(LOG_INFO, "Start process-id=%d", (int)getpid());

	/*
	 * Drop the privileges
	 */
	if ((pw = getpwnam(DHCPV6PDD_USER)) == NULL) {
		dhcpv6pd_log(LOG_ERR, "%s: gwpwnam: %m", __func__);
		goto fail;
	}

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

	if (pledge("stdio recvfd", NULL) == -1) {
		dhcpv6pd_log(LOG_ERR, "pledge: %m");
		goto fail;
	}

	memset(&parent_iev, 0, sizeof(parent_iev));
	imsg_init(&parent_iev.ibuf, IMSG_PARENT_FILENO);
	parent_iev.handler = main_dispatch_parent;

	memset(&control_iev, 0, sizeof(parent_iev));
	control_iev.ibuf.fd = -1;

	event_init();

	signal(SIGPIPE, SIG_IGN);

	imsg_event_add(&parent_iev);

	event_loop(0);

	if (parent_iev.ibuf.fd >= 0) {
		close(parent_iev.ibuf.fd);
		parent_iev.ibuf.fd = -1;
	}
	imsg_clear(&parent_iev.ibuf);
	event_del(&parent_iev.ev);

	if (control_iev.ibuf.fd >= 0) {
		close(control_iev.ibuf.fd);
		control_iev.ibuf.fd = -1;
	}
	imsg_clear(&control_iev.ibuf);
	event_del(&control_iev.ev);

	event_loop(0);

	dhcpv6pd_log(LOG_INFO, "Terminated");

	exit(EXIT_SUCCESS);
 fail:
	exit(EXIT_FAILURE);
}

void
main_dispatch_parent(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	ssize_t		 n, datalen;

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
		if ((n = imsg_get(&iev->ibuf, &imsg)) == -1) {
			/* handle read error */
			dhcpv6pd_log(LOG_ERR, "%s: imsg_get() failed: %m",
			    __func__);
			goto fail;
		}
		if (n == 0)     /* no more messages */
			break;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_TERMINATE:
			event_loopbreak();
			break;
		case IMSG_PIPE_CONTROL:
			DHCPV6PD_ASSERT(control_iev.ibuf.fd == -1);
			imsg_init(&control_iev.ibuf, imsg.fd);
			control_iev.handler = main_dispatch_control;
			imsg_event_add(&control_iev);
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
	return;
}

void
main_dispatch_control(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	ssize_t		 n, datalen;

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
		if ((n = imsg_get(&iev->ibuf, &imsg)) == -1) {
			/* handle read error */
			dhcpv6pd_log(LOG_ERR, "%s: imsg_get() failed: %m",
			    __func__);
			goto fail;
		}
		if (n == 0)     /* no more messages */
			break;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_CTL_PING:
			imsg_compose_event(iev, IMSG_CTL_PONG, imsg.hdr.peerid,
			    -1, -1, "OK", 2);
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
	return;
}
