/*
 * Copyright (c) 2023 YASUOKA Masahiko <yasuoka@yasuoka.net>
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>

#include <netinet/in.h>

#include "dhcpv6pdd.h"
#include "dhcpv6pdd_local.h"
#include "dhcpv6.h"

#include <net/if.h>
static int	dhcpv6_client_sock = -1;
struct event	ev_dhcpv6_client_sock;
static uint32_t	iaid_seq;

enum dhcpv6_client_state {
	STATE_INIT = 0,
	STATE_SELECTING,
	STATE_REQUESTING,
	STATE_BOUND,
	STATE_RENEWING,
	STATE_REBINDING,
	STATE_RELEASING
};

struct dhcpv6_client {
	enum dhcpv6_client_state	 state;
	int				 sock;
	char				 ifname[IFNAMSIZ];
	u_int				 ifidx;

	uint8_t				 xid[3];	/* Transaction Id */
	int64_t				 xstart;	/* Transaction Start */
	int				 xtx;		/* # transmit */
	int64_t				 rt;		/* Retrasmit Time */
	int64_t				 t0;

	struct dhcpv6_duid_ll		 cid;		/* Client Identifier */
	uint8_t				 cid_lladdr_space[6];
	uint32_t			*sid;
	int				 sid_len;
	uint32_t			 iaid;
	struct dhcpv6_pd		*pd;

	struct event			 ev_timer;
	TAILQ_ENTRY(dhcpv6_client)	 next;
};
static TAILQ_HEAD(, dhcpv6_client)	 dhcpv6_clients;

static struct dhcpv6pdd_conf		 config;

struct dhcpv6_interface {
	u_int				 ifidx;
	int				 tb_ntokens;
	int64_t				 tb_last_replanish;
	int				 solicit_sent;
	TAILQ_ENTRY(dhcpv6_interface)	 next;
};
static TAILQ_HEAD(, dhcpv6_interface)	 dhcpv6_interfaces;

static struct imsgev parent_iev, control_iev;

static void	 main_dispatch_parent(int, short, void *);
static void	 main_dispatch_control(int, short, void *);

static void	 dhcpv6_client_transition(struct dhcpv6_client *,
		    enum dhcpv6_client_state);
static void	 dhcpv6_client_set_timer(struct dhcpv6_client *, int64_t);
static int	 dhcpv6_client_receive(struct dhcpv6_client *, u_char *, int);
static void	 dhcpv6_client_set_timer(struct dhcpv6_client *, int64_t);
static int	 dhcpv6_client_close(struct dhcpv6_client *);
static void	 dhcpv6_client_on_event(int, short, void *);
static void	 dhcpv6_client_on_timer(int, short, void *);
static int	 dhcpv6_client_init(struct dhcpv6_client *,
		    struct dhcpv6pdd_iface *);
static int	 dhcpv6_client_reinit(struct dhcpv6_client *);
static u_char	*dhcpv6_option_find(u_char *, int, uint16_t, int *);
static int	 dhcpv6_client_transmit(struct dhcpv6_client *, u_char);
static struct dhcpv6_pd
		*dhcpv6_client_retrive_ia_pd(struct dhcpv6_client *, u_char *,
		    int);
static const char
		*dhcpv6_pd_to_string(struct dhcpv6_pd *, char *, int);
static void	 dhcpv6_client_log(struct dhcpv6_client *, int, const char *,
		    ...) __attribute__((__format__ (printf, 3, 4)));

static struct dhcpv6_interface
		*dhcpv6_interface_find(u_int);
static void	 dhcpv6_interface_prepare(u_int);
static bool	 dhcpv6_interface_check_ratelimit(u_int);

static int64_t	 get_uptime(bool);
static void	*xcalloc(size_t, size_t);
static const char
		*hex_string(u_char *, int, char *, int );


void
dhcpv6pd_main(void)
{
	struct passwd		*pw;
	struct dhcpv6_client	*client, *client0;

	setsid();
	openlog(NULL, LOG_PID, LOG_DAEMON);
	setproctitle(PROC_NAME_MAIN);

	get_uptime(true);

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

	if (pledge("stdio recvfd inet mcast", NULL) == -1) {
		dhcpv6pd_log(LOG_ERR, "pledge: %m");
		goto fail;
	}

	TAILQ_INIT(&dhcpv6_clients);
	TAILQ_INIT(&dhcpv6_interfaces);

	iaid_seq = arc4random();

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
	if (dhcpv6_client_sock >= 0)
		event_del(&ev_dhcpv6_client_sock);
	TAILQ_FOREACH_SAFE(client, &dhcpv6_clients, next, client0)
		dhcpv6_client_close(client);

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

	get_uptime(true);	/* update on event hander */

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
		case IMSG_CONFIG:
			if (datalen < sizeof(struct dhcpv6pdd_conf))
				fatal("Received a invalid IMSG_CONFIG: length "
				    "is wrong");
			memcpy(&config, imsg.data, sizeof(config));
			break;
		case IMSG_CLIENT_SOCK:
			dhcpv6_client_sock = imsg.fd;
			event_set(&ev_dhcpv6_client_sock, dhcpv6_client_sock,
			    EV_READ | EV_PERSIST, dhcpv6_client_on_event, NULL);
			event_add(&ev_dhcpv6_client_sock, NULL);
			break;
		case IMSG_NEW_INTERFACE:
		    {
			struct dhcpv6pdd_iface	*iface =
			    (struct dhcpv6pdd_iface *)imsg.data;
			if ((size_t)datalen < sizeof(struct dhcpv6pdd_iface))
				fatal("Received a invalid "
				    "IMSG_NEW_INTERFACE: length is wrong");
			struct dhcpv6_client *client =
			    xcalloc(1, sizeof(struct dhcpv6_client));
			if (dhcpv6_client_init(client, iface) == -1)
				break;

			dhcpv6_client_transition(client, STATE_SELECTING);
			break;
		    }
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);

	return;
 fail:
	dhcpv6_client_sock = -1;
	close(dhcpv6_client_sock);
	event_loopbreak();
	return;
}

void
main_dispatch_control(int fd, short ev, void *ctx)
{
	struct imsgev	*iev = ctx;
	struct imsg	 imsg;
	ssize_t		 n, datalen;

	get_uptime(true);	/* update on event hander */

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
			dhcpv6pd_log(LOG_ERR,
			    "%s: imsg_get() failed: %m", __func__);
			goto fail;
		}
		if (n == 0)     /* no more messages */
			break;
		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_CTL_PING:

dhcpv6_client_transition(TAILQ_FIRST(&dhcpv6_clients), STATE_RELEASING);
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

/***********************************************************************
 *
 ***********************************************************************/
void
dhcpv6_client_transition(struct dhcpv6_client *self,
    enum dhcpv6_client_state new_state)
{
	int64_t				 delay;
	enum dhcpv6_client_state	 old_state;
	char				 msgbuf[128];
	struct dhcpv6_interface		*iface;

#define RANDOM_1OF10(_val) (((_val) * 9 + arc4random() % (_val) * 2) / 10)

	DHCPV6PD_DBG("%s(state=%u->%d)", __func__, (int)self->state,
	    new_state);

	old_state = self->state;
	if (self->state != new_state) {
		arc4random_buf(self->xid, sizeof(self->xid));
		self->xstart = get_uptime(false);
		self->xtx = 0;
		self->rt = 0;
	}
	self->state = new_state;

	switch (self->state) {
	case STATE_INIT:
		break;
	case STATE_SELECTING:
		iface = dhcpv6_interface_find(self->ifidx);
		DHCPV6PD_ASSERT(iface != NULL);
		if (old_state != STATE_SELECTING && iface->solicit_sent == 0) {
			/*
			 * The first Solicit message from the client on the
			 * interface SHOULD be delayed by a random amount of
			 * time between 0 and SOL_MAX_DELAY. (RFC 8514 p.56)
			 */
			if (config.sol_max_delay != 0) {
				dhcpv6_client_set_timer(self,
				    arc4random() % config.sol_max_delay);
				break;
			}
		}
		if (self->xtx == 1) { /* The end of First RT period */
			/*
			 * select the server which sent the valid advertisement
			 * if any
			 */
			if (self->pd != NULL && self->sid != NULL) {
				dhcpv6_client_transition(self,
				    STATE_REQUESTING);
				break;
			}
		}
		dhcpv6_client_transmit(self, DHCPV6_MSGTYPE_SOLICIT);
		iface->solicit_sent++;
		if (self->rt == 0)
			/*
			 * the first RT MUST be selected to be strictly
			 * greater than IRT by choosing RAND to be strictly
			 * greater than 0 (RFC 8514 p.57)
			 */
			self->rt = config.sol_timeout +
			    arc4random() % (config.sol_timeout / 10);
		else
			self->rt = self->rt * 2;
		if (self->rt > config.sol_max_rt)
			self->rt = RANDOM_1OF10(config.sol_max_rt);
		dhcpv6_client_set_timer(self, self->rt);
		break;
	case STATE_REQUESTING:
		if (self->xtx >= config.req_max_rc) {
			dhcpv6_client_log(self, LOG_WARNING,
			    "The selected server didn't reponse for "
			    "our request");
			dhcpv6_client_reinit(self);
			break;
		} else if (self->xtx == 0)
			self->rt = RANDOM_1OF10(config.req_timeout);
		else {
			self->rt = self->rt * 2;
			if (self->rt > config.req_max_rt)
				self->rt = RANDOM_1OF10(config.req_max_rt);
		}
		dhcpv6_client_transmit(self, DHCPV6_MSGTYPE_REQUEST);
		dhcpv6_client_set_timer(self, self->rt);
		break;
	case STATE_BOUND:
		if (old_state != STATE_BOUND) {
			dhcpv6_client_log(self, LOG_INFO,
			    "%s PD successfully.  %s",
			    (old_state == STATE_RENEWING)? "Renew" : "Bound",
			    dhcpv6_pd_to_string(self->pd, msgbuf,
			    sizeof(msgbuf)));
			self->t0 = get_uptime(false);
		}
		/* T1 and T2 is interval since the packet reception */
		if (self->pd->t1 == 0xffffffff)
			delay = 0xffffffff;
		else if (self->pd->t1 < 3)
			delay = 3000;
		else
			delay = self->pd->t1 * 1000 -
			    (get_uptime(false) - self->t0);
		if (delay < 0)
			dhcpv6_client_transition(self, STATE_RENEWING);
		else
			dhcpv6_client_set_timer(self, delay);
		break;
	case STATE_RENEWING:
		/* T1 and T2 is interval since the packet reception */
		if (self->pd->t2 == 0xffffffff)
			delay = 0xffffffff;
		else if (self->pd->t2 < 3)
			delay = 3000;
		else
			delay = self->pd->t2 * 1000 -
			    (get_uptime(false) - self->t0);
		if (delay < 0) {
			free(self->sid);
			self->sid = NULL;
			dhcpv6_client_transition(self, STATE_REBINDING);
			break;
		} else if (self->xtx == 0)
			self->rt = RANDOM_1OF10(config.ren_timeout);
		else {
			self->rt = self->rt * 2;
			if (self->rt > config.ren_max_rt)
				self->rt = RANDOM_1OF10(config.ren_max_rt);
		}
		dhcpv6_client_transmit(self, DHCPV6_MSGTYPE_RENEW);
		dhcpv6_client_set_timer(self, self->rt);
		break;
	case STATE_REBINDING:
		if (get_uptime(false) - self->t0 >=
		    self->pd->prefix[0].valid * 1000) {
			dhcpv6_client_log(self, LOG_WARNING, "Lease expired ");
			dhcpv6_client_reinit(self);
			break;
		} else if (self->xtx == 0)
			self->rt = RANDOM_1OF10(config.reb_timeout);
		else {
			self->rt = self->rt * 2;
			if (self->rt > config.reb_max_rt)
				self->rt = RANDOM_1OF10(config.reb_max_rt);
		}
		dhcpv6_client_transmit(self, DHCPV6_MSGTYPE_REBIND);
		dhcpv6_client_set_timer(self, self->rt);
		break;
	case STATE_RELEASING:
		if (self->xtx >= config.rel_max_rc) {
			dhcpv6_client_log(self, LOG_WARNING,
			    "The selected server didn't reponse for "
			    "our request");
			dhcpv6_client_reinit(self);
			break;
		} else if (self->xtx == 0)
			self->rt = RANDOM_1OF10(config.rel_timeout);
		else
			self->rt = self->rt * 2;
		dhcpv6_client_transmit(self, DHCPV6_MSGTYPE_RELEASE);
		dhcpv6_client_set_timer(self, self->rt);
		break;
	default:
		break;
	}
}

void
dhcpv6_client_set_timer(struct dhcpv6_client *self, int64_t millis)
{
	struct timeval	 tv;
	if (evtimer_pending(&self->ev_timer, NULL))
		evtimer_del(&self->ev_timer);
	tv.tv_sec = millis / 1000; 
	tv.tv_usec = (millis % 1000) * 1000;
	evtimer_add(&self->ev_timer, &tv);
	DHCPV6PD_DBG("%s(state=%u) %lld.%06ld", __func__, (int)self->state,
	tv.tv_sec, tv.tv_usec);

}

int
dhcpv6_client_receive(struct dhcpv6_client *self, u_char *pkt, int pktlen)
{
	struct dhcpv6_hdr	*hdr;
	u_char			*sid, *sts;
	uint16_t		 status_code = DHCPV6_STATUS_SUCCESS;
	int			 sid_len, sts_len;
	bool			 sid_ok = false, pd_ok = false,
				 pd_identical = true;
	struct dhcpv6_pd	*pd;
	char			 msgbuf[128];

	DHCPV6PD_DBG("%s(state=%u)", __func__, (int)self->state);

	hdr = (struct dhcpv6_hdr *)pkt;

	/* Check Server Identifier */
	sid = dhcpv6_option_find(pkt, pktlen, DHCPV6_OPTION_SERVERID, &sid_len);
	if (self->sid != NULL && self->sid_len == sid_len &&
	    memcmp(self->sid, sid, sid_len) == 0)
		sid_ok = true;

	pd = dhcpv6_client_retrive_ia_pd(self, pkt, pktlen);
	if (pd != NULL && pd->nprefix > 0 &&
	    pd->prefix[0].status_code == DHCPV6_STATUS_SUCCESS) {
		pd_ok = true;
		if (self->pd != NULL && self->iaid == pd->iaid &&
		    self->pd->prefix[0].prefix_len == pd->prefix[0].prefix_len
		    && memcmp(&self->pd->prefix[0].prefix,
		    &pd->prefix[0].prefix, sizeof(pd->prefix[0].prefix)) == 0)
			pd_identical = true;
	}
	if ((sts = dhcpv6_option_find(pkt, pktlen,
	    DHCPV6_OPTION_STATUS_CODE, &sts_len)) != NULL &&
	    sts_len >= 2)
		status_code = sts[4] << 4 | sts[5];

	switch (self->state) {
	case STATE_INIT:
		break;
	case STATE_SELECTING:
		if (self->state == STATE_SELECTING &&
		    hdr->msg_type == DHCPV6_MSGTYPE_ADVERTISE)
			;/* OK */
		else {
			/* XXX handle other msg types */
			dhcpv6_client_log(self, LOG_DEBUG,
			    "Received an unexpected message(type=%d) in "
			    "selecting state", (int)hdr->msg_type);
			break;
		}
		if (pd == NULL) {
			dhcpv6_client_log(self, LOG_WARNING, "received an "
			    "advertise which doesn't have an IA-PD");
			break;
		}
		if (sid == NULL) {
			dhcpv6_client_log(self, LOG_WARNING, "received an "
			    "advertise which doesn't have server identity");
			break;
		}
		if (status_code != DHCPV6_STATUS_SUCCESS) {
			dhcpv6_client_log(self, LOG_WARNING, "received an "
			    "Server(%s) replied status=%u for %s",
			    hex_string(sid, sid_len, msgbuf, sizeof(msgbuf)),
			    status_code, (self->state == STATE_SELECTING)?
			    "Solicit" : "Rebind");
			break;
		} else if (pd_ok) {
			/* OK take this */
			free(self->pd);
			self->pd = pd;
			/* Select the server */
			free(self->sid);
			self->sid = xcalloc(1, sid_len);
			memcpy(self->sid, sid, sid_len);
			self->sid_len = sid_len;
		}
		break;
	case STATE_REBINDING:
		if (hdr->msg_type == DHCPV6_MSGTYPE_REPLY &&
		    status_code == DHCPV6_STATUS_SUCCESS && pd_ok) {
			/* Select the server */
			free(self->sid);
			self->sid = xcalloc(1, sid_len);
			memcpy(self->sid, sid, sid_len);
			self->sid_len = sid_len;
			sid_ok = true;
		}
		/* FALLTHROUGH */
	case STATE_REQUESTING:
	case STATE_RENEWING:
		if (!sid_ok)
			break;	/* not interested in */
		if (hdr->msg_type != DHCPV6_MSGTYPE_REPLY) {
			dhcpv6_client_log(self, LOG_DEBUG,
			    "Received an unexpected message(type=%d) in "
			    "requesting state", (int)hdr->msg_type);
			break;
		}
		if (status_code != DHCPV6_STATUS_SUCCESS) {
			dhcpv6_client_log(self, LOG_WARNING, "received an "
			    "Server(%s) replied status=%u for %s",
			    hex_string(sid, sid_len, msgbuf, sizeof(msgbuf)),
			    status_code, (self->state == STATE_REQUESTING)?
			    "Request" : (self->state == STATE_RENEWING)?
			    "Renew" : "Rebind");
			dhcpv6_client_log(self, LOG_WARNING, "Gived up ");
			dhcpv6_client_reinit(self);
			break;
		}
		if (!pd_ok) {
			/* XXX OK? */
			dhcpv6_client_log(self, LOG_DEBUG,
			    "Received an reply but invalid IA_PD");
			break;
		}
		if (!pd_identical) {
			/* XXX OK? */
			dhcpv6_client_log(self, LOG_DEBUG,
			    "Received acceptable IA_PD but it differs from "
			    "requested");
			break;
		}
		/* Update valued which might be changed */
		self->pd->t1 = pd->t1;
		self->pd->t2 = pd->t2;
		self->pd->prefix[0].preferred = pd->prefix[0].preferred;
		self->pd->prefix[0].valid = pd->prefix[0].valid;

		dhcpv6_client_transition(self, STATE_BOUND);
		break;
	case STATE_BOUND:
		break;
	case STATE_RELEASING:
		dhcpv6_client_log(self, LOG_DEBUG,
		    "Received msg type=%u status=%u sts=%p",
		    (unsigned)hdr->msg_type, (unsigned)status_code, sts);
		if (hdr->msg_type == DHCPV6_MSGTYPE_REPLY) {
			if (status_code == DHCPV6_STATUS_SUCCESS) {
				dhcpv6_client_log(self, LOG_INFO,
				    "Release successfully");
				dhcpv6_client_reinit(self);
			}
		}
		break;
	}

	return (0);
}

int
dhcpv6_client_close(struct dhcpv6_client *self)
{
	if (self->sock >= 0)
		close(self->sock);

	free(self->pd);
	free(self->sid);
	evtimer_del(&self->ev_timer);

	return (0);
}

void
dhcpv6_client_on_event(int fd, short ev, void *ctx)
{
	struct sockaddr_storage	 ss;
	socklen_t		 sslen;
	char			 buf[8192];
	u_char			*cid = NULL;
	int			 cid_len;
	struct dhcpv6_hdr	*hdr;
	ssize_t			 sz;
	struct dhcpv6_client	*client;

	get_uptime(true);	/* update on event hander */

	sslen = sizeof(ss);
	if ((sz = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss,
	    &sslen)) < 0) {
		dhcpv6pd_log(LOG_WARNING, "%s: recvfrom: %m", __func__);
		goto on_error;
	}
	if (sz < sizeof(struct dhcpv6_hdr)) {
		dhcpv6pd_log(LOG_WARNING,
		    "%s: received packet is too small %d", __func__, (int)sz);
		return;
	}
	hdr = (struct dhcpv6_hdr *)buf;
	if ((cid = dhcpv6_option_find(buf, sz, DHCPV6_OPTION_CLIENTID,
	    &cid_len)) == NULL) {
		dhcpv6pd_log(LOG_WARNING,
		    "Received advertisement has no client-id");
		return;
	}
	TAILQ_FOREACH(client, &dhcpv6_clients, next) {
		if (cid_len == DHCPV6_OPT_LENGTH(&client->cid.hdr) &&
		    memcmp(&client->cid, cid, cid_len) == 0 &&
		    memcmp(client->xid, hdr->xid, sizeof(client->xid)) == 0)
			break;
	}
	if (client != NULL)
		dhcpv6_client_receive(client, buf, sz);
	return;
on_error:
	event_del(&ev_dhcpv6_client_sock);
	close(dhcpv6_client_sock);
	dhcpv6_client_sock = -1;
	event_loopbreak();
}

void
dhcpv6_client_on_timer(int fd, short ev, void *ctx)
{
	struct dhcpv6_client *self = ctx;

	DHCPV6PD_DBG("%s: %s(state=%u)", self->ifname, __func__,
	    (int)self->state);
	get_uptime(true);	/* update on event hander */

	dhcpv6_client_transition(self, self->state);
}

int
dhcpv6_client_init(struct dhcpv6_client *self, struct dhcpv6pdd_iface *iface)
{
	int			 sock = -1, ival;

	dhcpv6_interface_prepare(iface->ifidx);
	/* Client Identifier */
	self->cid.hdr.opt_code = htons(DHCPV6_OPTION_CLIENTID);
	self->cid.hdr.opt_len = htons(offsetof(struct dhcpv6_duid_ll,
	    lladdr[6]) - sizeof(struct dhcpv6_opt));
	self->cid.duid_type = htons(DHCPV6_DUID_LL);
	self->cid.hw_type = htons(ARP_HW_TYPE_ETHER);
	memcpy(self->cid.lladdr, iface->lladdr, 6);

	self->ifidx = iface->ifidx;
	memcpy(self->ifname, iface->ifname, sizeof(self->ifname));

	if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dhcpv6_client_log(self, LOG_ERR, "socket() failed: %m");
		goto on_error;
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &self->ifidx,
	    sizeof(self->ifidx)) == -1) {
		dhcpv6_client_log(self, LOG_ERR,
		    "setsockopt(,,IPV6_MULTICAST_IF): %m");
		goto on_error;
	}
	ival = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ival,
	    sizeof(ival)) == -1) {
		dhcpv6_client_log(self, LOG_ERR,
		    "setsockopt(,,IPV6_MULTICAST_HOPS): %m");
		goto on_error;
	}

	self->iaid = iaid_seq++;
	self->sock = sock;
	evtimer_set(&self->ev_timer, dhcpv6_client_on_timer, self);

	TAILQ_INSERT_TAIL(&dhcpv6_clients, self, next);
	dhcpv6_client_transition(self, STATE_INIT);

	return (0);
 on_error:
	if (sock >= 0)
		close(sock);
	return (-1);
}

int
dhcpv6_client_reinit(struct dhcpv6_client *self)
{
	free(self->pd);
	self->pd = NULL;
	free(self->sid);
	self->sid = NULL;
	dhcpv6_client_transition(self, STATE_INIT);

	return (0);
}

u_char *
dhcpv6_option_find(u_char *pkt, int pktlen, uint16_t code, int *optlen)
{
	struct dhcpv6_opt	 opt0;
	int			 off;

	off = sizeof(struct dhcpv6_hdr);
	while (off + sizeof(opt0) <= pktlen) {
		memcpy(&opt0, pkt + off, sizeof(opt0));
		NTOHS(opt0.opt_code);
		NTOHS(opt0.opt_len);
		if (opt0.opt_code == code && opt0.opt_len <= pktlen - off) {
			if (optlen)
				*optlen =
				    sizeof(struct dhcpv6_opt) + opt0.opt_len;
			return (pkt + off);
		}
		off += sizeof(struct dhcpv6_opt) + opt0.opt_len;
	}

	return (NULL);
}

int
dhcpv6_client_transmit(struct dhcpv6_client *self, u_char msg_code)
{
	struct iovec			 iov[10];
	int				 niov = 0;
	struct dhcpv6_hdr		 hdr;
	struct msghdr			 msg;
	struct sockaddr_in6		 sin6;
	struct in6_addr			 dst = IP6_ALL_DHCP_SERVERS;
	struct dhcpv6_elapsed_time	 et;
	struct dhcpv6_ia_pd		 ia_pd;
	struct dhcpv6_ia_prefix		 pfx;

	DHCPV6PD_DBG("%s(state=%u)", __func__, (int)self->state);
	if (!dhcpv6_interface_check_ratelimit(self->ifidx)) {
		DHCPV6PD_DBG("%s: transmit aborted by rate limit",
		    self->ifname);
		return (-1);
	}
	hdr.msg_type = msg_code;
	memcpy(hdr.xid, self->xid, sizeof(hdr.xid));

	/* Header */
	iov[niov].iov_base = &hdr;
	iov[niov].iov_len = sizeof(hdr);
	niov++;

	/* Client Identifier */
	iov[niov].iov_base = &self->cid;
	iov[niov].iov_len = DHCPV6_OPT_LENGTH(&self->cid.hdr);
	niov++;

	/* Server Identifier */
	if (self->sid != NULL) {
		iov[niov].iov_base = self->sid;
		iov[niov].iov_len = self->sid_len;
		niov++;
	}

	/* Elapsed Time */
	et.elapsed_time = htons((get_uptime(false) - self->xstart) / 10);
	et.hdr.opt_code = htons(DHCPV6_OPTION_ELAPSED_TIME);
	et.hdr.opt_len = htons(sizeof(et.elapsed_time));
	iov[niov].iov_base = &et;
	iov[niov].iov_len = sizeof(et);
	niov++;

	/* Identity Association for Prefix Delegation (IAPD) Option */
	/* NOTE: we use the first ia-prefix only */
	memset(&ia_pd, 0, sizeof(ia_pd));
	memset(&pfx, 0, sizeof(pfx));
	ia_pd.hdr.opt_code = htons(DHCPV6_OPTION_IA_PD);
	ia_pd.hdr.opt_len = htons(sizeof(struct dhcpv6_ia_pd) +
	    sizeof(struct dhcpv6_ia_prefix) - sizeof(struct dhcpv6_opt));
	pfx.hdr.opt_code = htons(DHCPV6_OPTION_IAPREFIX);
	pfx.hdr.opt_len = htons(sizeof(struct dhcpv6_ia_prefix) -
	    sizeof(struct dhcpv6_opt));
	ia_pd.iaid = ntohl(self->iaid);
	if (self->pd != NULL) {
		ia_pd.t1 = ntohl(self->pd->t1);
		ia_pd.t2 = ntohl(self->pd->t2);
		pfx.preferred = htonl(self->pd->prefix[0].preferred);
		pfx.valid = htonl(self->pd->prefix[0].valid);
		pfx.prefix_len = self->pd->prefix[0].prefix_len;
		memcpy(pfx.ipv6_prefix, &self->pd->prefix[0].prefix,
		    sizeof(pfx.ipv6_prefix));
	}
	iov[niov].iov_base = &ia_pd;
	iov[niov].iov_len = sizeof(ia_pd);
	niov++;
	iov[niov].iov_base = &pfx;
	iov[niov].iov_len = sizeof(pfx);
	niov++;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_port = htons(DHCPV6_SERVER_PORT);
	sin6.sin6_addr = dst;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sin6;
	msg.msg_namelen = sizeof(sin6);
	msg.msg_iov = iov;
	msg.msg_iovlen = niov;

	if (sendmsg(self->sock, &msg, 0) == -1) {
		dhcpv6_client_log(self, LOG_ERR, "sendmsg() failed: %m");
		return (-1);
	}
	self->xtx++;

	return (0);
}

struct dhcpv6_pd *
dhcpv6_client_retrive_ia_pd(struct dhcpv6_client *self, u_char *buf, int bufsz)
{
	int				 i, opt_len, sts_len, off;
	u_char				*opt, *sts;
	struct dhcpv6_ia_pd		 ia_pd;
	struct dhcpv6_ia_prefix		 prefix;
	struct dhcpv6_pd		*pd = NULL;

	opt = dhcpv6_option_find(buf, bufsz, DHCPV6_OPTION_IA_PD, &opt_len);
	if (opt == NULL)
		return (NULL);
	if (opt_len <= sizeof(struct dhcpv6_ia_pd)) {
		dhcpv6_client_log(self, LOG_WARNING,
		    "Received IA-PD is invalid size");
		goto badmsg;
	}
	memcpy(&ia_pd, opt, sizeof(ia_pd));

	for (i = 0, off = sizeof(ia_pd);
	    off + sizeof(struct dhcpv6_ia_prefix) <= opt_len;
	    off += DHCPV6_OPT_LENGTH(&prefix.hdr), i++) {
		memcpy(&prefix, opt + off, sizeof(prefix));
		if (ntohs(prefix.hdr.opt_code) != DHCPV6_OPTION_IAPREFIX) {
			dhcpv6_client_log(self, LOG_WARNING, "Received IA-PD "
			    "has an option which is not an IA-prefix");
			goto badmsg;
		}
		if (DHCPV6_OPT_LENGTH(&prefix.hdr) < sizeof(prefix) ||
		    DHCPV6_OPT_LENGTH(&prefix.hdr) > opt_len - off) {
			dhcpv6_client_log(self, LOG_WARNING, "Received IA-PD "
			    "has an option which length is invalid");
			goto badmsg;
		}
	}
	if (i == 0) {
		dhcpv6_client_log(self, LOG_WARNING, "Received IA-PD has no "
		    "IA-Prefix option");
		goto badmsg;
	}
	pd = xcalloc(1, offsetof(struct dhcpv6_pd, prefix[i]));
	pd->nprefix = i;
	pd->iaid = ntohl(ia_pd.iaid);
	pd->t1 = ntohl(ia_pd.t1);
	pd->t2 = ntohl(ia_pd.t2);
	for (i = 0, off = sizeof(ia_pd);
	    off + sizeof(struct dhcpv6_ia_prefix) <= opt_len;
	    off += DHCPV6_OPT_LENGTH(&prefix.hdr), i++) {
		memcpy(&prefix, opt + off, sizeof(prefix));
		pd->prefix[i].prefix_len = prefix.prefix_len;
		pd->prefix[i].preferred = htonl(prefix.preferred);
		pd->prefix[i].valid = htonl(prefix.valid);
		memcpy(&pd->prefix[i].prefix, prefix.ipv6_prefix,
		    sizeof(pd->prefix[i].prefix));
		if ((sts = dhcpv6_option_find(buf, bufsz,
		    DHCPV6_OPTION_STATUS_CODE, &sts_len)) != NULL) {
			if (sts_len < 6) {
				dhcpv6_client_log(self, LOG_WARNING,
				    "Received a bad status code option");
				goto badmsg;
			}
			pd->prefix[i].status_code = sts[4] << 4 | sts[5];
			if (sts_len > 6) {
				memcpy(pd->prefix[i].status_msg, sts + 6,
				    MINIMUM(sts_len - 6,
				    sizeof(pd->prefix[i].status_msg) - 1));
			}
		}
	}

	return (pd);
badmsg:
	free(pd);
	return (NULL);
}

const char *
dhcpv6_pd_to_string(struct dhcpv6_pd *pd, char *buf, int bufsz)
{
	int i, len;
	char buf1[80];

	len = snprintf(buf, bufsz,
	    "IAID=%u T1=%u T2=%u Prefix=[", pd->iaid, pd->t1, pd->t2);

	for (i = 0; len + 1 < bufsz && i < pd->nprefix; i++) {
		inet_ntop(AF_INET6, &pd->prefix[i].prefix, buf1, sizeof(buf1));
		len += snprintf(buf + len, bufsz - len,
		    "%s%s/%d(preferred=%u,valid=%u,status=%d)",
		    (i != 0)? "," : "",
		    buf1, (int)pd->prefix[i].prefix_len,
		    pd->prefix[i].preferred, pd->prefix[i].valid,
		    (int)pd->prefix[i].status_code);
	}
	if (len + 1 < bufsz)
		len += snprintf(buf + len, bufsz - len, "]");
	return (buf);
}

void
dhcpv6_client_log(struct dhcpv6_client *self, int prio, const char *fmt, ...)
{
	va_list	 ap;
	char	 fmt0[BUFSIZ];

	strlcpy(fmt0, self->ifname, sizeof(fmt0));
	strlcat(fmt0, ": ", sizeof(fmt0));
	strlcat(fmt0, fmt, sizeof(fmt0));

	va_start(ap, fmt);
	vlog(prio, fmt0, ap);
	va_end(ap);
}

/***********************************************************************
 * dhcpv6_interface
 ***********************************************************************/
struct dhcpv6_interface *
dhcpv6_interface_find(u_int ifidx)
{
	struct dhcpv6_interface	*e;

	TAILQ_FOREACH(e, &dhcpv6_interfaces, next) {
		if (e->ifidx == ifidx)
			break;
	}
	return (e);
}

void
dhcpv6_interface_prepare(u_int ifidx)
{
	struct dhcpv6_interface	*e;

	e = dhcpv6_interface_find(ifidx);
	if (e == NULL) {
		e = xcalloc(1, sizeof(struct dhcpv6_interface));
		e->ifidx = ifidx;
		e->tb_ntokens = config.rate_limit_packets;
		e->tb_last_replanish = get_uptime(false);
		TAILQ_INSERT_TAIL(&dhcpv6_interfaces, e, next);
	}
}

bool
dhcpv6_interface_check_ratelimit(u_int ifidx)
{
	struct dhcpv6_interface	*e = dhcpv6_interface_find(ifidx);
	int64_t			 d, r;
	int			 rtokens;

	DHCPV6PD_ASSERT(e != NULL);

	/* duration since last replanish */
	d = get_uptime(false) - e->tb_last_replanish;

	/* calc replanish interval */
	r = (config.rate_limit_seconds * 1000) / config.rate_limit_packets;
	/* replanish if possible */
	if (d > r) {
		rtokens = d / r;
		e->tb_ntokens =
		    MINIMUM(e->tb_ntokens + rtokens, config.rate_limit_packets);
		e->tb_last_replanish += rtokens * d;
	}

	if (e->tb_ntokens > 0) {
		e->tb_ntokens--;
		return (true);
	}
	return (false);
}

/***********************************************************************
 * Utilities
 ***********************************************************************/
int64_t
get_uptime(bool update)
{
	static int64_t	 curr_uptime = 0;
	struct timespec	 now;

	if (curr_uptime == 0 || update) {
		clock_gettime(CLOCK_UPTIME, &now);
		curr_uptime = now.tv_sec * 1000 + now.tv_nsec / 1000000L;
	}

	return (curr_uptime);
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void	*ret;

	ret = calloc(nmemb, size);
	if (ret == NULL)
		fatal("calloc() failed");
	return (ret);
}

const char *
hex_string(u_char *bytes, int byteslen, char *buf, int buflen)
{
	int		 i, j;
	const char	 hexstr[] = "0123456789abcdef";

	if (buflen < byteslen * 2 + 1)
		return (NULL);
	for (i = 0, j = 0; i < byteslen; i++) {
		buf[j++] = hexstr[bytes[i] >> 4];
		buf[j++] = hexstr[bytes[i] & 0xf];
	}
	buf[j] = '\0';

	return (buf);
}
