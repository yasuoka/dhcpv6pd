/*
 * Copyright (c) 2023 YASUOKA Masahiko <yasuoka@yasuoka.net>
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
#include <netinet/in.h>

/* DHCP Message Types */
#define DHCPV6_MSGTYPE_SOLICIT		1
#define DHCPV6_MSGTYPE_ADVERTISE	2
#define DHCPV6_MSGTYPE_REQUEST		3
#define DHCPV6_MSGTYPE_CONFIRM		4
#define DHCPV6_MSGTYPE_RENEW		5
#define DHCPV6_MSGTYPE_REBIND		6
#define DHCPV6_MSGTYPE_REPLY		7
#define DHCPV6_MSGTYPE_RELEASE		8
#define DHCPV6_MSGTYPE_DECLINE		9
#define DHCPV6_MSGTYPE_RECONFIGURE	10
#define DHCPV6_MSGTYPE_INFO_REQ		11
#define DHCPV6_MSGTYPE_RELAY_FORW	12
#define DHCPV6_MSGTYPE_RELAY_REPL	13

#define DHCPV6_CLIENT_PORT		546
#define DHCPV6_SERVER_PORT		547

#define DHCPV6_OPTION_CLIENTID		1
#define DHCPV6_OPTION_SERVERID		2
#define DHCPV6_OPTION_ORO		6
#define DHCPV6_OPTION_ELAPSED_TIME	8
#define DHCPV6_OPTION_STATUS_CODE	13
#define DHCPV6_OPTION_IA_PD		25
#define DHCPV6_OPTION_IAPREFIX		26


#define DHCPV6_STATUS_SUCCESS		0
#define DHCPV6_STATUS_UNSPEC_FAIL	1
#define DHCPV6_STATUS_NO_ADDRS_AVAIL	2
#define DHCPV6_STATUS_NO_BINDING	3
#define DHCPV6_STATUS_NOT_ON_LINK	4
#define DHCPV6_STATUS_USE_MULTICAST	5
#define DHCPV6_STATUS_NO_PREFIX_AVAIL	6

#define DHCPV6_DUID_LL			3
#define DHCPV6_DUID_UUID		4

#define ARP_HW_TYPE_ETHER		1

/* All_DHCP_Relay_Agents_and_Servers (ff02::1:2) */
#define IP6_ALL_DHCP_SERVERS \
    {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 }}};

struct dhcpv6_hdr {
	uint8_t		 msg_type;
	uint8_t		 xid[3];
} __packed;

struct dhcpv6_opt {
	uint16_t	 opt_code;
	uint16_t	 opt_len;
	uint8_t	 	 opt_data[0];
} __packed;

#define DHCPV6_OPT_LENGTH(_opt) \
	(sizeof(struct dhcpv6_opt) + ntohs((_opt)->opt_len))

struct dhcpv6_duid_ll {
	struct dhcpv6_opt
			 hdr;
	uint16_t	 duid_type;
	uint16_t	 hw_type;
	uint8_t		 lladdr[0];
};

struct dhcpv6_elapsed_time {
	struct dhcpv6_opt
			 hdr;
	uint16_t	 elapsed_time;
};

struct dhcpv6_ia_pd {
	struct dhcpv6_opt	 hdr;
	uint32_t		 iaid;
	uint32_t		 t1;
	uint32_t		 t2;
} __packed;

struct dhcpv6_ia_prefix {
	struct dhcpv6_opt	 hdr;
	uint32_t		 preferred;
	uint32_t		 valid;
	uint8_t			 prefix_len;
	uint8_t			 ipv6_prefix[16];
} __packed;

struct dhcpv6_pd {
	uint32_t		 iaid;
	uint32_t		 t1;
	uint32_t		 t2;
	int			 nprefix;
	struct {
		uint32_t	 preferred;
		uint32_t	 valid;
		struct in6_addr	 prefix;
		uint16_t	 prefix_len;
		uint16_t	 status_code;
		char		 status_msg[128];
	} prefix[0];
};

/* Default timeouts Derived from RFC 8415 */
#define DHCPV6_SOL_MAX_DELAY	1000	/* Max delay of first Solicit */
#define DHCPV6_SOL_TIMEOUT	1000	/* Initial Solicit timeout */
#define DHCPV6_SOL_MAX_RT	3600000 /* Max Solicit timeout value */
#define DHCPV6_REQ_TIMEOUT	1000	/* Initial Request timeout */
#define DHCPV6_REQ_MAX_RT	30000	/* Max Request timeout value */
#define DHCPV6_REQ_MAX_RC	10	/* Max Request retry attempts */
#define DHCPV6_CNF_MAX_DELAY	1000	/* Max delay of first Confirm */
#define DHCPV6_CNF_TIMEOUT	1000	/* Initial Confirm timeout */
#define DHCPV6_CNF_MAX_RT	4000	/* Max Confirm timeout */
#define DHCPV6_CNF_MAX_RD	10000	/* Max Confirm duration */
#define DHCPV6_REN_TIMEOUT	10000	/* Initial Renew timeout */
#define DHCPV6_REN_MAX_RT	600000	/* Max Renew timeout value */
#define DHCPV6_REB_TIMEOUT	10000	/* Initial Rebind timeout */
#define DHCPV6_REB_MAX_RT	600000	/* Max Rebind timeout value */
#define DHCPV6_INF_MAX_DELAY	1000	/* Max delay of first
					   Information-request */
#define DHCPV6_INF_TIMEOUT	1000	/* Initial Information-request
					   timeout */
#define DHCPV6_INF_MAX_RT	3600000 /* Max Information-request timeout
					   value */
#define DHCPV6_REL_TIMEOUT	1000	/* Initial Release timeout */
#define DHCPV6_REL_MAX_RC	4	/* Max Release retry attempts */
#define DHCPV6_DEC_TIMEOUT	1000	/* Initial Decline timeout */
#define DHCPV6_DEC_MAX_RC	4	/* Max Decline retry attempts */
#define DHCPV6_REC_TIMEOUT	2000	/* Initial Reconfigure timeout */
#define DHCPV6_REC_MAX_RC	8	/* Max Reconfigure attempts */
#define DHCPV6_HOP_COUNT_LIMIT	8	/* Max hop count in a Relay-forward
					   message */
#define DHCPV6_IRT_DEFAULT	86400000/* Default information refresh time */
#define DHCPV6_IRT_MINIMUM	600000	/* Min information refresh time */
#define DHCPV6_MAX_WAIT_TIME	60000	/* Max required time to wait for a
					   response */
