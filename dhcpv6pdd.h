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
#ifndef DHCPV6PDD_H
#define DHCPV6PDD_H 1

#define	DHCPV6PDD_CONF	"/etc/dhcpv6pdd.conf"
#define	DHCPV6PDD_SOCK	"/var/run/dhcpv6pd.sock"
#define	DHCPV6PDD_USER	"www"	/* XXX */

enum imsg_type {
	IMSG_TERMINATE,
	IMSG_CTL_PING,	/* for test */
	IMSG_CTL_PONG,	/* for test */
	IMSG_MIN
};

#endif
