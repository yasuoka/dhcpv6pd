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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>	/* for including <imsg.h> */
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <err.h>
#include <imsg.h>

#include "parser.h"
#include "dhcpv6pdd.h"

static void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s\n", __progname);
}

int
main(int argc, char *argv[])
{
	int			 ch, sock, done = 0, n, datalen;
	struct parse_result	*res;
	struct sockaddr_un	 sun;
	struct imsgbuf		 ibuf;
	struct imsg		 imsg;

	while ((ch = getopt(argc, argv, "")) != -1)
		switch (ch) {
		default:
			usage();
			exit(EX_USAGE);
		}
	argc -= optind;
	argv += optind;

	if (unveil(DHCPV6PDD_SOCK, "rw") == -1)
		err(EX_OSERR, "unveil");
	if (pledge("stdio unix", NULL) == -1)
		err(EX_OSERR, "pledge");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, DHCPV6PDD_SOCK, sizeof(sun.sun_path));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		err(EX_OSERR, "socket");
	if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(EX_OSERR, "connect");
	imsg_init(&ibuf, sock);

	res = parse(argc, argv);
	if (res == NULL)
		exit(EX_USAGE);

	switch (res->action) {
	case PING:
		imsg_compose(&ibuf, IMSG_CTL_PING, 0, 0, -1, NULL, 0);
		break;
	case NONE:
		done = 1;
		break;
	}
	while (ibuf.w.queued) {
		if (msgbuf_write(&ibuf.w) <= 0 && errno != EAGAIN)
			err(1, "ibuf_ctl: msgbuf_write error");
	}
	while (!done) {
		if (((n = imsg_read(&ibuf)) == -1 && errno != EAGAIN) || n == 0)
			break;
		for (;;) {
			if ((n = imsg_get(&ibuf, &imsg)) <= 0) {
				if (n != 0)
					done = 1;
				break;
			}
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			switch (res->action) {
			case PING:
				printf("%*s\n", datalen,
				    (const char *)imsg.data);
				done = 1;
				break;
			default:
				break;
			}
			imsg_free(&imsg);
			if (done)
				break;
		}
	}
	close(sock);

	exit(EXIT_SUCCESS);
}
