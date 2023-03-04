PROG=			dhcpv6pdd
SRCS=			dhcpv6pdd.c dhcpv6pd_main.c parse.y control.c
LDADD=			-levent -lutil
DPADD=			${LIBEVENT} ${LIBUTIL}
NOMAN=			#

.include <bsd.prog.mk>
