CPPFLAGS=	-I${.CURDIR}/..

WARNINGS=	yes
COPTS+=		-Wno-sign-compare -DDHCPV6PD_DEBUG

.PATH:	${.CURDIR}/..
