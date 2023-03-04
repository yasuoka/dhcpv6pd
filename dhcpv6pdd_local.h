#ifndef DEAEMON_LOCAL_H
#define DEAEMON_LOCAL_H 1

#include <sys/cdefs.h>
#include <sys/types.h>

#include <event.h>
#include <imsg.h>
#include "dhcpv6pdd.h"

#define PROC_NAME_MAIN		"main"
#define PROC_NAME_PARENT	"parent"
#define PROC_NAME_CONTROL	"control"

#define IMSG_PARENT_FILENO	4

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	short			 events;
};

/* internal messages */
enum dhcpv6pdd_imsg_type {
	IMSG_PIPE_CONTROL = IMSG_MIN,
	IMSG_PIPE_MAIN
};

struct dhcpv6pdd_conf {
};

#ifndef nitems
#define nitems(_x) (sizeof((_x)) / sizeof((_x)[0]))
#endif

/* from parse.y */
struct dhcpv6pdd_conf
		*parse_config(const char *);

/* from dhcpv6pdd.c */
void		 dhcpv6pd_log(int, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
__dead void	 fatal(const char *);
__dead void	 fatalx(const char *);
void		 log_warn(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 log_warnx(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 log_debug(const char *fmt, ...)
		    __attribute__((__format__ (printf, 1, 2)));

void		 imsg_event_add(struct imsgev *);
int		 imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
		    int, void *, uint16_t);
struct iovec;
int		 imsg_composev_event(struct imsgev *, uint16_t, uint32_t,
		    pid_t, int, struct iovec *, int);

/* from dhcpv6pd_main */
void		 dhcpv6pd_main(void);

/* for debug */
#ifndef DHCPV6PD_DEBUG
#define DHCPV6PD_DBG(...)
#define DHCPV6PD_ASSERT(_cond)
#else
#include <ctype.h>
#define DHCPV6PD_DBG(...)					\
	do {						\
		dhcpv6pd_log(LOG_DEBUG, __VA_ARGS__);	\
	} while(0)
#define DHCPV6PD_ASSERT(_cond)						\
	do {								\
		if (!(_cond)) {						\
			dhcpv6pd_log(LOG_CRIT,				\
			    "ASSERT(%s) failed in %s():%s:%d",		\
			    #_cond, __func__, __FILE__, __LINE__);	\
			abort();					\
		}							\
	} while (0 /* CONSTCOND */)
#endif

#endif
