/*
 * ircd_osdep.h
 *
 * $Id: ircd_osdep.h,v 1.2 2005/01/03 03:53:13 bugs Exp $
 */
#ifndef INCLUDED_ircd_osdep_h
#define INCLUDED_ircd_osdep_h

struct Client;
struct sockaddr_in;
struct MsgQ;

typedef enum IOResult {
  IO_FAILURE = -1,
  IO_BLOCKED = 0,
  IO_SUCCESS = 1
} IOResult;

/*
 * NOTE: osdep.c files should never need to know the actual size of a
 * Client struct. When passed as a parameter, the pointer just needs
 * to be forwarded to the enumeration function.
 */
typedef void (*EnumFn)(struct Client*, const char* msg);

extern int os_disable_options(int);
extern int os_get_rusage(struct Client*, int, EnumFn);
extern int os_get_sockerr(int);
extern int os_get_sockname(int, struct sockaddr_in *);
extern int os_get_peername(int, struct sockaddr_in *);
extern IOResult os_recv_nonb(int, char *, unsigned int, unsigned int *);
extern IOResult os_send_nonb(int, const char *, unsigned int, unsigned int *);
extern IOResult os_sendv_nonb(int, struct MsgQ *, unsigned int *, unsigned int *);
extern IOResult os_recvfrom_nonb(int, char *, unsigned int,
					unsigned int *, struct sockaddr_in *);
extern IOResult os_connect_nonb(int, const struct sockaddr_in *);
extern int os_set_fdlimit(unsigned int);
extern int os_set_listen(int, int);
extern int os_set_nonblocking(int);
extern int os_set_reuseaddr(int);
extern int os_set_sockbufs(int, unsigned int, unsigned int);
extern int os_set_tos(int, int);

#endif /* INCLUDED_ircd_osdep_h */

