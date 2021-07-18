/*
 * support.h
 *
 * $Id: support.h,v 1.3 2005/11/27 21:42:25 bugs Exp $
 */
#ifndef INCLUDED_support_h
#define INCLUDED_support_h

/*
 * Given a number of bits, make a netmask out of it.
 */
#define NETMASK(bits) htonl((0xffffffff>>(32-(bits)))<<(32-(bits)))


/*
 * Prototypes
 */

extern int dgets(int, char*, int);
  
extern int check_if_ipmask(const char *mask);
extern void write_log(const char *filename, const char *pattern, ...);
extern unsigned long ParseInterval(const char *interval);
extern int is_timestamp(char *str);

#endif /* INCLUDED_support_h */
