/*
 * opercmds.h
 *
 * $Id: opercmds.h,v 1.1.1.1 2004/02/28 11:11:06 bugs Exp $
 */
#ifndef INCLUDED_opercmds_h
#define INCLUDED_opercmds_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;

/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */
/*
 * Proto types
 */

extern char *militime(char* sec, char* usec);
extern char *militime_float(char* start);

#endif /* INCLUDED_opercmds_h */
