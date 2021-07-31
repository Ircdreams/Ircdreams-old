/** @file opercmds.h
 * @brief Declarations of AsLL ping helper commands.
 * @version $Id: opercmds.h,v 1.1.1.1 2005/10/01 17:26:59 progs Exp $
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
extern char *militime_float(char *start);

#endif /* INCLUDED_opercmds_h */
