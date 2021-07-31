/*
 * - ASUKA ---------------------------------------------------------------------
 * These are the declarations of the CHECK functions for Asuka.
 * Some of this code is from previous QuakeNet ircds, and some of it is my own.
 * The old code was written by Durzel (durzel@quakenet.org).
 *
 * qoreQ (qoreQ@quakenet.org) - 08/14/2002
 * -----------------------------------------------------------------------------
 */

#ifndef INCLUDED_check_h
#define INCLUDED_check_h

#define HEADERLINE "--------------------------------------------------------------------"
#define COLOR_OFF  '\017'

extern void checkChannel(struct Client *sptr, struct Channel *chptr);
extern void checkUsers(struct Client *sptr, struct Channel *chptr, int flags);
extern void checkClient(struct Client *sptr, struct Client *acptr);
extern void checkServer(struct Client *sptr, struct Client *acptr);
extern signed int checkHostmask(struct Client *sptr, char *hoststr, int flags);

#endif /* INCLUDED_check_h */
