/** @file s_numeric.h
 * @brief Send a numeric message to a client.
 * @version $Id: s_numeric.h,v 1.1.1.1 2005/10/01 17:27:01 progs Exp $
 */
#ifndef INCLUDED_s_numeric_h
#define INCLUDED_s_numeric_h

struct Client;

/*
 * Prototypes
 */

extern int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
    int parc, char *parv[]);

#endif /* INCLUDED_s_numeric_h */
