/*
 * whocmds.h
 *
 * $Id: whocmds.h,v 1.1.1.1 2004/02/28 11:11:20 bugs Exp $
 */
#ifndef INCLUDED_whocmds_h
#define INCLUDED_whocmds_h

struct Client;
struct Channel;


/*
 * m_who() 
 * m_who with support routines rewritten by Nemesi, August 1997
 * - Alghoritm have been flattened (no more recursive)
 * - Several bug fixes
 * - Strong performance improvement
 * - Added possibility to have specific fields in the output
 * See readme.who for further details.
 */

/* Macros used only in here by m_who and its support functions */

#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || ((b & WHOSELECT_EXTRA) && MyConnect(ac) && (HasPriv((s), PRIV_SHOW_INVIS) || HasPriv((s), PRIV_SHOW_ALL_INVIS))))

#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SHOW_ALL_INVIS)))

#define SHOW_MORE(sptr, counter) (HasPriv(sptr, PRIV_UNLIMIT_QUERY) || (!(counter-- < 0)) )

#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SEE_CHAN)))

#define MAX_WHOIS_LINES 50

#endif /* INCLUDED_whocmds_h */
