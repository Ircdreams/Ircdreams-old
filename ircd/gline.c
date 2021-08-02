/*
 * IRC - Internet Relay Chat, ircd/gline.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: gline.c,v 1.12 2005/05/15 18:50:28 bugs Exp $
 */
#include "../config.h"

#include "gline.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "ircd_struct.h"
#include "support.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define CHECK_APPROVED	   0	/* Mask is acceptable */
#define CHECK_OVERRIDABLE  1	/* Mask is acceptable, but not by default */
#define CHECK_REJECTED	   2	/* Mask is totally unacceptable */

#define MASK_WILD_0	0x01	/* Wildcards in the last position */
#define MASK_WILD_1	0x02	/* Wildcards in the next-to-last position */

#define MASK_WILD_MASK	0x03	/* Mask out the positional wildcards */

#define MASK_WILDS	0x10	/* Mask contains wildcards */
#define MASK_IP		0x20	/* Mask is an IP address */
#define MASK_HALT	0x40	/* Finished processing mask */

struct Gline* GlobalGlineList  = 0;
struct Gline* BadChanGlineList = 0;

static int count_users(const char *mask)
{
  struct Client *acptr;
  int count = 0;
  char namebuf[NICKLEN + USERLEN + HOSTLEN + 3];
  char ipbuf[USERLEN + 16 + 2];

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;

    ircd_snprintf(0, namebuf, sizeof(namebuf), "%s!%s@%s", cli_name(acptr),
		  cli_user(acptr)->username, cli_user(acptr)->host);
    ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%s!%s@%s", cli_name(acptr),
		   cli_user(acptr)->username, ircd_ntoa((const char *) &(cli_ip(acptr))));

    if (!match(mask, namebuf) || !match(mask, ipbuf))
      count++;
  }

  return count;
}

static void
canon_userhost(char *userhost, char **nick_p, char **user_p, char **host_p, char *def_user)
{
  char *tmp, *s;

  if ((tmp = strchr(userhost, '!'))) {
    *nick_p = userhost;
    *(tmp++) = '\0';
  } else {
    *nick_p = def_user;
    tmp = userhost;
  }

  if (!(s = strchr(tmp, '@'))) {
    *user_p = def_user;
    *host_p = tmp;
  } else {
    *user_p = tmp;
    *(s++) = '\0';
    *host_p = s;
  }
}

static struct Gline *
make_gline(char *nick, char *user, char *host, char *reason, time_t expire,
	   time_t lastmod, unsigned int flags)
{
  struct Gline *gline, *sgline, *after = 0;

  if (!(flags & GLINE_BADCHAN)) { /* search for overlapping glines first */

    for (gline = GlobalGlineList; gline; gline = sgline) {
		sgline = gline->gl_next;

		if (gline->gl_expire <= CurrentTime)
			gline_free(gline);
		else if (((gline->gl_flags & GLINE_LOCAL) != (flags & GLINE_LOCAL)) ||
				(gline->gl_host && !host) || (!gline->gl_host && host))
			continue;
		else if (!mmatch(gline->gl_nick, nick) && /* gline contains new mask */
				!mmatch(gline->gl_user, user) &&
				!mmatch(gline->gl_host, host)) {
			if (expire <= gline->gl_expire) /* will expire before wider gline */
				return 0;
			else
				after = gline; /* stick new gline after this one */
		} else if (!mmatch(nick, gline->gl_nick) && /* new mask contains gline */
				!mmatch(user, gline->gl_user) &&
				!mmatch(host, gline->gl_host) &&
				gline->gl_expire <= expire) /* gline expires before new one */
			gline_free(gline); /* save some memory */
    }
  }

  gline = (struct Gline *)MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != gline);

  DupString(gline->gl_reason, reason); /* initialize gline... */
  gline->gl_expire = expire;
  gline->gl_lastmod = lastmod;
  gline->gl_flags = flags & GLINE_MASK;

  if (flags & GLINE_BADCHAN) { /* set a BADCHAN gline */
    DupString(gline->gl_user, user); /* first, remember channel */
    gline->gl_nick = 0;
    gline->gl_host = 0;

    gline->gl_next = BadChanGlineList; /* then link it into list */
    gline->gl_prev_p = &BadChanGlineList;
    if (BadChanGlineList)
      BadChanGlineList->gl_prev_p = &gline->gl_next;
    BadChanGlineList = gline;
  } else {
    DupString(gline->gl_nick, nick);
    DupString(gline->gl_user, user); /* remember them... */
    DupString(gline->gl_host, host);

    if (check_if_ipmask(host)) { /* mark if it's an IP mask */
		int class;
		char ipname[16];
		int ad[4] = { 0 };
		int bits2 = 0;
		char *ch;
		int seenwild;
		int badmask=0;

		/* Sanity check for dodgy IP masks
		 * Any mask featuring a digit after a wildcard will
		 * not behave as expected. */
		for (seenwild=0,ch=host;*ch;ch++) {
			if (*ch=='*' || *ch=='?')
			seenwild=1;
			if (IsDigit(*ch) && seenwild) {
			badmask=1;
			break;
			}
		}

		if (badmask) {
			/* It's bad - let's make it match 0.0.0.0/32 */
			gline->bits=32;
			gline->ipnum.s_addr=0;
		} else {

			class = sscanf(host,"%d.%d.%d.%d/%d",
						&ad[0],&ad[1],&ad[2],&ad[3], &bits2);
			if (class!=5) {
			gline->bits=class*8;
			}
			else {
			gline->bits=bits2;
			}
			ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
						ad[2], ad[3]);
			gline->ipnum.s_addr = inet_addr(ipname);
		}
		Debug((DEBUG_DEBUG,"IP gline: %08x/%i",gline->ipnum.s_addr,gline->bits));
		gline->gl_flags |= GLINE_IPMASK;
    }

    if (after) {
      gline->gl_next = after->gl_next;
      gline->gl_prev_p = &after->gl_next;
      if (after->gl_next)
	after->gl_next->gl_prev_p = &gline->gl_next;
      after->gl_next = gline;
    } else {
      gline->gl_next = GlobalGlineList; /* then link it into list */
      gline->gl_prev_p = &GlobalGlineList;
      if (GlobalGlineList)
	GlobalGlineList->gl_prev_p = &gline->gl_next;
      GlobalGlineList = gline;
    }
  }

  return gline;
}

static int
do_gline(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (!GlineIsActive(gline)) /* no action taken on inactive glines */
    return 0;

  if (GlineIsBadChan(gline)) {
    /* Handle BADCHAN gline */
    struct Channel *chptr,*nchptr;
    struct Membership *member,*nmember;

    for(chptr=GlobalChannelList;chptr;chptr=nchptr) {
      nchptr=chptr->next;
      if (match(gline->gl_user, chptr->chname))
        continue;
      for (member=chptr->members;member;member=nmember) {
        nmember=member->next_member;
	if (!MyUser(member->user) || IsZombie(member) || IsAnOper(member->user))
	  continue;
	sendcmdto_serv_butone(&me, CMD_KICK, NULL, "%H %C :G-lined (%s)", chptr, member->user, gline->gl_reason);
	sendcmdto_channel_butserv_butone(&me, CMD_KICK, chptr, NULL, 0, 
		"%H %C :G-lined (%s)", chptr, member->user, gline->gl_reason);
	make_zombie(member, member->user, &me, &me, chptr);
	retval=1;
      }
    }
  } else {
    /* Handle normal gline */
    for (fd = HighestFd; fd > 0; --fd) {
      /*
       * get the users!
       */
      if ((acptr = LocalClientArray[fd])) {

	if (!cli_user(acptr))
  	continue;

        if (cli_name(acptr) &&
            match (gline->gl_nick, cli_name(acptr)) != 0)
                 continue;

        if (cli_user(acptr)->username &&
            match (gline->gl_user, (cli_user(acptr))->username) != 0)
                 continue;

        if (GlineIsIpMask(gline)) {
          Debug((DEBUG_DEBUG,"IP gline: %08x %08x/%i",(cli_ip(cptr)).s_addr,gline->ipnum.s_addr,gline->bits));
          if (((cli_ip(acptr)).s_addr & NETMASK(gline->bits)) != gline->ipnum.s_addr)
            continue;
        }
        else {
          if (match(gline->gl_host, cli_sockhost(acptr)) != 0)
            continue;
        }
	
	if (IsAnAdmin(acptr))
	    continue;

        /* ok, here's one that got G-lined */
        send_reply(acptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s",
        	   gline->gl_reason);

        /* let the ops know about it */
        sendto_allops(&me, SNO_GLINE, "G-line active for %s in %s",
			get_client_name(acptr, SHOW_IP), cli_name(&me));

        /* and get rid of him */
        if ((tval = exit_client_msg(cptr, acptr, &me, "G-lined (%s)", gline->gl_reason)))
          retval = tval; /* retain killed status */
      }
    }
  }
  return retval;
}


/*
 * This routine implements the mask checking applied to local
 * G-lines.  Basically, host masks must have a minimum of two non-wild
 * domain fields, and IP masks must have a minimum of 16 bits.  If the
 * mask has even one wild-card, OVERRIDABLE is returned, assuming the
 * other check doesn't fail.
 */
static int
gline_checkmask(char *mask)
{
  unsigned int flags = MASK_IP;
  unsigned int dots = 0;
  unsigned int ipmask = 0;

  for (; *mask; mask++) { /* go through given mask */
    if (*mask == '.') { /* it's a separator; advance positional wilds */
      flags = (flags & ~MASK_WILD_MASK) | ((flags << 1) & MASK_WILD_MASK);
      dots++;

      if ((flags & (MASK_IP | MASK_WILDS)) == MASK_IP)
	ipmask += 8; /* It's an IP with no wilds, count bits */
    } else if (*mask == '*' || *mask == '?')
      flags |= MASK_WILD_0 | MASK_WILDS; /* found a wildcard */
    else if (*mask == '/') { /* n.n.n.n/n notation; parse bit specifier */
      ++mask;
      ipmask = strtoul(mask, &mask, 10);

      if (*mask || dots != 3 || ipmask > 32 || /* sanity-check to date */
	  (flags & (MASK_WILDS | MASK_IP)) != MASK_IP)
	return CHECK_REJECTED; /* how strange... */

      if (ipmask < 32) /* it's a masked address; mark wilds */
	flags |= MASK_WILDS;

      flags |= MASK_HALT; /* Halt the ipmask calculation */

      break; /* get out of the loop */
    } else if (!IsDigit(*mask)) {
      flags &= ~MASK_IP; /* not an IP anymore! */
      ipmask = 0;
    }
  }

  /* Sanity-check quads */
  if (dots > 3 || (!(flags & MASK_WILDS) && dots < 3)) {
    flags &= ~MASK_IP;
    ipmask = 0;
  }

  /* update bit count if necessary */
  if ((flags & (MASK_IP | MASK_WILDS | MASK_HALT)) == MASK_IP)
    ipmask += 8;

  /* Check to see that it's not too wide of a mask */
  if (flags & MASK_WILDS &&
      ((!(flags & MASK_IP) && (dots < 2 || flags & MASK_WILD_MASK)) ||
       (flags & MASK_IP && ipmask < 16)))
    return CHECK_REJECTED; /* to wide, reject */

  /* Ok, it's approved; require override if it has wildcards, though */
  return flags & MASK_WILDS ? CHECK_OVERRIDABLE : CHECK_APPROVED;
}

int
gline_propagate(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || (IsUser(sptr) && !gline->gl_lastmod))
    return 0;

  if (gline->gl_lastmod)
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr, "* %c%s%s%s%s%s %Tu %Tu :%s",
			  GlineIsRemActive(gline) ? '+' : '-',
			  GlineIsBadChan(gline) ? "" : gline->gl_nick,
			  GlineIsBadChan(gline) ? "" : "!",
			  gline->gl_user,
			  GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_lastmod,
			  gline->gl_reason);
  else
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr,
			  (GlineIsRemActive(gline) ?
			   "* +%s%s%s%s%s %Tu :%s" : "* -%s%s%s%s%s"),
			  GlineIsBadChan(gline) ? "" : gline->gl_nick,
			  GlineIsBadChan(gline) ? "" : "!",
			  gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_reason);

  return 0;
}

int
gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, unsigned int flags)
{
  struct Gline *agline;
  char uhmask[NICKLEN + USERLEN + HOSTLEN + 3];
  char *nick, *user, *host;
  char buf[1024];
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);

  /* NO_OLD_GLINE allows *@#channel to work correctly */
  if (*userhost == '#' || *userhost == '&'
# ifndef NO_OLD_GLINE
      || userhost[2] == '#' || userhost[2] == '&'
# endif /* OLD_GLINE */
      ) {
    if ((flags & GLINE_LOCAL) && !HasPriv(sptr, PRIV_LOCAL_BADCHAN))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    flags |= GLINE_BADCHAN;
# ifndef NO_OLD_GLINE
    if (userhost[2] == '#' || userhost[2] == '&')
      user = userhost + 2;
    else
# endif /* OLD_GLINE */
      user = userhost;
    host = 0;
  } else {
    canon_userhost(userhost, &nick, &user, &host, "*");
    if (sizeof(uhmask) <
	ircd_snprintf(0, uhmask, sizeof(uhmask), "%s!%s@%s", nick, user, host))
      return send_reply(sptr, ERR_LONGMASK);
    else if (MyUser(sptr) || (IsUser(sptr) && flags & GLINE_LOCAL)) {
      switch (gline_checkmask(host)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
	if (flags & GLINE_OPERFORCE)
	  break;
	/*FALLTHROUGH*/
/*      case CHECK_REJECTED: --Desactivé (glines nick!*@* marchent plus)
	return send_reply(sptr, ERR_MASKTOOWIDE, uhmask);
	break;*/
      }

      if ((tmp = count_users(uhmask)) >=
	  feature_int(FEAT_GLINEMAXUSERCOUNT) && !(flags & GLINE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than GLINE_MAX_EXPIRE.
   */
  if (!(flags & GLINE_FORCE) && (expire <= 0 || expire > GLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* Inform ops... */
if(!(flags & GLINE_LOCAL)) {
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
		       SNO_AUTO, "%s adding a global %s for %s%s%s%s%s, expiring at %Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE",
		       flags & GLINE_BADCHAN ? "" : nick,
		       flags & GLINE_BADCHAN ? "" : "!",
			   user,
		       flags & GLINE_BADCHAN ? "" : "@",
		       flags & GLINE_BADCHAN ? "" : host,
		       expire + TSoffset, reason);
  if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_GLINE))
  {  	
  ircd_snprintf(0, buf, sizeof buf, "%s adding a global %s for %s%s%s%s%s, expiring at %Tu: %s",
                       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                       cli_name(sptr) : cli_name((cli_user(sptr))->server),
                       flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE",
                       flags & GLINE_BADCHAN ? "" : nick,
                       flags & GLINE_BADCHAN ? "" : "!",
                           user,
                       flags & GLINE_BADCHAN ? "" : "@",
                       flags & GLINE_BADCHAN ? "" : host,
                       expire + TSoffset, reason);
  admin_sendmail(buf);
  }

} else {
  sendto_allops(&me, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
		       SNO_AUTO, "%s adding to %s a local %s for %s%s%s%s%s, expiring at %Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
			   cli_name(&me),
		       flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE",
		       flags & GLINE_BADCHAN ? "" : nick,
		       flags & GLINE_BADCHAN ? "" : "!",
			   user,
		       flags & GLINE_BADCHAN ? "" : "@",
		       flags & GLINE_BADCHAN ? "" : host,
		       expire + TSoffset, reason);
  if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_GLINE))
  {
  ircd_snprintf(0, buf, sizeof buf, "%s adding to %s a local %s for %s%s%s%s%s, expiring at %Tu: %s",
                       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                       cli_name(sptr) : cli_name((cli_user(sptr))->server),
                           cli_name(&me),
                       flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE",
                       flags & GLINE_BADCHAN ? "" : nick,
                       flags & GLINE_BADCHAN ? "" : "!",
                           user,
                       flags & GLINE_BADCHAN ? "" : "@",
                       flags & GLINE_BADCHAN ? "" : host,
                       expire + TSoffset, reason);
  admin_sendmail(buf);
  }
}
  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s %s for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & GLINE_LOCAL ? "local" : "global",
	    flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE",
	    flags & GLINE_BADCHAN ? "" : nick,
	    flags & GLINE_BADCHAN ? "" : "!",
	    userhost,
	    expire + TSoffset, reason);


  /* make the gline */
  agline = make_gline(nick, user, host, reason, expire, lastmod, flags);

  if (!agline) /* if it overlapped, silently return */
    return 0;

  gline_propagate(cptr, sptr, agline);


  return do_gline(cptr, sptr, agline); /* knock off users if necessary */
}

int
gline_activate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
	       time_t lastmod, unsigned int flags)
{
  char buf[1024];
  unsigned int saveflags = 0;

  assert(0 != gline);

  saveflags = gline->gl_flags;

  if (flags & GLINE_LOCAL)
    gline->gl_flags &= ~GLINE_LDEACT;
  else {
    gline->gl_flags |= GLINE_ACTIVE;

    if (gline->gl_lastmod) {
      if (gline->gl_lastmod >= lastmod) /* force lastmod to increase */
	gline->gl_lastmod++;
      else
	gline->gl_lastmod = lastmod;
    }
  }

  if ((saveflags & GLINE_ACTMASK) == GLINE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global %s for %s%s%s%s%s, "
		       "expire à %Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       GlineIsBadChan(gline) ? "" : gline->gl_nick,
		       GlineIsBadChan(gline) ? "" : "!",
		       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire + TSoffset, gline->gl_reason);
  if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_GLINE))
  {
  ircd_snprintf(0, buf, sizeof buf, "%s activating global %s for %s%s%s%s%s, "
                       "expire à %Tu: %s",
                       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                       cli_name(sptr) : cli_name((cli_user(sptr))->server),
                       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
                       GlineIsBadChan(gline) ? "" : gline->gl_nick,
                       GlineIsBadChan(gline) ? "" : "!",
                       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
                       GlineIsBadChan(gline) ? "" : gline->gl_host,
                       gline->gl_expire + TSoffset, gline->gl_reason);

  admin_sendmail(buf);
  }

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global %s for %s%s%s%s%s, expiring at %Tu: %s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	    GlineIsBadChan(gline) ? "" : gline->gl_nick,
	    GlineIsBadChan(gline) ? "" : "!",
	    gline->gl_user,
	    GlineIsBadChan(gline) ? "" : "@",
	    GlineIsBadChan(gline) ? "" : gline->gl_host,
	    gline->gl_expire + TSoffset, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  return GlineIsBadChan(gline) ? 0 : do_gline(cptr, sptr, gline);
}

int
gline_deactivate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
		 time_t lastmod, unsigned int flags)
{
  char buf[1024];
  unsigned int saveflags = 0;

  assert(0 != gline);

  saveflags = gline->gl_flags;

#if 0
  if (GlineIsLocal(gline))
    msg = "removing local";
  else if (!gline->gl_lastmod && !(flags & GLINE_LOCAL)) {
    msg = "removing global";
    gline->gl_flags &= ~GLINE_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";
#endif

  gline->gl_flags &= ~GLINE_ACTIVE;

  if (gline->gl_lastmod) {
	if (gline->gl_lastmod >= lastmod)
	  gline->gl_lastmod++;
	else
	  gline->gl_lastmod = lastmod;
  }

  if ((saveflags & GLINE_ACTMASK) != GLINE_ACTIVE)
      return 0; /* was inactive to begin with */

  /* Inform ops and log it */
  if (!GlineIsLocal(gline)) { 
  sendto_opmask_butone(0, SNO_GLINE, "%s removing a global %s for %s%s%s%s%s, expiring at %Tu: "
		       "%s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       GlineIsBadChan(gline) ? "" : gline->gl_nick,
		       GlineIsBadChan(gline) ? "" : "!",
		       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire + TSoffset, gline->gl_reason);

  if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_GLINE))
  {
  ircd_snprintf(0, buf, sizeof buf,  "%s removing a global %s for %s%s%s%s%s, expiring at %Tu: "
                       "%s",
                       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                       cli_name(sptr) : cli_name((cli_user(sptr))->server),
                       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
                       GlineIsBadChan(gline) ? "" : gline->gl_nick,
                       GlineIsBadChan(gline) ? "" : "!",
                       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
                       GlineIsBadChan(gline) ? "" : gline->gl_host,
                       gline->gl_expire + TSoffset, gline->gl_reason);
  admin_sendmail(buf);
  }

  } else {
  sendto_allops(&me, SNO_GLINE, "%s removing to %s a local %s for %s%s%s%s%s, expiring at %Tu: "
		       "%s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       cli_name(&me), GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       GlineIsBadChan(gline) ? "" : gline->gl_nick,
		       GlineIsBadChan(gline) ? "" : "!",
		       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire + TSoffset, gline->gl_reason);

  if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_GLINE))
  {
  ircd_snprintf(0, buf, sizeof buf, "%s removing to %s a local %s for %s%s%s%s%s, expiring at %Tu: "
                       "%s",
                       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                       cli_name(sptr) : cli_name((cli_user(sptr))->server),
                       cli_name(&me), GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
                       GlineIsBadChan(gline) ? "" : gline->gl_nick,
                       GlineIsBadChan(gline) ? "" : "!",
                       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
                       GlineIsBadChan(gline) ? "" : gline->gl_host,
                       gline->gl_expire + TSoffset, gline->gl_reason);
  admin_sendmail(buf);
  }

  }

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s %s for %s%s%s%s%s, expiring at %Tu: %s", sptr, GlineIsLocal(gline) ? "removing local" : "removing global",
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	    GlineIsBadChan(gline) ? "" : gline->gl_nick,
	    GlineIsBadChan(gline) ? "" : "!",
	    gline->gl_user,
	    GlineIsBadChan(gline) ? "" : "@",
	    GlineIsBadChan(gline) ? "" : gline->gl_host,
	    gline->gl_expire + TSoffset, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  /* if it's a local gline or a Uworld gline (and not locally deactivated).. */
// if (GlineIsLocal(gline) || (!gline->gl_lastmod && !(flags & GLINE_LOCAL)))
    gline_free(gline); /* get rid of it */

  return 0;
}

struct Gline *
gline_find(char *userhost, unsigned int flags)
{
  struct Gline *gline;
  struct Gline *sgline;
  char *nick, *user, *host, *t_uh;

  if (flags & (GLINE_BADCHAN | GLINE_ANY)) {
    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	       (flags & GLINE_LASTMOD && !gline->gl_lastmod))
	continue;
      else if ((flags & GLINE_EXACT ? ircd_strcmp(gline->gl_user, userhost) :
		match(gline->gl_user, userhost)) == 0)
	return gline;
    }
  }

  if ((flags & (GLINE_BADCHAN | GLINE_ANY)) == GLINE_BADCHAN ||
      *userhost == '#' || *userhost == '&'
#ifndef NO_OLD_GLINE
      || userhost[2] == '#' || userhost[2] == '&'
#endif /* NO_OLD_GLINE */
      )
    return 0;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &nick, &user, &host, 0);

  if(BadPtr(user))
    return 0;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	     (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;
    else if (flags & GLINE_EXACT) {
      if (ircd_strcmp(gline->gl_host, host) == 0 &&
		 ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
		 (user && ircd_strcmp(gline->gl_user, user) == 0)) &&
		 ((!nick && ircd_strcmp(gline->gl_nick, "*") == 0) ||
		 (nick && ircd_strcmp(gline->gl_nick, nick) == 0)))
	break;
    } else {
      if (match(gline->gl_host, host) == 0 &&
		 ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
		 (user && match(gline->gl_user, user) == 0)) &&
		 ((!nick && ircd_strcmp(gline->gl_nick, "*") == 0) ||
		 (nick && (match(gline->gl_nick, nick) == 0))))
      break;
    }
  }

  MyFree(t_uh);

  return gline;
}

struct Gline *
gline_lookup(struct Client *cptr, unsigned int flags)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) {
      gline_free(gline);
      continue;
    }

    if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	     (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;

    if (match(gline->gl_nick, cli_name(cptr)) != 0)
      continue;

    if (match(gline->gl_user, (cli_user(cptr))->username) != 0)
      continue;

    if (GlineIsIpMask(gline)) {
      Debug((DEBUG_DEBUG,"IP gline: %08x %08x/%i",(cli_ip(cptr)).s_addr,gline->ipnum.s_addr,gline->bits));
      if (((cli_ip(cptr)).s_addr & NETMASK(gline->bits)) != gline->ipnum.s_addr)
        continue;
    }
    else {
      if (match(gline->gl_host, (cli_user(cptr))->realhost) != 0)
        continue;
    }
    return gline;
  }
  /*
   * No Glines matched
   */
  return 0;
}

void
gline_free(struct Gline *gline)
{
  assert(0 != gline);

  *gline->gl_prev_p = gline->gl_next; /* squeeze this gline out */
  if (gline->gl_next)
    gline->gl_next->gl_prev_p = gline->gl_prev_p;

  if (gline->gl_nick)
    MyFree(gline->gl_nick);
  MyFree(gline->gl_user); /* free up the memory */
  if (gline->gl_host)
    MyFree(gline->gl_host);
  MyFree(gline->gl_reason);
  MyFree(gline);
}

void
gline_burst(struct Client *cptr)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s!%s@%s %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_nick, gline->gl_user,
		    gline->gl_host, gline->gl_expire - CurrentTime,
		    gline->gl_lastmod, gline->gl_reason);
  }

  for (gline = BadChanGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_expire - CurrentTime, gline->gl_lastmod,
		    gline->gl_reason);
  }
}

int
gline_resend(struct Client *cptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || !gline->gl_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s%s%s %Tu %Tu :%s",
		GlineIsRemActive(gline) ? '+' : '-',
		GlineIsBadChan(gline) ? "" : gline->gl_nick,
		GlineIsBadChan(gline) ? "" : "!",
		gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		GlineIsBadChan(gline) ? "" : gline->gl_host,
		gline->gl_expire - CurrentTime, gline->gl_lastmod,
		gline->gl_reason);

  return 0;
}

int
gline_list(struct Client *sptr, char *userhost)
{
  struct Gline *gline;
  struct Gline *sgline;

  if (userhost) {
    if (!(gline = gline_find(userhost, GLINE_ANY))) /* no such gline */
      return send_reply(sptr, ERR_NOSUCHGLINE, userhost);

    /* send gline information along */
    send_reply(sptr, RPL_GLIST,
	       GlineIsBadChan(gline) ? "" : gline->gl_nick,
	       GlineIsBadChan(gline) ? "" : "!",
	       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	       GlineIsBadChan(gline) ? "" : gline->gl_host,
	       gline->gl_expire + TSoffset,
	       GlineIsLocal(gline) ? cli_name(&me) : "*",
	       GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	send_reply(sptr, RPL_GLIST, gline->gl_nick, "!", gline->gl_user, "@",
	       gline->gl_host, gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? cli_name(&me) : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }

    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	send_reply(sptr, RPL_GLIST, "", "", gline->gl_user, "", "",
		   gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? cli_name(&me) : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }
  }

  /* end of gline information */
  return send_reply(sptr, RPL_ENDOFGLIST);
}

void
gline_stats(struct Client *sptr, struct StatDesc *sd, int stat, char *param)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else
      send_reply(sptr, RPL_STATSGLINE, 'G', gline->gl_nick, "!", gline->gl_user, gline->gl_host,
		 gline->gl_expire + TSoffset, gline->gl_reason);
  }
}

int
gline_memory_count(size_t *gl_size)
{
  struct Gline *gline;
  unsigned int gl = 0;

  for (gline = GlobalGlineList; gline; gline = gline->gl_next) {
    gl++;
    gl_size += sizeof(struct Gline);
    gl_size += gline->gl_nick ? (strlen(gline->gl_nick) + 1) : 0;
    gl_size += gline->gl_user ? (strlen(gline->gl_user) + 1) : 0;
    gl_size += gline->gl_host ? (strlen(gline->gl_host) + 1) : 0;
    gl_size += gline->gl_reason ? (strlen(gline->gl_reason) + 1) : 0;
  }
  return gl;
}

struct Gline *
IsNickGlined(struct Client *cptr, char *nick)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) {
      gline_free(gline);
      continue;
    }

    if (!ircd_strcmp(gline->gl_nick, "*"))	/* skip glines w. wildcarded nick */
      continue;

    if (match(gline->gl_nick, nick) != 0)
      continue;

    if (match(gline->gl_user, (cli_user(cptr))->username) != 0)
      continue;

    if (GlineIsIpMask(gline)) {
      Debug((DEBUG_DEBUG,"IP gline: %08x %08x/%i",(cli_ip(cptr)).s_addr,gline->ipnum.s_addr,gline->bits));
      if (((cli_ip(cptr)).s_addr & NETMASK(gline->bits)) != gline->ipnum.s_addr)
        continue;
    }
    else {
      if (match(gline->gl_host, (cli_user(cptr))->realhost) != 0)
        continue;
    }
    return gline;
  }
  /*
   * No Glines matched
   */
  return 0;
}
