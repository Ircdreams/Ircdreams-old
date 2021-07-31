/*
 * IRC - Internet Relay Chat, ircd/m_who.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * $Id: m_who.c,v 1.8 2006/02/06 15:00:49 progs Exp $
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_user.h"
#include "s_debug.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || ((b & WHOSELECT_EXTRA) && MyConnect(ac) && (HasPriv((s), PRIV_SHOW_INVIS) || HasPriv((s), PRIV_SHOW_ALL_INVIS))))

#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SHOW_ALL_INVIS)))

#define SHOW_MORE(sptr, counter) (HasPriv(sptr, PRIV_UNLIMIT_QUERY) || (!(counter-- < 0)) )

#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SEE_CHAN)))

#define MAX_WHOIS_LINES 50

#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

struct SearchOptions
{
    struct Flags   umodes;
    char *nick;
    char *user;
    char *host;
    char *gcos;
    char *ip;
    struct Channel *channel;
    struct Client *server;
    char umode_plus:1;
    char nick_plus:1;
    char user_plus:1;
    char host_plus:1;
    char crypt:1; /* si host est une host cryptée */
    char gcos_plus:1;
    char ip_plus:1;
    char chan_plus:1;
    char serv_plus:1;
    char away_plus:1;
    char check_away:1;
    char check_umode:1;
    char spare:3; /* spare space for more stuff(?) */
    char extra:1; /* si le flag x est mis à la fin ça affiche les hosts uncrypt */
};

struct SearchOptions wsopts;
int build_searchopts(struct Client*, int, char* parv[]);
int chk_who(struct Client*, int);

/* Externally defined stuffs */
extern int lifesux;
//extern const struct UserMode userModeList[];

int build_searchopts(struct Client* sptr, int parc, char* parv[])
{
  static char *who_oper_help[] =
  {
      "/WHO [+|-][acghimnsuR] [args] [x]",
      "Flags are specified like chanmodes,",
      "flags cghimnsuC all have arguments.",
      "Flags are set to a positive check by +, a negative check by -",
      "\2Add 'x' as last argument to see realhosts\2",
      "The flags work as follows:",
      "Flag a: user is away",
      "Flag c <channel>  :user is on <channel>,",
      "                   no wildcards accepted, only positive check",
      "Flag g <realname> :user's realname matches <gcos> mask,",
      "Flag R <host>     :user's REAL hostname matches <host> mask",
      "Flag i <ip>       :user's IP matches <ip> mask",
      "Flag m <umodes>   :user has modes <usermodes>",
      "Flag n <nick>     :user's nickname matches <nick> mask",
      "Flag s <server>   :user is on server <server>",
      "                   no wildcards accepted, only positive check",
      "Flag u <user>     :user's ident matches <user> mask",
      "Flag h <host>     :user's current hostname matches <crypt> mask",
      NULL
  };

  static char *who_user_help[] =
  {
      "/WHO [+|-][achmnsu] [args]",
      "Flags are specified like chanmodes,",
      "flags cghmnsu all have arguments.",
      "Flags are set to a positive check by +, a negative check by -",
      "The flags work as follows:",
      "Flag a: user is away",
      "Flag c <channel>  :user is on <channel>,",
      "                   no wildcards accepted, only positive check",
      "Flag g <realname> :user's realname matches <gcos> mask,",
      "Flag m <umodes>   :user has modes <usermodes>",
      "Flag n <nick>     :user's nickname matches <nick> mask",
      "Flag u <user>     :user's ident matches <user> mask",
      "Flag h <host>     :user's hostname matches <crypt> mask",
      NULL
  };

  char *flags, change=1, *s;
  int args=1, i;

  memset((char *)&wsopts, '\0', sizeof(struct SearchOptions));
  /* if we got no extra arguments, send them the help. yeech. */
  /* if it's /who ?, send them the help */
  if(parc < 1 || parv[0][0]=='?')
  {
      /* So we don't confuse users with flags they cannot use,
         a different /who ? output will be given to users and
         opers -srd */

      char **ptr = NULL;

      if (!IsAnOper(sptr))
       ptr = who_user_help;
      else
       ptr = who_oper_help;

      for (; *ptr; ptr++)
	  send_reply(sptr, RPL_LISTUSAGE, *ptr);

      send_reply(sptr, RPL_ENDOFWHO, "?");
      return 0;
  }
  /* backwards compatibility */
  else if(parv[0][0]=='0' && parv[0][1]==0)
  {
      if(parc>1 && *parv[1]=='o')
      {
	  wsopts.check_umode=1;
	  wsopts.umode_plus=1;
	  FlagSet(&wsopts.umodes, FLAG_OPER);
      }
      wsopts.host_plus=1;
      wsopts.host="*";
      return 1;
  }
  /* if the first argument isn't a list of stuff */
  else if(parv[0][0]!='+' && parv[0][0]!='-')
  {
      if(parv[0][0]=='#' || parv[0][0]=='&')
      {
	  wsopts.channel = get_channel(sptr, parv[0], CGT_NO_CREATE);
	  if(wsopts.channel==NULL)
	  {
	  	send_reply(sptr, ERR_NOSUCHCHANNEL, parv[0]);
		return 0;
	  }
      }
      else
      {
	  /* If the arguement has a . in it, treat it as an
	   * address. Otherwise treat it as a nick. -Rak */
	  if (strchr(parv[0], '.'))
	  {
	      wsopts.host_plus=1;
	      if(!IsAnOper(sptr)) wsopts.crypt=1;
	      wsopts.host=parv[0];
	  }
	  else
	  {
	      wsopts.nick_plus=1;
	      wsopts.nick=parv[0];
	  }
      }
      if(parc>1 && parv[1][0]=='x' && HasPriv(sptr, PRIV_WHOX))
      	wsopts.extra=1;
      return 1;
  }
  /* now walk the list (a lot like set_mode) and set arguments
   * as appropriate. */
  flags=parv[0];
  while(*flags)
  {
      switch(*flags)
      {
      case '+':
      case '-':
	  change=(*flags=='+' ? 1 : 0);
	  break;
      case 'a':
	  if(change)
	      wsopts.away_plus=1; /* they want here people */
	  else
	      wsopts.away_plus=0;
	  wsopts.check_away=1;
	  break;
      case 'c':
	  if(parv[args]==NULL  || !change )
	  {
	    send_reply(sptr, ERR_WHOSYNTAX);
	    return 0;
	  }
	  wsopts.channel = get_channel(sptr, parv[args], CGT_NO_CREATE);
	  if(wsopts.channel==NULL)
	  {
	  	send_reply(sptr, ERR_NOSUCHCHANNEL, parv[args]);
		return 0;
	  }
	  wsopts.chan_plus=change;
	  args++;
	  break;
      case 'g':
	  if(parv[args]==NULL || !IsAnOper(sptr))
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.gcos=parv[args];
	  wsopts.gcos_plus=change;
	  args++;
	  break;
      case 'R':
	  if(parv[args]==NULL)
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.host=parv[args];
	  wsopts.host_plus=change;
	  if(!IsAnOper(sptr)) wsopts.crypt=1;
	  else wsopts.crypt=0;
	  args++;
	  break;
      case 'h':
	  if(!parv[args])
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.host=parv[args];
	  wsopts.crypt=1;
	  wsopts.host_plus=change;
	  args++;
	  break;
      case 'i':
	  if(parv[args]==NULL || !IsAnOper(sptr))
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.ip=parv[args];
	  wsopts.ip_plus=change;
	  args++;
	  break;
      case 'm':
	  if(parv[args]==NULL)
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.umode_plus=change;
	  s=parv[args];
	  while(*s)
	  {
	      for(i=0;i < USERMODELIST_SIZE;i++)
	      {
		  if(*s==userModeList[i].c && (IsAnOper(sptr) || userModeList[i].flag &(FLAG_OPER|FLAG_LOCOP)))
		  {
		      FlagSet(&wsopts.umodes, userModeList[i].flag);
		      /*wsopts.umodes|=userModeList[i].flag;*/
		      break;
		  }
	      }
	      s++;
	  }
	  if(&wsopts.umodes)
	      wsopts.check_umode=1;
	  args++;
	  break;
      case 'n':
	  if(parv[args]==NULL)
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.nick=parv[args];
	  wsopts.nick_plus=change;
	  args++;
	  break;
      case 's':
	  if(parv[args]==NULL || !change || !IsAnOper(sptr))
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.server=FindServer(parv[args]);
	  if(wsopts.server==NULL)
	  {
	      send_reply(sptr, ERR_NOSUCHSERVER, parv[args]);
	      return 0;
	  }
	  wsopts.serv_plus=change;
	  args++;
	  break;
      case 'u':
	  if(parv[args]==NULL)
	  {
	      send_reply(sptr, ERR_WHOSYNTAX);
	      return 0;
	  }
	  wsopts.user=parv[args];
	  wsopts.user_plus=change;
	  args++;
	  break;
      }
      flags++;
  }

  if(parv[args] && parv[args][0] == 'x' &&  IsAnOper(sptr))
  {
  	wsopts.extra=1;
	args--;
  }

  /* hey cool, it all worked! */
  return 1;
}

/* these four are used by chk_who to check gcos/nick/user/host
 * respectively */
int (*gchkfn)(const char *, const char *);
int (*nchkfn)(const char *, const char *);
int (*uchkfn)(const char *, const char *);
int (*hchkfn)(const char *, const char *);
int (*ichkfn)(const char *, const char *);

/* showall = 0 -> non ircop, affiche les -i
   showall = 1 -> ircop (ou membre du chan), affiche tout le monde*/
int chk_who(struct Client* ac, int showall)
{
    if(!IsUser(ac))
	return 0;
    if(IsInvisible(ac) && !showall)
	return 0;

    if(wsopts.check_umode)
    {
	int i, flag;

	for (i = 0; i < USERMODELIST_SIZE; ++i) {
		flag = userModeList[i].flag;
		if(FlagHas(&wsopts.umodes, flag))
		{
			if((wsopts.umode_plus && HasFlag(ac, flag)) ||
			   (!wsopts.umode_plus && !HasFlag(ac, flag)))
				continue;
			else
				return 0;
		}
	}
    }

    if(wsopts.check_away)
	if((wsopts.away_plus && cli_user(ac)->away==NULL) ||
	   (!wsopts.away_plus && cli_user(ac)->away!=NULL))
	    return 0;
    /* while this is wasteful now, in the future
     * when clients contain pointers to their servers
     * of origin, this'll become a 4 byte check instead of a mycmp
     * -wd */
    /* welcome to the future... :) - lucas */
    if(wsopts.serv_plus)
	if(wsopts.server != cli_user(ac)->server)
	    return 0;
    /* we only call match once, since if the first condition
     * isn't true, most (all?) compilers will never try the
     * second...phew :) */
    if(wsopts.user!=NULL)
	if((wsopts.user_plus && uchkfn(wsopts.user, cli_user(ac)->username)) ||
	   (!wsopts.user_plus && !uchkfn(wsopts.user, cli_user(ac)->username)))
	    return 0;

    if(wsopts.nick!=NULL)
	if((wsopts.nick_plus && nchkfn(wsopts.nick, cli_name(ac))) ||
	   (!wsopts.nick_plus && !nchkfn(wsopts.nick, cli_name(ac))))
	    return 0;

/*    Debug((DEBUG_INFO, "chk_who(); host_plus=%d, host=%s, crypt=%d; host=%s, crypt=%s, realhost=%s, extra=%d", wsopts.host_plus,
                  wsopts.host, wsopts.crypt, cli_user(ac)->host, cli_user(ac)->crypt), cli_user(ac)->realhost, wsopts.extra);    */
    if(wsopts.host!=NULL) /* si 'x', affiche les realhosts */
	if((wsopts.host_plus && hchkfn(wsopts.host, wsopts.crypt ? cli_user(ac)->host : cli_user(ac)->realhost)) ||
	   (!wsopts.host_plus && !hchkfn(wsopts.host, wsopts.crypt ? cli_user(ac)->host : cli_user(ac)->realhost)))
	    return 0;

    if(wsopts.ip!=NULL)
	if((wsopts.ip_plus && ichkfn(wsopts.ip, cli_connect(ac)->con_sock_ip)) ||
	   (!wsopts.ip_plus && !ichkfn(wsopts.ip,cli_connect(ac)->con_sock_ip)))
	    return 0;

    if(wsopts.gcos!=NULL)
	if((wsopts.gcos_plus && gchkfn(wsopts.gcos, cli_info(ac))) ||
	   (!wsopts.gcos_plus && !gchkfn(wsopts.gcos, cli_info(ac))))
	    return 0;
    return 1;
}

/* allow lusers only 200 replies from /who */
#define MAXWHOREPLIES 200
#define WHO_HOPCOUNT(s, a) ((!IsAnOper((s))) ? 0 : cli_hopcount(a))
int m_who(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
    struct Client* ac;
    struct Membership* cm;
    int shown=0, i=0, showall=IsAnOper(sptr);
    char status[4] = {0};

    /* drop nonlocal clients */
    if(!MyConnect(sptr))
	return 0;

    if(!build_searchopts(sptr, parc-1, parv+1))
	return 0; /* /who was no good */

    if(wsopts.gcos!=NULL && (strchr(wsopts.gcos, '?'))==NULL &&
       (strchr(wsopts.gcos, '*'))==NULL)
	gchkfn=ircd_strcmp;
    else
	gchkfn=match;
    if(wsopts.nick!=NULL && (strchr(wsopts.nick, '?'))==NULL &&
       (strchr(wsopts.nick, '*'))==NULL)
	nchkfn=ircd_strcmp;
    else
	nchkfn=match;
    if(wsopts.user!=NULL && (strchr(wsopts.user, '?'))==NULL &&
       (strchr(wsopts.user, '*'))==NULL)
	uchkfn=ircd_strcmp;
    else
	uchkfn=match;
    if(wsopts.host!=NULL && (strchr(wsopts.host, '?'))==NULL &&
       (strchr(wsopts.host, '*'))==NULL)
	hchkfn=ircd_strcmp;
    else
	hchkfn=match;

    if(wsopts.ip!=NULL && (strchr(wsopts.ip, '?'))==NULL &&
       (strchr(wsopts.ip, '*'))==NULL)
	ichkfn=ircd_strcmp;
    else
	ichkfn=match;


    if(wsopts.channel!=NULL)
    {
    	if(IsAnOper(sptr) || find_member_link(wsopts.channel, sptr))
	    showall=1;
	else
	    showall=0;
	if(showall || !SecretChannel(wsopts.channel))
	{
	    for(cm=wsopts.channel->members; cm; cm=cm->next_member)
	    {
		ac=cm->user;
		i=0;
		if(!chk_who(ac,showall))
		    continue;
		/* get rid of the pidly stuff first */
		/* wow, they passed it all, give them the reply...
		 * IF they haven't reached the max, or they're an oper */
		status[i++]=(cli_user(ac)->away==NULL ? 'H' : 'G');
		status[i]=(IsAnOper(ac) ? '*' : ((IsInvisible(ac) &&
						  IsOper(sptr) && !showall) ? '%' : 0));
		status[((status[i]) ? ++i : i)]=((cm->status&CHFL_CHANOP) ? '@'
						 : ((cm->status&CHFL_VOICE) ?
						    '+' : (cm->status & CHFL_DELAYED ? '<' : 0)));
		status[++i]=0;
		send_reply(sptr, RPL_WHOREPLY,
			   wsopts.channel->chname, cli_user(ac)->username,
			   wsopts.extra ? cli_user(ac)->realhost : cli_user(ac)->host,
			   cli_name(cli_user(ac)->server), cli_name(ac), status,
			   WHO_HOPCOUNT(sptr, ac), cli_info(ac));
	    }
	}
	send_reply(sptr, RPL_ENDOFWHO, wsopts.channel->chname);
	return 0;
    }
    /* if (for whatever reason) they gave us a nick with no
     * wildcards, just do a find_person, bewm! */
    else if(nchkfn==ircd_strcmp)
    {
	ac=FindUser(wsopts.nick);
	if(ac!=NULL)
	{
	    if(!chk_who(ac,1))
	    {
		send_reply(sptr, RPL_ENDOFWHO,
			   wsopts.host!=NULL ? wsopts.host : wsopts.nick);
		return 0;
	    }
	    else
	    {
		status[0]=(cli_user(ac)->away==NULL ? 'H' : 'G');
		status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) &&
						 IsAnOper(sptr) ? '%' : 0));
		status[2]=0;
		send_reply(sptr, RPL_WHOREPLY, "*", cli_user(ac)->username,
			   wsopts.extra ? cli_user(ac)->realhost : cli_user(ac)->host,
			   cli_name(cli_user(ac)->server), cli_name(ac), status,
			   WHO_HOPCOUNT(sptr, ac),
			   cli_info(ac));
		send_reply(sptr, RPL_ENDOFWHO, wsopts.host!=NULL ? wsopts.host : wsopts.nick);
		return 0;
	    }
	}
	send_reply(sptr, RPL_ENDOFWHO, wsopts.host!=NULL ? wsopts.host : wsopts.nick);
	return 0;
    }

    for(ac=GlobalClientList;ac;ac=cli_next(ac))
    {
	    if(!chk_who(ac,showall))
		continue;
	    /* wow, they passed it all, give them the reply...
	     * IF they haven't reached the max, or they're an oper */
	    if(shown==MAXWHOREPLIES && !IsAnOper(sptr))
	    {
	    	send_reply(sptr, ERR_QUERYTOOLONG, "WHO");
		break; /* break out of loop so we can send end of who */
	    }
	    status[0]=(cli_user(ac)->away==NULL ? 'H' : 'G');
	    status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) &&
					     IsAnOper(sptr) ? '%' : 0));
	    status[2]=0;
	    send_reply(sptr, RPL_WHOREPLY, "*", cli_user(ac)->username,
		       wsopts.extra ? cli_user(ac)->realhost : cli_user(ac)->host,
		       cli_name(cli_user(ac)->server), cli_name(ac), status,
		       WHO_HOPCOUNT(sptr, ac), cli_info(ac));
	    shown++;
    }
    send_reply(sptr, RPL_ENDOFWHO, (wsopts.host!=NULL ? wsopts.host :
		(wsopts.nick!=NULL ? wsopts.nick :
		 (wsopts.user!=NULL ? wsopts.user :
		  (wsopts.gcos!=NULL ? wsopts.gcos :
		   (wsopts.server!=NULL ? cli_name(wsopts.server) :
		    "*"))))));
    return 0;
}

#if 0 /* Ancien /who -- Progs */

/** Variable storing current cli_marker() value to mark visited clients. */
static int who_marker = 0;
/** Increment #who_marker, handling overflow if necessary. */
static void move_marker(void)
{
  if (!++who_marker)
  {
    struct Client *cptr = GlobalClientList;
    while (cptr)
    {
      cli_marker(cptr) = 0;
      cptr = cli_next(cptr);
    }
    who_marker++;
  }
}

#define CheckMark(x, y) ((x == y) ? 0 : (x = y))
#define Process(cptr) CheckMark(cli_marker(cptr), who_marker)

#define WHOSELECT_OPER 1   /**< Flag for /WHO: Show IRC operators. */
#define WHOSELECT_EXTRA 2  /**< Flag for /WHO: Pull rank to see users. */
#define WHOSELECT_DELAY 4  /**< Flag for /WHO: Show join-delayed users. */

#define WHO_FIELD_QTY 1    /**< Display query type. */
#define WHO_FIELD_CHA 2    /**< Show common channel name. */
#define WHO_FIELD_UID 4    /**< Show username. */
#define WHO_FIELD_NIP 8    /**< Show IP address. */
#define WHO_FIELD_HOS 16   /**< Show hostname. */
#define WHO_FIELD_SER 32   /**< Show server. */
#define WHO_FIELD_NIC 64   /**< Show nickname. */
#define WHO_FIELD_FLA 128  /**< Show flags (away, oper, chanop, etc). */
#define WHO_FIELD_DIS 256  /**< Show hop count (distance). */
#define WHO_FIELD_REN 512  /**< Show realname (info). */
#define WHO_FIELD_IDL 1024 /**< Show idle time. */
#define WHO_FIELD_ACC 2048 /**< Show account name. */

/** Default fields for /WHO */
#define WHO_FIELD_DEF ( WHO_FIELD_NIC | WHO_FIELD_UID | WHO_FIELD_HOS | WHO_FIELD_SER )

/** Is \a ac plainly visible to \a s?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 */
#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

/** Can \a s see \a ac by using the flags in \a b?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || \
                             ((b & WHOSELECT_EXTRA) && MyConnect(ac) && \
                             (HasPriv((s), PRIV_SHOW_INVIS) || \
                              HasPriv((s), PRIV_SHOW_ALL_INVIS))))

/** Can \a s see \a ac by using the flags in \a b?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || \
                            ((b & WHOSELECT_EXTRA) && \
                              HasPriv((s), PRIV_SHOW_ALL_INVIS)))

/** Should we show more clients to \a sptr?
 * @param[in] sptr Client listing other users.
 * @param[in,out] counter Default count for clients.
 */
#define SHOW_MORE(sptr, counter) (HasPriv(sptr, PRIV_UNLIMIT_QUERY) || (!(counter-- < 0)) )

/** Can \a s see \a chptr?
 * @param[in] s Client trying to see \a chptr.
 * @param[in] chptr Channel being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SEE_CHAN)))

/** Send a WHO reply to a client who asked.
 * @param[in] sptr Client who is searching for other users.
 * @param[in] acptr Client who may be shown to \a sptr.
 * @param[in] repchan Shared channel that provides visibility.
 * @param[in] fields Bitmask of WHO_FIELD_* values, indicating what to show.
 * @param[in] qrt Query type string (ignored unless \a fields & WHO_FIELD_QTY).
 */
static void do_who(struct Client* sptr, struct Client* acptr,
                   struct Channel* repchan, int fields, char* qrt)
{
  char *p1;
  struct Membership *chan = 0;

  static char buf1[512];
  /* NOTE: with current fields list and sizes this _cannot_ overrun,
     and also the message finally sent shouldn't ever be truncated */

  p1 = buf1;
  buf1[1] = '\0';

  /* If we don't have a channel and we need one... try to find it,
     unless the listing is for a channel service, we already know
     that there are no common channels, thus use PubChannel and not
     SeeChannel */
  if (repchan)
    chan = find_channel_member(acptr, repchan);
  else if ((!fields || (fields & (WHO_FIELD_CHA | WHO_FIELD_FLA)))
           && !IsChannelService(acptr))
  {
    for (chan = cli_user(acptr)->channel; chan; chan = chan->next_channel)
      if (PubChannel(chan->channel) &&
          (acptr == sptr || !IsZombie(chan)))
        break;
  }

  /* Place the fields one by one in the buffer and send it
     note that fields == NULL means "default query" */

  if (fields & WHO_FIELD_QTY)   /* Query type */
  {
    *(p1++) = ' ';
    if (BadPtr(qrt))
      *(p1++) = '0';
    else
      while ((*qrt) && (*(p1++) = *(qrt++)));
  }

  if (!fields || (fields & WHO_FIELD_CHA))
  {
    char *p2;
    *(p1++) = ' ';
    if ((p2 = (chan ? chan->channel->chname : NULL)))
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '*';
  }

  if (!fields || (fields & WHO_FIELD_UID))
  {
    char *p2 = cli_user(acptr)->username;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (fields & WHO_FIELD_NIP)
  {
    const char* p2 = (HasHiddenHost(acptr) || IsSetHost(acptr)) && !IsAnOper(sptr) ?
      feature_str(FEAT_HIDDEN_IP) :
      ircd_ntoa(&cli_ip(acptr));
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_HOS))
  {
    char *p2 = cli_user(acptr)->host;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_SER))
  {
    const char *p2 = (feature_bool(FEAT_HIS_WHO_SERVERNAME) && !IsAnOper(sptr)) ?
                       feature_str(FEAT_HIS_SERVERNAME) :
                       cli_name(cli_user(acptr)->server);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_NIC))
  {
    char *p2 = cli_name(acptr);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_FLA))
  {
    *(p1++) = ' ';
    if (cli_user(acptr)->away)
      *(p1++) = 'G';
    else
      *(p1++) = 'H';
    if SeeOper(sptr,acptr)
      *(p1++) = '*';
    if (!chan) {
      /* No flags possible for the channel, so skip them all. */
    }
    else if (fields) {
      /* If you specified flags then we assume you know how to parse
       * multiple channel status flags, as this is currently the only
       * way to know if someone has @'s *and* is +'d.
       */
      if (IsChanOp(chan))
        *(p1++) = '@';
      if (HasVoice(chan))
        *(p1++) = '+';
      if (IsZombie(chan))
        *(p1++) = '!';
      if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    else {
      if (IsChanOp(chan))
        *(p1++) = '@';
      else if (HasVoice(chan))
        *(p1++) = '+';
      else if (IsZombie(chan))
        *(p1++) = '!';
      else if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    if (IsDeaf(acptr))
      *(p1++) = 'd';
    if (IsAnOper(sptr))
    {
      if (IsInvisible(acptr))
        *(p1++) = 'i';
      if (SendWallops(acptr))
        *(p1++) = 'w';
      if (SendDebug(acptr))
        *(p1++) = 'g';
      if (IsSetHost(acptr))
        *(p1++) = 'h';
    }
    if (HasHiddenHost(acptr))
      *(p1++) = 'x';
  }

  if (!fields || (fields & WHO_FIELD_DIS))
  {
    *p1++ = ' ';
    if (!fields)
      *p1++ = ':';              /* Place colon here for default reply */
    if (feature_bool(FEAT_HIS_WHO_HOPCOUNT) && !IsAnOper(sptr))
      *p1++ = (sptr == acptr) ? '0' : '3';
    else
      /* three digit hopcount maximum */
      p1 += ircd_snprintf(0, p1, 3, "%d", cli_hopcount(acptr));
  }

  if (fields & WHO_FIELD_IDL)
  {
    *p1++ = ' ';
    if (MyUser(acptr) &&
	(IsAnOper(sptr) || !feature_bool(FEAT_HIS_WHO_SERVERNAME) ||
	 acptr == sptr))
      p1 += ircd_snprintf(0, p1, 11, "%d",
                          CurrentTime - cli_user(acptr)->last);
    else
      *p1++ = '0';
  }

  if (fields & WHO_FIELD_ACC)
  {
    char *p2 = cli_user(acptr)->account;
    *(p1++) = ' ';
    if (*p2)
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '0';
  }

  if (!fields || (fields & WHO_FIELD_REN))
  {
    char *p2 = cli_info(acptr);
    *p1++ = ' ';
    if (fields)
      *p1++ = ':';              /* Place colon here for special reply */
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  /* The first char will always be an useless blank and we
     need to terminate buf1 */
  *p1 = '\0';
  p1 = buf1;
  send_reply(sptr, fields ? RPL_WHOSPCRPL : RPL_WHOREPLY, ++p1);
}

/** Handle a WHO message.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is a nickname mask list
 * \li \a parv[2] is an additional selection flag string.  'i' selects
 * opers, 'd' shows join-delayed users as well, 'x' shows extended
 * information to opers with the WHOX privilege; %flags specifies
 * what fields to output; a ,querytype if the t flag is specified
 * so the final thing will be like o%tnchu,777.
 * \li \a parv[3] parv[3] is an _optional_ parameter that overrides
 * parv[1] This can be used as "/quote who foo % :The Black Hacker to
 * find me, parv[3] _can_ contain spaces!
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_who(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *mask;           /* The mask we are looking for              */
  char ch;                      /* Scratch char register                    */
  struct Channel *chptr;                /* Channel to show                          */
  struct Client *acptr;         /* Client to show                           */

  int bitsel;                   /* Mask of selectors to apply               */
  int matchsel;                 /* Which fields the match should apply on    */
  int counter;                  /* Query size counter,
                                   initially used to count fields           */
  int commas;                   /* Does our mask contain any comma ?
                                   If so is a list..                        */
  int fields;                   /* Mask of fields to show                   */
  int isthere = 0;              /* When this set the user is member of chptr */
  char *nick;                   /* Single element extracted from
                                   the mask list                            */
  char *p;                      /* Scratch char pointer                     */
  char *qrt;                    /* Pointer to the query type                */
  static char mymask[512];      /* To save the mask before corrupting it    */

  /* Let's find where is our mask, and if actually contains something */
  mask = ((parc > 1) ? parv[1] : 0);
  if (parc > 3 && parv[3])
    mask = parv[3];
  if (mask && ((mask[0] == '\0') ||
      (mask[1] == '\0' && ((mask[0] == '0') || (mask[0] == '*')))))
    mask = 0;

  /* Evaluate the flags now, we consider the second parameter
     as "matchFlags%fieldsToInclude,querytype"           */
  bitsel = fields = counter = matchsel = 0;
  qrt = 0;
  if (parc > 2 && parv[2] && *parv[2])
  {
    p = parv[2];
    while (((ch = *(p++))) && (ch != '%') && (ch != ','))
      switch (ch)
      {
        case 'd':
        case 'D':
          bitsel |= WHOSELECT_DELAY;
          continue;
        case 'o':
        case 'O':
          bitsel |= WHOSELECT_OPER;
          continue;
        case 'x':
        case 'X':
          bitsel |= WHOSELECT_EXTRA;
          if (HasPriv(sptr, PRIV_WHOX))
	    log_write(LS_WHO, L_INFO, LOG_NOSNOTICE, "%#C WHO %s %s", sptr,
		      (BadPtr(parv[3]) ? parv[1] : parv[3]), parv[2]);
          continue;
        case 'n':
        case 'N':
          matchsel |= WHO_FIELD_NIC;
          continue;
        case 'u':
        case 'U':
          matchsel |= WHO_FIELD_UID;
          continue;
        case 'h':
        case 'H':
          matchsel |= WHO_FIELD_HOS;
          continue;
        case 'i':
        case 'I':
          matchsel |= WHO_FIELD_NIP;
          continue;
        case 's':
        case 'S':
          matchsel |= WHO_FIELD_SER;
          continue;
        case 'r':
        case 'R':
          matchsel |= WHO_FIELD_REN;
          continue;
        case 'a':
        case 'A':
          matchsel |= WHO_FIELD_ACC;
          continue;
      }
    if (ch == '%')
      while ((ch = *p++) && (ch != ','))
      {
        counter++;
        switch (ch)
        {
          case 'c':
          case 'C':
            fields |= WHO_FIELD_CHA;
            break;
          case 'd':
          case 'D':
            fields |= WHO_FIELD_DIS;
            break;
          case 'f':
          case 'F':
            fields |= WHO_FIELD_FLA;
            break;
          case 'h':
          case 'H':
            fields |= WHO_FIELD_HOS;
            break;
          case 'i':
          case 'I':
            fields |= WHO_FIELD_NIP;
            break;
          case 'l':
          case 'L':
            fields |= WHO_FIELD_IDL;
          case 'n':
          case 'N':
            fields |= WHO_FIELD_NIC;
            break;
          case 'r':
          case 'R':
            fields |= WHO_FIELD_REN;
            break;
          case 's':
          case 'S':
            fields |= WHO_FIELD_SER;
            break;
          case 't':
          case 'T':
            fields |= WHO_FIELD_QTY;
            break;
          case 'u':
          case 'U':
            fields |= WHO_FIELD_UID;
            break;
          case 'a':
          case 'A':
            fields |= WHO_FIELD_ACC;
            break;
          default:
            break;
        }
      };
    if (ch)
      qrt = p;
  }

  if (!matchsel)
    matchsel = WHO_FIELD_DEF;
  if (!fields)
    counter = 7;

  if (feature_bool(FEAT_HIS_WHO_SERVERNAME) && !IsAnOper(sptr))
    matchsel &= ~WHO_FIELD_SER;

  if (qrt && (fields & WHO_FIELD_QTY))
  {
    p = qrt;
    if (!((*p > '9') || (*p < '0')))
      p++;
    if (!((*p > '9') || (*p < '0')))
      p++;
    if (!((*p > '9') || (*p < '0')))
      p++;
    *p = '\0';
  }
  else
    qrt = 0;

  /* I'd love to add also a check on the number of matches fields per time */
  counter = (2048 / (counter + 4));
  if (mask && (strlen(mask) > 510))
    mask[510] = '\0';
  move_marker();
  commas = (mask && strchr(mask, ','));

  /* First treat mask as a list of plain nicks/channels */
  if (mask)
  {
    strcpy(mymask, mask);
    for (p = 0, nick = ircd_strtok(&p, mymask, ","); nick;
        nick = ircd_strtok(&p, 0, ","))
    {
      if (IsChannelName(nick) && (chptr = FindChannel(nick)))
      {
        isthere = (find_channel_member(sptr, chptr) != 0);
        if (isthere || SEE_CHANNEL(sptr, chptr, bitsel))
        {
          struct Membership* member;
          for (member = chptr->members; member; member = member->next_member)
          {
            acptr = member->user;
            if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
              continue;
            if ((acptr != sptr)
                && ((member->status & CHFL_ZOMBIE)
                    || ((member->status & CHFL_DELAYED)
                        && !(bitsel & WHOSELECT_DELAY))))
              continue;
            if (!(isthere || (SEE_USER(sptr, acptr, bitsel))))
              continue;
            if (!Process(acptr))        /* This can't be moved before other checks */
              continue;
            if (!(isthere || (SHOW_MORE(sptr, counter))))
              break;
            do_who(sptr, acptr, chptr, fields, qrt);
          }
        }
      }
      else
      {
        if ((acptr = FindUser(nick)) &&
            ((!(bitsel & WHOSELECT_OPER)) || SeeOper(sptr,acptr)) &&
            Process(acptr) && SHOW_MORE(sptr, counter))
        {
          do_who(sptr, acptr, 0, fields, qrt);
        }
      }
    }
  }

  /* If we didn't have any comma in the mask treat it as a
     real mask and try to match all relevant fields */
  if (!(commas || (counter < 1)))
  {
    struct irc_in_addr imask;
    int minlen, cset;
    unsigned char ibits;

    if (mask)
    {
      matchcomp(mymask, &minlen, &cset, mask);
      if (!ipmask_parse(mask, &imask, &ibits))
        matchsel &= ~WHO_FIELD_NIP;
      if ((minlen > NICKLEN) || !(cset & NTL_IRCNK))
        matchsel &= ~WHO_FIELD_NIC;
      if ((matchsel & WHO_FIELD_SER) &&
          ((minlen > HOSTLEN) || (!(cset & NTL_IRCHN))
          || (!markMatchexServer(mymask, minlen))))
        matchsel &= ~WHO_FIELD_SER;
      if ((minlen > USERLEN) || !(cset & NTL_IRCUI))
        matchsel &= ~WHO_FIELD_UID;
      if ((minlen > HOSTLEN) || !(cset & NTL_IRCHN))
        matchsel &= ~WHO_FIELD_HOS;
      if ((minlen > ACCOUNTLEN))
        matchsel &= ~WHO_FIELD_ACC;
    }

    /* First of all loop through the clients in common channels */
    if ((!(counter < 1)) && matchsel) {
      struct Membership* member;
      struct Membership* chan;
      for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
        chptr = chan->channel;
        for (member = chptr->members; member; member = member->next_member)
        {
          acptr = member->user;
          if (!(IsUser(acptr) && Process(acptr)))
            continue;           /* Now Process() is at the beginning, if we fail
                                   we'll never have to show this acptr in this query */
 	  if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
	    continue;
          if ((mask)
              && ((!(matchsel & WHO_FIELD_NIC))
              || matchexec(cli_name(acptr), mymask, minlen))
              && ((!(matchsel & WHO_FIELD_UID))
              || matchexec(cli_user(acptr)->username, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_SER))
              || (!(HasFlag(cli_user(acptr)->server, FLAG_MAP))))
              && ((!(matchsel & WHO_FIELD_HOS))
              || matchexec(cli_user(acptr)->host, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_HOS))
	      || !HasHiddenHost(acptr)
	      || !IsAnOper(sptr)
              || matchexec(cli_user(acptr)->realhost, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_REN))
              || matchexec(cli_info(acptr), mymask, minlen))
              && ((!(matchsel & WHO_FIELD_NIP))
	      || (HasHiddenHost(acptr) && !IsAnOper(sptr))
              || !ipmask_check(&cli_ip(acptr), &imask, ibits))
              && ((!(matchsel & WHO_FIELD_ACC))
              || matchexec(cli_user(acptr)->account, mymask, minlen))
              )
            continue;
          if (!SHOW_MORE(sptr, counter))
            break;
          do_who(sptr, acptr, chptr, fields, qrt);
        }
      }
    }
    /* Loop through all clients :-\, if we still have something to match to
       and we can show more clients */
    if ((!(counter < 1)) && matchsel)
      for (acptr = cli_prev(&me); acptr; acptr = cli_prev(acptr))
      {
        if (!(IsUser(acptr) && Process(acptr)))
          continue;
	if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
	  continue;
        if (!(SEE_USER(sptr, acptr, bitsel)))
          continue;
        if ((mask)
            && ((!(matchsel & WHO_FIELD_NIC))
            || matchexec(cli_name(acptr), mymask, minlen))
            && ((!(matchsel & WHO_FIELD_UID))
            || matchexec(cli_user(acptr)->username, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_SER))
                || (!(HasFlag(cli_user(acptr)->server, FLAG_MAP))))
            && ((!(matchsel & WHO_FIELD_HOS))
            || matchexec(cli_user(acptr)->host, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_HOS))
	    || !HasHiddenHost(acptr)
	    || !IsAnOper(sptr)
            || matchexec(cli_user(acptr)->realhost, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_REN))
            || matchexec(cli_info(acptr), mymask, minlen))
            && ((!(matchsel & WHO_FIELD_NIP))
	    || (HasHiddenHost(acptr) && !IsAnOper(sptr))
            || !ipmask_check(&cli_ip(acptr), &imask, ibits))
            && ((!(matchsel & WHO_FIELD_ACC))
            || matchexec(cli_user(acptr)->account, mymask, minlen))
            )
          continue;
        if (!SHOW_MORE(sptr, counter))
          break;
        do_who(sptr, acptr, 0, fields, qrt);
      }
  }

  /* Make a clean mask suitable to be sent in the "end of" */
  if (mask && (p = strchr(mask, ' ')))
    *p = '\0';
  send_reply(sptr, RPL_ENDOFWHO, BadPtr(mask) ? "*" : mask);

  /* Notify the user if we decided that his query was too long */
  if (counter < 0)
    send_reply(sptr, ERR_QUERYTOOLONG, "WHO");

  return 0;
}
#endif
