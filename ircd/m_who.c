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
 * $Id: m_who.c,v 1.14 2005/09/26 14:31:24 bugs Exp $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "../config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "send.h"
#include "s_user.h"
#include "ircd_struct.h"
#include "support.h"
#include "whocmds.h"

#include <assert.h>
#include <string.h>

#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

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
      "/WHO [+|-][acghimnsuC] [args] [x]",
      "Les flags sont spécifiés comme des chanmodes,",
      "les flags cghimnsuC demandent tous un argument.",
      "Les flags font des tests positifs via +, négatifs via -",
      "\2Vous pouvez indiquer 'x' à la fin pour afficher les realhosts\2",
      "Voici les flags disponibles:",
      "Flag a: l'user est away",
      "Flag c <channel>: l'user est sur <channel>,",
      "                  wildcard non-acceptées, test positif uniquement",
      "Flag g <realname>: l'user a <gcos> dans son realname,",
      "                   wildcards acceptées, oper uniquement",
      "Flag h <host>: l'user a <host> dans son real hostname,",
      "               wildcards acceptées",
      "Flag i <ip>: l'user se connecte depuis <ip>",
	  "             wildcards acceptées",
      "Flag m <usermodes>: l'user a les modes <usermodes> activés",
      "Flag n <nick>: l'user a <nick> dans son pseudo",
      "               wildcards acceptées",
      "Flag s <server>: l'user est sur le serveur <server>",
      "                 wildcard non-acceptées, test positif uniquement",
      "Flag u <user>: l'user a <user> dans son ident",
      "               wildcards acceptées",
      "Flag C <crypt>: l'user a <crypt> dans son crypthost",
      "                wilcards acceptées",
      NULL
  };

  static char *who_user_help[] =
  {
      "/WHO [+|-][acghimnsuC] [args]",
      "Les flags sont spécifiés comme des chanmodes,",
      "les flags cghimnsuC demandent tous un argument.",
      "Les flags font des tests positifs via +, négatifs via -",
      "Voici les flags disponibles:",
      "Flag a: l'user est away",
      "Flag c <channel>: l'user est sur <channel>,",
      "                  wildcard non-acceptées, test positif uniquement",
      "Flag h <host>: l'user a <host> dans son real hostname,",
      "               wildcards acceptées",
      "Flag m <usermodes>: l'user a les modes <usermodes> activés (réservé aux ircops)",
      "Flag n <nick>: l'user a <nick> dans son pseudo",
      "               wildcards acceptées",
      "Flag s <server>: l'user est sur le serveur <server>",
      "                 wildcard non-acceptées, test positif uniquement",
      "Flag u <user>: l'user a <user> dans son ident",
      "               wildcards acceptées",
      "Flag C <crypt>: l'user a <crypt> dans son crypthost",
      "                wilcards acceptées",
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
      if(parv[0][0]=='#')
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
      if(parc>1 && parv[1][0]=='x' && IsAnOper(sptr))
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
      case 'h':
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
      case 'C':
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
	  if(parv[args]==NULL || !IsAnOper(sptr))
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
		  if(*s==userModeList[i].c && (IsAnOper(sptr) || userModeList[i].flag &(FLAG_OPER|FLAG_ADMIN)))
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
	  Debug((DEBUG_INFO, "m_who.c; wsopts.umode=%d, umode_plus=%d, check_umode=%d", wsopts.umodes, wsopts.umode_plus, wsopts.check_umode));
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
	  if(parv[args]==NULL || !change)
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

  if(parv[args] && parv[args][0] == 'x' && IsAnOper(sptr))
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
    if(!IsUser(ac) || IsHiding(ac))
	return 0;

    if((IsInvisible(ac) || IsHideOper(ac)) && !showall)
	return 0;

#if 1 /* TODO: supporter les modes */
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
#endif
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

    /*Debug((DEBUG_INFO, "chk_who(); host_plus=%d, host=%s, crypt=%d; host=%s, crypt=%s", wsopts.host_plus,
                  wsopts.host, wsopts.crypt, cli_user(ac)->host, cli_user(ac)->crypt));                    */
    if(wsopts.host!=NULL) /* si 'x', affiche les realhosts */
	if((wsopts.host_plus && hchkfn(wsopts.host, wsopts.crypt ? cli_user(ac)->crypt : cli_user(ac)->host)) ||
	   (!wsopts.host_plus && !hchkfn(wsopts.host, wsopts.crypt ? cli_user(ac)->crypt : cli_user(ac)->host)))
	    return 0;

    if(wsopts.ip!=NULL)
	if((wsopts.ip_plus && ichkfn(wsopts.ip, ircd_ntoa((const char*) &(cli_ip(ac))))) ||
	   (!wsopts.ip_plus && !ichkfn(wsopts.ip, ircd_ntoa((const char*) &(cli_ip(ac))))))
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
		if(IsDelayedJoin(cm) && !IsAnOper(sptr))
		    continue;

		if(!chk_who(ac,showall))
		    continue;

		/* get rid of the pidly stuff first */
		/* wow, they passed it all, give them the reply...
		 * IF they haven't reached the max, or they're an oper */
		status[i++]=(cli_user(ac)->away==NULL ? 'H' : 'G');
		status[i]=((IsAnOper(ac) && (!IsHideOper(ac) || IsAnOper(sptr) || ac == sptr)) ? '*'
			: (((IsInvisible(ac) || IsHiding(ac) || IsHideOper(ac)) &&
			 IsOper(sptr)) ? '$' : 0)); /* $ pour les non visibles car le % est deja pris */
		status[((status[i]) ? ++i : i)]=((cm->status&CHFL_CHANOP) ? '@'
						 : ((cm->status&CHFL_HALFOP) ? '%'
						 : ((cm->status&CHFL_VOICE) ? '+' : 0)));
		status[++i]=0;
		send_reply(sptr, RPL_WHOREPLY,
			   wsopts.channel->chname, cli_user(ac)->username,
			   wsopts.extra ? cli_user(ac)->host : cli_user(ac)->crypt,
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
		status[1]=((IsAnOper(ac) && (!IsHideOper(ac) || IsAnOper(sptr) || ac == sptr)) ? '*'
			: ((IsInvisible(ac) || IsHiding(ac) || IsHideOper(ac)) &&
			IsAnOper(sptr) ? '$' : 0));
		status[2]=0;
		send_reply(sptr, RPL_WHOREPLY, "*", cli_user(ac)->username,
			   wsopts.extra ? cli_user(ac)->host : cli_user(ac)->crypt,
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
	    status[1]=((IsAnOper(ac) && (!IsHideOper(ac) || IsAnOper(sptr) || ac == sptr)) ? '*'
		: ((IsInvisible(ac) || IsHiding(ac) || IsHideOper(ac)) &&
		IsAnOper(sptr) ? '$' : 0));
	    status[2]=0;
	    send_reply(sptr, RPL_WHOREPLY, "*", cli_user(ac)->username,
		       wsopts.extra ? cli_user(ac)->host : cli_user(ac)->crypt,
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
