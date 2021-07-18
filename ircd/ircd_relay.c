/*
 * IRC - Internet Relay Chat, ircd/ircd_relay.c
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
 * $Id: ircd_relay.c,v 1.25 2005/11/28 02:47:38 bugs Exp $
 */
#include "../config.h"

#include "ircd_relay.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_defs.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> 

#define iswseperator(c) ((u_char)c == 32) /* recherche des espaces */

char *our_strcasestr(char *haystack, char *needle) {
int i;
int nlength = strlen (needle);
int hlength = strlen (haystack);

        if (nlength > hlength) return NULL;
        if (hlength <= 0) return NULL;
        if (nlength <= 0) return haystack;
        for (i = 0; i <= (hlength - nlength); i++) {
                if (strncasecmp (haystack + i, needle, nlength) == 0)
                        return haystack + i;
        }
  return NULL; /* not found */
}

/* Fonction str_replace a été repris de unreal.
 * Elle a biensur été modifié pour les besoins
 * BuGs <bugs@ircdreams.org>
 */

inline int str_replace(char *badword, char *line, char *buf, int max)
{
	char *replacew = REPLACEWORD;
	char *pold = line, *pnew = buf;
	char *poldx = line;
	int replacen = -1;
	int searchn = -1;
	char *startw, *endw;
	char *c_eol = buf + max - 1;
	int run = 1;
	int cleaned = 0;

	while(run) {
                pold = our_strcasestr(pold, badword);
                if (!pold)
                        break;
                if (replacen == -1)
                        replacen = strlen(replacew);
                if (searchn == -1)
                        searchn = strlen(badword);
                /* Hunt for start of word */
		if (pold > line) {
                        for (startw = pold; (!iswseperator(*startw) && (startw != line)); startw--);
                        if (iswseperator(*startw))
                                startw++; /* Don't point at the space/seperator but at the word! */
                }
		else startw = pold;

		for (endw = pold; ((*endw != '\0') && (!iswseperator(*endw))); endw++);

                cleaned = 1; /* still too soon? Syzop/20050227 */

                if (poldx != startw) {
                        int tmp_n = startw - poldx;
                        if (pnew + tmp_n >= c_eol) {
                                /* Partial copy and return... */
                                memcpy(pnew, poldx, c_eol - pnew);
                                *c_eol = '\0';
                                return 1;
                        }

                        memcpy(pnew, poldx, tmp_n);
                        pnew += tmp_n;
                }

                if (replacen) {
	                if ((pnew + replacen) >= c_eol) {
                                /* Partial copy and return... */
                                memcpy(pnew, replacew, c_eol - pnew);
                                *c_eol = '\0';
                                return 1;
                        }
                        memcpy(pnew, replacew, replacen);
                        pnew += replacen;
                }
                poldx = pold = endw;
        }

        if (*poldx) {
                strncpy(pnew, poldx, c_eol - pnew);
                *(c_eol) = '\0';
        } else {
                *pnew = '\0';
        }
        return cleaned;
}

/*
 * This file contains message relaying functions for client and server
 * private messages and notices
 * TODO: This file contains a lot of cut and paste code, and needs
 * to be cleaned up a bit. The idea is to factor out the common checks
 * but not introduce any IsOper/IsUser/MyUser/IsServer etc. stuff.
 */

/* nouveau code du +c , suppression du code des couleurs du texte */

#define IS_DIGIT(x) (x >= '0' && x <= '9')
#define IS_NDIGIT(x) (x < '0' || x > '9')
const char* TextStripColour(const char* text)
{
  static char stripped[BUFSIZE];
      const char *src;
      char *dest;
      
       dest = stripped;
             for (src = text; (*src); src++) {
                 switch (*src) {
                   default:
                     *dest++ = *src;
                    case COLOUR_BOLD:
                    case COLOUR_REVERSE:
                    case COLOUR_UNDERLINE:
                    case COLOUR_NORMAL:
                       break;
                    case COLOUR_COLOUR:
                       if ( IS_NDIGIT(src[1]) ) break;
                       src++;
                       if ( IS_DIGIT(src[1]) ) src++;
                       if ( src[1]==',' && IS_DIGIT(src[2]) ) src+=2;
                       else break;
                       if ( IS_DIGIT(src[1]) ) src++;
                       break;
                   }
              }
              *dest = '\0';
              return (const char*) stripped;
}
#undef IS_DIGIT
#undef IS_NDIGIT

void relay_channel_message(struct Client* sptr, const char* name, const char* text, int total)
{
  struct Channel* chptr;
  struct Membership* chan;
  const char *ch;
  char finaltext[514];
  char final[514];
  int i, ctcp = 0, n= 0;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 1)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }
  if ((chptr->mode.mode & MODE_NOPRIVMSGS) && check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  chan = find_member_link(chptr, sptr);

  if ((chptr->mode.mode & MODE_NOAMSG) && (total > 1) && !IsProtect(sptr) && !IsChannelService(sptr) &&
	!is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
    send_reply(sptr, ERR_NOMULTITARGET, chptr->chname);
    return;
  }

  /* +cC checks
   * nouveau code du +c qui permet de supprimé la couleur du texte
   * j'ai autorisé également la couleur au mode +Z, @ et %
   */

  if ((chptr->mode.mode & MODE_NOCOLOUR) && !IsProtect(sptr) && !IsChannelService(sptr) &&
	!is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr))
    text = TextStripColour(text);

  if ((chptr->mode.mode & MODE_NOCTCP) && ircd_strncmp(text,"\001ACTION ",8) && !IsProtect(sptr) && !is_chan_op(sptr,chptr))
    for (ch=text;*ch;)
      if (*ch++==1) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }

  ircd_strncpy(finaltext,text, BUFSIZE);

  if (finaltext[0]==1) ctcp=1;
  if ((chptr->mode.mode & MODE_NOCAPS) && !IsProtect(sptr) && !IsChannelService(sptr) && 
	!is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr))
  {
  	for (i=0; i<strlen(finaltext); i++)
        {
        	if (ctcp==0)
              	{
                	if(finaltext[i]=='É')
                  	finaltext[i]='é';
                	else if(finaltext[i]=='È')
                  	finaltext[i]='è';
                	else if(finaltext[i]=='Ê')
                  	finaltext[i]='ê';
                	else if(finaltext[i]=='Ë')
                  	finaltext[i]='ë';
                	else if(finaltext[i]=='Î')
                  	finaltext[i]='î';
                	else if(finaltext[i]=='Ï')
                  	finaltext[i]='ï';
                	else if(finaltext[i]=='Â')
                  	finaltext[i]='â';
                	else if(finaltext[i]=='À')
                  	finaltext[i]='à';
                	else if(finaltext[i]=='Ä')
                  	finaltext[i]='ä';
                	else if(finaltext[i]=='Ç')
                	finaltext[i]='ç';
                	else if(finaltext[i]=='Û')
                  	finaltext[i]='û';
                	else if(finaltext[i]=='Ü')
                  	finaltext[i]='ü';
                	else if(finaltext[i]=='Ù')
                  	finaltext[i]='ù';
                	else if(finaltext[i]=='Ô')
                  	finaltext[i]='ô';
                	else if(finaltext[i]=='Ö')
                  	finaltext[i]='ö';
                	else if(finaltext[i]=='´')
                  	finaltext[i]='¸';
                	else if(finaltext[i]=='¾')
                  	finaltext[i]='ÿ';
                	else if(finaltext[i]=='¦')
                  	finaltext[i]='¨';
			else
                  	finaltext[i]=tolower(finaltext[i]);
              	}
              	else
                	if (finaltext[i]==32) ctcp=0;
        }
            	finaltext[i]=0;
  }

  if ((chptr->mode.mode & MODE_NOCHANPUB) && !IsProtect(sptr) && !IsChannelService(sptr) && 
		!is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
  	n= str_replace("#", finaltext, final, BUFSIZE);
  	ircd_strncpy(finaltext, final, BUFSIZE);
  }
  
  if ((chptr->mode.mode & MODE_NOWEBPUB) && !IsProtect(sptr) && !IsChannelService(sptr) && 
		!is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
	n= str_replace("www.", finaltext, final, BUFSIZE);
	ircd_strncpy(finaltext, final, BUFSIZE);
	n= str_replace("http:", finaltext, final, BUFSIZE);
	ircd_strncpy(finaltext, final, BUFSIZE);
  }

  sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, finaltext);
}

void relay_channel_notice(struct Client* sptr, const char* name, const char* text, int total)
{
  struct Channel* chptr;
  const char *ch;
  char final[514];
  char finaltext[514];
  int i, ctcp = 0, n= 0;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 1))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if((chptr->mode.mode & MODE_NONOTICE) && !IsAnOper(sptr) && !is_chan_op(sptr,chptr))
  {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }

  if ((chptr->mode.mode & MODE_NOAMSG) && (total > 1) && !IsProtect(sptr) && !IsChannelService(sptr) &&
        !is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
    send_reply(sptr, ERR_NOMULTITARGET, chptr->chname);
    return;
  }

  /* +cC checks */
  if (chptr->mode.mode & MODE_NOCOLOUR && !IsProtect(sptr) && !IsChannelService(sptr) && !is_chan_op(sptr,chptr))
    text = TextStripColour(text);
    
  if ((chptr->mode.mode & MODE_NOCTCP) && ircd_strncmp(text,"\001ACTION ",8) && !IsProtect(sptr) && !is_chan_op(sptr,chptr))
    for (ch=text;*ch;)
      if (*ch++==1) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }

  ircd_strncpy(finaltext,text, BUFSIZE);

  if (finaltext[0]==1) ctcp=1;
  if ((chptr->mode.mode & MODE_NOCAPS) && !IsProtect(sptr) && !IsChannelService(sptr) &&
        !is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr))
  {
        for (i=0; i<strlen(finaltext); i++)
        {
                if (ctcp==0)
                {
                        if(finaltext[i]=='É')
                        finaltext[i]='é';
                        else if(finaltext[i]=='È')
                        finaltext[i]='è';
                        else if(finaltext[i]=='Ê')
                        finaltext[i]='ê';
                        else if(finaltext[i]=='Ë')
                        finaltext[i]='ë';
                        else if(finaltext[i]=='Î')
                        finaltext[i]='î';
                        else if(finaltext[i]=='Ï')
                        finaltext[i]='ï';
                        else if(finaltext[i]=='Â')
                        finaltext[i]='â';
                        else if(finaltext[i]=='À')
                        finaltext[i]='à';
                        else if(finaltext[i]=='Ä')
                        finaltext[i]='ä';
                        else if(finaltext[i]=='Ç')
                        finaltext[i]='ç';
                        else if(finaltext[i]=='Û')
                        finaltext[i]='û';
                        else if(finaltext[i]=='Ü')
                        finaltext[i]='ü';
                        else if(finaltext[i]=='Ù')
                        finaltext[i]='ù';
                        else if(finaltext[i]=='Ô')
                        finaltext[i]='ô';
                        else if(finaltext[i]=='Ö')
                        finaltext[i]='ö';
                        else if(finaltext[i]=='´')
                        finaltext[i]='¸';
                        else if(finaltext[i]=='¾')
                        finaltext[i]='ÿ';
                        else if(finaltext[i]=='¦')
                        finaltext[i]='¨';
                        else
                        finaltext[i]=tolower(finaltext[i]);
                }
                else
                        if (finaltext[i]==32) ctcp=0;
        }
                finaltext[i]=0;
  }

  if ((chptr->mode.mode & MODE_NOCHANPUB) && !IsProtect(sptr) && !IsChannelService(sptr) &&
                !is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
        n= str_replace("#", finaltext, final, BUFSIZE);
        ircd_strncpy(finaltext, final, BUFSIZE);
  }

  if ((chptr->mode.mode & MODE_NOWEBPUB) && !IsProtect(sptr) && !IsChannelService(sptr) &&
                !is_chan_op(sptr,chptr) && !is_halfop(sptr,chptr)) {
        n= str_replace("www.", finaltext, final, BUFSIZE);
        ircd_strncpy(finaltext, final, BUFSIZE);
        n= str_replace("http:", finaltext, final, BUFSIZE);
        ircd_strncpy(finaltext, final, BUFSIZE);
  }

  sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, finaltext);
}

void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    /*
     * XXX - do we need to send this back from a remote server?
     */
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
  else
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
}

void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
}


void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if ((acptr = FindServer(server + 1)) == NULL 
#if 0
/* X doesn't say it's a service yet! */
      || !IsService(acptr)
#endif
      ) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  /* As reported by Vampire-, it's possible to brute force finding users
   * by sending a message to each server and see which one succeeded.
   * This means we have to remove error reporting.  Sigh.  Better than
   * removing the ability to send directed messages to client servers 
   * Thanks for the suggestion Vampire=.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow messages to non +k clients :/  I hate
   * this. -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->crypt)) ||
      !IsChannelService(acptr)) {
    /*
     * By this stage we might as well not bother because they will
     * know that this server is currently linked because of the
     * increased lag.
     */
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr)))
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
}

void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1)))
    return;
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->crypt)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  if (!(is_silenced(sptr, acptr)))
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
}

void relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if ((!IsChannelService(acptr) &&
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr))
    return;

  if(IsHiding(acptr) && !IsAnOper(sptr))
  {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  if((IsNoPrivate(acptr) && !IsAnOper(sptr)) || (IsPAccOnly(acptr) && !IsAccount(sptr) && !IsAnOper(sptr)))
  {
     send_reply(sptr, ERR_CANTSENDPRIVATE, name);
     return;
  }

  /*
   * send away message if user away
   */
  if (cli_user(acptr) && cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}

void relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name)))
    return;
  if ((!IsChannelService(acptr) && 
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr))
    return;

  if(IsHiding(acptr) && !IsAnOper(sptr))
  {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

void server_relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr)) {
    send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHNICK, "* :Target left %s. "
	       "Failed to deliver: [%.20s]", feature_str(FEAT_NETWORK), text);
    return;
  }
  if (is_silenced(sptr, acptr))
    return;

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}


void server_relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr))
    return;

  if (is_silenced(sptr, acptr))
    return;

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

void relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}
