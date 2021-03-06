/*
 * IRC - Internet Relay Chat, ircd/m_sahost.c
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
 * $Id: m_svscmds.c,v 1.3 2006/03/18 15:32:13 bugs Exp $
 */

#include "channel.h"
#include "../config.h"
#include "client.h"
#include "gline.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_alloc.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_debug.h"
#include "s_misc.h"
#include "userload.h"
#include "patchlevel.h"
#include "sys.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

/* 
 * SVSHOST
 */ 

int ms_svshost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  
  char *s;
  int legalhost=1;

  if(parc<3)
    return(need_more_params(sptr, "SVSHOST"));

  if(!(acptr = findNUser(parv[1])))
    return send_reply(sptr, ERR_SVSCOM, "SVSHOST", "Ce Pseudo n'existe pas");

  /*
   * Check that the given real name is not greater
   * than HOSTLEN.
   */
  if (strlen(parv[2]) > HOSTLEN)
    return send_reply(sptr, ERR_SVSCOM, "SVSHOST", "Host trop long");

  for (s = parv[2]; *s; s++)
  {
    if (!IsHostChar(*s))
    {
      legalhost = 0;
      break;
    }
  }

  if (legalhost == 0)   
    return send_reply(sptr, ERR_SVSCOM, "SVSHOST", "caract?res invalides dans le hostname");
 
  ircd_strncpy(cli_user(acptr)->crypt, parv[2], HOSTLEN);
  SetSetHost(acptr);

  sendcmdto_serv_butone(sptr, CMD_SVSHOST, cptr, "%s%s %s", acptr->cli_user->server->cli_yxx,
	acptr->cli_yxx, parv[2]);
  if (MyUser(acptr)) send_reply(acptr, RPL_SVSHOST, parv[2]);

  return 0;
}


/*
 * ms_svsjoin
 * parv[1] = num
 * parv[2] = salon
 */
int ms_svsjoin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  unsigned int flags = 0;
  char *name;

  if (parc < 3) {
	protocol_violation(sptr,"Trop peu d'argument pour SVSJOIN");
    	return need_more_params(sptr, "SVSJOIN");
  }

  if(!(acptr = findNUser(parv[1]))) {
	protocol_violation(sptr,"SVSJOIN le numeric n'existe pas");
    return 0;
  }

  if(IsChannelService(acptr)) return send_reply(sptr, ERR_SVSCOM, "SVSJOIN", "Ce pseudo est un Service");

  joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());

  if ((chptr = FindChannel(parv[2]))) {
        flags = CHFL_DEOPPED;
        if (find_member_link(chptr, acptr)) return 0; /* already on channel */
  } else
        flags = CHFL_CHANOP;

  name = parv[2];
  clean_channelname(name);

  if (join0(&join, acptr, acptr, name)) /* did client do a JOIN 0? */
  {
	sendcmdto_serv_butone(sptr, CMD_SVSJOIN, cptr, "%s%s 0", acptr->cli_user->server->cli_yxx, acptr->cli_yxx);
	return 0;
  }

  if ((!IsChannelName(name)) || (HasCntrl(name))) {
      return send_reply(sptr, ERR_NOSUCHCHANNEL, name);
  }

 if (chptr) {
    joinbuf_join(&join, chptr, flags);
 } else {
	if (!MyUser(acptr)) {
	sendcmdto_serv_butone(sptr, CMD_SVSJOIN, cptr, "%s%s %s", acptr->cli_user->server->cli_yxx, acptr->cli_yxx, parv[2]);
	return 0;
	}
      
      chptr = get_channel(acptr, name, CGT_CREATE);      
      joinbuf_join(&create, chptr, flags);
 }
  if (chptr->topic[0]) {
    send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
    send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
      chptr->topic_time);
  }

  do_names(acptr, chptr, NAMES_ALL|NAMES_EON); /* send /names list */

  joinbuf_flush(&join); /* must be first, if there's a JOIN 0 */
  joinbuf_flush(&create);
  
  sendcmdto_serv_butone(sptr, CMD_SVSJOIN, cptr, "%s%s %s", acptr->cli_user->server->cli_yxx, acptr->cli_yxx, parv[2]);
  return 0;
}


/*
 * ms_svsmode
 * pour les services / serveurs
 *
 * parv[1] = num
 * parv[2] = modes
 */
int ms_svsmode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char* param[4];

  if (parc < 3)
  {
    protocol_violation(sptr,"Trop peu d'argument pour SVSMODE");
    return need_more_params(sptr, "SVSMODE");
  }

  if ((acptr = findNUser(parv[1])) && !IsUser(acptr)) acptr = NULL;

  if (!acptr) return 0;

  if (FindUser(parv[2]) != NULL) return 0; // argh!

  if (MyUser(acptr))
  { // change nick
    param[0] = cli_name(acptr);
    param[1] = cli_name(acptr);
    param[2] = parv[2];
    param[3] = NULL;

    set_user_mode((void *) MAGIC_SVSMODE_OVERRIDE,acptr,3, param);
  } else
     sendcmdto_one(sptr, MSG_SVSMODE, TOK_SVSMODE, acptr, "%C :%s", acptr, parv[2]);
  return 0;

}

/*
 * ms_svsnick
 *
 * parv[1] = num
 * parv[2] = nouveau nick
 */
int ms_svsnick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;

  if (parc < 3)
  {
    protocol_violation(sptr,"Trop peu d'argument pour SVSNICK");
    return need_more_params(sptr, "SVSNICK");
  }

  if ((acptr = findNUser(parv[1])) && !IsUser(acptr)) acptr = NULL;

  if (!acptr) return protocol_violation(sptr,"SVSNICK: Le pseudo donn? n'est pas un user.");

  if (FindUser(parv[2]) != NULL) return protocol_violation(sptr, "SVSNICK: Nouveau nick d?j? existant.");

  if (MyUser(acptr))
  {
    struct Membership *member;
    char nick[NICKLEN + 2];
    char* arg;
    char* s;

    arg = parv[2];
    if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
      arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

    if ((s = strchr(arg, '~')))
       *s = '\0';

    strcpy(nick, arg);

    if(!do_nick_name(nick) || isNickJuped(nick) ||
	IsNickGlined(acptr, nick) || IsChannelService(acptr))
		return protocol_violation(sptr, "SVSNICK: Nouveau nick incorrect.");

    /* Invalidate all bans against the user so we check them again */
    for (member = (cli_user(acptr))->channel; member;
           member = member->next_channel)
        ClearBanValid(member);
    if (0 != ircd_strcmp(parv[1], nick))
      cli_lastnick(sptr) = TStime();
    sendcmdto_common_channels_butone(acptr, CMD_NICK, NULL, ":%s", nick);
    add_history(acptr, 1);
    sendcmdto_serv_butone(acptr, CMD_NICK, acptr, "%s %Tu", nick, cli_lastnick(acptr));
    if ((cli_name(acptr))[0])
      hRemClient(acptr);
    strcpy(cli_name(acptr), nick);
    hAddClient(acptr);
  } else
     sendcmdto_one(sptr, MSG_SVSNICK, TOK_SVSNICK, acptr, "%C :%s", acptr, parv[2]);
  return 0;
}

/* pour les serveurs / services
 * svspart num salon
 */
int ms_svspart(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  unsigned int flags = 0;

  if (parc < 3) return need_more_params(sptr, "SVSPART");

  if(!(acptr = findNUser(parv[1]))) return send_reply(sptr, ERR_SVSCOM, "SVSPART", "Ce pseudo n'existe pas");

  if(IsChannelService(acptr)) return send_reply(sptr, ERR_SVSCOM, "SVSPART", "Ce pseudo est un Service");

  ClrFlag(acptr, FLAG_TS8);

  if (!(chptr = get_channel(acptr, parv[2], CGT_NO_CREATE)))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[2]);

  if (!(member = find_member_link(chptr, acptr)))
    return send_reply(sptr, ERR_USERNOTINCHANNEL, cli_name(acptr), parv[2]);

  /* init join/part buffer */
  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, 0, 0);

  assert(!IsZombie(member)); /* Local users should never zombie */

  if (!member_can_send_to_channel(member,0))
      flags |= CHFL_BANNED;

  if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

  joinbuf_join(&parts, chptr, flags);

  sendcmdto_serv_butone(sptr, CMD_SVSPART, cptr, "%s%s %s", acptr->cli_user->server->cli_yxx,
	acptr->cli_yxx, parv[2]);

  return joinbuf_flush(&parts);
}
