/*
 * IRC - Internet Relay Chat, ircd/m_svscmds.c
 * Copyright (C) 2003-2005 Progs
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
 */
/** @file
 * @brief SVS commands
 * @version $Id: m_svscmds.c,v 1.4 2005/10/23 14:04:23 progs Exp $
 */

#include "config.h"

#include "handlers.h"
#include "channel.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "whowas.h"

#include <stdlib.h>
#include <string.h>

static int do_nick_name(char* nick)
{
  char* ch  = nick;
  char* end = ch + NICKLEN;
  assert(0 != ch);

  if (*ch == '-' || IsDigit(*ch))        /* first character in [0..9-] */
    return 0;

  for ( ; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;

  *ch = '\0';

  return (ch - nick);
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
    protocol_violation(sptr,"Too few arguments to SVSNICK");
    return need_more_params(sptr, "SVSNICK");
  }

  if ((acptr = findNUser(parv[1])) && !IsUser(acptr)) acptr = NULL;

  if (!acptr) return protocol_violation(sptr,"SVSNICK: Supplied nickname is not an user.");

  if (FindUser(parv[2]) != NULL) return protocol_violation(sptr, "SVSNICK: Newnick already taken.");

  if (MyUser(acptr))
  {
    struct Membership *member;
    char nick[NICKLEN + 2];
    char* arg;
    char* s;

    arg = parv[2];
    if (strlen(arg) > NICKLEN)
      arg[NICKLEN] = '\0';

    if ((s = strchr(arg, '~')))
       *s = '\0';

    strcpy(nick, arg);

    if(!do_nick_name(nick) || isNickJuped(nick) || IsNickGlined(acptr, nick)) return protocol_violation(sptr, "SVSNICK: New nick is incorrect.");

    /* Invalidate all bans against the user so we check them again */
    for (member = (cli_user(acptr))->channel; member;
	   member = member->next_channel)
	ClearBanValid(member);
    if (0 != ircd_strcmp(parv[1], nick))
      cli_lastnick(sptr) = TStime();
    sendcmdto_common_channels_butone(acptr, CMD_NICK, NULL, ":%s", nick);
    add_history(acptr, 1);
    sendcmdto_serv_butone(acptr, CMD_NICK, acptr, "%s %Tu", nick,
                            cli_lastnick(acptr));
    if ((cli_name(acptr))[0])
      hRemClient(acptr);
    strcpy(cli_name(acptr), nick);
    hAddClient(acptr);
  } else
     sendcmdto_one(sptr, MSG_SVSNICK, TOK_SVSNICK, acptr, "%C :%s", acptr, parv[2]);
  return 0;
}

/*
 * ms_svsmode
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
    protocol_violation(sptr,"Too few arguments to SVSMODE");
    return need_more_params(sptr, "SVSMODE");
  }

  if ((acptr = findNUser(parv[1])) && !IsUser(acptr)) acptr = NULL;

  if (!acptr) return 0;

  if (FindUser(parv[2]) != NULL) return 0; // argh!

  if (MyUser(acptr))
  { // change nick
    int i;
    param[0] = cli_name(acptr);
    param[1] = cli_name(acptr);
    for(i=2;i<parc;i++) param[i] = parv[i];
    param[i] = NULL;

    set_user_mode((void *) MAGIC_SVSMODE_OVERRIDE,acptr,i, param);
  } else
     sendcmdto_one(sptr, MSG_SVSMODE, TOK_SVSMODE, acptr, "%C :%s", acptr, parv[2]);
  return 0;

}
