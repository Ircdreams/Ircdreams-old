/*
 * IRC - Internet Relay Chat, ircd/m_oper.c
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
 * $Id: m_oper.c,v 1.19 2006/02/23 05:55:13 bugs Exp $
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

#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_xopen.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"
#include "channel.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int oper_password_match(const char* to_match, const char* passwd)
{
  /*
   * use first two chars of the password they send in as salt
   *
   * passwd may be NULL. Head it off at the pass...
   */
  if (!to_match || !passwd)
    return 0;

  if (feature_bool(FEAT_CRYPT_OPER_PASSWORD))
    to_match = ircd_crypt(to_match, passwd);

  return (0 == strcmp(to_match, passwd));
}

/*
 * m_oper - generic message handler
 */
int m_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem* aconf;
  struct Membership *chan;
  char*            name;
  char*            password;
  char*		   join[2];
  char             salon[CHANNELLEN-1];
  char		   buf[512];

  assert(0 != cptr);
  assert(cptr == sptr);

  name     = parc > 1 ? parv[1] : 0;
  password = parc > 2 ? parv[2] : 0;

  if (EmptyString(name) || EmptyString(password))
    return need_more_params(sptr, "OPER");

  aconf = find_conf_exact(name, cli_username(sptr), cli_sockhost(sptr), CONF_OPERATOR);
  if (!aconf)
    aconf = find_conf_exact(name, cli_username(sptr),
                            ircd_ntoa((const char*) &(cli_ip(cptr))), CONF_OPERATOR);

  if (!aconf || IsIllegal(aconf)) {
    send_reply(sptr, ERR_NOOPERHOST);
    sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s), oline %s",
			 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost, name);
    if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_OPER))
    {
    	ircd_snprintf(0, buf, sizeof buf, "Failed OPER attempt by %s (%s@%s), oline %s (invalid host)",
                 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost, name);
    	admin_sendmail(buf);
    }
    return 0;
  }
  assert(0 != (aconf->status & CONF_OPERATOR));

  if (oper_password_match(password, aconf->passwd)) {
    struct Flags old_mode = cli_flags(sptr);

    if (ACR_OK != attach_conf(sptr, aconf)) {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s "
			   "(%s@%s), oline %s", parv[0], cli_user(sptr)->username,
			   cli_user(sptr)->realhost, name);
      if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_OPER))
      {
      	ircd_snprintf(0, buf, sizeof buf, "Failed OPER attempt by %s (%s@%s), oline %s (invalid host)",
		 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost, name);
      	admin_sendmail(buf);
      }
      return 0;
    }
    /*
     * prevent someone from being both oper and local oper
     */
    if (!(aconf->port & OFLAG_ADMIN))
    {        /* Global Oper  */
	SetOper(sptr);
	ClearAdmin(sptr);
	if(aconf->port & OFLAG_GLOBAL) OSetGlobal(sptr);
	if(aconf->port & OFLAG_REHASH) OSetRehash(sptr);
	if(aconf->port & OFLAG_DIE) OSetDie(sptr);
	if(aconf->port & OFLAG_GLINE) OSetGline(sptr);
    }
    else
    {     /* Admin */
	SetOper(sptr);
	SetAdmin(sptr);
	OSetRehash(sptr);
	OSetDie(sptr);
	OSetGlobal(sptr);
	OSetGline(sptr);
    }

   if(aconf->port & OFLAG_INVISIBLE) OSetInv(sptr);
   if(aconf->port & OFLAG_SETVARS) OSetSetVars(sptr);
   if(aconf->port & OFLAG_SA) OSetSA(sptr);

   ++UserStats.opers;
   
   cli_handler(cptr) = OPER_HANDLER;

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);

    if(!IsAnAdmin(sptr)) cli_oflags(sptr) = aconf->port;

    set_snomask(sptr, IsAnAdmin(sptr) ? SNO_ALL : SNO_OPERDEFAULT, SNO_ADD); /* les admins ont un mask +s total -Progs */
    client_set_privs(sptr);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    send_umode_out(cptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
    send_reply(sptr, RPL_YOUREOPER);

    if(IsAnAdmin(sptr))
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Administrator (A%s%s) on oline %s",
			 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost,
			 CanSetVars(sptr) ? "V" : "", CanSA(sptr) ? "S" : "", name);
    else 
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Operator (%s) on oline %s",
			 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost,
			 oflagstr(cli_oflags(sptr)), name);
    
    if (feature_bool(FEAT_OPERMOTD))
      m_opermotd(sptr, sptr, 1, parv);

    if (feature_bool(FEAT_AUTOJOIN_OPER)) {
      if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE)) {
            sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));
      }
      ircd_strncpy(salon, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
      join[0] = cli_name(sptr);
      join[1] = salon;
      m_join(sptr, sptr, 2, join);
    }
    for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel)
    {
    	if(MyUser(sptr))
	    do_names(sptr,chan->channel, NAMES_ALL|NAMES_EON);
    }

    log_write(LS_OPER, L_INFO, 0, "OPER (%s) by (%#R)", name, sptr);
  }
  else {
    send_reply(sptr, ERR_PASSWDMISMATCH);
    sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) on oline %s",
			 parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost, name);
    if(feature_bool(FEAT_LOG_GESTION_MAIL) && feature_bool(FEAT_ALERTE_OPER))
    {
	ircd_snprintf(0, buf, sizeof buf, "Failed OPER attempt by %s (%s@%s) on oline %s (invalid password)",
 	       parv[0], cli_user(sptr)->username, cli_user(sptr)->realhost, name);
    	admin_sendmail(buf);
    }
  }
  return 0;
}

/*
 * ms_oper - server message handler
 */
int ms_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(IsServer(cptr));
  /*
   * if message arrived from server, trust it, and set to oper
   */
  if (!IsServer(sptr) && !IsOper(sptr)) {
    ++UserStats.opers;
    SetFlag(sptr, FLAG_OPER);
    sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s :+o", parv[0]);
  }
  return 0;
}

/*
 * mo_oper - oper message handler
 */
int mo_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  send_reply(sptr, RPL_YOUREOPER);
  return 0;
}
