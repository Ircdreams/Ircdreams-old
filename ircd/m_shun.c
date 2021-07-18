/*
 * IRC - Internet Relay Chat, ircd/m_shun.c
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
 * $Id: m_shun.c,v 2.2 2005/11/06 03:24:19 bugs Exp $
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
#include "config.h"

#include "client.h"
#include "shun.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#include <stdlib.h>
#include <string.h>

/*
 * ms_shun - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<Shun mask>
 * parv[3] = Shun lifetime
 *
 * From Uworld:
 *
 * parv[4] = Comment
 *
 * From somewhere else:
 *
 * parv[4] = Last modification time
 * parv[5] = Comment
 *
 */
int
ms_shun(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Shun *ashun;
  unsigned int flags = 0;
  time_t expire_off, lastmod = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason";

  if (*mask == '!') {
    mask++;

    flags |= SHUN_OPERFORCE; /* assume oper had WIDE_SHUN */
  }

  if ((parc == 3 && *mask == '-') || parc == 5) {
    if (!find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD))
      return need_more_params(sptr, "SHUN");

    if (parc > 4)
      reason = parv[4];
    flags |= SHUN_FORCE;
  } else if (parc > 5) {
    lastmod = atoi(parv[4]);
    reason = parv[5];
  } else if(*mask != '-' && parc < 4)
    return need_more_params(sptr, "SHUN");

  if (IsServer(sptr))
    flags |= SHUN_FORCE;

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!( (acptr = FindNServer(target)) ||
           (acptr = SeekServer(target)) ) )
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate */
      if (!lastmod)
	sendcmdto_one(sptr, CMD_SHUN, acptr,
		      (parc == 3) ? "%s %s" : "%s %s %s :%s", target, mask,
		      parv[3], reason);
      else
	sendcmdto_one(sptr, CMD_SHUN, acptr, "%s %s%s %s %s :%s", target,
		      flags & SHUN_OPERFORCE ? "!" : "", mask, parv[3],
		      parv[4], reason);
      return 0;
    }
	flags |= SHUN_LOCAL;
  }

  if (*mask == '-')
    mask++;
  else if (*mask == '+') {
    flags |= SHUN_ACTIVE;
    mask++;
  } else
    flags |= SHUN_ACTIVE;

  expire_off = parc < 5 ? 0 : atoi(parv[3]);

  ashun = shun_find(mask, SHUN_ANY | SHUN_EXACT);

  if (ashun) {
  	if (!(flags & SHUN_ACTIVE)) /* shun -host */
	{
		if(!(flags & SHUN_LOCAL)) /* remove global */
			return shun_deactivate(cptr, sptr, ashun, lastmod, flags);
		else if(ShunIsLocal(ashun)) /* Remove local */
			return shun_deactivate(cptr, sptr, ashun, lastmod, flags);
		else
			return 0; /* Remove local, global en place */
	}

    if (ShunIsLocal(ashun) && !(flags & SHUN_LOCAL)) /* global over local */
      shun_free(ashun);
    else if (!lastmod && ((flags & SHUN_ACTIVE) == ShunIsRemActive(ashun)))
      return shun_propagate(cptr, sptr, ashun);
    else if (!lastmod || ShunLastMod(ashun) < lastmod) { /* new mod */
      if (flags & SHUN_ACTIVE)
	return shun_activate(cptr, sptr, ashun, lastmod, flags);
      else
	return shun_deactivate(cptr, sptr, ashun, lastmod, flags);
    } else if (ShunLastMod(ashun) == lastmod || IsBurstOrBurstAck(cptr))
      return 0;
    else
      return shun_resend(cptr, ashun); /* other server desynched WRT shun */
  } else if (!(flags & SHUN_ACTIVE)) {
    if (!(flags & SHUN_LOCAL)) /* Pas de shun trouvée, propagation qd meme */
      sendcmdto_serv_butone(sptr, CMD_SHUN, cptr, "* -%s", mask);
    return 0;
  } else if (parc < 5)
    return need_more_params(sptr, "SHUN");

  return shun_add(cptr, sptr, mask, reason, expire_off, lastmod, flags);
}

/*
 * mo_shun - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<Shun mask>]
 *
 * Local (to me) style:
 *
 * parv[2] = [Expiration offset]
 * parv[3] = [Comment]
 *
 * Global (or remote local) style:
 *
 * parv[2] = [target]
 * parv[3] = [Expiration offset]
 * parv[4] = [Comment]
 *
 */
int
mo_shun(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Shun *ashun;
  unsigned int flags = 0;
  time_t expire_off = 0;
  char *mask = parv[1], *target = 0, *reason = "Aucune Raison", all[2] = {0};

  strcpy(all, "*");

  if (parc < 2)
    return shun_list(sptr, 0);

  if (*mask == '!') {
    mask++;

    if (HasPriv(sptr, PRIV_WIDE_SHUN))
      flags |= SHUN_OPERFORCE;
  }

  if (*mask == '+') {
    flags |= SHUN_ACTIVE;
    mask++;

  } else if (*mask == '-')
    mask++;
  else
    return shun_list(sptr, mask);

	if (!(flags & SHUN_ACTIVE)) {
		if(parc >= 3) target = parv[2];
		else target = all;
	} else if (parc == 4) {
		expire_off = atoi(parv[2]);
		reason = parv[3];
		flags |= SHUN_LOCAL;
	} else if (parc > 4) {
		target = parv[2];
		expire_off = atoi(parv[3]);
		reason = parv[4];
	} else
		return need_more_params(sptr, "SHUN");

	if (target) {
		if (!(target[0] == '*' && target[1] == '\0')) {
			if (!(acptr = find_match_server(target)))
				return send_reply(sptr, ERR_NOSUCHSERVER, target);

			if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
				if (!feature_bool(FEAT_CONFIG_OPERCMDS))
					return send_reply(sptr, ERR_DISABLED, "SHUN");

				if (!HasPriv(sptr, PRIV_SHUN))
					return send_reply(sptr, ERR_NOPRIVILEGES);

				if(flags & SHUN_ACTIVE)
					sendcmdto_one(sptr, CMD_SHUN, acptr, "%C %s+%s %s %Tu :%s", acptr,
							flags & SHUN_OPERFORCE ? "!" : "",
							mask, parv[3],
							TStime(), reason);
				else
					sendcmdto_one(sptr, CMD_SHUN, acptr, "%C %s-%s %s", acptr,
							flags & SHUN_OPERFORCE ? "!" : "",
							mask, target);
				return 0;
			}

			flags |= SHUN_LOCAL;
		}
	}

	if (!(flags & SHUN_LOCAL) && !feature_bool(FEAT_CONFIG_OPERCMDS))
		return send_reply(sptr, ERR_DISABLED, "SHUN");

	if (!CanGline(sptr) || !HasPriv(sptr, (flags & SHUN_LOCAL ? PRIV_LOCAL_SHUN : PRIV_SHUN)))
		return send_reply(sptr, ERR_NOPRIVILEGES);

	ashun = shun_find(mask, SHUN_ANY | SHUN_EXACT);
	if (ashun) {
		if (ShunIsLocal(ashun)) /* Locale en place */
		{
			/* On vire la locale dans le cas d'une délétion locale ou globale */
			if(!(flags & SHUN_ACTIVE)) return shun_deactivate(cptr, sptr, ashun, 0, flags);
			if(flags & SHUN_LOCAL) return 0; /* local over local = return */
			shun_free(ashun); /* global over local */
		} else { /* on a une globale en place */
			if(!(flags & SHUN_ACTIVE)) /* deletion globale */
				return shun_deactivate(cptr, sptr, ashun,
						0, (flags &= ~SHUN_LOCAL)/* Meme si /shun -host target, deletion globale */);
			if(flags & SHUN_LOCAL) return 0; /* local over global = return */
		}
	}
	if(!(flags & SHUN_ACTIVE)) return 0; /* /shun -host avec shun inconnue */
	return shun_add(cptr, sptr, mask, reason, expire_off, TStime(), flags);
}

/*
 * m_shun - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_shun(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHSHUN, "");

  if (feature_bool(FEAT_HIS_USERSHUN))
    return send_reply(sptr, ERR_DISABLED, "SHUN");

  return shun_list(sptr, parv[1]);
}

