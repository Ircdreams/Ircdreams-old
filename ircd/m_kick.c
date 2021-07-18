/*
 * IRC - Internet Relay Chat, ircd/m_kick.c
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
 * $Id: m_kick.c,v 1.28 2006/04/05 11:35:16 bugs Exp $
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
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <assert.h>

/*
 * m_kick - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int m_kick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *who;
  struct Channel *chptr;
  struct Membership *member = 0;
  char *name, *comment;

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, "KICK");

  name = parv[1];

  /* simple checks */
  if (!(chptr = get_channel(sptr, name, CGT_NO_CREATE)))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, name);

  if (!(is_chan_op(sptr, chptr) || is_halfop(sptr, chptr) || IsAnOper(sptr) || IsChannelService(sptr)))
    return send_reply(sptr, ERR_CHANOPRIVSNEEDED, name);

  if (!(who = find_chasing(sptr, parv[2], 0)))
    return 0; /* find_chasing sends the reply for us */

  /* Don't allow the channel service to be kicked */
  if (IsChannelService(who))
    return send_reply(sptr, ERR_ISCHANSERVICE, cli_name(who), chptr->chname);

  if (IsHiding(who))
    return send_reply(sptr, ERR_USERNOTINCHANNEL, cli_name(who), chptr->chname);    

  /* On ne kick pas les godmode, Le Monsieur il a dit non ! */
  if(IsProtect(who))
    return send_reply(sptr, ERR_ISGODMODE, cli_name(who), chptr->chname);

  if(IsHelper(who) && !IsAnOper(sptr) && who != sptr)
    return send_reply(sptr, ERR_ISHELPER, cli_name(who), chptr->chname);
 
  if (!IsAnOper(sptr) && is_halfop(sptr, chptr) && ( (is_chan_op(who, chptr) || is_halfop(who, chptr)) && (who != sptr) && !is_chan_op(sptr,chptr)))
        return send_reply(sptr, ERR_NOKICKAUTORIZED, "Un halfop n'a pas le pouvoir de kicker un opérateur ou un autre halfop");
  
  /* check if kicked user is actually on the channel */
  if (!(member = find_member_link(chptr, who)) || IsZombie(member))
    return send_reply(sptr, ERR_USERNOTINCHANNEL, cli_name(who), chptr->chname);

  /* We rely on ircd_snprintf to truncate the comment */
  comment = EmptyString(parv[parc - 1]) ? parv[0] : parv[parc - 1];

  sendcmdto_serv_butone(sptr, CMD_KICK, cptr, "%H %C :%s", chptr, who,
			  comment);

  if (IsDelayedJoin(member)) {
    /* If it's a delayed join, only send the KICK to the person doing
     * the kicking and the victim */
    if (MyUser(who)) {
      sendcmdto_one(sptr, CMD_KICK, who, "%H %C :%s", chptr, who, comment);
    }
    sendcmdto_one(sptr, CMD_KICK, sptr, "%H %C :%s", chptr, who, comment);
    CheckDelayedJoins(chptr);
  } else {
    sendcmdto_channel_butserv_butone(sptr, CMD_KICK, chptr, NULL, 0, "%H %C :%s", chptr, who,
                                     comment);
  }

  make_zombie(member, who, cptr, sptr, chptr);


  return 0;
}

/*
 * ms_kick - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int ms_kick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *who;
  struct Channel *chptr;
  struct Membership *member = 0, *sptr_link = 0;
  char *name, *comment;

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, "KICK");

  name = parv[1];
  comment = parv[parc - 1];

  /* figure out who gets kicked from what */
  if (!(chptr = get_channel(sptr, name, CGT_NO_CREATE)) ||
      !(who = findNUser(parv[2])))
    return 0;

  /* We go ahead and pass on the KICK for users not on the channel */
  if (!(member = find_member_link(chptr, who)) || IsZombie(member))
    member = 0;

  /* Send HACK notice, but not for servers in BURST */
  /* 2002-10-17: Don't send HACK if the users local server is kicking them */
  if (IsServer(sptr) 
      && !IsBurstOrBurstAck(sptr)
      && sptr!=cli_from(who))
    sendto_opmask_butone(0, SNO_HACK4, "HACK: %C KICK %H %C %s", sptr, chptr,
			 who, comment);

  /* Unless someone accepted it downstream (or the user isn't on the channel
   * here), if kicker is not on channel, or if kicker is not a channel
   * operator, bounce the kick
   */
  if (!IsServer(sptr) && member && cli_from(who) != cptr &&
      (!(sptr_link = find_member_link(chptr, sptr)) || !(IsChanOp(sptr_link) || IsHalfop(sptr_link) ||
        IsAnOper(sptr) || IsChannelService(sptr)))) {
    sendto_opmask_butone(0, SNO_HACK2, "HACK: %C KICK %H %C %s", sptr, chptr,
			 who, comment);

    sendcmdto_one(who, CMD_JOIN, cptr, "%H", chptr);

    /* Reop/revoice member */
    if (IsChanOp(member) || HasVoice(member) || IsHalfop(member)) {
      struct ModeBuf mbuf;

      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_SERVER |  /* Send mode to a server */
		    MODEBUF_DEST_DEOP   |  /* Deop the source */
		    MODEBUF_DEST_BOUNCE)); /* And bounce the MODE */

      if (IsChanOp(member))
	modebuf_mode_client(&mbuf, MODE_DEL | MODE_CHANOP, who);
      if (IsHalfop(member))
      	modebuf_mode_client(&mbuf, MODE_DEL | MODE_HALFOP, who);	
      if (HasVoice(member))
	modebuf_mode_client(&mbuf, MODE_DEL | MODE_VOICE, who);

      modebuf_flush(&mbuf);
    }
  } else {
    /* Propagate kick... */
    sendcmdto_serv_butone(sptr, CMD_KICK, cptr, "%H %C :%s", chptr, who,
			  comment);

    if (member) { /* and tell the channel about it, unless
                   * it's a delayed join, in which case we just
                   * tell the target */
      if (IsDelayedJoin(member)) {
        if (MyUser(who))
          sendcmdto_one(sptr, CMD_KICK, who, "%H %C :%s", chptr, who, comment);
        CheckDelayedJoins(chptr);
      } else {
      sendcmdto_channel_butserv_butone(IsServer(sptr) && feature_bool(FEAT_HIS_SERVERMODE) ? &me : sptr,
                                       CMD_KICK, chptr, NULL, 0, "%H %C :%s", chptr, who,
                                       comment);
      }

      make_zombie(member, who, cptr, sptr, chptr);
    }
  }

  return 0;
}
