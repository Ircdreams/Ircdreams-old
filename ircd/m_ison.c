/*
 * IRC - Internet Relay Chat, ircd/m_ison.c
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
 * $Id: m_ison.c,v 1.3 2005/09/18 15:55:12 bugs Exp $
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
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msgq.h"
#include "numeric.h"
#include "send.h"

#include <assert.h>
#include <string.h>

/*
 * m_ison
 *
 * Added by Darren Reed 13/8/91 to act as an efficent user indicator
 * with respect to cpu/bandwidth used. Implemented for NOTIFY feature in
 * clients. Designed to reduce number of whois requests. Can process
 * nicknames in batches as long as the maximum buffer length.
 *
 * format:
 * ISON :nicklist
 *
 * XXX - this is virtually the same as send_user_info, but doesn't send
 * no nick found, might be refactored so that m_userhost, m_userip, and
 * m_ison all use the same function with different formatters. --Bleep
 */
int m_ison(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client* acptr;
  char*          name;
  char*          p = 0;
  struct MsgBuf* mb;
  int i;

  if (parc < 2)
    return need_more_params(sptr, "ISON");

  mb = msgq_make(sptr, rpl_str(RPL_ISON), cli_name(&me), cli_name(sptr));

  for (i = 1; i < parc; i++) {
    for (name = ircd_strtok(&p, parv[i], " "); name;
	 name = ircd_strtok(&p, 0, " ")) {
      if ((acptr = FindUser(name)) && (!IsHiding(acptr) || IsAnOper(sptr))) {
		if (msgq_bufleft(mb) < strlen(cli_name(acptr)) + 1) {
		  send_buffer(sptr, mb, 0); /* send partial response */
	  	msgq_clean(mb); /* then do another round */
	  	mb = msgq_make(sptr, rpl_str(RPL_ISON), cli_name(&me),  cli_name(sptr));
	}
	msgq_append(0, mb, "%s ", cli_name(acptr));
      }
    }
  }

  send_buffer(sptr, mb, 0); /* send response */
  msgq_clean(mb);

  return 0;
}
