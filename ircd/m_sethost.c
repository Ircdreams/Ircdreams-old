/*
 * IRC - Internet Relay Chat, ircd/m_sethost.c
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
 */
/** @file
 * @brief SETHOST command
 * @version $Id: m_sethost.c,v 1.2 2005/10/23 14:04:23 progs Exp $
 */


#include "config.h"

#include "client.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_features.h"
#include "msgq.h"
#include "numeric.h"
#include "s_user.h"
#include "s_debug.h"
#include "struct.h"

#include <stdlib.h>

extern int is_hostmask(char *);

/*
 * m_sethost
 *
 * Usage :
 *  - Oper : SETHOST <vhost>
 *  - User : SETHOST <vhost> <pass>
 */
int m_sethost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
	struct Flags setflags;

	setflags = cli_flags(sptr);

	if ((!IsAnOper(sptr) && parc<3) || parc < 2)
		return need_more_params(sptr, "SETHOST");

	if (!is_hostmask(parv[1]))
	{
		send_reply(sptr, ERR_BADHOSTMASK, parv[1]);
		return 0;
	}
	if (set_vhost(sptr, parv[1], (parc < 3) ? NULL : parv[2], 1))
		FlagClr(&setflags, FLAG_SETHOST);

	send_umode_out(cptr, sptr, &setflags, 0);

	return 0;
}
