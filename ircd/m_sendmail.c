/*
 * IRC - Internet Relay Chat, ircd/m_sendmail.c
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
 * $Id: m_sendmail.c,v 2.4 2005/11/28 00:55:30 bugs Exp $
 */

#include "ircd.h"
#include "ircd_features.h"
#include "s_misc.h"
#include <stdio.h>

int admin_sendmail(const char *parv)
{
	FILE *fm;
	if(!(fm = popen(feature_str(FEAT_PROG_MAIL), "w"))) return 0;
	fprintf(fm, "From: \"Serveur\" <Serveur@%s>\nTo: \"Administrateur\" <%s>\n",
		cli_name(&me),feature_str(FEAT_GESTION_MAIL));
	fprintf(fm, "Subject: [INFORMATION] Serveur %s\n\n", feature_str(FEAT_NETWORK));
	fprintf(fm, "%s", parv);
	pclose(fm);
	return 0;
}
