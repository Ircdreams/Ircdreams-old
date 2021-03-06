#ifndef INCLUDED_features_h
#define INCLUDED_features_h
/*
 * IRC - Internet Relay Chat, include/features.h
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * $Id: ircd_features.h,v 1.43 2005/12/08 17:10:48 bugs Exp $
 */

struct Client;
struct StatDesc;

enum Feature {
  /* Misc. features */
  FEAT_LOG,
  FEAT_DOMAINNAME,
  FEAT_RELIABLE_CLOCK,
  FEAT_BUFFERPOOL,
  FEAT_HAS_FERGUSON_FLUSHER,
  FEAT_CLIENT_FLOOD,
  FEAT_SERVER_PORT,
  FEAT_NODEFAULTMOTD,
  FEAT_MOTD_BANNER,
  FEAT_PROVIDER,
  FEAT_KILL_IPMISMATCH,
  FEAT_IDLE_FROM_MSG,
  FEAT_HUB,
  FEAT_WALLOPS_OPER_ONLY,
  FEAT_NODNS,
  FEAT_RANDOM_SEED,
  FEAT_DEFAULT_LIST_PARAM,
  FEAT_NICKNAMEHISTORYLENGTH,
  FEAT_HOST_HIDING,
  FEAT_HIDDEN_HOST,
  FEAT_HIDDEN_IP,
  FEAT_CONNEXIT_NOTICES,
  FEAT_TOPIC_BURST,

  /* features that probably should not be touched */
  FEAT_KILLCHASETIMELIMIT,
  FEAT_MAXCHANNELSPERUSER,
  FEAT_NICKLEN,
  FEAT_AVBANLEN,
  FEAT_MAXBANS,
  FEAT_MAXSILES,
  FEAT_HANGONGOODLINK,
  FEAT_HANGONRETRYDELAY,
  FEAT_CONNECTTIMEOUT,
  FEAT_TIMESEC,
  FEAT_MAXIMUM_LINKS,
  FEAT_PINGFREQUENCY,
  FEAT_CONNECTFREQUENCY,
  FEAT_DEFAULTMAXSENDQLENGTH,
  FEAT_GLINEMAXUSERCOUNT,

  /* Some misc. default paths */
  FEAT_MPATH,
  FEAT_PPATH,

  /* Networking features */
  FEAT_VIRTUAL_HOST,
  FEAT_TOS_SERVER,
  FEAT_TOS_CLIENT,
  FEAT_POLLS_PER_LOOP,

  /* features that affect all operators */
  FEAT_CRYPT_OPER_PASSWORD,
  FEAT_OPER_NO_CHAN_LIMIT,
  FEAT_SHOW_INVISIBLE_USERS,
  FEAT_SHOW_ALL_INVISIBLE_USERS,
  FEAT_UNLIMIT_OPER_QUERY,
  FEAT_LOCAL_KILL_ONLY,
  FEAT_CONFIG_OPERCMDS,

  /* features that affect global opers on this server */
  FEAT_OPER_KILL,
  FEAT_OPER_REHASH,
  FEAT_OPER_RESTART,
  FEAT_OPER_DIE,
  FEAT_OPER_GLINE,
  FEAT_OPER_LGLINE,
  FEAT_OPER_JUPE,
  FEAT_OPER_LJUPE,
  FEAT_OPER_OPMODE,
  FEAT_OPER_FORCE_OPMODE,
  FEAT_OPER_BADCHAN,
  FEAT_OPER_LBADCHAN,
  FEAT_OPER_SET,
  FEAT_OPERS_SEE_IN_SECRET_CHANNELS,
  FEAT_OPER_WIDE_GLINE,

  /* HEAD_IN_SAND Features */
  FEAT_HIS_SNOTICES,
  FEAT_HIS_SNOTICES_OPER_ONLY,
  FEAT_HIS_DESYNCS,
  FEAT_HIS_DEBUG_OPER_ONLY,
  FEAT_HIS_WALLOPS,
  FEAT_HIS_MAP,
  FEAT_HIS_LINKS,
  FEAT_HIS_TRACE,
  FEAT_HIS_STATS_l,
  FEAT_HIS_STATS_c,
  FEAT_HIS_STATS_g,
  FEAT_HIS_STATS_h,
  FEAT_HIS_STATS_k,
  FEAT_HIS_STATS_f,
  FEAT_HIS_STATS_i,
  FEAT_HIS_STATS_j,
  FEAT_HIS_STATS_M,
  FEAT_HIS_STATS_m,
  FEAT_HIS_STATS_o,
  FEAT_HIS_STATS_p,
  FEAT_HIS_STATS_q,
  FEAT_HIS_STATS_r,
  FEAT_HIS_STATS_s,
  FEAT_HIS_STATS_d,
  FEAT_HIS_STATS_e,
  FEAT_HIS_STATS_t,
  FEAT_HIS_STATS_T,
  FEAT_HIS_STATS_u,
  FEAT_HIS_STATS_U,
  FEAT_HIS_STATS_v,
  FEAT_HIS_STATS_w,
  FEAT_HIS_STATS_W,
  FEAT_HIS_STATS_x,
  FEAT_HIS_STATS_y,
  FEAT_HIS_STATS_z,
  FEAT_HIS_WHOIS_SERVERNAME,
  FEAT_HIS_WHOIS_IDLETIME,
  FEAT_HIS_WHO_SERVERNAME,
  FEAT_HIS_WHO_HOPCOUNT,
  FEAT_HIS_BANWHO,
  FEAT_HIS_KILLWHO,
  FEAT_HIS_REWRITE,
  FEAT_HIS_REMOTE,
  FEAT_HIS_NETSPLIT,
  FEAT_HIS_SERVERNAME,
  FEAT_HIS_SERVERINFO,
  FEAT_HIS_URLSERVERS,

  /* Misc. random stuff */
  FEAT_NETWORK,
  FEAT_URL_CLIENTS,

  /* CoderZ Features */
  FEAT_KLINE_MAIL,
  FEAT_HIS_SERVERMODE,
  FEAT_OPCLEARMODE,
  FEAT_SETHOST_AUTO,
  
  /* IrcDreams Features */
  
  FEAT_AUTOJOIN_OPER,
  FEAT_AUTOJOIN_OPER_NOTICE,
  FEAT_AUTOJOIN_OPER_NOTICE_VALUE,
  FEAT_AUTOJOIN_OPER_CHANNEL,
  FEAT_OMPATH,
  FEAT_AUTOJOIN_USER,
  FEAT_AUTOJOIN_USER_NOTICE,
  FEAT_AUTOJOIN_USER_NOTICE_VALUE,
  FEAT_AUTOJOIN_USER_CHANNEL,
  FEAT_EPATH,
  FEAT_RULES,
  FEAT_PROTECTHOST,
  FEAT_HIS_STATS_b,
  FEAT_AUTOINVISIBLE,
  FEAT_TOO_MANY_FROM_IP,
  FEAT_LOG_GESTION_MAIL,
  FEAT_PROG_MAIL,
  FEAT_GESTION_MAIL,
  FEAT_ALERTE_OPER,
  FEAT_ALERTE_SETHOST,
  FEAT_ALERTE_GLINE,
  FEAT_ALERTE_NETSPLIT,
  FEAT_TPATH,
  FEAT_SHUNMAXUSERCOUNT, 
  FEAT_OPER_SHUN, 
  FEAT_OPER_LSHUN, 
  FEAT_OPER_WIDE_SHUN, 
  FEAT_LOCOP_LSHUN, 
  FEAT_LOCOP_WIDE_SHUN, 
  FEAT_HIS_SHUN, 
  FEAT_HIS_USERSHUN, 
  FEAT_HIS_STATS_S,
  FEAT_OPERMOTD,
  FEAT_WALL_CONNEXIT_NOTICES,

  FEAT_LAST_F
};
 

extern void feature_init(void);

extern int feature_set(struct Client* from, const char* const* fields,
		       int count);
extern int feature_reset(struct Client* from, const char* const* fields,
			 int count);
extern int feature_get(struct Client* from, const char* const* fields,
		       int count);

extern void feature_unmark(void);
extern void feature_mark(void);

extern void feature_report(struct Client* to, struct StatDesc* sd, int stat,
			   char* param);

extern int feature_int(enum Feature feat);
extern int feature_bool(enum Feature feat);
extern const char *feature_str(enum Feature feat);

#endif /* INCLUDED_features_h */
