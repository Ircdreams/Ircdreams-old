/*
 * s_conf.h
 *
 * $Id: s_conf.h,v 1.14 2006/01/25 16:35:34 bugs Exp $ 
 */
#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h
#ifndef INCLUDED_time_h
#include <time.h>              /* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>        /* struct in_addr */
#define INCLUDED_netinet_in_h
#endif

struct Client;
struct SLink;
struct TRecord;


/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macros
 */

#define CONF_ILLEGAL            0x80000000
#define CONF_MATCH              0x40000000
#define CONF_CLIENT             0x0002
#define CONF_SERVER             0x0004
#define CONF_OPERATOR           0x0020
#define CONF_LEAF               0x1000
#define CONF_HUB                0x4000
#define CONF_UWORLD             0x8000
#define CONF_HELPER             0x10000
#define CONF_VHOST		0x20000
#define CONF_WHOIS		0x40000

#define CONF_CLIENT_MASK        (CONF_CLIENT | CONF_OPERATOR | CONF_SERVER)

#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/*
 * Structures
 */

struct ConfItem {
  struct ConfItem*         next;
  unsigned int             status;      /* If CONF_ILLEGAL, delete when no clients */
  unsigned int             clients;     /* Number of *LOCAL* clients using this */
  struct ConnectionClass*  conn_class;  /* Class of connection */
  struct in_addr           ipnum;       /* ip number of host field */
  struct in_addr           origin;      /* ip number of connect origin */
  char*                    host;
  char*                    passwd;
  char*                    name;
  time_t                   hold;        /* Hold until this time (calendar time) */
  int                      dns_pending; /* a dns request is pending */
  unsigned short           port;
  char 		           bits;        /* Number of bits for ipkills */
};

struct ServerConf {
  struct ServerConf* next;
  char*              hostname;
  char*              passwd;
  char*              alias;
  struct in_addr     address;
  int                port;
  int                dns_pending;
  int                connected;
  time_t             hold;
  struct ConnectionClass*  conn_class;
};

struct DenyConf {
  struct DenyConf*    next;
  char*               hostmask;
  char*               message;
  char*               usermask;
  unsigned int        address;
  unsigned int        flags;
  char                bits;        /* Number of bits for ipkills */
};

#define DENY_FLAGS_FILE     0x0001 /* Comment is a filename */
#define DENY_FLAGS_IP       0x0002 /* K-line by IP address */
#define DENY_FLAGS_REALNAME 0x0004 /* K-line by real name */

/*
 * A line: A:<line 1>:<line 2>:<line 3>
 */
struct LocalConf {
  char*          name;
  char*          description;
  struct in_addr vhost_address;
  unsigned int   numeric;
  char*          location1;
  char*          location2;
  char*          contact;
};

struct MotdItem {
  char line[82];
  struct MotdItem *next;
};

struct MotdConf {
  struct MotdConf* next;
  char* hostmask;
  char* path;
};

enum {
  CRULE_AUTO = 1,
  CRULE_ALL  = 2,
  CRULE_MASK = 3
};

struct CRuleNode;

struct CRuleConf {
  struct CRuleConf* next;
  char*             hostmask;
  char*             rule;
  int               type;
  struct CRuleNode* node;
};

struct TRecord {
  struct TRecord *next;
  char *hostmask;
  struct MotdItem *tmotd;
  struct tm tmotd_tm;
};

enum AuthorizationCheckResult {
  ACR_OK,
  ACR_NO_AUTHORIZATION,
  ACR_TOO_MANY_IN_CLASS,
  ACR_TOO_MANY_FROM_IP,
  ACR_ALREADY_AUTHORIZED,
  ACR_BAD_SOCKET
};

struct qline {
  struct qline *next;
  char *chname;
  char *reason;
};

struct sline {
  struct sline *next;
  char *spoofhost;
  char *realhost;
  char *username;
  struct in_addr address;
  unsigned int flags;
  char bits; /* Number of bits for CIDR match on realhost */
};

#define SLINE_FLAGS_HOSTNAME 0x0001 /* S-line by hostname */
#define SLINE_FLAGS_IP       0x0002 /* S-line by IP address/CIDR */

/** Target set for a service pseudo-command. */
struct s_map {
  struct s_map *next;         /**< Next element in #GlobalServiceMapList. */
  struct Message *msg;        /**< Message element formed for this mapping. */
  char *nick;	              /**< nickname of the mapping. */
  char *serveur;	      /**< servername of the mapping */
  char *command;              /**< Command name to use. */
  char *prepend;              /**< Extra text to prepend to user's text. */
  unsigned int flags;         /**< Bitwise map of SMAP_* flags. */
};

/*
 * str2prefix() - converts a string to in_addr and bits.
 */

#define IPV4_MAX_BITLEN 32

struct prefix
{
    struct in_addr address;
    unsigned char bits;
};

/*
 * GLOBALS
 */
extern struct ConfItem* GlobalConfList;
extern int              GlobalConfCount;
extern struct tm        motd_tm;
extern struct MotdItem* motd;
extern struct MotdItem* rmotd;
extern struct TRecord*  tdata;
extern struct qline*	GlobalQuarantineList;
extern struct sline*	GlobalSList;
extern struct s_map*    GlobalServiceMapList;

/*
 * Proto types
 */

extern int init_conf(void);

extern const struct LocalConf* conf_get_local(void);
extern const struct MotdConf*  conf_get_motd_list(void);
extern const struct CRuleConf* conf_get_crule_list(void);
extern const struct DenyConf*  conf_get_deny_list(void);

extern const char* conf_eval_crule(const char* name, int mask);
extern struct ConfItem* find_vhost(char *username, char *password);
extern struct ConfItem* find_rhost(char *username, char *password);

extern struct ConfItem* attach_confs_byhost(struct Client* cptr, const char* host, int statmask);
extern struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host, int statmask);
extern struct ConfItem* find_conf_byname(struct SLink* lp, const char *name, int statmask);
extern struct ConfItem* conf_find_server(const char* name);

extern void det_confs_butmask(struct Client *cptr, int mask);
extern enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf);
extern struct ConfItem* find_conf_exact(const char* name, const char* user,
                                        const char* host, int statmask);
extern enum AuthorizationCheckResult conf_check_client(struct Client *cptr);
extern int  conf_check_server(struct Client *cptr);
extern struct ConfItem* find_conf_name(const char* name, int statmask);
extern int rehash(struct Client *cptr, int sig);
extern void read_tlines(void);
extern int find_kill(struct Client *cptr);
extern int find_restrict(struct Client *cptr);
extern struct MotdItem* read_motd(const char* motdfile);
extern char* find_quarantine(const char* chname);
extern char *oflagstr(long);
extern void conf_add_sline(const char* const* fields, int count);
extern int conf_check_slines(struct Client *cptr);
extern void clear_slines(void);
extern int str2prefix(char *s, struct prefix *p);
extern void free_mapping(struct s_map *smap);

#endif /* INCLUDED_s_conf_h */
