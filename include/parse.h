/** @file parse.h
 * @brief Declarations for parsing input from users and other servers.
 * @version $Id: parse.h,v 1.1.1.1 2005/10/01 17:26:59 progs Exp $
 */
#ifndef INCLUDED_parse_h
#define INCLUDED_parse_h

struct Client;
struct s_map;

/*
 * Prototypes
 */

extern int parse_client(struct Client *cptr, char *buffer, char *bufend);
extern int parse_server(struct Client *cptr, char *buffer, char *bufend);
extern void initmsgtree(void);

extern int register_mapping(struct s_map *map);
extern int unregister_mapping(struct s_map *map);

#endif /* INCLUDED_parse_h */
