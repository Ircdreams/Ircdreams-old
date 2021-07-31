/** @file crule.h
 * @brief Interfaces and declarations for connection rule checking.
 * @version $Id: crule.h,v 1.1.1.1 2005/10/01 17:26:50 progs Exp $
 */
#ifndef INCLUDED_crule_h
#define INCLUDED_crule_h

/*
 * Proto types
 */

/*
 * opaque node pointer
 */
struct CRuleNode;

extern void crule_free(struct CRuleNode** elem);
extern int crule_eval(struct CRuleNode* rule);
extern struct CRuleNode* crule_parse(const char* rule);

#endif /* INCLUDED_crule_h */
