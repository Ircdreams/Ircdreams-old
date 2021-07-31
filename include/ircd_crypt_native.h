/** @file
 * @brief Native crypt() function declarations.
 * @version $Id: ircd_crypt_native.h,v 1.1.1.1 2005/10/01 17:26:53 progs Exp $
 */
#ifndef INCLUDED_ircd_crypt_native_h
#define INCLUDED_ircd_crypt_native_h

extern const char* ircd_crypt_native(const char* key, const char* salt);
extern void ircd_register_crypt_native(void);

#endif /* INCLUDED_ircd_crypt_native_h */

