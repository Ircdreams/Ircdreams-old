/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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
 */
#include "../config.h"

#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "s_user.h"
#include "send.h"
#include "shun.h"
#include "ircd_struct.h"
#include "support.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h> 

#define CRYPTAGE_MD2
#define CRYPTAGE_MD5  
#include "ircd_md2.h"
#include "ircd_md5.h"

int is_hostmask(char *word);

static int userCount = 0;

/* PirO hp
* basé sur une alghorthime en SHA
* (1028 bits * 128 bits) source code issu
* du daemon : "shacrypt"
* (dispo sur sourceforge.net)
* principe :
* HostNonCrypté -> hachage -> conversion en pile mémoire
* -> cryptage -> conversion inverse -> HostCrypté
* la clé de hashage est éffectuée en fontion de l'host de maniére
* a obtenir toujour la meme clé pour la meme host , donc le meme cryptage.
*/

#define SIZEOF_INT 4

/* The number of bytes in a long.  */
#define SIZEOF_LONG 8

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* The number of bytes in a size_t.  */
#define SIZEOF_SIZE_T 4

#if SIZEOF_INT == 4
  typedef unsigned int uint32t;
#else
# if SIZEOF_LONG == 4
   typedef unsigned long uint32t;
# else
#  if SIZEOF_SHORT == 4
    typedef unsigned short uint32t;
#  else
#   error "unable to find 32-bit data type"
#  endif /* SHORT != 4 */
# endif /* LONG != 4 */
#endif /* INT != 4 */


#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    10

#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )           /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                       /* Rounds 20-39 */
#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                       /* Rounds 60-79 */

#define K1  0x5A827999L                                 /* Rounds  0-19 */
#define K2  0x6ED9EBA1L                                 /* Rounds 20-39 */
#define K3  0x8F1BBCDCL                                 /* Rounds 40-59 */
#define K4  0xCA62C1D6L                                 /* Rounds 60-79 */

#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

#define ROTL(n,X)  ( ( (X) << (n) ) | ( (X) >> ( 32 - (n) ) ) )

#define expand(W,i) ( W[ i & 15 ] = \
                      ROTL( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
                                 W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += ROTL( 5, a ) + f( b, c, d ) + k + data, b = ROTL( 30, b ) )

struct sha_ctx {
  uint32t digest[SHA_DIGESTLEN];  /* Message digest */
  uint32t count_l, count_h;       /* 64-bit block count */
  int index;                             /* index into buffer */
  char block[SHA_DATASIZE];     /* SHA data buffer */
};

static void sha_transform(struct sha_ctx *ctx, uint32t *data)
{
  uint32t A, B, C, D, E;     /* Local vars */

  /* Set up first buffer and local data buffer */
  A = ctx->digest[0];
  B = ctx->digest[1];
  C = ctx->digest[2];
  D = ctx->digest[3];
  E = ctx->digest[4];

  /* Heavy mangling, in 4 sub-rounds of 20 interations each. */
  subRound( A, B, C, D, E, f1, K1, data[ 0] );
  subRound( E, A, B, C, D, f1, K1, data[ 1] );
  subRound( D, E, A, B, C, f1, K1, data[ 2] );
  subRound( C, D, E, A, B, f1, K1, data[ 3] );
  subRound( B, C, D, E, A, f1, K1, data[ 4] );
  subRound( A, B, C, D, E, f1, K1, data[ 5] );
  subRound( E, A, B, C, D, f1, K1, data[ 6] );
  subRound( D, E, A, B, C, f1, K1, data[ 7] );
  subRound( C, D, E, A, B, f1, K1, data[ 8] );
  subRound( B, C, D, E, A, f1, K1, data[ 9] );
  subRound( A, B, C, D, E, f1, K1, data[10] );
  subRound( E, A, B, C, D, f1, K1, data[11] );
  subRound( D, E, A, B, C, f1, K1, data[12] );
  subRound( C, D, E, A, B, f1, K1, data[13] );
  subRound( B, C, D, E, A, f1, K1, data[14] );
  subRound( A, B, C, D, E, f1, K1, data[15] );
  subRound( E, A, B, C, D, f1, K1, expand( data, 16 ) );
  subRound( D, E, A, B, C, f1, K1, expand( data, 17 ) );
  subRound( C, D, E, A, B, f1, K1, expand( data, 18 ) );
  subRound( B, C, D, E, A, f1, K1, expand( data, 19 ) );

  subRound( A, B, C, D, E, f2, K2, expand( data, 20 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 21 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 22 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 23 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 24 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 25 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 26 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 27 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 28 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 29 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 30 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 31 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 32 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 33 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 34 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 35 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 36 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 37 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 38 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 39 ) );

  subRound( A, B, C, D, E, f3, K3, expand( data, 40 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 41 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 42 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 43 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 44 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 45 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 46 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 47 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 48 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 49 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 50 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 51 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 52 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 53 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 54 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 55 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 56 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 57 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 58 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 59 ) );

  subRound( A, B, C, D, E, f4, K4, expand( data, 60 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 61 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 62 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 63 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 64 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 65 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 66 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 67 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 68 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 69 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 70 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 71 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 72 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 73 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 74 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 75 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 76 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 77 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 78 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 79 ) );

  /* Build message digest */
  ctx->digest[0] += A;
  ctx->digest[1] += B;
  ctx->digest[2] += C;
  ctx->digest[3] += D;
  ctx->digest[4] += E;
}

#define EXTRACT_UCHAR(p)  (*(unsigned char *)(p))
#define STRING2INT(s) ((((((EXTRACT_UCHAR(s) << 8)    \
                         | EXTRACT_UCHAR(s+1)) << 8)  \
                         | EXTRACT_UCHAR(s+2)) << 8)  \
                         | EXTRACT_UCHAR(s+3))

static void sha_block(struct sha_ctx *ctx, char *block)
{
  uint32t data[SHA_DATALEN];
  int i;

  /* Update block count */
  if (!++ctx->count_l)
    ++ctx->count_h;

  /* Endian independent conversion */
  for (i = 0; i<SHA_DATALEN; i++, block += 4)
    data[i] = STRING2INT(block);

  sha_transform(ctx, data);
}

static void make_sha(char *buffer, uint32t len, uint32t *s)
{
  struct sha_ctx ctxbuf = {
    {h0init, h1init, h2init, h3init, h4init},
    0, 0, 0,
  };
  int i, words;
  uint32t data[SHA_DATALEN];

  while (len >= SHA_DATASIZE)
    {
      sha_block(&ctxbuf, buffer);
      buffer += SHA_DATASIZE;
      len -= SHA_DATASIZE;
    }
  if ((ctxbuf.index = len))     /* This assignment is intended */
    /* Buffer leftovers */
    memmove(ctxbuf.block, buffer, len);

  /*** sha_final ***/

  i = ctxbuf.index;
  /* Set the first char of padding to 0x80.  This is safe since there is
     always at least one byte free */
  ctxbuf.block[i++] = 0x80;

  /* Fill rest of word */
 for( ; i & 3; i++)
    ctxbuf.block[i] = 0;

  /* i is now a multiple of the word size 4 */
  words = i >> 2;
  for (i = 0; i < words; i++)
    data[i] = STRING2INT(ctxbuf.block + 4*i);

  if (words > (SHA_DATALEN-2))
    { /* No room for length in this block. Process it and
       * pad with another one */
      for (i = words ; i < SHA_DATALEN; i++)
        data[i] = 0;
      sha_transform(&ctxbuf, data);
      for (i = 0; i < (SHA_DATALEN-2); i++)
        data[i] = 0;
    }
  else
    for (i = words ; i < SHA_DATALEN - 2; i++)
      data[i] = 0;
  /* Theres 512 = 2^9 bits in one block */
  data[SHA_DATALEN-2] = (ctxbuf.count_h << 9) | (ctxbuf.count_l >> 23);
  data[SHA_DATALEN-1] = (ctxbuf.count_l << 9) | (ctxbuf.index << 3);
  sha_transform(&ctxbuf, data);

  /*
   * we don't want to use the digest as 20x8-bit character array, but
   * as 5x32-bit integer array, so we use this to make it endian-safe
   * for *our* purposes
   */
  memcpy(s, ctxbuf.digest, SHA_DIGESTSIZE);
}

#define KEYSIZE 128
unsigned char hostprotkey[KEYSIZE];
/* generates random data and fills the key buffer */
void make_hostprotkey()
{
  int fd;
  int i;
  fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0)
  {  /* we have a good /dev/urandom, read from it */
    if (read(fd, hostprotkey, KEYSIZE) == KEYSIZE)
    {
      close(fd);
      return;
    }
    /* there was an error reading, fall back to random() */
    close(fd);
  }
  /* i hope the following satisfies different implementations of random() */
  for (i = 0; i < KEYSIZE; i++)
    hostprotkey[i] = (unsigned char) ((random() & 0xff0000) >> 16);
}

static void make_digest_len(const char *src, uint32t *digest, int len)
{
  char buf[KEYSIZE + HOSTLEN];
  int i, k;

  i = KEYSIZE / 2;
  k = KEYSIZE - i;
  memcpy(buf, hostprotkey, i);
  memcpy(buf + i, src, len);
  memcpy(buf + i + len, hostprotkey + i, k);

  make_sha(buf, i + len + k, digest);
}

static void make_digest(const char *src, uint32t *digest)
{
  make_digest_len(src, digest, strlen(src));
}

static uint32t make_sum_from_digest(uint32t *digest)
{
  uint32t sum;

  sum = digest[0] ^ digest[1] ^ digest[2] ^ digest[3] ^ digest[4];
  /* instead of a simple (sum %= 0x7ffff), we use.. */
  sum = (sum & 0xFFFFFFFF) ^ ((sum & 0x4FFFFFFF) >> 13);
 /* sum = (sum & 0xFFFFFFFFFFF) ^ ((sum & 0x4FFFFFFF) >> 13); */
  /* this will give a number in the range 0 - 524287 */
  return sum;
}

char *makeHash(const char *mask)
{
static char final[HOSTLEN+1];

  uint32t digest[SHA_DIGESTLEN];
  uint32t sum;

  make_digest(mask, digest);
  sum = make_sum_from_digest(digest);

  sprintf(final, "%lu", (unsigned long) sum);
  return final;
}

int check_if_ip(const char *mask)
{
  int has_digit = 0;
  int digitcount = 0;
  const char *p;

  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '.' && *p != '/')
    {
      if (!isdigit(*p) || digitcount > 3)
        return 0;
          digitcount++;
      has_digit = -1;
    }
        else {
         digitcount = 0;
        }
  return has_digit;
}

char *hostprotcrypt(const char *mask)
{
  char host[HOSTLEN+1], * p, *crypted, domaine[HOSTLEN+1];
  static char final[HOSTLEN+1];
  int i, j, nbp=0;

  strcpy(host, mask);
        /* stage 1 : mask IP -> int */
  if(check_if_ip(host)) {
                char *prec = host;
                int num = 0;
                while((p = strchr(prec,'.')) != NULL) {
                        *p = '\0';
                        num <<= 8;
                        num |= (atoi(prec) & 0xFF);
                        prec = p + 1;
                }
                num <<= 8;
                num |= (atoi(prec) & 0xFF);


                /* stage 2 : IP int -> string */
                {
                        char toCrypt[9];
                        int i;
                        for(i = 0; i < 8; i++) {
                                toCrypt[i] = (num & 0xF) + 32;
                                num >>= 4;
                        }
                        toCrypt[8] = '\0';


                /* stage 3 string -> crypt */
                        {
                        char *crypted = makeHash(toCrypt);

                /* stage 4 crypt -> look like an adresse*/
                        {
				strcpy(final, crypted);
		                strcat(final,".ip");
                        }
                }
        }
  } else {
	crypted = (char *)makeHash(host);
        strcpy(final, crypted);
        strcat(final, ".");
 
	if (feature_int(FEAT_PROTECTHOST) == 3) {
		/* merci Progs pour ton aide ! */
                i=strlen(host)-1;
		for(;i>=0 && (host[i] != '.' || ++nbp<2); --i);
                j=strlen(host)-i-1;
                i=strlen(host)-1;
                domaine[j--]='\0';

                for(; j>=0; i--, j--) domaine[j] = host[i];

                strcat(final,domaine);
        } else {
	        p=strrchr(host,'.');
		if (p) {
	      		*p = '\0';
                	strcat(final,p + 1);
		}
		else strcat(final, "Crypted");
        }
  }
  return final;
}

/* fin du cryptage SHA */

/* cryptage MD2 MD5 */

static int is_ip(const char *ip)
{
	char *ptr = NULL;
	int i = 0, d = 0;

	for(;i < 4;++i) /* 4 dots expected (IPv4) */
	{	/* Note about strtol: stores in endptr either NULL or '\0' if conversion is complete */
		if(!isdigit((unsigned char) *ip) /* most current case (not ip, letter host) */
			|| (d = strtol(ip, &ptr, 10)) < 0 || d > 255 /* ok, valid number? */
			|| (ptr && *ptr != 0 && *ptr != '.' && ptr != ip)) return 0;
		if(ptr) ip = ptr + 1, ptr = NULL; /* jump the dot */
	}
	return 1;
}

#define CRYPTUNKNOWN "inconnu.ircdreams.org"

int protecthost(char *host, char *crypt)
{
  if (feature_int(FEAT_PROTECTHOST) == 1) {
  	u_int32_t sum, digest[4];
	int ip = is_ip(host);
  	char key1[HOSTLEN + 1], *key2 = strchr(host, '.'), *key = ip ? key2 : key1;

  	if (!host || !*host)
		strcpy(crypt, CRYPTUNKNOWN);
  	else if (!key2)
    		strcpy(crypt, host);
  	else
  	{
     		ircd_strncpy(key1, host, key2 - host);
     		key1[key2-host] = 0;

     		if(!host[0] % 2)
     		{
       			MD2BIS_CTX context;
       			MD2Init(&context);
       			MD2Update(&context, (unsigned char *) key, strlen(key));
       			MD2Update(&context, (unsigned char *) host, strlen(host));
       			MD2Final((void *) digest, &context);
     		}
     		else
     		{
       			MD5BIS_CTX context;
       			MD5Init(&context);
       			MD5Update(&context, (unsigned char *) key, strlen(key));
       			MD5Update(&context, (unsigned char *) host, strlen(host));
       			MD5Final((void *) digest, &context);
     		}

     		sum = digest[0] + digest[1] + digest[2] + digest[3];

     		if (!ip) ircd_snprintf(0, crypt, HOSTLEN, "%X%s", sum, key2);
     		else ircd_snprintf(0, crypt, HOSTLEN, "%s.%X", key1, sum);

   	}

  }
  if (feature_int(FEAT_PROTECTHOST) == 2 || feature_int(FEAT_PROTECTHOST) == 3) {
	strcpy(crypt,hostprotcrypt(host));	
  }
  return 0;
}




/*
 * 'make_user' add's an User information block to a client
 * if it was not previously allocated.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cli_user(cptr)) {
    cli_user(cptr) = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cli_user(cptr));

    /* All variables are 0 by default */
    memset(cli_user(cptr), 0, sizeof(struct User));
#ifdef  DEBUGMODE
    ++userCount;
#endif
    cli_user(cptr)->refcnt = 1;
  }
  return cli_user(cptr);
}

/*
 * free_user
 *
 * Decrease user reference count by one and release block, if count reaches 0.
 */
void free_user(struct User* user)
{
  assert(0 != user);
  assert(0 < user->refcnt);

  if (--user->refcnt == 0) {
    if (user->away)
      MyFree(user->away);
    if (user->swhois)
      MyFree(user->swhois);
    /*
     * sanity check
     */
    assert(0 == user->joined);
    assert(0 == user->invited);
    assert(0 == user->channel);

    MyFree(user);
#ifdef  DEBUGMODE
    --userCount;
#endif
  }
}

void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}


/*
 * next_client
 *
 * Local function to find the next matching client. The search
 * can be continued from the specified client entry. Normal
 * usage loop is:
 *
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (cli_prev(tmp) == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = cli_next(next))
    if (!match(ch, cli_name(next)))
      break;
  return next;
}

/*
 * hunt_server
 *
 *    Do the basic thing in delivering the message (command)
 *    across the relays to the specific server (server) for
 *    actions.
 *
 *    Note:   The command is a format string and *MUST* be
 *            of prefixed style (e.g. ":%s COMMAND %s ...").
 *            Command can have only max 8 parameters.
 *
 *    server  parv[server] is the parameter identifying the
 *            target server. It can be a nickname, servername,
 *            or server mask (from a local user) or a server
 *            numeric (from a remote server).
 *
 *    *WARNING*
 *            parv[server] is replaced with the pointer to the
 *            real servername from the matched client (I'm lazy
 *            now --msa).
 *
 *    returns: (see #defines)
 */
int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
                    struct Client *one, int MustBeOper, const char *pattern,
                    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from))
  {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
   } else if(!(acptr = FindNServer(to))) {
	send_reply(from, SND_EXPLICIT | ERR_NOSUCHSERVER, "* :Le serveur est déconnecté");
     return HUNTED_NOSUCH;        /* Server broke off in the meantime */
  }

  if (IsMe(acptr))
    return HUNTED_ISME;

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  assert(!IsServer(from));

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
                parv[4], parv[5], parv[6], parv[7], parv[8]);

  return HUNTED_PASS;
}

int hunt_server_prio_cmd(struct Client *from, const char *cmd, const char *tok,
			 struct Client *one, int MustBeOper,
			 const char *pattern, int server, int parc,
			 char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return HUNTED_ISME;

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return HUNTED_NOSUCH;
    }
  } else if (!(acptr = FindNServer(to)))
    return HUNTED_NOSUCH;        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return HUNTED_ISME;

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); SETTIME to particular destinations permitted */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_prio_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		     parv[4], parv[5], parv[6], parv[7], parv[8]);

  return HUNTED_PASS;
}


/*
 * clean_user_id
 *
 * Copy `source' to `dest', replacing all occurances of '~' and characters that
 * are not `isIrcUi' by an underscore.
 * Copies at most USERLEN - 1 characters or up till the first control character.
 * If `tilde' is true, then a tilde is prepended to `dest'.
 * Note that `dest' and `source' can point to the same area or to different
 * non-overlapping areas.
 */
static char *clean_user_id(char *dest, char *source, int tilde)
{
  char ch;
  char *d = dest;
  char *s = source;
  int rlen = USERLEN;

  ch = *s++;                        /* Store first character to copy: */
  if (tilde)
  {
    *d++ = '~';                        /* If `dest' == `source', then this overwrites `ch' */
    --rlen;
  }
  while (ch && !IsCntrl(ch) && rlen--)
  {
    char nch = *s++;        /* Store next character to copy */
    *d++ = IsUserChar(ch) ? ch : '_';        /* This possibly overwrites it */
    if (nch == '~')
      ch = '_';
    else
      ch = nch;
  }
  *d = 0;
  return dest;
}

/*
 * register_user
 *
 * This function is called when both NICK and USER messages
 * have been accepted for the client, in whatever order. Only
 * after this the USER message is propagated.
 *
 * NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have
 * to implement the following:
 *
 * 1) user telnets in and gives only "NICK foobar" and waits
 * 2) another user far away logs in normally with the nick
 *    "foobar" (quite legal, as this server didn't propagate it).
 * 3) now this server gets nick "foobar" from outside, but
 *    has already the same defined locally. Current server
 *    would just issue "KILL foobar" to clean out dups. But,
 *    this is not fair. It should actually request another
 *    nick from local user or kill him/her...
 */
int register_user(struct Client *cptr, struct Client *sptr,
                  const char *nick, char *username)
{
  struct ConfItem* aconf;
  struct Shun*     ashun = NULL;
  char*            parv[3];
  char* 	   join[2];
  char  	   salon[CHANNELLEN-1];
  char*            tmpstr;
  char*            tmpstr2;
  int              killreason;

  char 		   tosend[39 + HOSTLEN + 1];
  struct User*     user = cli_user(sptr);
  char             ip_base64[8];

  user->last = CurrentTime;
  parv[0] = cli_name(sptr);
  parv[1] = parv[2] = NULL;

  if (MyConnect(sptr))
  {
    static time_t last_too_many1;
    static time_t last_too_many2;
    
    /* users count pour le lusers */
    ++UserStats.conncount;

    assert(cptr == sptr);
    switch (conf_check_client(sptr))
    {
      case ACR_OK:
        break;
      case ACR_NO_AUTHORIZATION:
        sendto_opmask_butone(0, SNO_UNAUTH, "Connexion non-autorisée depuis %s.",
                             get_client_name(sptr, HIDE_IP));
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
                           "Pas d'autorisation - utilisez un autre serveur");
      case ACR_TOO_MANY_IN_CLASS:
        if (CurrentTime - last_too_many1 >= (time_t) 60)
        {
          last_too_many1 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Trop de connexions dans la classe "
                               "%i pour %s.", get_client_class(sptr),
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me,
                           "Désolé, votre classe de connexion est pleine - réessayez "
                           "plus tard ou essayez un autre serveur");
      case ACR_TOO_MANY_FROM_IP:
        if (CurrentTime - last_too_many2 >= (time_t) 60)
        {
          last_too_many2 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Trop de connexions depuis "
                               "la même IP pour %s.",
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
	if(feature_bool(FEAT_TOO_MANY_FROM_IP)) {
	  return exit_client(cptr, sptr, &me,
                           "Trop de connexions depuis votre host");
	} else break;

      case ACR_ALREADY_AUTHORIZED:
        /* Can this ever happen? */
      case ACR_BAD_SOCKET:
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me, "Erreur inconnue -- Réessayez");
    }
    ircd_strncpy(user->host, cli_sockhost(sptr), HOSTLEN);
    if(!IsChannelService(sptr) && !IsService(cptr) && (feature_int(FEAT_PROTECTHOST) !=0)) protecthost(cli_sockhost(sptr), user->crypt);
    else ircd_strncpy(user->crypt, cli_sockhost(sptr), HOSTLEN);
    ircd_strncpy(user->realhost, cli_sockhost(sptr), HOSTLEN);
    aconf = cli_confs(sptr)->value.aconf;

    
    clean_user_id(user->username,
        HasFlag(sptr, FLAG_GOTID) ? cli_username(sptr) : username,
        HasFlag(sptr, FLAG_DOID) && !HasFlag(sptr, FLAG_GOTID)
	&& !IsSetHost(sptr));


    if ((user->username[0] == '\0')
        || ((user->username[0] == '~') && (user->username[1] == '\000')))
      return exit_client(cptr, sptr, &me, "USER: ident erroné.");

    if (!EmptyString(aconf->passwd)
        && !(IsDigit(*aconf->passwd) && !aconf->passwd[1])
        && strcmp(cli_passwd(sptr), aconf->passwd))
    {
      ServerStats->is_ref++;
      send_reply(sptr, ERR_PASSWDMISMATCH);
      return exit_client(cptr, sptr, &me, "Mauvais mot de passe");
    }
    memset(cli_passwd(sptr), 0, sizeof(cli_passwd(sptr)));
    /*
     * following block for the benefit of time-dependent K:-lines
     */
    if ((killreason = find_kill(sptr))) {
      ServerStats->is_ref++;
      return exit_client(cptr, sptr, &me, (killreason == -1) ? "K-lined" : "G-Lined");
    }
    /*
     * Check for mixed case usernames, meaning probably hacked.  Jon2 3-94
     * Summary of rules now implemented in this patch:         Ensor 11-94
     * In a mixed-case name, if first char is upper, one more upper may
     * appear anywhere.  (A mixed-case name *must* have an upper first
     * char, and may have one other upper.)
     * A third upper may appear if all 3 appear at the beginning of the
     * name, separated only by "others" (-/_/.).
     * A single group of digits is allowed anywhere.
     * Two groups of digits are allowed if at least one of the groups is
     * at the beginning or the end.
     * Only one '-', '_', or '.' is allowed (or two, if not consecutive).
     * But not as the first or last char.
     * No other special characters are allowed.
     * Name must contain at least one letter.
     */
    tmpstr2 = tmpstr = (username[0] == '~' ? &username[1] : username);

    Count_unknownbecomesclient(sptr, UserStats);
  }
  else {
    ircd_strncpy(user->username, username, USERLEN);
    Count_newremoteclient(UserStats, user->server);
  }
  if(MyConnect(sptr) && feature_bool(FEAT_SETHOST_AUTO)) {
    if (conf_check_slines(sptr)) {
      ircd_snprintf(0, tosend, sizeof(tosend), "NOTICE AUTH :*** Utilisation du host virtuel %s\r\n", cli_user(sptr)->crypt);
      send(cli_fd(sptr), tosend, strlen(tosend), 0);
      SetSetHost(sptr);
    }
  }
  if (MyConnect(sptr) && feature_bool(FEAT_AUTOINVISIBLE))
    SetInvisible(sptr);

#ifdef USE_SSL
  if (MyConnect(sptr) && cli_socket(sptr).ssl)
    SetSSL(sptr);
#endif /* USE_SSL */

  SetUser(sptr);

  /* increment global count if needed */
  if (UserStats.globalclients < UserStats.clients && IsUser(sptr)) {
    if (UserStats.globalclients >= 0) {
      ++UserStats.globalclients;
      save_tunefile();
    }
  }

  /* increment local count if needed */
  if (UserStats.localclients < UserStats.local_clients && IsUser(sptr)) {
    if (UserStats.localclients >= 0) {
      ++UserStats.localclients;
      save_tunefile();
    }
  }

  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr))
    ++UserStats.opers;
  if (IsAccount(sptr))
    ++UserStats.authed;
  if (MyConnect(sptr)) {
    cli_handler(sptr) = CLIENT_HANDLER;
    release_dns_reply(sptr);
    if ((ashun = shun_lookup(sptr, 0))) { 
      sendto_opmask_butone(0, SNO_GLINE, "Shun actif à la connexion pour %s%s", 
                           IsUnknown(sptr) ? "un client non enregistré ":"", 
                           get_client_name(sptr, SHOW_IP)); 
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Vous êtes ignoré completement du serveur, vous êtes maintenant spectateur", sptr);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Raison : %s", sptr, ashun->sh_reason); 
    } 


    SetLocalNumNick(sptr);

    send_reply(
	sptr, 
	RPL_WELCOME,
	feature_str(FEAT_NETWORK),
	feature_str(FEAT_PROVIDER) ? " via " : "",
	feature_str(FEAT_PROVIDER) ? feature_str(FEAT_PROVIDER) : "",
	nick);
    /*
     * This is a duplicate of the NOTICE but see below...
     */
    send_reply(sptr, RPL_YOURHOST, cli_name(&me), version);
    send_reply(sptr, RPL_CREATED, creation);
    send_reply(sptr, RPL_MYINFO, cli_name(&me), version);
    send_supported(sptr);

#ifdef USE_SSL
    if (IsSSL(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Vous êtes connecté sur %s avec %s", sptr,
                    cli_name(&me), ssl_get_cipher(cli_socket(sptr).ssl));
#endif

    m_lusers(sptr, sptr, 1, parv);
    update_load();
    motd_signon(sptr);

/*      nextping = CurrentTime; */
    if (cli_snomask(sptr) & SNO_NOISY)
      set_snomask(sptr, cli_snomask(sptr) & SNO_NOISY, SNO_ADD);
    if (feature_bool(FEAT_CONNEXIT_NOTICES)) {
	if(feature_bool(FEAT_WALL_CONNEXIT_NOTICES)) {
		sendto_allops(&me, SNO_OLDSNO,
			   "Connexion: %s (Ident@Host: %s@%s) [Ip: %s] [Classe: %d] [SSL: %s] [Port: %d]",
			   cli_name(sptr), user->username, user->realhost,
			   cli_sock_ip(sptr), get_client_class(sptr), IsSSL(sptr) ? "Oui" : "Non",
			   cli_listener(sptr)->port);
	} else {
		sendto_opmask_butone(0, SNO_CONNEXIT,
			   "Connexion: %s (Ident@Host: %s@%s) [Ip: %s] [Classe: %d] [SSL: %s] [Port: %d]",
                           cli_name(sptr), user->username, user->realhost,
                           cli_sock_ip(sptr), get_client_class(sptr), IsSSL(sptr) ? "Oui" : "Non",
                           cli_listener(sptr)->port);
	}
    }
    IPcheck_connect_succeeded(sptr);
  }
  else
    /* if (IsServer(cptr)) */
  {
    struct Client *acptr;

    acptr = user->server;
    if (cli_from(acptr) != cli_from(sptr))
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
                    sptr, cli_name(&me), cli_name(user->server), cli_name(cli_from(acptr)),
                    cli_sockhost(cli_from(acptr)));
      SetFlag(sptr, FLAG_KILLED);
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else
      if (HasFlag(acptr, FLAG_TS8))
          SetFlag(sptr, FLAG_TS8);

    /*
     * Check to see if this user is being propogated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be speeded up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (acptr = user->server; acptr != &me; acptr = cli_serv(acptr)->up) {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (!IPcheck_remote_connect(sptr, (acptr != &me))) {
      /*
       * We ran out of bits to count this
       */
	if(feature_bool(FEAT_TOO_MANY_FROM_IP)) {
      		sendcmdto_one(&me, CMD_KILL, sptr, "%C :%s (Trop de connexions depuis "
		    "votre host -- Ghost)", sptr, cli_name(&me));
      		exit_one_client(sptr, "Trop de connexions depuis votre host"
			 " -- throttled"); /* exit_one_client pour pas que tous les servers 
                                            * soient informés du QUIT d'un client qu'ils 
                                            * n'ont jamais vu ! */
	}
      return 0; 
    }
  }
  tmpstr = umode_str(sptr);
  sendcmdto_serv_butone(user->server, CMD_NICK, cptr,
			"%s %d %Tu %s %s %s%s%s%s %s%s :%s",
			nick, cli_hopcount(sptr) + 1, cli_lastnick(sptr),
			user->username, user->realhost,
			*tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
			inttobase64(ip_base64, ntohl(cli_ip(sptr).s_addr), 6),
			NumNick(sptr), cli_info(sptr));

  /* Send umode to client */
  if (MyUser(sptr))
  {
    static struct Flags flags; /* automatically initialized to zeros */
    send_umode(cptr, sptr, &flags, ALL_UMODES);
    if (cli_snomask(sptr) != SNO_DEFAULT && HasFlag(sptr, FLAG_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    if (feature_bool(FEAT_RULES))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :*** Notice -- Merci de prendre connaissance des règles établies sur \2%s\2 en tapant \2/RULES\2", sptr, feature_str(FEAT_NETWORK));
    if (feature_bool(FEAT_AUTOJOIN_USER)) {
      if (feature_bool(FEAT_AUTOJOIN_USER_NOTICE)) {
            sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_USER_NOTICE_VALUE));
      }
      ircd_strncpy(salon, feature_str(FEAT_AUTOJOIN_USER_CHANNEL), CHANNELLEN-1);
      join[0] = cli_name(sptr);
      join[1] = salon;
      m_join(sptr, sptr, 2, join);
    }
  }  
  
  return 0;
}

/*
 * XXX - find a way to get rid of this
 */
static char umodeBuf[BUFSIZE];

int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[])
{
  if (IsServer(sptr)) {
    int   i;
    const char* account = 0;
    char* hostmask = 0;
    const char* p;

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    cli_hopcount(new_client) = atoi(parv[2]);
    cli_lastnick(new_client) = atoi(parv[3]);
    if (Protocol(cptr) > 9 && parc > 7 && *parv[6] == '+') {
      for (p = parv[6] + 1; *p; p++) {
        for (i = 0; i < USERMODELIST_SIZE; ++i) {
          if (userModeList[i].c == *p) {
            SetFlag(new_client, userModeList[i].flag);
	    if (userModeList[i].flag == FLAG_ACCOUNT)
	      account = parv[7];
	    if (userModeList[i].flag == FLAG_SETHOST)
	      hostmask = parv[parc - 4];
            break;
          }
        }
      }
    }
    client_set_privs(new_client); /* set privs on user */
    /*
     * Set new nick name.
     */
    strcpy(cli_name(new_client), nick);
    cli_user(new_client) = make_user(new_client);
    cli_user(new_client)->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    cli_ip(new_client).s_addr = htonl(base64toint(parv[parc - 3]));

    add_client_to_list(new_client);
    hAddClient(new_client);

    cli_serv(sptr)->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(cli_username(new_client), parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->host, parv[5], HOSTLEN);
    
    if(!IsChannelService(new_client) && !IsService(sptr) && (feature_int(FEAT_PROTECTHOST) !=0)) protecthost(parv[5], cli_user(new_client)->crypt);
    else ircd_strncpy(cli_user(new_client)->crypt, parv[5], HOSTLEN);

    ircd_strncpy(cli_user(new_client)->realhost, parv[5], HOSTLEN);
    ircd_strncpy(cli_info(new_client), parv[parc - 1], REALLEN);
    if (account)
      ircd_strncpy(cli_user(new_client)->account, account, ACCOUNTLEN);
    if (IsSetHost(new_client)) /* priorité à la shost */
	ircd_strncpy(cli_user(new_client)->crypt, hostmask, HOSTLEN);
    else if (HasHiddenHost(new_client))
	ircd_snprintf(0, cli_user(new_client)->crypt, HOSTLEN, "%s.%s",
        account, feature_str(FEAT_HIDDEN_HOST));

    return register_user(cptr, new_client, cli_name(new_client), cli_username(new_client));
  }
  else if ((cli_name(sptr))[0]) {
    /*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      struct Membership *member;
      if (!IsProtect(cptr) && (channel_name = find_no_nickchange_channel(sptr))) {
        return send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immedately after another
       * before limiting the nick flood. -Run
       */
      if (!IsProtect(cptr) && (CurrentTime < cli_nextnick(cptr))) {
        cli_nextnick(cptr) += 2;
        send_reply(cptr, ERR_NICKTOOFAST, parv[1],
                   cli_nextnick(cptr) - CurrentTime);
        /* Send error message */
        sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
        /* bounce NICK to user */
        return 0;                /* ignore nick change! */
      }
      else {
        /* Limit total to 1 change per NICK_DELAY seconds: */
        cli_nextnick(cptr) += NICK_DELAY;
        /* However allow _maximal_ 1 extra consecutive nick change: */
        if (cli_nextnick(cptr) < CurrentTime)
          cli_nextnick(cptr) = CurrentTime;
      }
      /* Invalidate all bans against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
	   member = member->next_channel)
	ClearBanValid(member);
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
    if (0 != ircd_strcmp(parv[0], nick))
      cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      sendcmdto_common_channels_butone(sptr, CMD_NICK, NULL, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
                            cli_lastnick(sptr));
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    if ((cli_name(sptr))[0])
      hRemClient(sptr);
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);
  }
  else {
    /* Local client setting NICK the first time */

    strcpy(cli_name(sptr), nick);
    if (!cli_user(sptr)) {
      cli_user(sptr) = make_user(sptr);
      cli_user(sptr)->server = &me;
    }
    hAddClient(sptr);

    /*
     * If the client hasn't gotten a cookie-ping yet,
     * choose a cookie and send it. -record!jegelhof@cloud9.net
     */
    if (!cli_cookie(sptr)) {
      do {
        cli_cookie(sptr) = (ircrandom() & 0x7fffffff);
      } while (!cli_cookie(sptr));
      sendrawto_one(cptr, MSG_PING " :%u", cli_cookie(sptr));
    }
    else if (*(cli_user(sptr))->host && cli_cookie(sptr) == COOKIE_VERIFIED) {
      /*
       * USER and PONG already received, now we have NICK.
       * register_user may reject the client and call exit_client
       * for it - must test this and exit m_nick too !
       */
      cli_lastnick(sptr) = TStime();        /* Always local client */
      if (register_user(cptr, sptr, nick, cli_user(sptr)->username) == CPTR_KILLED)
        return CPTR_KILLED;
    }
  }
  return 0;
}

static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/*
 * add_target
 *
 * sptr must be a local client!
 *
 * Cannonifies target for client `sptr'.
 */
void add_target(struct Client *sptr, void *target)
{
  /* Ok, this shouldn't work esp on alpha
  */
  unsigned char  hash = hash_target((unsigned long) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(cli_local(sptr));

  targets = cli_targets(sptr);
  /* 
   * Already in table?
   */
  for (i = 0; i < MAXTARGETS; ++i) {
    if (targets[i] == hash)
      return;
  }
  /*
   * New target
   */
  memmove(&targets[RESERVEDTARGETS + 1],
          &targets[RESERVEDTARGETS], MAXTARGETS - RESERVEDTARGETS - 1);
  targets[RESERVEDTARGETS] = hash;
}

/*
 * check_target_limit
 *
 * sptr must be a local client !
 *
 * Returns 'true' (1) when too many targets are addressed.
 * Returns 'false' (0) when it's ok to send to this target.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned long) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(cli_local(sptr));
  targets = cli_targets(sptr);
  /* If user is invited to channel, give him/her a free target */
  if (IsChannelName(name) && IsInvited(sptr, target))
    return 0;

  if (IsOper(sptr))
    return 0;

  /*
   * Same target as last time?
   */
  if (targets[0] == hash)
    return 0;
  for (i = 1; i < MAXTARGETS; ++i) {
    if (targets[i] == hash) {
      memmove(&targets[1], &targets[0], i);
      targets[0] = hash;
      return 0;
    }
  }
  /*
   * New target
   */
  if (!created) {
    if (CurrentTime < cli_nexttarget(sptr)) {
      if (cli_nexttarget(sptr) - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
        cli_nexttarget(sptr) += 2;
        send_reply(sptr, ERR_TARGETTOOFAST, name,
                   cli_nexttarget(sptr) - CurrentTime);
      }
      return 1;
    }
    else {
      cli_nexttarget(sptr) += TARGET_DELAY;
      if (cli_nexttarget(sptr) < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        cli_nexttarget(sptr) = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/*
 * whisper - called from m_cnotice and m_cprivmsg.
 *
 * parv[0] = sender prefix
 * parv[1] = nick
 * parv[2] = #channel
 * parv[3] = Private message text
 *
 * Added 971023 by Run.
 * Reason: Allows channel operators to sent an arbitrary number of private
 *   messages to users on their channel, avoiding the max.targets limit.
 *   Building this into m_private would use too much cpu because we'd have
 *   to a cross channel lookup for every private message!
 * Note that we can't allow non-chan ops to use this command, it would be
 *   abused by mass advertisers.
 *
 */
int whisper(struct Client* source, const char* nick, const char* channel,
            const char* text, int is_notice)
{
  struct Client*     dest;
  struct Channel*    chptr;
  struct Membership* membership;

  assert(0 != source);
  assert(0 != nick);
  assert(0 != channel);
  assert(MyUser(source));

  if (!(dest = FindUser(nick))) {
    return send_reply(source, ERR_NOSUCHNICK, nick);
  }
  if (!(chptr = FindChannel(channel))) {
    return send_reply(source, ERR_NOSUCHCHANNEL, channel);
  }
  /*
   * compare both users channel lists, instead of the channels user list
   * since the link is the same, this should be a little faster for channels
   * with a lot of users
   */
  for (membership = cli_user(source)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership) {
    return send_reply(source, ERR_NOTONCHANNEL, chptr->chname);
  }
  if (!IsVoicedOrOpped(membership)) {
    return send_reply(source, ERR_VOICENEEDED, chptr->chname);
  }
  /*
   * lookup channel in destination
   */
  assert(0 != cli_user(dest));
  for (membership = cli_user(dest)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership)) {
    return send_reply(source, ERR_USERNOTINCHANNEL, cli_name(dest), chptr->chname);
  }
  if (is_silenced(source, dest))
    return 0;

  if (cli_user(dest)->away)
    send_reply(source, RPL_AWAY, cli_name(dest), cli_user(dest)->away);
  if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);
  return 0;
}


/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
void send_umode_out(struct Client *cptr, struct Client *sptr, struct Flags *old,
		    int prop)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, prop ? SEND_UMODES : SEND_UMODES_BUT_OPER);

  for (i = HighestFd; i >= 0; i--) {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf)
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s %s", cli_name(sptr), umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, ALL_UMODES);
}


/*
 * send_user_info - send user info userip/userhost
 * NOTE: formatter must put info into buffer and return a pointer to the end of
 * the data it put in the buffer.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  struct MsgBuf* mb;

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  mb = msgq_make(sptr, rpl_str(rpl), cli_name(&me), cli_name(sptr));

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
	msgq_append(0, mb, " ");
      (*fmt)(acptr, sptr, mb);
    }
    if (5 == ++arg_count)
      break;
  }
  send_buffer(sptr, mb, 0);
  msgq_clean(mb);
}

/*
 * hide_hostmask()
 *
 * If, after setting the flags, the user has both HiddenHost and Account
 * set, its hostmask is changed.
 */
int hide_hostmask(struct Client *cptr, unsigned int flag)
{
  struct Membership *chan;

  if (MyConnect(cptr) && !feature_bool(FEAT_HOST_HIDING) && (flag == FLAG_HIDDENHOST))
    return 0;

  /* If the user is +H, we don't hide the hostmask.  Set the flag to keep sync though */
  if (IsSetHost(cptr)) {
    SetFlag(cptr, flag);
    return 0;
  }

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel)
     ClearBanValid(chan);

  if (((flag == FLAG_HIDDENHOST) && !HasFlag(cptr, FLAG_ACCOUNT)) || ((flag == FLAG_ACCOUNT) && !HasFlag(cptr, FLAG_HIDDENHOST))) {
    /* The user doesn't have both flags, don't change the hostmask */
    SetFlag(cptr, flag);
    return 0;
  }

  ircd_snprintf(0, cli_user(cptr)->crypt, HOSTLEN, "%s.%s",
    cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));

  SetFlag(cptr, flag);

  /* ok, the client is now fully hidden, so let them know -- hikari */
  if (MyConnect(cptr))
	send_reply(cptr, RPL_HOSTHIDDEN, cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));

  return 0;
}

/*
 * set_hostmask() - derived from hide_hostmask()
 *
 */
int set_hostmask(struct Client *cptr, char *hostmask)
{
  char hiddenhost[USERLEN + HOSTLEN + 2];

  Debug((DEBUG_INFO, "set_hostmask() %C, %s, %s", cptr, hostmask));

  ircd_strncpy(cli_user(cptr)->crypt, hostmask, HOSTLEN);
  SetSetHost(cptr);

  if (MyConnect(cptr)) {
    ircd_snprintf(0, hiddenhost, HOSTLEN + USERLEN + 2, "%s@%s", cli_user(cptr)->username, cli_user(cptr)->crypt);
    send_reply(cptr, RPL_SVSHOST, hiddenhost);
  }
  return 1;
}

/*
 * set_user_mode() added 15/10/91 By Darren Reed.
 *
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char** p;
  char*  m;
  struct Client *acptr;
  int what;
  int i;
  struct Flags setflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];
  char *hostmask = NULL;
  int prop = 0;
  int do_host_hiding = 0;
  int is_svsmode = 0;
  int do_set_host = 0;

  if (MyUser(sptr) && (((intptr_t)cptr) == MAGIC_SVSMODE_OVERRIDE))
  {
    is_svsmode = 1;
    cptr = sptr;
  }

  what = MODE_ADD;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (!(acptr = FindUser(parv[1])))
  {
    if (MyConnect(sptr))
      send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
    return 0;
  }

  if (IsServer(sptr) || sptr != acptr)
  {
    if (IsServer(cptr))
      sendwallto_group_butone(&me, WALL_WALLOPS, 0, 
	  		    "User Mode pour %s depuis %s!%s", parv[1],
                            cli_name(cptr), cli_name(sptr));
    else
      send_reply(sptr, ERR_USERSDONTMATCH);
    return 0;
  }

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; ++i) {
      if (HasFlag(sptr, userModeList[i].flag) &&
	  (userModeList[i].flag != FLAG_ACCOUNT) &&
	  (userModeList[i].flag != FLAG_SETHOST))
        *m++ = userModeList[i].c;
    }
    *m = '\0';
    send_reply(sptr, RPL_UMODEIS, buf);
    if (HasFlag(sptr, FLAG_SERVNOTICE) && MyConnect(sptr)
        && cli_snomask(sptr) !=
        (unsigned int)(IsOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = cli_flags(sptr);

  if (MyConnect(sptr))
    tmpmask = cli_snomask(sptr);

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p; p++) {       /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
      case '+':
        what = MODE_ADD;
        break;
      case '-':
        what = MODE_DEL;
        break;
      case 's':
        if (*(p + 1) && is_snomask(*(p + 1))) {
          snomask_given = 1;
          tmpmask = umode_make_snomask(tmpmask, *++p, what);
          tmpmask &= (IsAnOper(sptr) ? SNO_ALL : SNO_USER);
        }
        else
          tmpmask = (what == MODE_ADD) ?
              (IsAnOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT) : 0;
        if (tmpmask)
	  SetServNotice(sptr);
        else
	  ClearServNotice(sptr);
        break;
      case 'w':
        if (what == MODE_ADD)
          SetWallops(sptr);
        else
          ClearWallops(sptr);
        break;
      case 'a':
        if (what == MODE_ADD)
          SetAdmin(sptr);
        else
          ClrFlag(sptr, FLAG_ADMIN);
        break;
      case 'A':
        if (what == MODE_ADD)
           SetHelper(sptr);
        else
          ClearHelper(sptr);
        break;
      case 'o':
        if (what == MODE_ADD)
          SetOper(sptr);
        else {
          ClrFlag(sptr, FLAG_OPER);
	  ClrFlag(sptr, FLAG_ADMIN);
	  ClrFlag(sptr, FLAG_WANTRESTART);
	  ClrFlag(sptr, FLAG_PROTECT);
	  ClrFlag(sptr, FLAG_NOIDLE);
	  ClrFlag(sptr, FLAG_WHOIS);
	  ClrFlag(sptr, FLAG_NOCHAN);
	  ClrFlag(sptr, FLAG_WALLOP);
	  ClrFlag(sptr, FLAG_SERVNOTICE);
	  ClrFlag(sptr, FLAG_DEBUG);
	  ClrFlag(sptr, FLAG_HIDEOPER);
	  if(IsHiding(sptr)) {
		sendto_opmask_butone(0, SNO_OLDSNO, "[-X] Désactivation du mode de totale invisibilité de %s (%s@%s)", cli_name(sptr),
            		  cli_user(sptr)->username, cli_user(sptr)->realhost);
		ClrFlag(sptr, FLAG_HIDE);
		sendto_channels_inviso_join(sptr);
	  }
          if (MyConnect(sptr)) {
            tmpmask = cli_snomask(sptr) & ~SNO_OPER;
            cli_handler(sptr) = CLIENT_HANDLER;
	    cli_oflags(sptr) = 0;
          }
        }
        break;
      case 'i':
        if (what == MODE_ADD)
          SetInvisible(sptr);
        else
	  if (!feature_bool(FEAT_AUTOINVISIBLE) || IsOper(sptr))
            ClearInvisible(sptr);
        break;
      case 'd':
        if (what == MODE_ADD)
          SetDeaf(sptr);
        else
          ClearDeaf(sptr);
        break;
      case 'k':
        if (what == MODE_ADD)
          SetChannelService(sptr);
        else
          ClearChannelService(sptr);
        break;
      case 'D':
        if (what == MODE_ADD && IsAnOper(sptr))
	  SetWantRestart(sptr);
        else
	  ClearWantRestart(sptr);
        break;
      case 'g':
        if (what == MODE_ADD)
          SetDebug(sptr);
        else
          ClearDebug(sptr);
        break;
      case 'f':
        if (what == MODE_ADD)
	  SetFemale(sptr);
        else
	  ClearFemale(sptr);
        break;
      case 'h':
        if (what == MODE_ADD)
	  SetMale(sptr);
        else
	  ClearMale(sptr);
        break;
      case 'x':
        if (what == MODE_ADD)
	  do_host_hiding = 1;
	break;
      case 'Z':
        if (what == MODE_ADD && IsOper(sptr))
	  SetProtect(sptr);
	else
	  ClearProtect(sptr);
	break;
      case 'C':
      	if (what == MODE_ADD)
	  SetNoChan(sptr);
        else
          ClearNoChan(sptr);
        break;
      case 'I':
        if (what == MODE_ADD)
          SetNoIdle(sptr);
        else
          ClearNoIdle(sptr);
        break;
      case 'R':
        if (what == MODE_ADD && IsAccount(sptr))
	  SetPAccOnly(sptr);
	else
	  ClearPAccOnly(sptr);
	break;
      case 'P':
        if (what == MODE_ADD)
	  SetNoPrivate(sptr);
	else
	  ClearNoPrivate(sptr);
	break;
      case 'W':
        if (what == MODE_ADD && IsOper(sptr))
          SetWhois(sptr);
        else
          ClearWhois(sptr);
        break;
      case 'X':
        if (what == MODE_ADD && IsAnOper(sptr))
          SetHide(sptr);
        else
          ClearHide(sptr);
        break;
      case 'S':
	if (what == MODE_ADD)
	  SetHideOper(sptr);
	else
	  ClearHideOper(sptr);
	break;
      default: send_reply(sptr, ERR_UMODEUNKNOWNFLAG, *m); /* Wtf is this mode ? */
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */
  if (!IsServer(cptr) && !is_svsmode) {
    if (!FlagHas(&setflags, FLAG_HELPER) && IsHelper(sptr))
      ClearHelper(sptr);
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(sptr))
      ClearOper(sptr);
    if (!FlagHas(&setflags, FLAG_ADMIN) && IsAnAdmin(sptr))
      ClearAdmin(sptr);
    if (!FlagHas(&setflags, FLAG_PROTECT) && IsProtect(sptr) && !IsOper(sptr))
    {
      if(MyConnect(sptr)) send_reply(sptr, ERR_NOPRIVILEGES);
      ClearProtect(sptr);
    }
    /*
     * new umode; servers can set it, local users cannot;
     * prevents users from /kick'ing or /mode -o'ing
     */
    if (!FlagHas(&setflags, FLAG_CHSERV))
      ClearChannelService(sptr);
    if (!FlagHas(&setflags, FLAG_NOCHAN) && !IsOper(sptr))
          ClearNoChan(sptr);      
    if (!FlagHas(&setflags, FLAG_NOIDLE) && !IsOper(sptr))
          ClearNoIdle(sptr);
    if (!FlagHas(&setflags, FLAG_WHOIS) && !IsOper(sptr))
    	  ClearWhois(sptr);
    if (!FlagHas(&setflags, FLAG_HIDEOPER) && !IsOper(sptr))
	  ClearHideOper(sptr);

    /*
     * only send wallops to opers
     */
    if (feature_bool(FEAT_WALLOPS_OPER_ONLY) && !IsAnOper(sptr) &&
	!FlagHas(&setflags, FLAG_WALLOP))
      ClearWallops(sptr);

    if (feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY) && MyConnect(sptr) && 
	!IsAnOper(sptr) && !FlagHas(&setflags, FLAG_SERVNOTICE)) {
      ClearServNotice(sptr);
      set_snomask(sptr, 0, SNO_SET);
    }

    if (feature_bool(FEAT_HIS_DEBUG_OPER_ONLY) && !IsAnOper(sptr) &&
	!FlagHas(&setflags, FLAG_DEBUG))
      ClearDebug(sptr);

    if((!IsAnOper(sptr) || !CanInv(sptr)) && !FlagHas(&setflags, FLAG_HIDE) && IsHiding(sptr))
    {
	if(MyConnect(sptr)) send_reply(sptr, ERR_NOPRIVILEGES);
	ClearHide(sptr);
    }

    if((!IsAnOper(sptr) || !CanDie(sptr)) && !FlagHas(&setflags, FLAG_WANTRESTART) && WantRestart(sptr))
    {
	if(MyConnect(sptr)) send_reply(sptr, ERR_NOPRIVILEGES);
	ClearWantRestart(sptr);
    }
    if(!FlagHas(&setflags, FLAG_HIDDENHOST)) {
    do_host_hiding = 0;
    ClearHiddenHost(acptr);
    }

  }


  if (MyConnect(sptr)) {
    if (FlagHas(&setflags, FLAG_NOPRIVATE) && IsPAccOnly(sptr)) ClearNoPrivate(sptr);
    if (FlagHas(&setflags, FLAG_PACCONLY) && IsNoPrivate(sptr)) ClearPAccOnly(sptr);
    if (!FlagHas(&setflags, FLAG_NOPRIVATE) && !FlagHas(&setflags, FLAG_PACCONLY) &&
        IsNoPrivate(sptr) && IsPAccOnly(sptr))
    {
	ClearNoPrivate(sptr);
	ClearPAccOnly(sptr);
	sendcmdto_one(&me, MSG_NOTICE, TOK_NOTICE, sptr, "%C :Vous ne pouvez pas cumuler les modes R et P", sptr);
    }
    if(!FlagHas(&setflags, FLAG_NOPRIVATE) && IsNoPrivate(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Tous les messages privés sont maintenant ignoré !", sptr);
    if(!FlagHas(&setflags, FLAG_PACCONLY) && IsPAccOnly(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Les messages privés des utilisateurs non enregistrés sont maintenant ignoré !", sptr);
    
    if (FlagHas(&setflags, FLAG_MALE) && IsFemale(sptr)) ClearMale(sptr);
    if (FlagHas(&setflags, FLAG_FEMALE) && IsMale(sptr)) ClearFemale(sptr);
    if (!FlagHas(&setflags, FLAG_MALE) && !FlagHas(&setflags, FLAG_FEMALE) &&
        IsMale(sptr) && IsFemale(sptr))
    {
	ClearMale(sptr);
	ClearFemale(sptr);
	sendcmdto_one(&me, MSG_NOTICE, TOK_NOTICE, sptr, "%C :Vous êtes transexuel !?", sptr);
    }
    if(FlagHas(&setflags, FLAG_MALE) && !IsMale(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Un couteau, et hop, plus de penis encombrant", sptr);
    if(FlagHas(&setflags, FLAG_FEMALE) && !IsFemale(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :On verse un peu de cire, ni vu ni connu, le trou est comblé", sptr);
    if(!FlagHas(&setflags, FLAG_MALE) && IsMale(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Transformation en homme !", sptr);
    if(!FlagHas(&setflags, FLAG_FEMALE) && IsFemale(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Transformation en femme !", sptr);

    if (FlagHas(&setflags, FLAG_OPER) && !IsAnOper(sptr))
      det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPERATOR);

    if (SendServNotice(sptr)) {
      if (tmpmask != cli_snomask(sptr))
	set_snomask(sptr, tmpmask, SNO_SET);
      if (cli_snomask(sptr) && snomask_given)
	send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    } else
      set_snomask(sptr, 0, SNO_SET);
  }
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if (!FlagHas(&setflags, FLAG_OPER) && IsOper(sptr)) { /* user now oper */
    ++UserStats.opers;
    client_set_privs(sptr); /* may set propagate privilege */
  }
  if (HasPriv(sptr, PRIV_PROPAGATE)) /* remember propagate privilege setting */
    prop = 1;
  if (FlagHas(&setflags, FLAG_OPER) && !IsOper(sptr)) { /* user no longer oper */
    --UserStats.opers;
    client_set_privs(sptr); /* will clear propagate privilege */
  }
  if (FlagHas(&setflags, FLAG_INVISIBLE) && !IsInvisible(sptr))
    --UserStats.inv_clients;
  if (!FlagHas(&setflags, FLAG_INVISIBLE) && IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (!FlagHas(&setflags, FLAG_HIDDENHOST) && do_host_hiding)
    hide_hostmask(sptr, FLAG_HIDDENHOST);

  if (!FlagHas(&setflags, FLAG_HIDE)  && IsHiding(sptr) && IsAnOper(sptr))
  {
      sendto_opmask_butone(0, SNO_OLDSNO, "[+X] Activation du mode de totale invisibilité de %s (%s@%s)", cli_name(sptr),
              cli_user(sptr)->username, cli_user(sptr)->realhost);
      sendto_channels_inviso_part(sptr);
  }

  if (FlagHas(&setflags, FLAG_HIDE)  && !IsHiding(sptr) && IsAnOper(sptr))
  {
      sendto_opmask_butone(0, SNO_OLDSNO, "[-X] Désactivation du mode de totale invisibilité de %s (%s@%s)", cli_name(sptr),
              cli_user(sptr)->username, cli_user(sptr)->realhost);
      sendto_channels_inviso_join(sptr);
  }

  if(do_set_host && set_hostmask(sptr, hostmask) && hostmask)
    FlagClr(&setflags, FLAG_SETHOST);
  send_umode_out(cptr, sptr, &setflags, prop);

  return 0;
}

/*
 * Build umode string for BURST command
 * --Run
 */
char *umode_str(struct Client *cptr)
{
  char* m = umodeBuf;                /* Maximum string size: "owidgrx\0" */
  int   i;
  struct Flags c_flags;

  c_flags = cli_flags(cptr);
  if (HasPriv(cptr, PRIV_PROPAGATE))
    FlagSet(&c_flags, FLAG_OPER);
  else
    FlagClr(&c_flags, FLAG_OPER);

  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    if (FlagHas(&c_flags, userModeList[i].flag) &&
        (userModeList[i].flag >= FLAG_GLOBAL_UMODES))
      *m++ = userModeList[i].c;
  }

  if (IsAccount(cptr)) {
    char* t = cli_user(cptr)->account;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
      m--;
  }
  if (IsSetHost(cptr)) {
    *m++ = ' ';
    ircd_snprintf(0, m, HOSTLEN, "%s", cli_user(cptr)->crypt);
  } else
    *m = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/*
 * Send the MODE string for user (sptr) to connection cptr
 * -avalon
 */
void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old, int sendset)
{
  int i;
  int flag;
  int needhost = 0;
  char *m;
  int what = MODE_NULL;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (cli_flags(sptr)) and 'old', but skipping
   * the modes indicated by sendset.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    flag = userModeList[i].flag;
    if (FlagHas(old, flag) == HasFlag(sptr, flag))
      continue;
    switch (sendset)
    {
      case ALL_UMODES:
        break;
      case SEND_UMODES_BUT_OPER:
        if (flag == FLAG_OPER)
          continue;
        /* and fall through */
      case SEND_UMODES:
        if (flag < FLAG_GLOBAL_UMODES)
          continue;
        break;
    }
    /* Special case for SETHOST.. */
    if (flag == FLAG_SETHOST) {
      /* Don't send to users */
      if (cptr && MyUser(cptr))
      	continue;

      /* If we're setting +h, add the parameter later */
      if (!FlagHas(old, flag))
     	needhost++;
    }
    if (FlagHas(old, flag))
    {
      if (what == MODE_DEL)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_DEL;
        *m++ = '-';
        *m++ = userModeList[i].c;
      }
    }
    else /* !FlagHas(old, flag) */
    {
      if (what == MODE_ADD)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_ADD;
        *m++ = '+';
        *m++ = userModeList[i].c;
      }
    }
  }
  if (needhost) {
    *m++ = ' ';
    ircd_snprintf(0, m, USERLEN + HOSTLEN + 1, "%s", cli_user(sptr)->crypt);
  } else
    *m = '\0';
  if (*umodeBuf && cptr)
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s %s", cli_name(sptr), umodeBuf);
}

/*
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 */
int is_snomask(char *word)
{
  if (word)
  {
    for (; *word; word++)
      if (IsDigit(*word))
        return 1;
      else if (IsAlpha(*word))
        return 0;
  }
  return 0;
}

/*
 * Check to see if it resembles a valid hostmask.
 */
int is_hostmask(char *word)
{
  int i = 0;
  char *host = word;

  Debug((DEBUG_INFO, "is_hostmask() %s", word));

  if (strlen(word) > (HOSTLEN + USERLEN + 1) || strlen(word) <= 0)
    return 0;

  if(strchr(word, '@')) return 0; /* non utilisation des user@host */

  /* if a host is specified, make sure it's valid */
  if(*++host == 0 || strlen(host) > HOSTLEN)
     return 0;

  if (word) {
    if ('@' == *word)	/* no leading @'s */
        return 0;

    if ('#' == *word) {	/* numeric index given? */
      for (word++; *word; word++) {
        if (!IsDigit(*word))
          return 0;
      }
      return 1;
    }

    /* normal hostmask, account for at most one '@' */
    for (; *word; word++) {
      if ('@' == *word) {
        i++;
        continue;
      }
      if (!IsHostChar(*word))
        return 0;
    }
    return (1 < i) ? 0 : 1; /* no more than on '@' */
  }
  return 0;
}

/*
 * If it begins with a +, count this as an additive mask instead of just
 * a replacement.  If what == MODE_DEL, "+" has no special effect.
 */
unsigned int umode_make_snomask(unsigned int oldmask, char *arg, int what)
{
  unsigned int sno_what;
  unsigned int newmask;
  if (*arg == '+')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_ADD;
    else
      sno_what = SNO_DEL;
  }
  else if (*arg == '-')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_DEL;
    else
      sno_what = SNO_ADD;
  }
  else
    sno_what = (what == MODE_ADD) ? SNO_SET : SNO_DEL;
  /* pity we don't have strtoul everywhere */
  newmask = (unsigned int)atoi(arg);
  if (sno_what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (sno_what == SNO_ADD)
    newmask |= oldmask;
  return newmask;
}

static void delfrom_list(struct Client *cptr, struct SLink **list)
{
  struct SLink* tmp;
  struct SLink* prv = NULL;

  for (tmp = *list; tmp; tmp = tmp->next) {
    if (tmp->value.cptr == cptr) {
      if (prv)
        prv->next = tmp->next;
      else
        *list = tmp->next;
      free_link(tmp);
      break;
    }
    prv = tmp;
  }
}

/*
 * This function sets a Client's server notices mask, according to
 * the parameter 'what'.  This could be even faster, but the code
 * gets mighty hard to read :)
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cli_snomask(cptr);

  if (what == SNO_ADD)
    newmask |= oldmask;
  else if (what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (what != SNO_SET)        /* absolute set, no math needed */
    sendto_opmask_butone(0, SNO_OLDSNO, "setsnomask called with %d ?!", what);

  newmask &= (IsAnOper(cptr) ? SNO_ALL : SNO_USER);

  diffmask = oldmask ^ newmask;

  for (i = 0; diffmask >> i; i++) {
    if (((diffmask >> i) & 1))
    {
      if (((newmask >> i) & 1))
      {
        tmp = make_link();
        tmp->next = opsarray[i];
        tmp->value.cptr = cptr;
        opsarray[i] = tmp;
      }
      else
        /* not real portable :( */
        delfrom_list(cptr, &opsarray[i]);
    }
  }
  cli_snomask(cptr) = newmask;
}

/*
 * is_silenced : Does the actual check wether sptr is allowed
 *               to send a message to acptr.
 *               Both must be registered persons.
 * If sptr is silenced by acptr, his message should not be propagated,
 * but more over, if this is detected on a server not local to sptr
 * the SILENCE mask is sent upstream.
 */
int is_silenced(struct Client *sptr, struct Client *acptr)
{
  struct SLink *lp;
  struct User *user;
  static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
  /*static char senderip[16 + NICKLEN + USERLEN + 5];
  static char senderh[HOSTLEN + ACCOUNTLEN + USERLEN + 6]; */

  if (!cli_user(acptr) || !(lp = cli_user(acptr)->silence) || !(user = cli_user(sptr)))
    return 0;
  ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s", cli_name(sptr),
		user->username, user->crypt);
  /*ircd_snprintf(0, senderip, sizeof(senderip), "%s!%s@%s", cli_name(sptr),
		user->username, ircd_ntoa((const char*) &(cli_ip(sptr))));*/
  /*if (HasHiddenHost(sptr))
    ircd_snprintf(0, senderh, sizeof(senderh), "%s!%s@%s", cli_name(sptr),
		  user->username, user->realhost);*/
  /* On vérifie seulement l'host crypté */
  for (; lp; lp = lp->next)
  {
    if (!match(lp->value.cp, sender)/* || (HasHiddenHost(sptr) && !match(lp->value.cp, senderh))*/)
    {
      if (!MyConnect(sptr))
      {
        sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr,
                      lp->value.cp);
      }
      return 1;
    }
  }
  return 0;
}

/*
 * del_silence
 *
 * Removes all silence masks from the list of sptr that fall within `mask'
 * Returns -1 if none where found, 0 otherwise.
 */
int del_silence(struct Client *sptr, char *mask)
{
  struct SLink **lp;
  struct SLink *tmp;
  int ret = -1;

  for (lp = &(cli_user(sptr))->silence; *lp;) {
    if (!mmatch(mask, (*lp)->value.cp))
    {
      tmp = *lp;
      *lp = tmp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      ret = 0;
    }
    else
      lp = &(*lp)->next;
  }
  return ret;
}

int add_silence(struct Client* sptr, const char* mask)
{
  struct SLink *lp, **lpp;
  int cnt = 0, len = strlen(mask);
  char *ip_start;

  for (lpp = &(cli_user(sptr))->silence, lp = *lpp; lp;)
  {
    if (0 == ircd_strcmp(mask, lp->value.cp))
      return -1;
    if (!mmatch(mask, lp->value.cp))
    {
      struct SLink *tmp = lp;
      *lpp = lp = lp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      continue;
    }
    if (MyUser(sptr))
    {
      len += strlen(lp->value.cp);
      if ((len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXSILES))) ||
	  (++cnt >= feature_int(FEAT_MAXSILES)))
      {
        send_reply(sptr, ERR_SILELISTFULL, mask);
        return -1;
      }
      else if (!mmatch(lp->value.cp, mask))
        return -1;
    }
    lpp = &lp->next;
    lp = *lpp;
  }
  lp = make_link();
  memset(lp, 0, sizeof(struct SLink));
  lp->next = cli_user(sptr)->silence;
  lp->value.cp = (char*) MyMalloc(strlen(mask) + 1);
  assert(0 != lp->value.cp);
  strcpy(lp->value.cp, mask);
  if ((ip_start = strrchr(mask, '@')) && check_if_ipmask(ip_start + 1))
    lp->flags = CHFL_SILENCE_IPMASK;
  cli_user(sptr)->silence = lp;
  return 0;
}

int
send_supported(struct Client *cptr)
{
  char featurebuf[512];

  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES1, FEATURESVALUES1);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);
  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES2, FEATURESVALUES2);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);

  return 0; /* convenience return, if it's ever needed */
}
