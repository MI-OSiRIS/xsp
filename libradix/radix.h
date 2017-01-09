// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
/*
 * $Id: radix.h,v 1.2 2004/04/21 13:31:12 swany Exp $
 * $Imported: radix.h,v 1.1 2003/06/11 03:14:45 swany Exp $
 */

#ifndef _RADIX_H
#define _RADIX_H

#include "../include/config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>

#include <netinet/in.h>
#include <pthread.h>

/* bit manipulation */
#define MAXLINE         512

#define BIT_SET(f, b)   ((f) |= b)
#define BIT_RESET(f, b) ((f) &= ~(b))
#define BIT_FLIP(f, b)  ((f) ^= (b))
#define BIT_TEST(f, b)  ((f) & (b))
#define BIT_MATCH(f, b) (((f) & (b)) == (b))
#define BIT_COMPARE(f, b1, b2)  (((f) & (b1)) == b2)
#define BIT_MASK_MATCH(f, g, b) (!(((f) ^ (g)) & (b)))

typedef unsigned long bitx_mask_t;
#define BITX_NBITS (sizeof (bitx_mask_t) * 8)

#define BITX_SET(p, n) ((p)->bits[(n)/BITX_NBITS] |= \
		                            ((unsigned)1 << ((n) % BITX_NBITS)))
#define BITX_RESET(p, n) ((p)->bits[(n)/BITX_NBITS] &= \
		                            ~((unsigned)1 << ((n) % BITX_NBITS)))
#define BITX_TEST(p, n) ((p)->bits[(n)/BITX_NBITS] & \
		                            ((unsigned)1 << ((n) % BITX_NBITS)))

#ifndef byte
#define byte u_char
#endif

#if defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE_EXTENDED - 1 == 0)
typedef unsigned char   u_char;
typedef unsigned int    u_int;
typedef unsigned short  u_short;
typedef unsigned long   u_long;
#endif /* defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE_EXTENDED - 1 == 0) */
/*end bit manipulation */


#define prefix_tolong(prefix) (assert ((prefix)->family == AF_INET),\
                               (prefix)->add.sin.s_addr)
#define prefix_tochar(prefix) ((char *)&(prefix)->add.sin)
#define prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)
#define prefix_toaddr(prefix) (&(prefix)->add.sin)
#define prefix_getfamily(prefix) ((prefix)->family)
#define prefix_getlen(prefix) (((prefix)->bitlen)/8)
#ifdef HAVE_IPV6
#define prefix_toaddr6(prefix) (assert ((prefix)->family == AF_INET6),\
                                &(prefix)->add.sin6)
#endif /* IPV6 */


typedef void (*void_fn_t)(void *arg1);
typedef void (*void_fn2_t)(void *arg1, void *arg2);

typedef struct _prefix_t {
  u_short family;             /* AF_INET | AF_INET6 */
  u_short bitlen;             /* same as mask? */
  int ref_count;              /* reference count */
  pthread_mutex_t mutex_lock; /* lock down structure */
  union {
    struct in_addr sin;
#ifdef HAVE_IPV6
    struct in6_addr sin6;
#endif /* IPV6 */
  } add;
} prefix_t;

typedef struct _prefix4_t {
  u_short family;             /* AF_INET | AF_INET6 */
  u_short bitlen;             /* same as mask? */
  int ref_count;              /* reference count */
  pthread_mutex_t mutex_lock; /* lock down structure */
  struct in_addr sin;
} prefix4_t;

#ifdef HAVE_IPV6
typedef struct _prefix6_t {
  u_short family;             /* AF_INET | AF_INET6 */
  u_short bitlen;             /* same as mask? */
  int ref_count;              /* reference count */
  pthread_mutex_t mutex_lock; /* lock down structure */
  struct in6_addr sin6;
} prefix6_t;
#endif /* IPV6 */

typedef struct _radix_node_t {
  u_int bit;			/* flag if this node used */
  prefix_t *prefix;		/* who we are in radix tree */
  struct _radix_node_t *l, *r;	/* left and right children */
  struct _radix_node_t *parent;/* may be used */
  void *data;			/* pointer to data */
  void	*user1;			/* pointer to usr data (ex. route flap info) */
} radix_node_t;

typedef struct _radix_tree_t {
  radix_node_t 	*head;
  u_int		maxbits;	/* for IP, 32 bit addresses */
  int num_active_node;		/* for debug purpose */
} radix_tree_t;


radix_node_t *radix_search_exact (radix_tree_t *radix, prefix_t *prefix);
radix_node_t *radix_search_best (radix_tree_t *radix, prefix_t *prefix);
radix_node_t * radix_search_best2 (radix_tree_t *radix, prefix_t *prefix,
                                   int inclusive);
radix_node_t *radix_lookup (radix_tree_t *radix, prefix_t *prefix);
void radix_remove (radix_tree_t *radix, radix_node_t *node);
radix_tree_t *New_Radix (int maxbits);
void Destroy_Radix (radix_tree_t *radix, void_fn_t func);
void radix_process (radix_tree_t *radix, void_fn2_t func);

char *
prefix_toa (prefix_t * prefix);
char *
prefix_toa2 (prefix_t *prefix, char *tmp);

prefix_t *
New_Prefix (int family, void * dest, int bitlen);
prefix_t *Change_Prefix (int family, void * dest, int bitlen, prefix_t * prefix);
prefix_t *Ref_Prefix (prefix_t * prefix);
void Deref_Prefix (prefix_t * prefix);
void Delete_Prefix (prefix_t * prefix);
//int prefix_check_prefix_in_list (LINKED_LIST * ll_prefix, prefix_t * prefix);
//void print_prefix_list (LINKED_LIST * ll_prefixes);
void print_prefix (prefix_t * p_prefix);
prefix_t *copy_prefix (prefix_t * prefix);
//void print_pref_prefix_list (LINKED_LIST * ll_prefixes, u_short *pref);

struct sockaddr *prefix_tosockaddr(prefix_t *);
prefix_t *name_toprefix(char *);
prefix_t *string_toprefix(char *);
char *prefix_toname(prefix_t *prefix);
char *
prefix_toa (prefix_t * prefix);
char *
prefix_toa2 (prefix_t *prefix, char *tmp);
char *
prefix_toa2x (prefix_t *prefix, char *tmp, int with_len);
prefix_t *
ascii2prefix (int family, char *string);
int comp_with_mask (void *addr, void *dest, u_int mask);


#define RADIX_MAXBITS 128
#define RADIX_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define RADIX_NBYTE(x)       ((x) >> 3)

#define RADIX_DATA_GET(node, type) (type *)((node)->data)
#define RADIX_DATA_SET(node, value) ((node)->data = (void *)(value))

#define RADIX_WALK(Xhead, Xnode) \
    do { \
        radix_node_t *Xstack[RADIX_MAXBITS+1]; \
        radix_node_t **Xsp = Xstack; \
        radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
            if (Xnode->prefix)

#define RADIX_WALK_ALL(Xhead, Xnode) \
do { \
        radix_node_t *Xstack[RADIX_MAXBITS+1]; \
        radix_node_t **Xsp = Xstack; \
        radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
	    if (1)

#define RADIX_WALK_BREAK { \
	    if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	     } else { \
		Xrn = (radix_node_t *) 0; \
	    } \
	    continue; }

#define RADIX_WALK_END \
            if (Xrn->l) { \
                if (Xrn->r) { \
                    *Xsp++ = Xrn->r; \
                } \
                Xrn = Xrn->l; \
            } else if (Xrn->r) { \
                Xrn = Xrn->r; \
            } else if (Xsp != Xstack) { \
                Xrn = *(--Xsp); \
            } else { \
                Xrn = (radix_node_t *) 0; \
            } \
        } \
    } while (0)

#endif /* _RADIX_H */
