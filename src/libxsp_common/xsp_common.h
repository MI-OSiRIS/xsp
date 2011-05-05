#ifndef XSP_COMMON_H
#define XSP_COMMON_H

enum xsp_direction_t { XSP_INCOMING, XSP_OUTGOING, XSP_BOTH };

int id_equal_fn( const void *k1, const void *k2);
unsigned int id_hash_fn( const void *k1 );

#endif
