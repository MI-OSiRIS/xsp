#ifndef XSPD_COMMON_H
#define XSPD_COMMON_H

enum xspd_direction_t { XSPD_INCOMING, XSPD_OUTGOING, XSPD_BOTH };

int id_equal_fn( const void *k1, const void *k2);
unsigned int id_hash_fn( const void *k1 );

#endif
