#include <string.h>
#include "hashtable_util.h"


inline unsigned int xsp_hash_string(const void *key) {
    return hashlittle(key, strlen((char*)key), HASHLITTLE_INIT_VAL);
}

int xsp_equalkeys_string(const void *k1, const void *k2) {
    size_t len = strlen(k1);
    if (len != strlen(k2)) return 0;
    return (memcmp(k1, k2, len) == 0);
}
