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
#include <config.h>
#include "mac-learning.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "hash.h"
#include "list.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "tag.h"
#include "timeval.h"
#include "util.h"

#define THIS_MODULE openflow
#include "vlog.h"

#define MAC_HASH_BITS 10
#define MAC_HASH_MASK (MAC_HASH_SIZE - 1)
#define MAC_HASH_SIZE (1u << MAC_HASH_BITS)

#define CT_MAX 1024

/* A controller table entry. */
struct ctrl_table_entry {
    struct list hash_node;      /* Element in a controller 'table' list. */
    struct list lru_node;       /* Element in 'lrus' or 'free' list. */
    //time_t expires;             /* Expiration time. */
    uint32_t ip_src;            /* allowed ip src address -- has to pair with ip dst */
    uint32_t ip_dst;            /* allowed ip dst address -- has to pair with ip src */
    enum ofp_action_type action; /* Action type for the entry */
};

/* controller table. */
struct ctrl_table {
    struct list free;                       /* Not-in-use entries. */
    struct list lrus;                       /* In-use entries, least recently used at the
                                               front, most recently used at the back. */
    struct list table[MAC_HASH_SIZE];        /* Hash table. */
    struct ctrl_table_entry entries[CT_MAX]; /* All entries. */
};

bool
isempty(struct ctrl_table * ct) {
    return list_is_empty(&ct->lrus);
}

/* hash the ip-pair */
static uint32_t
ctrl_table_hash(uint32_t ip_src, uint32_t ip_dst)
{
    uint32_t ips[2] = {ip_src, ip_dst};
    return hash_words(ips, 2/*words of ips*/, 0/*VLAN, the starting 'basis'--mac learning feature*/);
}

/* given the lru node, return the entry that contains it */
static struct ctrl_table_entry *
ctrl_table_entry_from_lru_node(struct list *list)
{
    return CONTAINER_OF(list, struct ctrl_table_entry, lru_node);
}

/* Returns a tag that represents that 'mac' is on an unknown port in 'vlan'.
 * (When we learn where 'mac' is in 'vlan', this allows flows that were
 * flooded to be revalidated.) */
/*static tag_type
make_unknown_mac_tag(const struct ctrl_table *ct,
                     uint32_t ip_src, uint32_t ip_dst)
{
    uint32_t h = hash_bytes(&ml->secret, sizeof ml->secret,
                            ctrl_table_hash(mac, vlan));
    return tag_create_deterministic(h);
}*/

static struct list *
ctrl_table_bucket(const struct ctrl_table *ct,
                  uint32_t ip_src, uint32_t ip_dst)
{
    uint32_t hash = ctrl_table_hash(ip_src, ip_dst);
    const struct list *list = &ct->table[hash & MAC_HASH_MASK];
    return (struct list *) list;
}

static struct ctrl_table_entry *
search_bucket(struct list *bucket, uint32_t ip_src, uint32_t ip_dst)
{
    struct ctrl_table_entry *e;
    LIST_FOR_EACH (e, struct ctrl_table_entry, hash_node, bucket) {
        if (e->ip_src == ip_src && e->ip_dst == ip_dst) {
            return e;
        }
    }
    return NULL;
}

/* If the LRU list is not empty, stores the least-recently-used entry in '*e'
 * and returns true.  Otherwise, if the LRU list is empty, stores NULL in '*e'
 * and return false. */
static bool
get_lru(struct ctrl_table *ct, struct ctrl_table_entry **e)
{
    if (!list_is_empty(&ct->lrus)) {
        *e = ctrl_table_entry_from_lru_node(ct->lrus.next);
        return true;
    } else {
        *e = NULL;
        return false;
    }
}

/* Removes 'e' from the 'ct' hash table.  'e' must not already be on the free
 * list. */
static void
free_ctrl_table_entry(struct ctrl_table *ct, struct ctrl_table_entry *e)
{
    list_remove(&e->hash_node);
    list_remove(&e->lru_node);
    list_push_front(&ct->free, &e->lru_node);
}

/* Creates and returns a new controller table. */
struct ctrl_table *
ctrl_table_create(void)
{
    struct ctrl_table *ct;
    int i;

    ct = xmalloc(sizeof *ct);
    list_init(&ct->lrus);
    list_init(&ct->free);
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        list_init(&ct->table[i]);
    }
    for (i = 0; i < CT_MAX; i++) {
        struct ctrl_table_entry *s = &ct->entries[i];
        list_push_front(&ct->free, &s->lru_node);
    }

    return ct;
}

/* Destroys controller table 'ct'. */
void
ctrl_table_destroy(struct ctrl_table *ct)
{
    free(ct);
}

/* Attempts to make 'ct' learn from the fact that a policy that ip_src and ip_dst
 * pair packet will have the 'action'.
 *
 * Returns true if we actually learned something from this, false if it just
 * confirms what we already knew. */
bool
ctrl_table_learn(struct ctrl_table *ct, uint32_t ip_src, uint32_t ip_dst, enum ofp_action_type action)
{
    struct ctrl_table_entry *e;
    struct list *bucket;

    bucket = ctrl_table_bucket(ct, ip_src, ip_dst);
    e = search_bucket(bucket, ip_src, ip_dst);
    if (!e) {
        if (!list_is_empty(&ct->free)) {
            e = ctrl_table_entry_from_lru_node(ct->free.next);
        } else {
            e = ctrl_table_entry_from_lru_node(ct->lrus.next);
            list_remove(&e->hash_node);
        }
        e->ip_src = ip_src;
        e->ip_dst = ip_dst;
        list_push_front(bucket, &e->hash_node);
        e->action = -1;
        //e->tag = make_unknown_mac_tag(ml, src_mac, vlan);
    }

    /* Make the entry most-recently-used. */
    list_remove(&e->lru_node); // delete from the list, whichever it is in now.
    list_push_back(&ct->lrus, &e->lru_node);
    //e->expires = time_now() + 3600;

    /* Did we learn something? */
    if (e->action != action) {
        //tag_type old_tag = e->tag;
        e->action = action;
        //e->tag = tag_create_random();        
        return true;
    }
    return false;
}

/* Looks up ip_src, ip_dst pair in 'ct'. Returns the action for the pair, reject-action if unknown. */
enum ofp_action_type
ctrl_table_lookup(const struct ctrl_table *ct, uint32_t ip_src, uint32_t ip_dst)
{
    struct ctrl_table_entry *e = search_bucket(ctrl_table_bucket(ct, ip_src, ip_dst), ip_src, ip_dst);
    if (e) {
        return e->action;
    } else {
        return -1;
    }
}

/* Expires all the ctrl_table entries in 'ct'. */
void
ctrl_table_flush(struct ctrl_table *ct)
{
    struct ctrl_table_entry *e;
    while (get_lru(ct, &e)){
        free_ctrl_table_entry(ct, e);
    }
}

/*void
ctrl_table_run(struct ctrl_table *ct, struct tag_set *set)
{
    struct ctrl_table_entry *e;
    while (get_lru(ml, &e) && time_now() >= e->expires) {
        if (set) {
            tag_set_add(set, e->tag);
        }
        free_mac_entry(ml, e);
    }
}

void
ctrl_table_wait(struct mac_learning *ml)
{
    if (!list_is_empty(&ml->lrus)) {
        struct mac_entry *e = mac_entry_from_lru_node(ml->lrus.next);
        poll_timer_wait((e->expires - time_now()) * 1000);
    }
}*/
