#ifndef CTRL_TABLE_H
#define CTRL_TABLE_H 1

#include "packets.h"

struct ctrl_table *ctrl_table_create(void);
void ctrl_table_destroy(struct ctrl_table *);

bool ctrl_table_learn(struct ctrl_table *, uint32_t ip_src, uint32_t ip_dst, enum ofp_action_type action);
enum ofp_action_type ctrl_table_lookup(const struct ctrl_table *, uint32_t ip_src, uint32_t ip_dst);

bool isempty(struct ctrl_table *);

void ctrl_table_flush(struct ctrl_table *);
//void ctrl_table_run(struct ctrl_table *, struct tag_set *);
//void ctrl_table_wait(struct ctrl_table *);

#endif
