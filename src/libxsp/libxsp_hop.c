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
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libxsp_hop.h"

xspHop *xsp_alloc_hop() {
	xspHop *new_hop;

	new_hop = malloc(sizeof(xspHop));
	if (!new_hop)
		goto error_exit;

	bzero(new_hop, sizeof(xspHop));

	return new_hop;

error_exit:
	return NULL;
}

void xsp_free_hop(xspHop *hop, int free_children) {
	int i;

	if (free_children) {
		for(i = 0; i < hop->child_count; i++)
			xsp_free_hop(hop->child[i], 1);
	}

	if (hop->child)
		free(hop->child);

	free(hop);
}

/*
 *  int xsp_hop_merge_children(xspHop *dst, xspHop *src):
 *      Merges the children of dst and src together in dst. Note: this does not
 *      copy the children, both hops point to the same children.
 */
int xsp_hop_merge_children(xspHop *dst, xspHop *src) {
	xspHop **new_child_list;
	int i;

	if (src->child_count == 0)
		return 0;

	new_child_list = realloc(dst->child, sizeof(xspHop *) * (src->child_count + dst->child_count));
	if (!new_child_list)
		return -1;

	for(i = 0; i < src->child_count; i++) {
		new_child_list[dst->child_count + i] = src->child[i];
	}

	dst->child = new_child_list;
	dst->child_count = src->child_count;

	return 0;
}

int xsp_hop_add_child(xspHop *parent, xspHop *child) {
	struct xsp_hop **new_list;

	new_list = realloc(parent->child, sizeof(struct xsp_hop *) * (parent->child_count + 1));
	if (!new_list)
		goto error_exit;

	new_list[parent->child_count] = child;
	parent->child = new_list;

	parent->child_count++;

	return 0;

error_exit:
	return -1;
}

int xsp_hop_copy(xspHop **dest, xspHop *src) {
	int i;
	int ret;
	
	xspHop *hop;

	hop = malloc(sizeof(xspHop));
	if (!hop)
		return -1;
	
	hop->opt_type = src->opt_type;
	hop->flags = src->flags;
	hop->child_count = src->child_count;
	hop->session = src->session;

	memcpy(hop->hop_id, src->hop_id, XSP_HOPID_LEN + 1);
	memcpy(hop->protocol, src->protocol, XSP_PROTO_NAME_LEN + 1);

	hop->child = malloc(src->child_count * sizeof(xspHop*));
	
	for (i = 0; i < src->child_count; i++) {
		ret = xsp_hop_copy(&(hop->child[i]), src->child[i]);
		if (ret != 0)
			return -1;
	}

	*dest = hop;
	return 0;
}
	
int xsp_hop_total_child_count(xspHop *hop) {
	int i;
	int count = 0;
	
	for (i=0; i<hop->child_count; i++)
		count += xsp_hop_total_child_count(hop->child[i]);
	
	return hop->child_count + count;
}

