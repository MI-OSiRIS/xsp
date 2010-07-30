#include <stdlib.h>
#include <strings.h>

#include "compat.h"
#include "libxsp_hop.h"

xspHop *xsp_alloc_hop() {
	xspHop *new_hop;

	new_hop = malloc(sizeof(xspHop));
	if (!new_hop)
		goto error_exit;

	bzero(new_hop, sizeof(*new_hop));

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

inline char *xsp_hop_getid(xspHop *hop) {
	return hop->hop_id;
}

inline void xsp_hop_setid(xspHop *hop, const char *hop_id) {
	strlcpy(hop->hop_id, hop_id, XSP_HOPID_LEN + 1);
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

inline void xsp_hop_set_flag(xspHop *hop, uint16_t flag) {
	hop->flags |= flag;
}

inline int xsp_hop_check_flag(xspHop *hop, uint16_t flag) {
	return (hop->flags & flag);
}
