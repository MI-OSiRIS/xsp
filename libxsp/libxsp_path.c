#include <string.h>

#include "libxsp_hop.h"
#include "libxsp_path.h"

/*
 *  int xsp_path_merge_duplicates(xspHop *root):
 *      Goes through a path and removes any duplicate links between two nodes
 */
int xsp_path_merge_duplicates(xspHop *root) {
	int i, curr;

	curr = 0;
	do {
		// find a duplicate
		for(i = curr + 1; i < root->child_count; i++) {
			if (!strcmp(root->child[curr]->hop_id, root->child[i]->hop_id))
				break;
		}

		if (i < root->child_count) {
			// if we find a duplicate entry, merge the children together
			if (xsp_hop_merge_children(root->child[curr], root->child[i])) {
				return -1;
			}

			xsp_free_hop(root->child[i], 0);

			// move the final hop down to replace the removed node
			root->child[i] = root->child[root->child_count - 1];
			root->child_count--;
		} else {
			// no duplicate found, check the subtree below this hop
			if (xsp_path_merge_duplicates(root->child[curr])) {
				return -1;
			}

			curr++;
		}

	} while (curr < root->child_count);

	return 0;
}
