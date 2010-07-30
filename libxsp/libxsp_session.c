#include <stdlib.h>
#include <strings.h>

#include "compat.h"

#include "libxsp_session.h"
#include "libxsp_path.h"

xspSess *xsp_alloc_sess() {
	xspSess *new_sess;

	new_sess = malloc(sizeof(xspSess));
	if (!new_sess)
		goto error_exit;

	bzero(new_sess, sizeof(*new_sess));

	return new_sess;

error_exit:
	return NULL;
}

void xsp_free_sess(xspSess *sess) {
	int i;

	if (sess->child) {
		for(i = 0; i < sess->child_count; i++) {
			xsp_free_hop(sess->child[i], 1);
		}

		free(sess->child);
	}

	free(sess);
}

int xsp_sess_addhop(xspSess *sess, xspHop *hop) {
	xspHop **new_list;
	int new_count;

	new_count = sess->child_count + 1;

	new_list = (xspHop **) realloc(sess->child, sizeof(xspHop *) * new_count);
	if (!new_list)
		return -1;

	sess->child = new_list;

	sess->child[sess->child_count] = hop;
	sess->child_count++;

	hop->session = sess;

	return 0;
}
