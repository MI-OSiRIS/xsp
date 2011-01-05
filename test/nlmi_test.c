#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "option_types.h"
#include "libxsp_client.h"

#include "bson.h"

struct sockaddr_in *nameport2sa(const char *name_port);

int main(int argc, char *argv[])
{
	int i;
	libxspSess *sess;

	int bsz;
	bson_buffer bb;
	bson b;

	if (libxsp_init() < 0) {
		perror("libxsp_init(): failed");
		exit(errno);
	}

	sess = xsp_session();
	if (!sess) {
		perror("xsp_session() failed");
		exit(errno);
	}

	xsp_sess_appendchild(sess, argv[argc - 1], XSP_HOP_NATIVE);

	/* argc - 1 is the ultimate dest */
	if (xsp_connect(sess)) {
		perror("xsp_client: connect failed");
		exit(errno);
	}

	bson_buffer_init(&bb);
	bson_ensure_space(&bb, 131072);
	
	bson_append_start_object(&bb, "subject");
	bson_append_start_array(&bb, "host");

	for(i=0; i <= 5; i++) {
		bson_append_string(&bb, "", "test");
	}
	bson_append_finish_object(&bb); /* [host] */
	bson_append_finish_object(&bb); /* {subject} */

	bson_from_buffer(&b, &bb);
	bsz = bson_size(&b);

	bson_print(&b);

	xsp_send_msg(sess, b.data, bsz, NLMI_BSON);	
	
	xsp_close2(sess);

	return 0;
}
