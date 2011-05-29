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

struct sockaddr_in *nameport2sa(const char *name_port);

int main(int argc, char *argv[])
{
	libxspSess *sess;

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

	char buf[20] = "This is a test";
	char *ret_buf;
	uint64_t ret_len;
	int ret_type;

	xsp_send_msg(sess, buf, strlen(buf)+1, 0x20);
	xsp_recv_msg(sess, (void**)&ret_buf, &ret_len, &ret_type);
	ret_buf[ret_len] = '\0';

	printf("got message[%d]: %s\n", ret_type, ret_buf);

	free(ret_buf);

	xsp_close2(sess);

	return 0;
}
