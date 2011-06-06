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
	libxspSecInfo *sec;

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
	
	sec = xsp_security("ezra", NULL, "/home/ezra/.ssh/id_rsa_pl.pub",
			   "/home/ezra/.ssh/id_rsa_pl", NULL);

	if (xsp_sess_set_security(sess, sec, XSP_SEC_NONE)) {
		fprintf(stderr, "could not set requested xsp security method\n");
		exit(-1);
	}

	/* argc - 1 is the ultimate dest */
	if (xsp_connect(sess)) {
		perror("xsp_client: connect failed");
		exit(errno);
	}

	char buf[20] = "This is a test";
	char *ret_buf = NULL;
	uint64_t ret_len;
	int ret_type;

	//xsp_send_msg(sess, buf, strlen(buf)+1, 0x20);
	//xsp_recv_msg(sess, (void**)&ret_buf, &ret_len, &ret_type);

	if (ret_buf) {
	  ret_buf[ret_len] = '\0';
	  printf("got message[%d]: %s\n", ret_type, ret_buf);
	  free(ret_buf);
	}
	
	libxspNetPath *path;
	path = xsp_net_path("OSCARS", XSP_NET_PATH_CREATE);
	
	//xsp_sess_signal_path(sess, path);

	xsp_close2(sess);

	return 0;
}
