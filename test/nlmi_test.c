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
	
	/*
	 *   "version" : [ 0, 0, 0 ],
	 */
	bson_append_start_array(&bb, "version");
	    bson_append_int(&bb, "", 0);
	    bson_append_int(&bb, "", 0);
	    bson_append_int(&bb, "", 0);
	bson_append_finish_object(&bb);


	/*
	 *   "subject" : {
     *         "_id": "sub1",
     *         "node": {
     *                 "hostName": "test.our.edu",
     *         },
     *   },
    */
	bson_append_start_object(&bb, "subject");
	    bson_append_string(&bb, "_id", "sub1");
	    bson_append_start_object(&bb, "node");
	        bson_append_string(&bb, "hostName", "test.our.edu");
	    bson_append_finish_object(&bb);
	bson_append_finish_object(&bb);


	/*   "param" : {
     *         "_id" : "param1",
     *   },
     */
	bson_append_start_object(&bb, "param");
	    bson_append_string(&bb, "_id", "param1");
	bson_append_finish_object(&bb);


	/*
	 *  "data": {
     *          "http://ggf.org/ns/nmwg/characteristic/utilization/2.0" : {
     *              "ts" : 1282786560,
     *              "n" : 10,
     *              "dt" : 5,
     *              "values" : {
     *                  "value" : [ 5, 7, 8, 3, 2, 10, 11, 20, 25, 21, ],
     *                  "valueUnits" : [
     *                          "Mbps", "Mbps", "Mbps", "Mbps", "Mbps",
     *                          "Mbps", "Mbps", "Mbps", "Mbps", "Mbps",
     *                  ],
     *               }
     *          }
     *   }
	 */
	bson_append_start_object(&bb, "data");
        bson_append_start_object(&bb,
                "http://ggf.org/ns/nmwg/characteristic/utilization/2.0");
            bson_append_int(&bb, "ts", 1282786560);
            bson_append_int(&bb, "n", 10);
            bson_append_int(&bb, "dt", 5);
            bson_append_start_object(&bb, "values");
                bson_append_start_array(&bb, "value");
                {
                    int value[] = { 5, 7, 8, 3, 2, 10, 11, 20, 25, 21 };
                    for (i = 0; i < 10; i++)
                        bson_append_int(&bb, "", value[i]);
                }
                bson_append_finish_object(&bb);
                bson_append_start_array(&bb, "valueUnis");
                    for (i = 0; i < 10; i++)
                        bson_append_string(&bb, "", "Mbps");
                bson_append_finish_object(&bb);
            bson_append_finish_object(&bb);
        bson_append_finish_object(&bb);
    bson_append_finish_object(&bb);

	bson_from_buffer(&b, &bb);
	bsz = bson_size(&b);

	bson_print(&b);

	xsp_send_msg(sess, b.data, bsz, NLMI_BSON);	
	
	xsp_close2(sess);

	return 0;
}
