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

#include "mongo.h"

struct sockaddr_in *nameport2sa(const char *name_port);

int main(int argc, char *argv[]) {
  int i;
  libxspSess *sess;

  bson b[1];

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

  bson_init(b);
  bson_append_double( b, "d", 3.14 );
  bson_append_string( b, "s", "hello" );
  bson_append_string_n( b, "s_n", "goodbye cruel world", 7 );
  bson_finish(b);

  bson_print(b);

  xsp_send_msg(sess, bson_data(b), bson_size(b), BLIPP_BSON_META);
  xsp_close2(sess);

  return 0;
}
