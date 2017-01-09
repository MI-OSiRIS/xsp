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
#include "libxsp.h"
#include "libxsp_proto.h"

#ifdef HAVE_GLOBUS
#include "globus_common.h"
#endif

int xsp_globus_send_token(void *arg, void *token, size_t token_length) {
  int sd = *((int *) arg);
  xspGlobusToken xsp_token;

  xsp_token.token_length = token_length;
  xsp_token.token = token;

  xsp_put_msg(sd, 0, XSP_MSG_GLOBUS_TOKEN, NULL, &xsp_token);

  return 0;
}

int xsp_globus_get_token(void *arg, void **token, size_t *token_length) {
  int sd = *((int *) arg);
  xspGlobusToken *xsp_token;
  xspMsg *msg;

  msg = xsp_get_msg(sd, 0);
  if (!msg)
    goto error_exit;

  if (msg->type != XSP_MSG_GLOBUS_TOKEN)
    goto error_exit2;

  xsp_token = msg->msg_body;

  *token_length = xsp_token->token_length;

  *token = xsp_token->token;

  free(xsp_token);
  free(msg);

  return 0;

error_exit2:
  xsp_free_msg(msg);
error_exit:
  return -1;
}
