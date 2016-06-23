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
#ifndef XSP_GLOBUS_H
#define XSP_GLOBUS_H

int xsp_globus_init();
int xsp_globus_authorize(xspConn *conn, void **ret_creds);
int xsp_globus_request_authorization(xspSess *sess, xspConn *new_conn);

#endif
