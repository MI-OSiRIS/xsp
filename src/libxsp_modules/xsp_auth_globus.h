#ifndef XSP_GLOBUS_H
#define XSP_GLOBUS_H

int xsp_globus_init();
int xsp_globus_authorize(xspConn *conn, void **ret_creds);
int xsp_globus_request_authorization(xspSess *sess, xspConn *new_conn);

#endif
