#include <stdlib.h>
#include <string.h>

#include "queue.h"

#include "xspd_tpool.h"
#include "xspd_frontend_default.h"
#include "xspd_listener.h"
#include "xspd_settings.h"
#include "xspd_conn.h"
#include "xspd_logger.h"
#include "xspd_protocols.h"
#include "xspd_config.h"
#include "xspd_session.h"
#include "compat.h"

static int xspd_frontend_connection_handler(xspdListener *listener, xspdConn *conn, void *arg);
void *xspd_default_handle_conn(void *arg);

int xspd_frontend_default_start() {
	char **protocols;
	int i, num_protocols;
	xspdSettings *settings;

	protocols = xspd_get_protocol_list(&num_protocols);
	if (!protocols) {
		xspd_err(0, "No protocols loaded");
		return -1;
	}
	if (xspd_main_settings_get_section("listeners", &settings) != 0) {
		xspd_info(5, "No listeners sections found, going with defaults");
		settings = xspd_settings_alloc();
	}
	
	for (i = 0; i < num_protocols; i++) {
		xspdListener *listener;
		int disabled = 0;

		if (xspd_settings_get_bool_2(settings, protocols[i], "disabled", &disabled) != 0) {
			xspd_info(8, "Did not find a 'disabled' element in section '%s'", protocols[i]);
			disabled = 0;
		} else {
			xspd_info(8, "Found 'disabled' in section '%s': %d", protocols[i], disabled);
		}
		
		xspd_info(0, "Setting up listener for %s", protocols[i]);
		
		if ((listener = xspd_protocol_setup_listener(protocols[i], protocols[i], settings, 0, xspd_frontend_connection_handler, NULL)) == NULL) {
			xspd_err(0, "Couldn't setup listener for protocol %s", protocols[i]);
			return -1;
		}
		if (xspd_listener_start(listener) != 0) {
			xspd_err(0, "Couldn't start listener for protocol %s", protocols[i]);
			return -1;
		}
	}

	strlist_free(protocols, num_protocols);
	xspd_settings_free(settings);
	return 0;
}

static int xspd_frontend_connection_handler(xspdListener *listener, xspdConn *conn, void *arg) {
	int retval;
    
	xspd_info(0, "spawning default_handle_conn for %s", conn->description);

	retval = xspd_tpool_exec(xspd_default_handle_conn, conn);
	
	xspd_info(0, "done spawning default_handle_conn for %s", conn->description);

	return retval;
}

void *xspd_default_handle_conn(void *arg) {
	xspdConn *new_conn = (xspdConn *) arg;
	xspMsg *msg;
	xspdSess *sess;
	xspAuthType *auth_type;
 	char **error_msgs;
	int authenticated;
        int have_session;
	int sess_close;

	char *gw_name;

	authenticated = FALSE;
	have_session = FALSE;
	sess_close = FALSE;

	xspd_info(0,"xspd_default_handle_conn \n");
	do {
		msg = xspd_conn_get_msg(new_conn, 0);
		if (!msg) {
			xspd_err(5, "Did not receive properly formed message.");
			goto error_exit;
		}
		
		switch(msg->type) {
		
		case XSP_MSG_SESS_CLOSE:
			{
				// so we can close the connection after ping/pong
				xspd_info(10, "Close session message received.");
				xsp_free_msg(msg);
				goto error_exit;
			}
			break;
			
		case XSP_MSG_PING:
			{
				xspd_info(10, "PING/PONG");
				xsp_free_msg(msg);
				xspd_conn_send_msg(new_conn, XSP_MSG_PONG, NULL);
			}
			break;

		case XSP_MSG_AUTH_TYPE:
			{
				auth_type = msg->msg_body;
				/*
				if (xspd_authenticate_connection(new_conn, auth_type->name, &credentials) != 0) {
					xspd_err(0, "Authentication failed.");
					goto error_exit;
				}
				*/
				xsp_free_msg(msg);
				authenticated = TRUE;
			}
			break;
			
		case XSP_MSG_SESS_OPEN:
			{
				if (!authenticated) {
					xspd_err(0, "Session open before authentication.");
					xsp_free_msg(msg);
					goto error_exit;
				}
				
				sess = xspd_convert_xspSess((xspSess *) msg->msg_body);
				if (!sess) {
					free(msg->msg_body);
					free(msg);
					xspd_err(0, "xspSess conversion failed");
					xsp_free_msg(msg);
					goto error_exit;
				}
				have_session = TRUE;
			}
			break;
		       
		default:
			{
				xspd_err(0, "Invalid message received");
				free(msg);
				goto error_exit;
			}
		}

	} while (!authenticated || !have_session);

	xspd_session_get_id(sess);

	xspd_info(0, "new session: %s", xspd_session_get_id(sess));

	free(msg->msg_body);
	free(msg);

	LIST_INSERT_HEAD(&sess->parent_conns, new_conn, sess_entries);
	
	error_msgs = (char **) malloc(sess->child_count * sizeof(char*));

	/*
	sess->credentials = credentials;
	xspd_session_set_user(sess, strdup(credentials->get_user(credentials)));
       
	xspd_info(0, "new user: \"%s\"(%s) from \"%s\"",
		 xspd_session_get_user(sess),
		 credentials->get_email(credentials),
		 credentials->get_institution(credentials));
	*/

	gettimeofday(&sess->start_time, NULL);

	// send an ACK back once session is opened
	xspd_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);
	
	// now start another protocol loop
	do {
                msg = xspd_conn_get_msg(new_conn, 0);
                if (!msg) {
                        xspd_err(5, "Did not receive properly formed message.");
                        goto error_exit;
                }

                switch(msg->type) {
			
                case XSP_MSG_SESS_CLOSE:
                        {
                                xspd_info(10, "Close session message received.");
                                xsp_free_msg(msg);
                                sess_close = 1;
                        }
                        break;
		case XSP_MSG_PATH_OPEN:
			{
				if (xspd_session_setup_path(sess, msg->msg_body, error_msgs) < 0)
					goto error_exit1;
				xspd_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);
				xsp_free_msg(msg);
			}
			break;
		case XSP_MSG_DATA_OPEN:
			{
				if (xspd_session_data_open(sess, msg->msg_body, error_msgs) < 0)
					goto error_exit1;
				//xspd_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);
				xsp_free_msg(msg);
			}
			break;
		case XSP_MSG_APP_DATA:
			{
				if (xspd_session_app_data(sess, msg->msg_body, error_msgs) < 0)
					goto error_exit1;
				xsp_free_msg(msg);
			}
			break;
		default:
                        {
                                xspd_err(0, "Invalid message received");
                                free(msg);
                                goto error_exit;
                        }
                }

        } while (!sess_close);

	gettimeofday(&sess->end_time, NULL);

	xspd_info(5, "session finished: %s", xspd_session_get_id(sess));

	xspd_session_finalize(sess);

	xspd_session_put_ref(sess);

	return NULL;

error_exit1:
	{
 		char nack_msg[1024];
 		int i;
 
 		nack_msg[0] = '\0';
 		if (!error_msgs) {
 			strlcat(nack_msg, "An internal error occurred", sizeof(nack_msg));
 		} else {
 			for(i = 0; i < sess->child_count; i++) {
 				if (error_msgs[i]) {
 					strlcat(nack_msg, "Connect to ", sizeof(nack_msg));
 					strlcat(nack_msg, xsp_hop_getid(sess->child[i]), sizeof(nack_msg));
 					strlcat(nack_msg, " failed: ", sizeof(nack_msg));
 					strlcat(nack_msg, error_msgs[i], sizeof(nack_msg));
 					strlcat(nack_msg, "\n", sizeof(nack_msg));
 				}
 			}
 		}
 
 		xspd_info(0, "Sending NACK");
 
 		xspd_conn_send_msg(new_conn, XSP_MSG_SESS_NACK, nack_msg);
 	}

	xspd_end_session(sess); // the new connection will get nuked(ugh this is ugly).
	return NULL;

error_exit:
	xspd_conn_shutdown(new_conn, (XSPD_SEND_SIDE | XSPD_RECV_SIDE));
	xspd_conn_free(new_conn);
	return NULL;
}
