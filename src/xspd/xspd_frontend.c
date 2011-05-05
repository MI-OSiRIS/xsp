#include <stdlib.h>
#include <string.h>

#include "queue.h"

#include "xsp_tpool.h"
#include "xsp_listener.h"
#include "xsp_settings.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_protocols.h"
#include "xsp_config.h"
#include "xsp_session.h"
#include "compat.h"

#include "xspd_frontend.h"

static int xsp_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg);
void *xsp_default_handle_conn(void *arg);

int xsp_frontend_start() {
	char **protocols;
	int i, num_protocols;
	xspSettings *settings;

	protocols = xsp_get_protocol_list(&num_protocols);
	if (!protocols) {
		xsp_err(0, "No protocols loaded");
		return -1;
	}
	if (xsp_main_settings_get_section("listeners", &settings) != 0) {
		xsp_info(5, "No listeners sections found, going with defaults");
		settings = xsp_settings_alloc();
	}
	
	for (i = 0; i < num_protocols; i++) {
		xspListener *listener;
		int disabled = 0;

		if (xsp_settings_get_bool_2(settings, protocols[i], "disabled", &disabled) != 0) {
			xsp_info(8, "Did not find a 'disabled' element in section '%s'", protocols[i]);
			disabled = 0;
		} else {
			xsp_info(8, "Found 'disabled' in section '%s': %d", protocols[i], disabled);
		}
		
		xsp_info(0, "Setting up listener for %s", protocols[i]);
		
		if ((listener = xsp_protocol_setup_listener(protocols[i], protocols[i], settings, 0, xsp_frontend_connection_handler, NULL)) == NULL) {
			xsp_err(0, "Couldn't setup listener for protocol %s", protocols[i]);
			return -1;
		}
		if (xsp_listener_start(listener) != 0) {
			xsp_err(0, "Couldn't start listener for protocol %s", protocols[i]);
			return -1;
		}
	}

	strlist_free(protocols, num_protocols);
	xsp_settings_free(settings);
	return 0;
}

static int xsp_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg) {
	int retval;
    
	xsp_info(0, "spawning default_handle_conn for %s", conn->description);

	retval = xsp_tpool_exec(xsp_default_handle_conn, conn);
	
	xsp_info(0, "done spawning default_handle_conn for %s", conn->description);

	return retval;
}

void *xsp_default_handle_conn(void *arg) {
	xspConn *new_conn = (xspConn *) arg;
	xspMsg *msg;
	comSess *sess;
	xspAuthType *auth_type;
	int authenticated;
        int have_session;
	int sess_close;
	char **error_msgs;
	char *gw_name;

	authenticated = FALSE;
	have_session = FALSE;
	sess_close = FALSE;

	xsp_info(0,"xsp_default_handle_conn");
	do {
		msg = xsp_conn_get_msg(new_conn, 0);
		if (!msg) {
			xsp_err(5, "Did not receive properly formed message.");
			goto error_exit;
		}
		
		switch(msg->type) {
		
		case XSP_MSG_SESS_CLOSE:
			{
				// so we can close the connection after ping/pong
				xsp_info(10, "Close session message received.");
				xsp_free_msg(msg);
				goto error_exit;
			}
			break;
			
		case XSP_MSG_PING:
			{
				xsp_info(10, "PING/PONG");
				xsp_free_msg(msg);
				xsp_conn_send_msg(new_conn, XSP_MSG_PONG, NULL);
			}
			break;

		case XSP_MSG_AUTH_TYPE:
			{
				auth_type = msg->msg_body;
				/*
				if (xsp_authenticate_connection(new_conn, auth_type->name, &credentials) != 0) {
					xsp_err(0, "Authentication failed.");
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
					xsp_err(0, "Session open before authentication.");
					xsp_free_msg(msg);
					goto error_exit;
				}
				
				sess = xsp_convert_xspSess((xspSess *) msg->msg_body);
				if (!sess) {
					free(msg->msg_body);
					free(msg);
					xsp_err(0, "xspSess conversion failed");
					xsp_free_msg(msg);
					goto error_exit;
				}
				have_session = TRUE;
			}
			break;
		       
		default:
			{
				xsp_err(0, "Invalid message received");
				free(msg);
				goto error_exit;
			}
		}

	} while (!authenticated || !have_session);

	xsp_info(0, "new session: %s", xsp_session_get_id(sess));

	//free(msg->msg_body);
	//free(msg);
	
	LIST_INSERT_HEAD(&sess->parent_conns, new_conn, sess_entries);
	
	/*
	sess->credentials = credentials;
	xsp_session_set_user(sess, strdup(credentials->get_user(credentials)));
       
	xsp_info(0, "new user: \"%s\"(%s) from \"%s\"",
		 xsp_session_get_user(sess),
		 credentials->get_email(credentials),
		 credentials->get_institution(credentials));
	*/

	gettimeofday(&sess->start_time, NULL);

	// send an ACK back once session is opened
	xsp_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);

	error_msgs = (char**)malloc(sess->child_count * sizeof(char*));

	// now start another protocol loop
	do {
		msg = xsp_conn_get_msg(new_conn, 0);
                if (!msg) {
                        xsp_err(5, "Did not receive properly formed message.");
                        goto error_exit;
                }

                switch(msg->type) {
			
                case XSP_MSG_SESS_CLOSE:
                        {
                                xsp_info(10, "Close session message received.");
                                xsp_free_msg(msg);
                                sess_close = 1;
                        }
                        break;
		case XSP_MSG_PATH_OPEN:
			{
				if (xsp_session_setup_path(sess, msg->msg_body, &error_msgs) < 0)
					goto error_exit1;
				xsp_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);
				xsp_free_msg(msg);
			}
			break;
                case XSP_MSG_PING:
		        {
			        xsp_info(10, "PING/PONG");
				xsp_free_msg(msg);
				xsp_conn_send_msg(new_conn, XSP_MSG_PONG, NULL);
			}
			break;
		case XSP_MSG_DATA_OPEN:
			{
				if (xsp_session_data_open(sess, msg->msg_body, &error_msgs) < 0)
					goto error_exit1;
				//xsp_conn_send_msg(new_conn, XSP_MSG_SESS_ACK, NULL);
				xsp_free_msg(msg);
			}
			break;
		case XSP_MSG_APP_DATA:
			{
				if (xsp_session_app_data(sess, msg->msg_body, &error_msgs) < 0)
					goto error_exit1;
				xsp_free_msg(msg);
			}
			break;
		default:
                        {
                                xsp_err(0, "Invalid message received");
                                free(msg);
                                goto error_exit;
                        }
                }

        } while (!sess_close);

	gettimeofday(&sess->end_time, NULL);

	xsp_info(5, "session finished: %s", xsp_session_get_id(sess));

	xsp_session_finalize(sess);

	xsp_session_put_ref(sess);

	return NULL;

error_exit1:
	{
		int i;
		char nack_msg[1024];
 
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
		
 		xsp_info(5, "Sending NACK: %s", nack_msg);
 		xsp_conn_send_msg(new_conn, XSP_MSG_SESS_NACK, nack_msg);
 	}
	xsp_end_session(sess); // the new connection will get nuked(ugh this is ugly).
	return NULL;
	
error_exit:
	xsp_conn_shutdown(new_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
	xsp_conn_free(new_conn);
	return NULL;
}
