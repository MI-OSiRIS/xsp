#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

#include "xspd_conn.h"
#include "xspd_logger.h"
#include "xspd_settings.h"
#include "xspd_session.h"

#include "libxsp.h"
#include "libxsp_proto.h"
/*
xspdConn_defStats *xspd_conn_stats_alloc_def() {
	xspdConn_defStats *retval;

	retval = malloc(sizeof(xspdConn_defStats));
	if (!retval)
		return NULL;

	bzero(retval, sizeof(xspdConn_defStats));

	return retval;
}

void xspd_conn_free_stats_def(xspdConn *conn) {
	xspdConn_defStats *stats = conn->stats_private;

	free(stats);
}
/*
int xspd_conn_default_get_stat(xspdConn *conn, uint16_t type, void *optval, size_t *optlen) {
	int retval = -1;

	switch(type) {
		case XSPD_STATS_BYTES_READ:
			if (*optlen >= sizeof(uint64_t)) {
				*((uint64_t *) optval) = ((xspdConn_defStats *) conn->stats_private)->bytes_read;
				*optlen = sizeof(uint64_t);
				retval = 0;
			}
			break;

		case XSPD_STATS_BYTES_WRITTEN:
			if (*optlen >= sizeof(uint64_t)) {
				*((uint64_t *) optval) = ((xspdConn_defStats *) conn->stats_private)->bytes_written;
				*optlen = sizeof(uint64_t);
				retval = 0;
			}
			break;

		default:
			break;
	}

	return retval;
}
*/
xspdConn *xspd_conn_alloc() {
	xspdConn *new_conn;

	new_conn = malloc(sizeof(xspdConn));
	if (!new_conn)
		goto error_exit;

	bzero(new_conn, sizeof(xspdConn));

	if (pthread_mutex_init(&(new_conn->lock), NULL))
		goto error_exit_conn;

	if (pthread_cond_init(&(new_conn->cond), NULL))
		goto error_exit_mutex;

	return new_conn;

error_exit_mutex:
	pthread_mutex_destroy(&(new_conn->lock));
error_exit_conn:
	free(new_conn);
error_exit:
	return NULL;
}

void xspd_conn_free(xspdConn *conn) {
	if (conn->conn_private != NULL)
		conn->free_conn_private2(conn);
	/*
	if (conn->stats_private != NULL)
		conn->free_stats2(conn);
	*/
	if (conn->settings)
		xspd_settings_free(conn->settings);

	if (conn->description)
		free(conn->description);

	if (conn->id)
		free(conn->id);

	if (conn->hostname)
		free(conn->hostname);

	pthread_mutex_destroy(&(conn->lock));
	pthread_cond_destroy(&(conn->cond));
	free(conn);
}

int xspd_conn_splice(xspdConn *src, xspdConn *sink, int fd, size_t len, int flags) {
	return src->splice2(src, sink, len, flags);
}

int xspd_conn_src_splice(xspdConn *conn, int fd,  size_t len, int flags) {
	return conn->src_splice2(conn, fd, len, flags);
}

int xspd_conn_sink_splice(xspdConn *conn, int fd, size_t len, int flags) {
	return conn->sink_splice2(conn, fd, len, flags);
}

int xspd_conn_read(xspdConn *conn, void *buf, size_t len, int flags) {
	return conn->read2(conn, buf, len, flags);
}

int xspd_conn_write(xspdConn *conn, const void *buf, size_t len, int flags) {
	return conn->write2(conn, buf, len, flags);
}

int xspd_conn_setbufsize(xspdConn *conn, uint8_t direction, int size) {
	return conn->setbufsize2(conn, direction, size);
}

int xspd_conn_settimeout(xspdConn *conn, uint8_t direction, int seconds) {
	return conn->settimeout2(conn, direction, seconds);
}
/*
int xspd_conn_get_stat (xspdConn *conn, uint16_t type, void *optval, size_t *optlen) {
	return conn->get_stat2(conn, type, optval, optlen);
}
*/
int xspd_conn_shutdown(xspdConn *conn, int side) {
	int n, was_connected;

	was_connected = (conn->status == STATUS_CONNECTED);

	n = conn->shutdown2(conn, side);

//	if (conn->status == STATUS_UNCONNECTED && was_connected && conn->session) {
//		lsd_session_event(conn->session, XSPD_CONN_CLOSED, conn->id);
//	}

	return n;
}

xspMsg *xspd_conn_get_msg(xspdConn *conn, unsigned int flags) {
	return conn->get_msg2(conn, flags);
}

int xspd_conn_send_msg(xspdConn *conn, uint8_t type, void *msg_body) {
	return conn->send_msg2(conn, type, msg_body);
}

xspMsg *xspd_conn_default_get_msg(xspdConn *conn, unsigned int flags) {
       char *buf = NULL;
       char hdr_buf[sizeof(xspMsgHdr)];
       int amt_read, remainder;
       xspMsg *msg;
       xspMsgHdr *hdr;

       // read the header in
       amt_read = xspd_conn_read(conn, hdr_buf, sizeof(xspMsgHdr), MSG_WAITALL);

       if (amt_read < sizeof(xspMsgHdr)) {
               if (amt_read < 0) {
		       perror("error:");
	       }
               goto error_exit;
       }

       hdr = (xspMsgHdr *) hdr_buf;

       // obtain the length of the message and verify that it fits in bounds
       remainder = ntohs(hdr->length);
       if (remainder < 0 || remainder > XSP_MAX_LENGTH) {
               goto error_exit;
       }

       if (remainder > 0) {
               // allocate space for the remainder
               buf = (char *) malloc(sizeof(char) * remainder);
               if (!buf)
                       goto error_exit;

               // grab the remainder
               amt_read = xspd_conn_read(conn, buf, remainder, MSG_WAITALL);
               if (amt_read < remainder) {
                       goto error_exit2;
               }
       }

       // allocate a message to return
       msg = (xspMsg *) malloc(sizeof(xspMsg));
       if (!msg) {
               goto error_exit2;
       }

       // fill in the message
       msg->type = hdr->type;
       msg->version = hdr->version;
       bin2hex(hdr->sess_id, msg->sess_id, XSP_SESSIONID_LEN);

       if (xsp_parse_msgbody(msg, buf, amt_read, &(msg->msg_body)) != 0)
               goto error_exit3;

       if (buf)
               free(buf);

       return msg;

error_exit3:
       free(msg);
error_exit2:
       if (buf)
               free(buf);
error_exit:
       return NULL;
}

int xspd_conn_default_send_msg(xspdConn *conn, uint8_t type, void *msg_body) {
       char *msg_buf;
       int msg_buf_len;
       int msg_len;
       int retval;
       xspMsg msg;

       msg_buf = (char *) malloc(sizeof(char) * XSP_MAX_LENGTH);
       if (!msg_buf)
               goto error_exit;

       msg_buf_len = XSP_MAX_LENGTH;

       msg.version = XSP_v0;
       msg.type = type;
       msg.msg_body = msg_body;

       if (conn->session)
	       memcpy(msg.sess_id, xspd_session_get_id(conn->session), 2*XSP_SESSIONID_LEN+1);
       else
	       bzero(msg.sess_id, XSP_SESSIONID_LEN*2);
       
       msg_len = xsp_writeout_msg(msg_buf, msg_buf_len, XSP_v0, type, (void*)&msg, msg_body);
       if (msg_len < 0)
               goto error_exit2;

       retval = xspd_conn_write(conn, msg_buf, msg_len, 0);

       free(msg_buf);

       return retval;

error_exit2:
       free(msg_buf);
error_exit:
       return -1;
}
