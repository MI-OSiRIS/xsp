#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>

#include "queue.h"
#include "hashtable.h"
#include "xsp_peering.h"

#include "xsp_unis.h"
#include "xsp_session.h"
#include "xsp_tpool.h"
#include "xsp_listener.h"
#include "xsp_settings.h"
#include "xsp_main_settings.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_protocols.h"
#include "xsp_config.h"
#include "xsp_auth.h"
#include "xsp_modules.h"

/* GLOBALS */
static struct hashtable *peer_table;
static pthread_cond_t ping_cond;
static pthread_mutex_t ping_lock;
static pthread_cond_t cntl_cond;
static pthread_mutex_t cntl_lock;

static xspPeerConfig config;
/* END GLOBALS */

int xsp_peering_init();
static int xsp_peering_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

void *xsp_peering_peer_conn_thread(void *arg);
void *xsp_peering_ping_thread(void *arg);

/* TODO: need public interface to allow other modules to send messages over peering connections */

xspModule xsp_peering_module = {
	.desc = "PEERING Module",
        .dependencies = "tcp",
	.init = xsp_peering_init,
	.opt_handler = xsp_peering_opt_handler
};

xspModule *module_info() {
	return &xsp_peering_module;
}

int xsp_peering_init() {
	const xspSettings *settings;
	xspModule *module;

	settings = xsp_main_settings();
	if (xsp_settings_get_int_2(settings, "peering", "keepalive", &config.keepalive_timer) != 0) {
		xsp_info(0, "Keepalive timeout not specified, using default %d", XSP_PEER_KEEPALIVE_TO);
		config.keepalive_timer = XSP_PEER_KEEPALIVE_TO;
	}

	xsp_settings_get_list_2(settings, "peering", "peers", &config.static_peer_list, &config.static_peer_count);
	if (!config.static_peer_count) {
		xsp_info(0, "No static peers found, remaining passive");
	}
	else {
		/* start threads that will connect to each static peer */
		pthread_t ctrl_thread;
		int i;

		for (i=0; i<config.static_peer_count; i++) {
			pthread_create(&ctrl_thread, NULL, xsp_peering_peer_conn_thread, config.static_peer_list[i]);
		}
	}

	/* basic test of UNIS service lookup */
	char service[] = "xspd";
	char **unis_peers;
	int num_peers;
	int i;

	/* invoke external lookup module (UNIS) to find other peers */
	if ((module = xsp_find_module("unis")) != NULL) {
		xsp_unis_get_service_access_points(service, &unis_peers, &num_peers);
		for (i=0; i<num_peers; i++) {
			xsp_info(0, "Also connecting to peer: %s", unis_peers[i]);
		}
	}
	
	return 0;
}

static int xsp_peering_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {
	
	/* option blocks arrive from peers, handle this */

	return 0;
}

void *xsp_peering_peer_conn_thread(void *arg) {
	char *peer = (char*) arg;
	
	xsp_info(0, "Connecting to peer: %s", peer);

	/* resolve peer name (could be IP, URN, hop-id, etc.)
	   start new session, but check if peer has already connected to us first
	   save in peer table
	   start keepalive thread */

	pthread_exit(NULL);
}

void *xsp_peering_ping_thread(void *arg) {
	comSess *sess;
	xspConn *conn;
	int rc;
	struct timeval tp;
	struct timespec sleep_time;
	struct timespec remaining_time;
	struct timespec pong_wait_time;

	sess = (comSess*) arg;
	
	conn = LIST_FIRST(&sess->child_conns);
        if (!conn) {
                xsp_err(0, "couldn't get slabs control conn!");
                goto error_exit;
        }

	while (1) {
		pthread_mutex_lock(&cntl_lock);
		{
			xspMsg ping_msg = {
				.version = sess->version,
				.type = XSP_MSG_PING,
				.flags = 0,
			};
			if (xsp_conn_send_msg(conn, &ping_msg, XSP_OPT_NULL) <= 0) {
				xsp_err(0, "PING send failed, thread exiting...");
				goto error_exit;
			}
		}
		pthread_mutex_unlock(&cntl_lock);
		
		gettimeofday(&tp, NULL);
		
		pong_wait_time.tv_sec = tp.tv_sec;
		pong_wait_time.tv_nsec = tp.tv_usec * 1000;
		pong_wait_time.tv_sec += config.keepalive_timer;
		
		pthread_mutex_lock(&ping_lock);
		{
			/* now we wait for the other side to PING us */
			rc = pthread_cond_timedwait(&ping_cond, &ping_lock, &pong_wait_time);
		}
		pthread_mutex_unlock(&ping_lock);

		if (rc == ETIMEDOUT) {
			xsp_err(0,
				"Did not receive PING from remote side within %d seconds",
				config.keepalive_timer);
			goto error_exit;
		}
		
		sleep_time.tv_sec = config.keepalive_timer;
		sleep_time.tv_nsec = 0;
		nanosleep(&sleep_time, &remaining_time);
	}

 error_exit:
	pthread_exit(NULL);
}
