#ifndef __LIBXSP_H
#define __LIBXSP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#ifdef DEBUG
#define d_printf(fmt, args...) fprintf(stderr, "XSP:"fmt, ##args)
#else
#define d_printf(fmt, args...)
#endif

#include "xsp-proto.h"
#include "libxsp_session.h"
#include "libxsp_sec.h"
#include "libxsp_hop.h"
#include "libxsp_block.h"
#include "libxsp_path.h"
#include "libxsp_net_path.h"

/* XSP Defines */

#define XSP_MSG_NOWAIT                  0x01

#define XSP_SESS_SAVE_STREAM	        0x01
#define XSP_SESS_LSRR		        0x02

#define XSP_HOP_NATIVE 	                0x01
#define XSP_UNNECESSARY	                0x02

#define XSP_DEFAULT_SPORT               0

#define XSP_MSG_INVALID			0
#define XSP_MSG_SESS_OPEN		1
#define XSP_MSG_SESS_ACK		2
#define XSP_MSG_SESS_CLOSE		3
#define XSP_MSG_BLOCK_HEADER		4
#define XSP_MSG_AUTH_TYPE		8
#define XSP_MSG_AUTH_TOKEN		9
#define XSP_MSG_SESS_NACK		10
#define XSP_MSG_PING			11
#define XSP_MSG_PONG			12
#define XSP_MSG_DATA_CHAN               13
#define XSP_MSG_NET_PATH                14
#define XSP_MSG_APP_DATA                15
#define XSP_MSG_SLAB_INFO               16


/* XSP Objects */

typedef struct xsp_message_t {
        uint8_t version;
        uint8_t flags;
        uint16_t type;
	uint16_t opt_cnt;

        struct xsp_addr src_eid;
        struct xsp_addr dst_eid;

	char sess_id[2*XSP_SESSIONID_LEN + 1];
	void *msg_body;
} xspMsg;

typedef struct xsp_authorization_type_t {
	char name[XSP_AUTH_NAME_LEN];
} xspAuthType;

typedef struct xsp_auth_token_t {
	size_t token_length;
	void *token;
} xspAuthToken;

typedef struct xsp_data_open_header_t {
	uint16_t flags;
	char hop_id[XSP_HOPID_LEN];
	char proto[XSP_PROTO_NAME_LEN];
} xspDataOpen;

typedef struct xsp_rdma_mr_t {
	uintptr_t addr;
	uint64_t size;
	uint32_t rkey;
} xspRDMA_MR;

typedef struct slab_record_t {
	char sess_id[2*XSP_SESSIONID_LEN + 1];
        uint16_t flags;
        uint32_t offset;
        uint32_t length;
        uint32_t crc;
	union {
                struct xsp_rdma_mr_t mr;
        } rdma;
} xspSlabRec;

typedef struct slabs_info_t {
	uint32_t seq;
        uint32_t length;
        uint32_t rec_count;
        xspSlabRec **entries;
} xspSlabInfo;

/* XSP Functions */
int xsp_init();
void xsp_free_msg(xspMsg *msg);

struct addrinfo *xsp_lookuphop(const char *hop_id);

char *xsp_sa2hopid(const struct sockaddr *sa, SOCKLEN_T sa_len, int resolve);

char *xsp_sa2hopid_r(const struct sockaddr *sa, SOCKLEN_T sa_len, char *output_buf, size_t buflen, int resolve);

int xsp_make_connection(char *hop_id);

int xsp_set_eid(struct xsp_addr *eid, void *arg, int eid_type);

int xsp_make_hopid(const char *name, const int port, char *output_buf, size_t buflen);
int xsp_parse_hopid(const char *hop_id, char **ret_server, char **ret_port);

int gen_rand_hex(char *output_buf, int size);

long gen_rand_seed();

#endif /* __LIBXSP_H */
