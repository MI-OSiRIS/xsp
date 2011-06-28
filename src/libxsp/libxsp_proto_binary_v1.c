#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libxsp_proto_binary_v1.h"

#include "compat.h"

#define LIBXSP_PROTO_BINARY_V1_ID	XSP_v1

#define LIBXSP_PROTO_BINARY_V1_MAX 	XSP_MSG_SLAB_INFO

static xspProtoHandler bin_handler_v1;

int libxsp_proto_binary_v1_init() {
	bin_handler_v1.write_hdr = xsp_writeout_hdr;

	bin_handler_v1.parse = (int (**)(const void*, int, void**)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_V1_MAX + 1));
	if (!bin_handler_v1.parse)
		return -1;

	bin_handler_v1.writeout = (int (**)(void*, char*, int)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_V1_MAX + 1));
	if (!bin_handler_v1.writeout)
		return -1;

	bin_handler_v1.parse[XSP_MSG_INVALID] = NULL;
	bin_handler_v1.parse[XSP_MSG_SESS_OPEN] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_SESS_ACK] = NULL;
	bin_handler_v1.parse[XSP_MSG_SESS_CLOSE] = NULL;
	bin_handler_v1.parse[XSP_MSG_AUTH_TYPE] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_AUTH_TOKEN] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_BLOCK_HEADER] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_SESS_NACK] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_PING] = NULL;
	bin_handler_v1.parse[XSP_MSG_PONG] = NULL;
	bin_handler_v1.parse[XSP_MSG_DATA_CHAN] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_NET_PATH] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_APP_DATA] = xsp_parse_app_data_block_list;
	bin_handler_v1.parse[XSP_MSG_SLAB_INFO] = xsp_parse_default_block_list;

	bin_handler_v1.writeout[XSP_MSG_INVALID] = NULL;
	bin_handler_v1.writeout[XSP_MSG_SESS_OPEN] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_SESS_ACK] = NULL;
	bin_handler_v1.writeout[XSP_MSG_SESS_CLOSE] = NULL;
	bin_handler_v1.writeout[XSP_MSG_AUTH_TYPE] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_AUTH_TOKEN] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_BLOCK_HEADER] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_SESS_NACK] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_PING] = NULL;
	bin_handler_v1.writeout[XSP_MSG_PONG] = NULL;
	bin_handler_v1.writeout[XSP_MSG_DATA_CHAN] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_NET_PATH] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_APP_DATA] = xsp_writeout_app_data_block_list;
	bin_handler_v1.writeout[XSP_MSG_SLAB_INFO] = xsp_writeout_default_block_list;

	bin_handler_v1.max_msg_type = LIBXSP_PROTO_BINARY_V1_MAX;

	return xsp_add_proto_handler(LIBXSP_PROTO_BINARY_V1_ID, &bin_handler_v1);
}

static int xsp_writeout_hdr(void *arg, char *buf) {
	d_printf("in v1 writeout hdr\n");

        xspMsg *msg = (xspMsg*)arg;
        xspv1MsgHdr *hdr;

        hdr = (xspv1MsgHdr *) buf;

        d_printf("xsp_writeout_hdr: ver   : %d\n", msg->version);
        d_printf("xsp_writeout_hdr: flags : %d\n", msg->flags);
        d_printf("xsp_writeout_hdr: type  : %d\n", msg->type);
	d_printf("xsp_writeout_hdr: opt_c : %d\n", msg->opt_cnt);

        hdr->version = msg->version;
        hdr->flags = msg->flags;
        hdr->type = htons(msg->type);
	hdr->opt_cnt = htons(msg->opt_cnt);
	hdr->reserved = 0x0000;
	
        memcpy(&(hdr->src_eid), &(msg->src_eid), sizeof(struct xsp_addr));
        memcpy(&(hdr->dst_eid), &(msg->dst_eid), sizeof(struct xsp_addr));

        if (msg->sess_id != NULL) {
                d_printf("xsp_writeout_hdr: sid : %s\n", msg->sess_id);
                hex2bin(msg->sess_id, hdr->sess_id, XSP_SESSIONID_LEN * 2);
        } else {
                bzero(hdr->sess_id, XSP_SESSIONID_LEN);
        }

        return sizeof(xspv1MsgHdr);
}

static int xsp_writeout_block_hdr(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
        xspv1BlockHdr *hdr;
        int len_offset = 0;

        // if there isn't enough room to write the structure, don't do it
        if (remainder < sizeof(xspv1BlockHdr)) {
                return -1;
        }

        hdr = (xspv1BlockHdr *) buf;

        hdr->type = htons(block->type);
        hdr->sport = htons(block->sport);

        if (block->length >= XSP_MAX_LENGTH) {
                uint64_t *len = (uint64_t*)(buf+3*sizeof(uint16_t));
		uint64_t nbo = htonll(block->length);
                memcpy(len, &nbo, sizeof(uint64_t));
                hdr->length = htons(0xFFFF);
                len_offset = sizeof(uint64_t);
        }
        else
                hdr->length = htons(block->length);

        return sizeof(xspv1BlockHdr) + len_offset;
}

static int xsp_parse_default_block_list(const void *arg, int length, void **msg_body) {
	xspBlockList *bl = (xspBlockList*) arg;
	xspBlock *ret_block;
        xspBlock *block;
        int n;

        bl = (xspBlockList *) arg;

        for (block = bl->first; block != NULL; block = block->next) {
                switch (block->type) {
                case XSP_OPT_HOP:
                        n = xsp_parse_hops(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_AUTH_TYP:
                        n = xsp_parse_auth_type_msg(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_AUTH_TOK:
                        n = xsp_parse_auth_token_msg(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_NACK:
                        n = xsp_parse_nack_msg(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_DATA:
                        n = xsp_parse_data_chan_msg(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_PATH:
                        n = xsp_parse_net_path_msg(block, block->length, (void**)&ret_block);
                        break;
                case XSP_OPT_SLAB:
                        n = xsp_parse_slab_info(block, block->length, (void**)&ret_block);
                        break;
                default:
                        n = xsp_parse_block_msg(block, block->length, (void**)&ret_block);
                        break;
                }

		if (n != 0) {
			d_printf("error parsing block type %d\n", block->type);
			return -1;
		}
	}
	*msg_body = bl;
        return 0;
}

static int xsp_parse_app_data_block_list(const void *arg, int remainder, void **msg_body) {
	xspBlockList *bl = (xspBlockList*) arg;
        xspBlock *ret_block;
        xspBlock *block;
        int n;

        bl = (xspBlockList *) arg;

        for (block = bl->first; block != NULL; block = block->next) {
		n = xsp_parse_block_msg(block, block->length, (void**)&ret_block);
	}
	*msg_body = bl;
	return 0;
}

static int xsp_writeout_default_block_list(void *arg, char *buf, int remainder) {
	xspBlockList *bl;
	xspBlock *block;
	int orig_remainder = 0;
	int n;

	orig_remainder = remainder;
	
	bl = (xspBlockList *) arg;

	for (block = bl->first; block != NULL; block = block->next) {
		switch (block->type) {
		case XSP_OPT_HOP:
			n = xsp_writeout_hops(block, buf, remainder);
			break;
		case XSP_OPT_AUTH_TYP:
			n = xsp_writeout_auth_type_msg(block, buf, remainder);
			break;
		case XSP_OPT_AUTH_TOK:
			n = xsp_writeout_auth_token_msg(block, buf, remainder);
			break;
		case XSP_OPT_NACK:
			n = xsp_writeout_nack_msg(block, buf, remainder);
			break;
		case XSP_OPT_DATA:
			n = xsp_writeout_data_chan_msg(block, buf, remainder);
			break;
		case XSP_OPT_PATH:
			n = xsp_writeout_net_path_msg(block, buf, remainder);
			break;
		case XSP_OPT_SLAB:
			n = xsp_writeout_slab_info(block, buf, remainder);
			break;
		default:
			n = xsp_writeout_block_msg(block, buf, remainder);
			break;
		}
		remainder -= n;
	}

	return orig_remainder - remainder;
}

static int xsp_writeout_app_data_block_list(void *arg, char *buf, int remainder) {
        xspBlockList *bl;
        xspBlock *block;
        int orig_remainder = 0;
        int n;

        orig_remainder = remainder;

        bl = (xspBlockList *) arg;

        for (block = bl->first; block != NULL; block = block->next) {
		n = xsp_writeout_block_msg(block, buf, remainder);
		remainder -= n;
	}
	
	return orig_remainder - remainder;
}

static int xsp_parse_hops(const void *arg, int length, void **msg_body) {
	xspBlock *block = (xspBlock*)arg;
	char *buf = block->data;
	xspHop *hop;
	xspSess *ret_sess = NULL;
        xspSessOpen_HDR *hdr;
        int remainder;
        xspHop *next_hop;
	int size = 0;

        ret_sess = xsp_alloc_sess();
        if (!ret_sess)
                goto parse_error;

        hdr = (xspSessOpen_HDR *) buf;

        remainder = length;

        if (remainder < sizeof(xspSessOpen_HDR))
                goto parse_error;

        bin2hex(hdr->sess_id, ret_sess->sess_id, XSP_SESSIONID_LEN);
	ret_sess->hop_flags = ntohl(hdr->hop_flags);

	ret_sess->child = NULL;
	ret_sess->child_count = 0;
	
	buf += sizeof(xspSessOpen_HDR);
        remainder -= sizeof(xspSessOpen_HDR);

        while (remainder > 0) {
                int hop_size;

                d_printf("Grabbing next hop info\n");
		
                next_hop = xsp_parsehop(ret_sess, buf, remainder, &hop_size);
                if (!next_hop)
                        goto parse_error;

                if (xsp_sess_addhop(ret_sess, next_hop))
                        goto parse_error;
		
                buf += hop_size;
                remainder -= hop_size;
        }
	
	block->data = ret_sess;
	block->length = 0;

	*msg_body = block;

	return 0;

 parse_error:
        if (ret_sess)
                xsp_free_sess(ret_sess);

        return -1;
}

static xspHop *xsp_parsehop(xspSess *sess, void *arg, int remainder, int *size) {
	char *buf = (char*) arg;
	xspHop *new_hop = NULL;
	xspHop_HDR *hdr = NULL;
	int orig_remainder = 0;
	uint16_t child_count = 0;
	int child_size = 0;
	int i = 0;

	// verify that we have enough remaining to have a hop
	if (remainder < sizeof(xspHop_HDR)) {
		goto parse_error;
	}

	orig_remainder = remainder;

	// allocate a new hop
	new_hop = xsp_alloc_hop();
	if (!new_hop)
		return NULL;

	new_hop->session = sess;

	hdr = (xspHop_HDR *) buf;

	// grab the hop id and NULL terminate it
	memcpy(new_hop->hop_id, hdr->id, XSP_HOPID_LEN);
	new_hop->hop_id[XSP_HOPID_LEN] = '\0';

	d_printf("Parsing: %s\n", new_hop->hop_id);

	memcpy(new_hop->protocol, hdr->protocol, XSP_PROTO_NAME_LEN); 
	new_hop->protocol[XSP_PROTO_NAME_LEN] = '\0';

	// grab the flags for the given hop
	new_hop->flags = ntohs(hdr->flags);

	// grab the number of children to be read in
	child_count = ntohs(hdr->child_count);

	buf += sizeof(xspHop_HDR);
	remainder -= sizeof(xspHop_HDR);

	if (child_count == 0) {
		new_hop->child = NULL;
		new_hop->child_count = 0;
	} else {

		// allocate space for the children
		new_hop->child = (xspHop **) malloc(sizeof(xspHop *) * child_count);
		if (!new_hop->child)
			goto parse_error;

		// initialize the child count so that freeing works properly
		new_hop->child_count = 0;

		// try to parse each child
		for(i = 0; i < child_count; i++) {
			new_hop->child[i] = xsp_parsehop(sess, buf, remainder, &child_size);
			if (!new_hop->child[i])
				goto parse_error;

			buf += child_size;
			remainder -= child_size;

			new_hop->child_count++;
		}
	}

	*size = orig_remainder - remainder;

	return new_hop;

parse_error:
	if (new_hop)
		free(new_hop);
	return NULL;
}

static int xsp_parse_auth_token_msg(const void *arg, int remainder, void **msg_body) {
	xspBlock *block = (xspBlock*) arg;
	char *buf = (char*) block->data;
	xspAuthToken_HDR *hdr;
	xspAuthToken *new_token;

	*msg_body = NULL;

	if (remainder < sizeof(xspAuthToken_HDR))
		return -1;

	// allocate a new auth_token token structure
	new_token = malloc(sizeof(xspAuthToken));
	if (!new_token)
		return -1;

	hdr = (xspAuthToken_HDR *) buf;

	new_token->token_length = ntohs(hdr->token_length);

	remainder -= sizeof(xspAuthToken_HDR);

	// validate the token
	if (new_token->token_length > 1<<24 || new_token->token_length > remainder) {
		free(new_token);
		return -1;
	}
	// allocate space for the token
	new_token->token = malloc(sizeof(char) * new_token->token_length);
	if (!new_token->token) {
		free(new_token);
		return -1;
	}

	// copy the token from the message
	memcpy(new_token->token, buf + sizeof(xspAuthToken_HDR), new_token->token_length);

	block->data = new_token;
	block->length = 0;

	// set the return value
	*msg_body = block;

	// return success
	return 0;
}

static int xsp_parse_nack_msg(const void *arg, int remainder, void **msg_body) {
        xspBlock *block = (xspBlock*) arg;
	char *buf = (char*) block->data;
        xspSessNack_HDR *hdr;
	uint16_t len;
	char *error_msg;

	*msg_body = NULL;

	if (remainder < sizeof(xspSessNack_HDR))
                return -1;

        hdr = (xspSessNack_HDR *) buf;

	len = ntohs(hdr->length);

	remainder -= sizeof(xspSessNack_HDR);
	buf += sizeof(xspSessNack_HDR);

	// validate the token
	if (len > remainder) {
		return -1;
	}

	// allocate space for the token
	error_msg = malloc(sizeof(char) * (len + 1));
	if (!error_msg) {
		return -1;
	}

	// copy the token from the message
	memcpy(error_msg, buf, len);

	block->data = error_msg;
	block->length = 0;

	// set the return value
	*msg_body = block;

	// return success
	return 0;
}

static int xsp_parse_block_msg(const void *arg, int remainder, void **msg_body) {
	xspBlock *block = (xspBlock*) arg;

	// this is a block with data transparent to libxsp
	*msg_body = block;

	return 0;
}

static int xsp_parse_auth_type_msg(const void *arg, int remainder, void **msg_body) {
	xspBlock *block = (xspBlock*) arg;
	xspAuthType_HDR *hdr = (xspAuthType_HDR*) block->data;
	xspAuthType *new_auth_type;

	*msg_body = NULL;

	// allocate a new auth_type token structure
	new_auth_type = malloc(sizeof(xspAuthType));
	if (!new_auth_type)
		return -1;

	// read in the only entry so far in the header
	memcpy(new_auth_type->name, hdr->name, XSP_AUTH_NAME_LEN);
	
	free(block->data);
	block->data = new_auth_type;
	block->length = 0;

	// set the return value
	*msg_body = block;

	// return success
	return 0;
}

static int xsp_parse_data_chan_msg(const void *arg, int remainder, void **msg_body) {
	xspBlock *block = (xspBlock*) arg;
	xspDataOpen_HDR *hdr = (xspDataOpen_HDR*) block->data;
	xspDataOpen *new;

	*msg_body = NULL;

	new = malloc(sizeof(xspDataOpen));
	if (!new)
		return -1;
	
	memcpy(new->hop_id, hdr->hop_id, XSP_HOPID_LEN);
	new->hop_id[XSP_HOPID_LEN] = '\0';

	new->flags = ntohs(hdr->flags);

	block->data = new;
	block->length = 0;

	*msg_body = block;

	return 0;
}

static int xsp_parse_net_path_msg(const void *arg, int remainder, void **msg_body) {
	xspBlock *block = (xspBlock*) arg;
	char *buf = (char*) block->data;
	xspNetPath_HDR *hdr;
	xspNetPath *new;
	int i;

	*msg_body = NULL;

	new = xsp_alloc_net_path();
	if (!new)
		return -1;
	
	hdr = (xspNetPath_HDR *) buf;

	memcpy(new->type, hdr->type, XSP_NET_PATH_LEN);
	new->type[XSP_NET_PATH_LEN] = '\0';
        new->action = ntohs(hdr->action);
        new->rule_count = ntohs(hdr->rule_count);
	
	new->rules = (xspNetPathRule **)malloc(new->rule_count * sizeof(xspNetPathRule*));
	if (!new->rules)
		return -1;

	buf += sizeof(xspNetPath_HDR);

        for (i = 0; i < new->rule_count; i++) {
		xspNetPathRule *rule;
                xspNetPathRule_HDR *rhdr;

		rhdr = (xspNetPathRule_HDR *) buf;

                rule = new->rules[i];

                memcpy(&(rule->src_eid), &(rhdr->src_eid), sizeof(struct xsp_addr));
                memcpy(&(rule->src_mask), &(rhdr->src_mask), sizeof(struct xsp_addr));
                memcpy(&(rule->dst_eid), &(rhdr->dst_eid), sizeof(struct xsp_addr));
                memcpy(&(rule->dst_mask), &(rhdr->dst_mask), sizeof(struct xsp_addr));

                rule->src_port_min = ntohs(rhdr->src_port_min);
                rule->src_port_max = ntohs(rhdr->src_port_max);
                rule->dst_port_min = ntohs(rhdr->dst_port_min);
                rule->dst_port_max = ntohs(rhdr->dst_port_max);

                rule->direction = ntohs(rhdr->direction);
                rule->bandwidth = ntohll(rhdr->bandwidth);
                rule->status = ntohs(rhdr->status);

                buf += sizeof(xspNetPathRule_HDR);
        }

	block->data = new;
	block->length = 0;

	*msg_body = block;
	
	return 0;
}

static int xsp_writeout_hops(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
        xspHop *hop = block->data;
	xspSessOpen_HDR *sess_hdr;
	int bhdr_size;
	int child_size;
	int i;

        block->length = sizeof(xspSessOpen_HDR) + xsp_hop_total_child_count(hop) * sizeof(xspHop_HDR);

        bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
		goto write_error;

        remainder -= bhdr_size;
	buf += bhdr_size;

	sess_hdr = (xspSessOpen_HDR *) buf;

        hex2bin(hop->session->sess_id, sess_hdr->sess_id, 2*XSP_SESSIONID_LEN);
	sess_hdr->hop_flags = htonl(hop->flags);

        remainder -= sizeof(xspSessOpen_HDR);
        buf += sizeof(xspSessOpen_HDR);

        // if there isn't enough room to write the structure, don't do it
        if (remainder < sizeof(xspHop_HDR)) {
                goto write_error;
        }

	for(i = 0; i < hop->child_count; i++) {

                child_size = xsp_writeouthop(hop->child[i], buf, remainder);
                if (child_size < 0)
			goto write_error;

                buf += child_size;
                remainder -= child_size;
        }

	return bhdr_size + block->length;
	
 write_error:
	return -1;
}

static int xsp_writeouthop(xspHop *hop, char *buf, int remainder) {
	int i;
	int orig_remainder;
	xspHop_HDR *hdr;
	int child_size;

	if (remainder < sizeof(xspHop_HDR))
		goto write_error;

	if (!hop) {
		d_printf("Error: specified writeout of NULL hop");
		goto write_error;
	}

	orig_remainder = remainder;

	d_printf("Writing %s hop information\n", hop->hop_id);

	hdr = (xspHop_HDR *) buf;
	
	memcpy(hdr->id, hop->hop_id, XSP_HOPID_LEN);
	memcpy(hdr->protocol, hop->protocol, XSP_PROTO_NAME_LEN); 

	hdr->flags = htons(hop->flags);
	hdr->child_count = htons(hop->child_count);

	buf += sizeof(xspHop_HDR);
	remainder -= sizeof(xspHop_HDR);

	for(i = 0; i < hop->child_count; i++) {
		child_size = xsp_writeouthop(hop->child[i], buf, remainder);
		if (child_size < 0)
			goto write_error;

		buf += child_size;
		remainder -= child_size;
	}

	return orig_remainder - remainder;

write_error:
	return -1;
}

static int xsp_writeout_auth_token_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	xspAuthToken *xsp_token = block->data;
	xspAuthToken_HDR *hdr;
	int bhdr_size;
	
	block->length = sizeof(xspAuthToken_HDR) + xsp_token->token_length;

	bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
                return -1;

	remainder -= bhdr_size;
	// if there isn't enough room to write the structure, don't do it
	if (remainder < sizeof(xspAuthToken_HDR)) {
		return -1;
	}

	buf += bhdr_size;
	hdr = (xspAuthToken_HDR *) buf;

	// writeout the auth_token token structure in network byte order
	hdr->token_length = htons(xsp_token->token_length);

	remainder -= sizeof(xspAuthToken_HDR);

	if (remainder < xsp_token->token_length)
		return -1;

	memcpy(buf + sizeof(xspAuthToken_HDR), xsp_token->token, xsp_token->token_length);

	return bhdr_size + block->length;
}

static int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	xspAuthType *auth_type = block->data;
	xspAuthType_HDR *hdr;
	int bhdr_size;

	block->length = XSP_AUTH_NAME_LEN;

	bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
	if (bhdr_size < 0)
		return -1;

	remainder -= bhdr_size;
	if (remainder < sizeof(xspAuthType_HDR)) {
		return -1;
	}

	buf += bhdr_size;	
	hdr = (xspAuthType_HDR*) buf;
	memcpy(hdr->name, auth_type->name, block->length);

	return bhdr_size + block->length;
}

static int xsp_writeout_block_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	int bhdr_size;

        bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
                return -1;

        remainder -= bhdr_size;
	if (remainder < block->length)
		return -1;
	
	buf += bhdr_size;

	memcpy(buf, block->data, block->length);

	return bhdr_size + block->length;
}

static int xsp_writeout_nack_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	const char *error_msg = block->data;
	xspSessNack_HDR *hdr;
	int bhdr_size;

	block->length = sizeof(xspSessNack_HDR) + strlen(error_msg);

        bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
		goto write_error;

        remainder -= bhdr_size;
	if (remainder < sizeof(xspSessNack_HDR))
		goto write_error;

	buf += bhdr_size;
	hdr = (xspSessNack_HDR *) buf;

	hdr->length = htons(strlen(error_msg));

	remainder -= sizeof(xspSessNack_HDR);
	buf += sizeof(xspSessNack_HDR);

	if (remainder < strlen(error_msg))
		return -1;

	memcpy(buf, error_msg, strlen(error_msg));

	return bhdr_size + block->length;

 write_error:
	return -1;
}

static int xsp_writeout_data_chan_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	xspDataOpen *dopen = block->data;
	xspDataOpen_HDR *hdr;
        int bhdr_size;

	block->length = sizeof(xspDataOpen_HDR);

        bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
                goto write_error;

        remainder -= bhdr_size;
	if (remainder < sizeof(xspDataOpen_HDR))
                goto write_error;
	
        buf += bhdr_size;
	hdr = (xspDataOpen_HDR *) buf;
	
	hdr->flags = htons(dopen->flags);
	strlcpy(hdr->hop_id, dopen->hop_id, XSP_HOPID_LEN);
	strlcpy(hdr->proto, dopen->proto, XSP_PROTO_NAME_LEN);
	
	return bhdr_size + block->length;

 write_error:
	return -1;
}
static int xsp_writeout_net_path_msg(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
	xspNetPath *net_path = block->data;
	xspNetPath_HDR *hdr;
	int bhdr_size;
	int i;

	block->length = net_path->rule_count * sizeof(xspNetPathRule_HDR) + sizeof(xspNetPath_HDR);
	
	bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
                goto write_error;

        remainder -= bhdr_size;
        if (remainder < sizeof(xspNetPath_HDR))
                goto write_error;

	buf += bhdr_size;
	hdr = (xspNetPath_HDR *) buf;
	
	d_printf("net_path type: %s\n", net_path->type);

	memcpy(hdr->type, net_path->type, XSP_NET_PATH_LEN);
	hdr->action = htons(net_path->action);
	hdr->rule_count = htons(net_path->rule_count);

	buf += sizeof(xspNetPath_HDR);
	
	for (i = 0; i < net_path->rule_count; i++) {
		xspNetPathRule *rule;
		xspNetPathRule_HDR *rhdr;
		
		rule = net_path->rules[i];
		rhdr = (xspNetPathRule_HDR *) buf;
		
		memcpy(&(rhdr->src_eid), &(rule->src_eid), sizeof(struct xsp_addr));
		memcpy(&(rhdr->src_mask), &(rule->src_mask), sizeof(struct xsp_addr));
		memcpy(&(rhdr->dst_eid), &(rule->dst_eid), sizeof(struct xsp_addr));
		memcpy(&(rhdr->dst_mask), &(rule->dst_mask), sizeof(struct xsp_addr));

		rhdr->src_port_min = htons(rule->src_port_min);
		rhdr->src_port_max = htons(rule->src_port_max);
		rhdr->dst_port_min = htons(rule->dst_port_min);
		rhdr->dst_port_max = htons(rule->dst_port_max);
		
		rhdr->direction = htons(rule->direction);
		rhdr->bandwidth = htonll(rule->bandwidth);
		rhdr->status = htons(rule->status);
		
		buf += sizeof(xspNetPathRule_HDR);
	}
	
	return bhdr_size + block->length;
	
 write_error:
	return -1;
}

static int xsp_writeout_path_open_msg(void *arg, char *buf, int remainder) {
	
	
	return 0;
}

// some slabs additions
static int xsp_parse_slab_info(const void *arg, int remainder, void **msg_body) {
        xspBlock *block = (xspBlock*) arg;
        char *buf = (char*) block->data;
        xspSlabInfo *new_info;
        xspSlabInfo_HDR *in;
        int i;
        int rec_size = 0;

	*msg_body = NULL;

        if (remainder < sizeof(xspSlabInfo_HDR)) {
                return -1;
        }

        new_info = malloc(sizeof(xspSlabInfo));
        if (!new_info)
                return -1;
        bzero(new_info, sizeof(xspSlabInfo));

        in = (xspSlabInfo_HDR *) buf;

        new_info->length = ntohl(in->length);
        new_info->rec_count = ntohl(in->rec_count);

        buf += sizeof(xspSlabInfo_HDR);

        if (!new_info->rec_count) {
                new_info->entries = NULL;
        }
        else {
                new_info->entries = (xspSlabRec **) malloc(new_info->rec_count * sizeof(xspSlabRec*));
                if (!new_info->entries)
                        return -1;

                for (i=0; i<new_info->rec_count; i++) {
                        new_info->entries[i] = xsp_parse_slab_record(buf, remainder, &rec_size);
                        if (!new_info->entries[i])
                                return -1;

                        buf += rec_size;
                        remainder -= rec_size;
                }
        }

        block->data = new_info;
        block->length = 0;

        *msg_body = block;

        return 0;
}

static xspSlabRec *xsp_parse_slab_record(const void *arg, int remainder, int *size) {
	char *buf = (char*) arg;
        xspSlabRec *new_rec;
        xspSlabRec_HDR *in;
        int orig_remainder;

        orig_remainder = remainder;

        new_rec = malloc(sizeof(xspSlabRec));
        if (!new_rec)
                return NULL;
        bzero(new_rec, sizeof(xspSlabRec));

        in = (xspSlabRec_HDR *) buf;

        bin2hex(in->sess_id, new_rec->sess_id, XSP_SESSIONID_LEN);

        new_rec->offset = ntohl(in->offset);
        new_rec->length = ntohl(in->length);
        new_rec->crc = ntohl(in->crc);

        buf += sizeof(xspSlabRec_HDR);
        remainder -= sizeof(xspSlabRec_HDR);

        *size = orig_remainder - remainder;

        return new_rec;
}

static int xsp_writeout_slab_info(void *arg, char *buf, int remainder) {
	xspBlock *block = arg;
        xspSlabInfo *info = block->data;
        xspSlabInfo_HDR *out;
        int i;
	int bhdr_size;
        int rec_size;
        int orig_remainder;

	block->length = info->rec_count * sizeof(xspSlabRec_HDR) + sizeof(xspSlabInfo_HDR);

        bhdr_size = xsp_writeout_block_hdr(block, buf, remainder);
        if (bhdr_size < 0)
                goto write_error;

        remainder -= bhdr_size;
        if (remainder < sizeof(xspSlabInfo_HDR))
                goto write_error;

        buf += bhdr_size;

        if (remainder < sizeof(xspSlabInfo_HDR)) {
		goto write_error;
        }

        out = (xspSlabInfo_HDR *) buf;

        out->length = htonl(info->length);
        out->rec_count = htonl(info->rec_count);

        remainder -= sizeof(xspSlabInfo_HDR);
        buf += sizeof(xspSlabInfo_HDR);

        for (i=0; i<info->rec_count; i++) {

                rec_size = xsp_writeout_slab_record(info->entries[i], buf, remainder);
                if (rec_size < 0)
			goto write_error;

                buf += rec_size;
                remainder -= rec_size;
        }

	return bhdr_size + block->length;
	
 write_error:
	return -1;
}

static int xsp_writeout_slab_record(xspSlabRec *rec, char *buf, int remainder) {
        int orig_remainder;
        xspSlabRec_HDR *out;

        if (remainder < sizeof(xspSlabRec_HDR)) {
                return -1;
        }

        orig_remainder = remainder;

        out = (xspSlabRec_HDR *) buf;

        hex2bin(rec->sess_id, out->sess_id, 2*XSP_SESSIONID_LEN);

        out->offset = htonl(rec->offset);
        out->length = htonl(rec->length);
        out->crc = htonl(rec->crc);

        buf += sizeof(xspSlabRec_HDR);
        remainder -= sizeof(xspSlabRec_HDR);

        return orig_remainder - remainder;
}
