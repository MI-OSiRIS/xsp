#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libxsp_proto_binary_v1.h"

#include "compat.h"

#define LIBXSP_PROTO_BINARY_ID		XSP_v1

#define LIBXSP_PROTO_BINARY_MAX 	XSP_MSG_SLAB_INFO

static xspProtoHandler bin_handler_v1;

int libxsp_proto_binary_v1_init() {
	bin_handler_v1.write_hdr = xsp_write_hdr;

	bin_handler_v1.parse = (int (**)(const void*, int, void**)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_MAX + 1));
	if (!bin_handler_v1.parse)
		return -1;

	bin_handler_v1.writeout = (int (**)(void*, char*, int)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_MAX + 1));
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
	bin_handler_v1.parse[XSP_MSG_DATA_OPEN] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_DATA_CLOSE] = NULL;
	bin_handler_v1.parse[XSP_MSG_PATH_OPEN] = xsp_parse_default_block_list;
	bin_handler_v1.parse[XSP_MSG_PATH_CLOSE] = NULL;
	bin_handler_v1.parse[XSP_MSG_APP_DATA] = xsp_parse_default_block_list;
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
	bin_handler_v1.writeout[XSP_MSG_DATA_OPEN] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_DATA_CLOSE] = NULL;
	bin_handler_v1.writeout[XSP_MSG_PATH_OPEN] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_PATH_CLOSE] = NULL;
	bin_handler_v1.writeout[XSP_MSG_APP_DATA] = xsp_writeout_default_block_list;
	bin_handler_v1.writeout[XSP_MSG_SLAB_INFO] = xsp_writeout_default_block_list;

	bin_handler_v1.max_msg_type = LIBXSP_PROTO_BINARY_MAX;

	return xsp_add_proto_handler(LIBXSP_PROTO_BINARY_ID, &bin_handler_v1);
}

static int xsp_write_hdr(void *arg, char *buf) {
	d_printf("in v1 write hdr\n");

        xspMsg *msg = (xspMsg*)arg;
        xspv1MsgHdr *hdr;

        hdr = (xspv1MsgHdr *) buf;

        d_printf("xsp_write_hdr: ver   : %d\n", msg->version);
        d_printf("xsp_write_hdr: flags : %d\n", msg->flags);
        d_printf("xsp_write_hdr: type  : %d\n", msg->type);
	d_printf("xsp_write_hdr: opt_c : %d\n", msg->opt_cnt);

        hdr->version = msg->version;
        hdr->flags = msg->flags;
        hdr->type = msg->type;
	hdr->opt_cnt = msg->opt_cnt;
	hdr->reserved = 0x0000;
	
        memcpy(&(hdr->src_eid), &(msg->src_eid), sizeof(struct xsp_addr));
        memcpy(&(hdr->dst_eid), &(msg->dst_eid), sizeof(struct xsp_addr));

        if (msg->sess_id != NULL) {
                d_printf("xsp_write_hdr: sid : %s\n", msg->sess_id);
                hex2bin(msg->sess_id, hdr->sess_id, XSP_SESSIONID_LEN * 2);
        } else {
                bzero(hdr->sess_id, XSP_SESSIONID_LEN);
        }

        return sizeof(xspv1MsgHdr);
}


static int xsp_parse_default_block_list(const void *arg, int length, void **msg_body) {
	
	

}

static int xsp_writeout_default_block_list(void *arg, char *buf, int remainder) {
	xspBlockList *bl = (xspBlockList*) arg;
	xspBlock *block;
	int orig_remainder = 0;
	int n;
	int count;

	orig_remainder = remainder;
	
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
			n = xsp_writeout_data_open_msg(block, buf, remainder);
			break;
		case XSP_OPT_PATH:
			n = xsp_writeout_path_open_msg(block, buf, remainder);
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

static int xsp_parse_hops(const void *arg, int length, void **msg_body) {

	
	return 0;

parse_error:

	return -1;
}

static xspHop *xsp_parsehop(xspSess *sess, const void *arg, int remainder, int *size) {
	char *buf = (char*) arg;
	xspHop *new_hop = NULL;
	xspHop_HDR *hdr = NULL;
	int orig_remainder = 0;
	uint16_t child_count = 0;
	int child_size = 0;
	int i = 0;

	// verify that we have enough remaining to have a hop
	if (remainder < sizeof(xspHop_HDR)) {
		d_printf("Bad Remainder: %d %d\n", remainder, sizeof(xspHop_HDR));
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
	bcopy(hdr->id, new_hop->hop_id, XSP_HOPID_LEN);
	new_hop->hop_id[XSP_HOPID_LEN] = '\0';

	d_printf("Parsing: %s\n", new_hop->hop_id);

	bcopy(hdr->protocol, new_hop->protocol, XSP_PROTO_NAME_LEN); 
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
	free(new_hop);
	return NULL;
}

static int xsp_parse_auth_token_msg(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
	xspAuthToken_HDR *hdr;
	xspAuthToken *new_token;

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
	bcopy(buf + sizeof(xspAuthToken_HDR), new_token->token, new_token->token_length);

	// set the return value
	*msg_body = new_token;

	// return success
	return 0;
}

static int xsp_parse_nack_msg(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
	xspSessNack_HDR *hdr;
	uint16_t len;
	char *error_msg;

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
	strlcpy(error_msg, buf, len);

	// set the return value
	*msg_body = error_msg;;

	// return success
	return 0;
}

static int xsp_parse_block_msg(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
	xspv1BlockHdr *hdr;
	xspBlock *new_header;
	int hdr_len;
	int len_offset = 0;
	uint64_t block_len;

	if (remainder < sizeof(xspv1BlockHdr))
		return -1;

	// allocate a new block structure
	new_header = malloc(sizeof(xspBlock));
	if (!new_header)
		return -1;

	hdr = (xspv1BlockHdr *) buf;
	
	new_header->type = ntohs(hdr->type);
	new_header->sport = ntohs(hdr->sport);
	hdr_len = ntohs(hdr->length);
	
	if (hdr_len == 0xFFFF) {
		memcpy(&block_len, buf + 3*sizeof(uint16_t), sizeof(uint64_t));
		len_offset = sizeof(uint64_t);
	}
	else
		block_len = hdr_len;
	
	new_header->length = block_len;
	
	remainder -= (sizeof(xspv1BlockHdr) + len_offset);

        // validate the data size
        if (new_header->length > 1<<24 || new_header->length > remainder) {
                free(new_header);
                return -1;
        }
        // allocate space for the data
        new_header->data = malloc(sizeof(char) * new_header->length);
        if (!new_header->data) {
                free(new_header);
                return -1;
        }

        // copy the data from the message
        memcpy(new_header->data, buf + sizeof(xspv1BlockHdr) + len_offset, new_header->length);

	*msg_body = new_header;

	return 0;
}

static int xsp_parse_auth_type_msg(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
	xspAuthType_HDR *hdr;
	xspAuthType *new_auth_type;

	if (remainder < sizeof(xspAuthType_HDR))
		return -1;

	// allocate a new auth_type token structure
	new_auth_type = malloc(sizeof(xspAuthType));
	if (!new_auth_type)
		return -1;

	hdr = (xspAuthType_HDR *) buf;

	// read in the only entry so far in the header
	bcopy(hdr->name, new_auth_type->name, XSP_AUTH_NAME_LEN);

	// set the return value
	*msg_body = new_auth_type;

	// return success
	return 0;
}

static int xsp_parse_data_open_msg(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
	xspDataOpen_HDR *hdr;
	xspDataOpenHeader *new;

	if (remainder < sizeof(xspDataOpen_HDR))
		return -1;

	new = malloc(sizeof(xspDataOpenHeader));
	if (!new)
		return -1;

	hdr = (xspDataOpen_HDR *) buf;
	bcopy(hdr->hop_id, new->hop_id, XSP_HOPID_LEN);
	new->flags = ntohs(hdr->flags);

	*msg_body = new;

	return 0;
}

static int xsp_writeout_hops(void *arg, char *buf, int remainder) {

	return 0;
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

	bcopy(hop->hop_id, hdr->id, XSP_HOPID_LEN);
	bcopy(hop->protocol, hdr->protocol, XSP_PROTO_NAME_LEN); 

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
	xspAuthToken *xsp_token = arg;
	xspAuthToken_HDR *hdr;

	// if there isn't enough room to write the structure, don't do it
	if (remainder < sizeof(xspAuthToken_HDR)) {
		return -1;
	}

	hdr = (xspAuthToken_HDR *) buf;

	// writeout the auth_token token structure in network byte order
	hdr->token_length = htons(xsp_token->token_length);

	remainder -= sizeof(xspAuthToken_HDR);

	if (remainder < xsp_token->token_length)
		return -1;

	bcopy(xsp_token->token, buf + sizeof(xspAuthToken_HDR), xsp_token->token_length);

	return sizeof(xspAuthToken_HDR) + xsp_token->token_length;
}

static int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder) {
	xspAuthType *auth_type = arg;
	xspAuthType_HDR *hdr;

	if (remainder < sizeof(xspAuthType_HDR)) {
		return -1;
	}

	hdr = (xspAuthType_HDR *) buf;

	bzero(buf, sizeof(xspAuthType_HDR));

	strlcpy(hdr->name, auth_type->name, XSP_AUTH_NAME_LEN);

	return sizeof(xspAuthType_HDR);
}

static int xsp_writeout_block_msg(void *arg, char *buf, int remainder) {
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
		memcpy(len, &(block->length), sizeof(uint64_t));
		hdr->length = htons(0xFFFF);
		len_offset = sizeof(uint64_t);
	}
	else
		hdr->length = htons(block->length);
	
	remainder -= (sizeof(xspv1BlockHdr) + len_offset);

	if (remainder < block->length)
		return -1;
	
	memcpy(buf + sizeof(xspv1BlockHdr) + len_offset, block->data, block->length);

	return sizeof(xspv1BlockHdr) + len_offset + block->length;
}

static int xsp_writeout_nack_msg(void *arg, char *buf, int remainder) {
	const char *error_msg = arg;
	xspSessNack_HDR *hdr;

	// if there isn't enough room to write the structure, don't do it
	if (remainder < sizeof(xspSessNack_HDR)) {
		return -1;
	}

	hdr = (xspSessNack_HDR *) buf;

	// writeout the auth_token token structure in network byte order
	hdr->length = htons(strlen(error_msg));

	remainder -= sizeof(xspSessNack_HDR);
	buf += sizeof(xspSessNack_HDR);

	if (remainder < strlen(error_msg))
		return -1;

	strlcpy(buf, error_msg, strlen(arg));

	return sizeof(xspSessNack_HDR) + strlen(error_msg);
}

static int xsp_writeout_data_open_msg(void *arg, char *buf, int remainder) {
	xspDataOpenHeader *dopen = arg;
	xspDataOpen_HDR *hdr;

	if (remainder < sizeof(xspDataOpen_HDR)) {
		return -1;
	}
	       
	hdr = (xspDataOpen_HDR *) buf;
	
	hdr->flags = htons(dopen->flags);
	strlcpy(hdr->hop_id, dopen->hop_id, XSP_HOPID_LEN);
	strlcpy(hdr->proto, dopen->proto, XSP_PROTO_NAME_LEN);
	
	remainder -= sizeof(xspDataOpen_HDR);
	
	return sizeof(xspDataOpen_HDR);
}

static int xsp_writeout_path_open_msg(void *arg, char *buf, int remainder) {


	return 0;
}

// some slabs additions

static int xsp_parse_slab_info(const void *arg, int remainder, void **msg_body) {
	char *buf = (char*) arg;
        xspSlabInfo *new_info;
        xspSlabInfo_HDR *in;
        int i;
        int rec_size = 0;

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

        *msg_body = new_info;

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
        int orig_remainder;
        xspSlabInfo *info = (xspSlabInfo*) arg;
        xspSlabInfo_HDR *out;
        int i;
        int rec_size;

        orig_remainder = remainder;

        if (remainder < sizeof(xspSlabInfo_HDR)) {
                return -1;
        }

        out = (xspSlabInfo_HDR *) buf;

        out->length = htonl(info->length);
        out->rec_count = htonl(info->rec_count);

        remainder -= sizeof(xspSlabInfo_HDR);
        buf += sizeof(xspSlabInfo_HDR);

        for (i=0; i<info->rec_count; i++) {

                rec_size = xsp_writeout_slab_record(info->entries[i], buf, remainder);
                if (rec_size < 0)
                        return -1;

                buf += rec_size;
                remainder -= rec_size;
        }

        return orig_remainder - remainder;
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
