#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libxsp_proto_binary.h"

#include "compat.h"

#define LIBXSP_PROTO_BINARY_ID		0

#define LIBXSP_PROTO_BINARY_MAX 	XSP_MSG_SLAB_INFO

xspProtoHandler bin_handler;

int libxsp_proto_binary_init() {
	bin_handler.parse = (int (**)(const char*, int, void**)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_MAX + 1));
	if (!bin_handler.parse)
		return -1;

	bin_handler.writeout = (int (**)(void*, char*, int)) malloc(sizeof(void *) * (LIBXSP_PROTO_BINARY_MAX + 1));
	if (!bin_handler.writeout)
		return -1;

	bin_handler.parse[XSP_MSG_INVALID] = NULL;
	bin_handler.parse[XSP_MSG_SESS_OPEN] = xsp_parse_sess_open_msg;
	bin_handler.parse[XSP_MSG_SESS_ACK] = NULL;
	bin_handler.parse[XSP_MSG_SESS_CLOSE] = NULL;
	bin_handler.parse[XSP_MSG_AUTH_TYPE] = xsp_parse_auth_type_msg;
	bin_handler.parse[XSP_MSG_AUTH_TOKEN] = xsp_parse_auth_token_msg;
	bin_handler.parse[XSP_MSG_BLOCK_HEADER] = xsp_parse_block_header_msg;
	bin_handler.parse[XSP_MSG_SESS_NACK] = xsp_parse_nack_msg;
	bin_handler.parse[XSP_MSG_PING] = NULL;
	bin_handler.parse[XSP_MSG_PONG] = NULL;
	bin_handler.parse[XSP_MSG_DATA_OPEN] = xsp_parse_data_open_msg;
	bin_handler.parse[XSP_MSG_DATA_CLOSE] = NULL;
	bin_handler.parse[XSP_MSG_PATH_OPEN] = xsp_parse_block_header_msg;
	bin_handler.parse[XSP_MSG_PATH_CLOSE] = NULL;
	bin_handler.parse[XSP_MSG_SLAB_INFO] = xsp_parse_slab_info;

	bin_handler.writeout[XSP_MSG_INVALID] = NULL;
	bin_handler.writeout[XSP_MSG_SESS_OPEN] = xsp_writeout_sess_open_msg;
	bin_handler.writeout[XSP_MSG_SESS_ACK] = NULL;
	bin_handler.writeout[XSP_MSG_SESS_CLOSE] = NULL;
	bin_handler.writeout[XSP_MSG_AUTH_TYPE] = xsp_writeout_auth_type_msg;
	bin_handler.writeout[XSP_MSG_AUTH_TOKEN] = xsp_writeout_auth_token_msg;
	bin_handler.writeout[XSP_MSG_BLOCK_HEADER] = xsp_writeout_block_header_msg;
	bin_handler.writeout[XSP_MSG_SESS_NACK] = xsp_writeout_nack_msg;
	bin_handler.writeout[XSP_MSG_PING] = NULL;
	bin_handler.writeout[XSP_MSG_PONG] = NULL;
	bin_handler.writeout[XSP_MSG_DATA_OPEN] = xsp_writeout_data_open_msg;
	bin_handler.writeout[XSP_MSG_DATA_CLOSE] = NULL;
	bin_handler.writeout[XSP_MSG_PATH_OPEN] = xsp_writeout_block_header_msg;
	bin_handler.writeout[XSP_MSG_PATH_CLOSE] = NULL;
	bin_handler.writeout[XSP_MSG_SLAB_INFO] = xsp_writeout_slab_info;

	bin_handler.max_msg_type = LIBXSP_PROTO_BINARY_MAX;

	return xsp_add_proto_handler(LIBXSP_PROTO_BINARY_ID, &bin_handler);
}

int xsp_parse_sess_open_msg(const char *buf, int length, void **msg_body) {
	xspSess *ret_sess = NULL;
	xspSess_HDR *hdr;
	int remainder;
	xspHop *next_hop;

	ret_sess = xsp_alloc_sess();
	if (!ret_sess)
		goto parse_error;

	hdr = (xspSess_HDR *) buf;

	remainder = length;

	d_printf("Remainder: %d %d\n", remainder, sizeof(xspSess_HDR));

	if (remainder < sizeof(xspSess_HDR))
		goto parse_error;

	bin2hex(hdr->sess_id, ret_sess->sess_id, XSP_SESSIONID_LEN);
	bcopy(hdr->src_id, ret_sess->src_id, XSP_HOPID_LEN);
	ret_sess->src_id[XSP_HOPID_LEN] = '\0';

	d_printf("src: %s\n", ret_sess->src_id);

	ret_sess->sess_flags = ntohl(hdr->sess_flags);

	ret_sess->hop_flags = ntohl(hdr->hop_flags);

	buf += sizeof(xspSess_HDR);
	remainder -= sizeof(xspSess_HDR);

	while (remainder > 0) {
		int hop_size;

		d_printf("Grabbing next hop info\n");

		next_hop = xsp_parsehop(ret_sess, buf, remainder, &hop_size);
		if (!next_hop)
			goto parse_error;

		if (xsp_sess_addhop(ret_sess, next_hop))
			goto parse_error;

		d_printf("HOP SIZE: %d\n", hop_size);

		buf += hop_size;
		remainder -= hop_size;
	}

	*msg_body = ret_sess;

	return 0;

parse_error:
	if (ret_sess)
		xsp_free_sess(ret_sess);

	return -1;
}

xspHop *xsp_parsehop(xspSess *sess, const char *buf, int remainder, int *size) {
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

int xsp_parse_auth_token_msg(const char *buf, int remainder, void **msg_body) {
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

int xsp_parse_nack_msg(const char *buf, int remainder, void **msg_body) {
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

int xsp_parse_block_header_msg(const char *buf, int remainder, void **msg_body) {
	xspBlockHeader_HDR *hdr;
	xspBlockHeader *new_header;

	if (remainder < sizeof(xspBlockHeader_HDR))
		return -1;

	// allocate a new block structure
	new_header = malloc(sizeof(xspBlockHeader));
	if (!new_header)
		return -1;

	hdr = (xspBlockHeader_HDR *) buf;

	new_header->length = ntohl(hdr->length);

	remainder -= sizeof(xspBlockHeader_HDR);

        // validate the blob size
        if (new_header->length > 1<<24 || new_header->length > remainder) {
                free(new_header);
                return -1;
        }
        // allocate space for the blob
        new_header->blob = malloc(sizeof(char) * new_header->length);
        if (!new_header->blob) {
                free(new_header);
                return -1;
        }

        // copy the blob from the message
        bcopy(buf + sizeof(xspBlockHeader_HDR), new_header->blob, new_header->length);

	*msg_body = new_header;

	return 0;
}

int xsp_parse_auth_type_msg(const char *buf, int remainder, void **msg_body) {
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

int xsp_parse_data_open_msg(const char *buf, int remainder, void **msg_body) {
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



int xsp_writeout_sess_open_msg(void *arg, char *buf, int remainder) {
	int orig_remainder;
	xspHop *hop = (xspHop *) arg;
	xspSess_HDR *sess_hdr;
	int i;
	int child_size;

	orig_remainder = remainder;

	if (remainder < sizeof(xspSess_HDR))
		goto write_error;

	sess_hdr = (xspSess_HDR *) buf;

	hex2bin(hop->session->sess_id, sess_hdr->sess_id, 2*XSP_SESSIONID_LEN);
	bcopy(hop->session->src_id, sess_hdr->src_id, XSP_HOPID_LEN);

	sess_hdr->sess_flags = htonl(hop->session->sess_flags);
	sess_hdr->hop_flags = htonl(hop->flags);

	remainder -= sizeof(xspSess_HDR);
	buf += sizeof(xspSess_HDR);

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

int xsp_writeouthop(xspHop *hop, char *buf, int remainder) {
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

int xsp_writeout_auth_token_msg(void *arg, char *buf, int remainder) {
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

int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder) {
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

int xsp_writeout_block_header_msg(void *arg, char *buf, int remainder) {
	xspBlockHeader *block = arg;
	xspBlockHeader_HDR *hdr;

	// if there isn't enough room to write the structure, don't do it
	if (remainder < sizeof(xspBlockHeader_HDR)) {
		return -1;
	}

	hdr = (xspBlockHeader_HDR *) buf;

	// writeout the block header structure in network byte order
	hdr->length = htonl(block->length);

	remainder -= sizeof(xspBlockHeader_HDR);

	if (remainder < block->length)
		return -1;

	bcopy(block->blob, buf + sizeof(xspBlockHeader_HDR), block->length);

	return sizeof(xspBlockHeader_HDR) + block->length;
}

int xsp_writeout_nack_msg(void *arg, char *buf, int remainder) {
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

int xsp_writeout_data_open_msg(void *arg, char *buf, int remainder) {
	const char *hop_id = arg;
	xspDataOpen_HDR *hdr;

	if (remainder < sizeof(xspDataOpen_HDR)) {
		return -1;
	}
	       
	hdr = (xspDataOpen_HDR *) buf;
	
	strlcpy(hdr->hop_id, hop_id, XSP_HOPID_LEN);
	hdr->flags = htons(0x0);
	
	remainder -= sizeof(xspDataOpen_HDR);
	
	return sizeof(xspDataOpen_HDR);
}

// some slabs additions

int xsp_parse_slab_info(const char *buf, int remainder, void **msg_body) {
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

xspSlabRec *xsp_parse_slab_record(const char *buf, int remainder, int *size) {
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

int xsp_writeout_slab_info(void *arg, char *buf, int remainder) {
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

int xsp_writeout_slab_record(xspSlabRec *rec, char *buf, int remainder) {
        int i;
        int orig_remainder;
        xspSlabRec_HDR *out;
        int rec_size;

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
