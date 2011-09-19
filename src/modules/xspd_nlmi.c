#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_settings.h"
#include "xsp_listener.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "hashtable.h"
#include "hashtable_util.h"

#include "option_types.h"
#include "compat.h"

#include "bson.h"

int xspd_nlmi_init();
int xspd_nlmi_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

#define BLIPP_VERSION "0.1"

static xspModule xspd_nlmi_module = {
	.desc = "NLMI Module",
	.dependencies = "",
	.init = xspd_nlmi_init,
	.opt_handler = xspd_nlmi_opt_handler
};

xspModule *module_info() {
	return &xspd_nlmi_module;
}

typedef struct xspd_nlmi_data_t {
	struct hashtable *mds_dict;
	pthread_mutex_t mds_dict_lock;
	struct hashtable *data_dict;
	pthread_mutex_t data_dict_lock;
	int currmd;
	bson_buffer *md_out;
	int currdata;
	bson_buffer *data_out;
	pthread_mutex_t out_lock;
} nlmiData;

static struct hashtable *nlmi_map;
static pthread_mutex_t nlmi_map_lock;

nlmiData *xspd_nlmi_ts_aggregation(comSess *sess, bson *msg);

int xspd_nlmi_init() {
	
	// do any initialization code here
	nlmi_map = create_hashtable(16, xsp_hash_string, xsp_equalkeys_string);
	pthread_mutex_init(&nlmi_map_lock, NULL);
	
	return 0;
}

int xspd_nlmi_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(0, "handling nlmi message of type: %d", block->type);
	// block->blob has the data of length block->length

	switch(block->type) {

	case NLMI_BSON:
		{
			bson *bpp;
			char *bpp_data;
			nlmiData *nd;
			
			bpp_data = (char *)malloc(block->length);
			memcpy(bpp_data, block->data, block->length);
			
			bpp = (bson *)malloc(sizeof(bson));
			bson_init(bpp, bpp_data, 1);

			nd = xspd_nlmi_ts_aggregation(sess, bpp);

			bson_destroy(bpp);

			pthread_mutex_lock(&nd->out_lock);
			{
				if (nd->md_out || nd->data_out) {
					bson_buffer bb;
					bson_buffer_init(&bb);
					bson_append_string(&bb, "version", BLIPP_VERSION);

					if (nd->md_out) {
						bson b;
						bson_iterator it;

						bson_append_finish_object(nd->md_out);
						bson_from_buffer(&b, nd->md_out);
						// XXX: doesn't seem to be a better way to append directly
						bson_find(&it, &b, "meta");
						bson_append_element(&bb, NULL, &it);

						bson_buffer_destroy(nd->md_out);
						nd->md_out = NULL;
					}
					else {
						bson_append_start_array(&bb, "meta");
						bson_append_finish_object(&bb);
					}

					if (nd->data_out) {
						bson b;
						bson_iterator it;

						bson_append_finish_object(nd->data_out);
						bson_from_buffer(&b, nd->data_out);
						bson_find(&it, &b, "data");
						bson_append_element(&bb, NULL, &it);

						bson_buffer_destroy(nd->data_out);
						nd->data_out = NULL;
					}
					else {
						bson_append_start_array(&bb, "data");
						bson_append_finish_object(&bb);
					}

					bson_from_buffer(bpp, &bb);
					bson_print(bpp);
				}
			}
			pthread_mutex_unlock(&nd->out_lock);

			// fill in an option block to return
			char *ret_str = "holla";
			*ret_block = xsp_block_new(block->type, 0, strlen(ret_str), ret_str);
		}
		break;
	default:
		break;
		
	}
	
	return 0;
}

#define TS_AGGREGATION_DT 60.0

typedef struct values_t {
	double start_time;
	double end_time;
	unsigned int currv;
	double *v;
} values;

typedef struct {
	const char *id;
	const char *pid;
	int is_ts; // -1: unprocessed, 0: not timeseries, 1: timeseries
	double ts;
	double dt;
} MetaEntry;

typedef struct {
	char *mid;
	bson_buffer databuf;
	values raw_values;
	//values aggregated_values;
	int sampling_ratio; /* (aggregated dt / raw dt), might be 0 */
	pthread_mutex_t mtx;
} DataEntry;

MetaEntry *create_mds_entry(const char *id) {
	MetaEntry *entry;
	entry = malloc(sizeof(MetaEntry));
	entry->id = strdup(id);
	entry->pid = NULL;
	entry->is_ts = -1;
	return entry;
}

DataEntry *create_data_entry(int sratio, double ts, const char *mid) {
	DataEntry *entry;

	entry = malloc(sizeof(DataEntry));
	entry->sampling_ratio = sratio;

	if (sratio) {
		entry->raw_values.start_time = ts;
		entry->raw_values.end_time = ts + TS_AGGREGATION_DT;
		entry->raw_values.currv = 0;
		entry->raw_values.v = (double*) malloc(sizeof(double)*sratio);
	}

	pthread_mutex_init(&entry->mtx, NULL);

	entry->mid = strdup(mid);

	// TODO: this is not working for some reason
	// create a template for this data object
	//bson_buffer_init(&entry->databuf);
	//bson_iterator_init(&it, data->data);
	//while (bson_iterator_next(&it)) {
	//	if (!strcmp(bson_iterator_key(&it), "values"))
	//		continue;
	//	bson_append_element(&entry->databuf, NULL, &it);
	//}
	//bson_append_start_array(&entry->databuf, "values");

	return entry;
}

void destroy_data_entry(DataEntry *entry) {
	pthread_mutex_destroy(&entry->mtx);
	bson_buffer_destroy(&entry->databuf);
	free(entry);
}

void add_data_out(nlmiData *sess_data, bson *data) {
	char index[10];

	pthread_mutex_lock(&sess_data->out_lock);
	{
		if (!sess_data->data_out) {
			sess_data->data_out = (bson_buffer*) malloc(sizeof(bson_buffer));
			bson_buffer_init(sess_data->data_out);
			bson_append_start_array(sess_data->data_out, "data");
			sess_data->currdata = 0;
		}
		sprintf(index, "%d", sess_data->currdata++);
		bson_append_bson(sess_data->data_out, index, data);
	}
	pthread_mutex_unlock(&sess_data->out_lock);
}

/* XXX: Right now consolidation function is 'mean' */
void aggregate(nlmiData *sess_data, DataEntry *entry) {
	int i;
	double v = 0;
	bson data;
	bson_buffer data_buf;

	/* TODO: missing values are 0 right now */
	for (i = 0; i < entry->raw_values.currv; i++)
		v += entry->raw_values.v[i];
	v /= entry->sampling_ratio;

	// copy template (with other field like mid) and add value
	// XXX: this is hacking the internals of bson since there's no buffer copy
	// TODO: not working for some reason
	//memcpy(&data_buf, &entry->databuf, sizeof(bson_buffer));
	//data_buf.buf = (char*)malloc(entry->databuf.bufSize);
	//memcpy(data_buf.buf, entry->databuf.buf, sizeof(entry->databuf.bufSize));
    //data_buf.cur = data_buf.buf + (entry->databuf.cur - entry->databuf.buf);

	bson_buffer_init(&data_buf);
	bson_append_string(&data_buf, "mid", entry->mid);
    bson_append_start_array(&data_buf, "0");
    bson_append_double(&data_buf, "0", entry->raw_values.start_time);
    bson_append_double(&data_buf, "1", v);
    bson_append_finish_object(&data_buf);

	bson_from_buffer(&data, &data_buf);
	bson_print(&data);

	add_data_out(sess_data, &data);

	bson_destroy(&data);

	entry->raw_values.start_time = entry->raw_values.end_time;
	entry->raw_values.end_time += TS_AGGREGATION_DT;
	entry->raw_values.currv = 0;
}

static nlmiData *create_nlmi_data() {
	nlmiData *sess_data = (nlmiData*) malloc(sizeof(nlmiData));
	memset(sess_data, 0, sizeof(nlmiData));

	sess_data->mds_dict = create_hashtable(16, xsp_hash_string,
			xsp_equalkeys_string);
	sess_data->data_dict = create_hashtable(16, xsp_hash_string,
			xsp_equalkeys_string);
	pthread_mutex_init(&sess_data->mds_dict_lock, NULL);
	pthread_mutex_init(&sess_data->data_dict_lock, NULL);
	pthread_mutex_init(&sess_data->out_lock, NULL);

	return sess_data;
}

nlmiData *xspd_nlmi_ts_aggregation(comSess *sess, bson *msg) {
	int sratio;
	double v;
	double vts;
	const char *mdid;
	const char *mpid;
	bson md;
	bson data;
	bson params;
	bson_iterator msg_it;
	bson_iterator meta_it;
	bson_iterator data_it;
	bson_iterator field_it;
	bson_iterator values_it;
	MetaEntry *md_entry;
	MetaEntry *md_tmp;
	DataEntry *data_entry;
	nlmiData *sess_data;

	pthread_mutex_lock(&nlmi_map_lock);
	{
		if (!(sess_data = hashtable_search(nlmi_map, sess->id))) {
			sess_data = create_nlmi_data();
			if (!hashtable_insert(nlmi_map, strdup(sess->id), sess_data))
				exit(-1); // TODO: fail properly
		}
	}
	pthread_mutex_unlock(&nlmi_map_lock);

	// search for any metadatas in msg and register them in session
	if (bson_find(&msg_it, msg, "meta")) {
		// XXX: not doing any validation on the schema right now
		bson_iterator_subiterator(&msg_it, &meta_it);

		while (bson_iterator_next(&meta_it)) {
			bson_iterator_subobject(&meta_it, &md);

			bson_find(&field_it, &md, "id");

			mdid = bson_iterator_string(&field_it);

			pthread_mutex_lock(&sess_data->mds_dict_lock);
			{
				md_entry = hashtable_search(sess_data->mds_dict, mdid);
			}
			pthread_mutex_unlock(&sess_data->mds_dict_lock);

			if (md_entry == NULL) {
				md_entry = create_mds_entry(mdid);

				if (bson_find(&field_it, &md, "pid"))
					md_entry->pid = strdup(bson_iterator_string(&field_it));

				bson_find(&field_it, &md, "params");
				bson_iterator_subobject(&field_it, &params);

				if (bson_find(&field_it, &params, "ts")
						&& bson_find(&field_it, &params, "dt")) {
					md_entry->is_ts = 1;
					md_entry->dt = bson_iterator_double(&field_it);
					if (md_entry->dt < TS_AGGREGATION_DT)
						*((double *) bson_iterator_value(&field_it)) = TS_AGGREGATION_DT;
					bson_find(&field_it, &params, "ts");
					md_entry->ts = bson_iterator_double(&field_it);
				}

				pthread_mutex_lock(&sess_data->mds_dict_lock);
				{
					if (!hashtable_insert(sess_data->mds_dict, strdup(mdid),
							md_entry)) {
						fprintf(stderr, "failed to add mid: %s", mdid);
						exit(-1);
					}
				}
				pthread_mutex_unlock(&sess_data->mds_dict_lock);

				pthread_mutex_lock(&sess_data->out_lock);
				{
					char index[10];
					if (!sess_data->md_out) {
						sess_data->md_out = (bson_buffer*) malloc(sizeof(bson_buffer));
						bson_buffer_init(sess_data->md_out);
						bson_append_start_array(sess_data->md_out, "meta");
						sess_data->currmd = 0;
					}
					sprintf(index, "%d", sess_data->currmd++);
					bson_append_bson(sess_data->md_out, index, &md);
				}
				pthread_mutex_unlock(&sess_data->out_lock);
			}
		}
	}

	if (!bson_find(&msg_it, msg, "data"))
		return sess_data;

	bson_iterator_subiterator(&msg_it, &data_it);

	while (bson_iterator_next(&data_it)) {
		bson_iterator_subobject(&data_it, &data);

		bson_find(&field_it, &data, "mid");

		mdid = bson_iterator_string(&field_it);

		pthread_mutex_lock(&sess_data->data_dict_lock);
		{
			data_entry = hashtable_search(sess_data->data_dict, mdid);
		}
		pthread_mutex_unlock(&sess_data->data_dict_lock);

		if (data_entry == NULL) {
			pthread_mutex_lock(&sess_data->mds_dict_lock);
			{
				md_entry = hashtable_search(sess_data->mds_dict, mdid);
			}
			pthread_mutex_unlock(&sess_data->mds_dict_lock);

			if (md_entry == NULL) {
				// TODO: Fail returning msg "Unknown metadata id"
				fprintf(stderr, "unknown mid: %s", mdid);
				return NULL;
			}

			if (md_entry->is_ts == -1) {
				// We know it's not in this md, otherwise would already
				// been set with the parent and go up the chain.
				mpid = md_entry->pid;
				while(mpid != NULL &&
						(md_tmp = hashtable_search(sess_data->mds_dict, mpid))) {
					if (md_tmp->is_ts == 1) {
						// If a parent is timeseries et, then this one also is.
						md_entry->is_ts = 1;
						md_entry->dt = md_tmp->dt;
						md_entry->ts = md_tmp->ts;
						break;
					}

					mpid = md_tmp->pid;
				}

				if (mpid == NULL)
					md_entry->is_ts = 0;
			}

			sratio = 0;
			if (md_entry->is_ts) {
				// sampling ratio = 0 means no aggregation.
				sratio = (int) (TS_AGGREGATION_DT / md_entry->dt);
				if (sratio == 1)
					sratio = 0; // save the trouble
			}

			data_entry = create_data_entry(sratio, md_entry->ts, mdid);

			pthread_mutex_lock(&sess_data->data_dict_lock);
			{
				DataEntry *tmp;
				tmp = hashtable_search(sess_data->data_dict, mdid);
				if (tmp == NULL) {
					if (!hashtable_insert(sess_data->data_dict, strdup(mdid),
					        data_entry)) {
						// fail
					}
				} else {
					// TODO: move outside of crit. section
					destroy_data_entry(data_entry);
					data_entry = tmp;
				}
			}
			pthread_mutex_unlock(&sess_data->data_dict_lock);
		}

		if (data_entry->sampling_ratio) {
			bson_find(&field_it, &data, "values");
			bson_iterator_subiterator(&field_it, &values_it);

			while (bson_iterator_next(&values_it)) {
				bson_iterator_subiterator(&values_it, &field_it);

				bson_iterator_next(&field_it);
				vts = bson_iterator_double(&field_it);
				bson_iterator_next(&field_it);
				v = bson_iterator_double(&field_it);

				pthread_mutex_lock(&data_entry->mtx);
				{
					/* TODO: unordered, missing, duplicate values handling. */

					if (!data_entry->raw_values.start_time) {
						// Assume this is the first value of this stream.
						data_entry->raw_values.start_time = vts;
						data_entry->raw_values.end_time = vts + TS_AGGREGATION_DT;
					}

					if (vts > data_entry->raw_values.end_time)
						aggregate(sess_data, data_entry);

					data_entry->raw_values.v[data_entry->raw_values.currv++] = v;

					if (data_entry->raw_values.currv == data_entry->sampling_ratio)
						aggregate(sess_data, data_entry);
				}
				pthread_mutex_unlock(&data_entry->mtx);
			}
		} else {
			// data block from non-ts metadata.. just copy raw
			add_data_out(sess_data, &data);
		}
	}

	return sess_data;
}
