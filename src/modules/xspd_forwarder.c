#define _GNU_SOURCE
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <dirent.h>

#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_main_settings.h"
#include "xsp_settings.h"
#include "xsp_listener.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "xspd_proto_photon.h"
#include "xspd_forwarder.h"
#include "compat.h"
#include "mongo.h"

#define MB_MULT 1024*1024

static SLAB *pool;
static pthread_t loaddir_thr;

int xspd_forwarder_init();
int xspd_forwarder_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

int __xspd_forwarder_mongo_insert(bson *bpp, char *collection);
void *__xspd_forwarder_loaddir_thread(void *arg);

struct xspd_forwarder_config_t {
	char *eid;
	int pool_size;
	int alloc_size;
	char *load_dir;
	char *store;
	char *db_name;
	char *db_host;
	int   db_port;
	char *ms_instance;
	char *unis_instance;
};
		
struct xspd_forwarder_config_t default_config = {
	.eid = "TODO",
	.pool_size = 50000,
	.alloc_size = 100,
	.load_dir = "/var/forwarder",
	.store = "mongo",
	.db_name = "xsp_forwarder",
	.db_host = "127.0.0.1",
	.db_port = 27017,
	.ms_instance = NULL,
	.unis_instance = NULL
};

struct xspd_forwarder_config_t config;

static xspModule xspd_forwarder_module = {
	.desc = "Forwarder Module",
	.dependencies = "photon",
	.init = xspd_forwarder_init,
	.opt_handler = xspd_forwarder_opt_handler
};

xspModule *module_info() {
	return &xspd_forwarder_module;
}

int xspd_forwarder_init() {
	int i;
	xspModule *module;
	xspSettings *settings;

	settings = xsp_main_settings();

	if (xsp_settings_get_2(settings, "forwarder", "eid", &config.eid) != 0) {
		xsp_info(5, "No Forwarder eid specified, will try to resolve...");
		config.eid = "TODO";
	}	

	if (xsp_settings_get_int_2(settings, "forwarder", "pool_size", &config.pool_size) != 0) {
		xsp_info(5, "No Forwarder pool size specified, using default %dM", default_config.pool_size);
		config.pool_size = default_config.pool_size;
	}	

	if (xsp_settings_get_int_2(settings, "forwarder", "alloc_size", &config.alloc_size) != 0) {
		xsp_info(5, "No Forwarder allocation size specified, using default %dM", default_config.alloc_size);
		config.alloc_size = default_config.alloc_size;
	}

	if (xsp_settings_get_2(settings, "forwarder", "load_dir", &config.load_dir) != 0) {
		xsp_info(5, "No Forwarder load directory specified, using default %s", default_config.load_dir);
		config.load_dir = default_config.load_dir;
	}

	if (xsp_settings_get_2(settings, "forwarder", "store", &config.store) != 0) {
		xsp_info(5, "No Forwarder store type specified, using default %s", default_config.store);
		config.store = default_config.store;
	}
	
	if (xsp_settings_get_2(settings, "forwarder", "db_name", &config.db_name) != 0) {
		xsp_info(5, "Forwarder database name not specified, using default %s", default_config.db_name);
		config.db_name = default_config.db_name;
	}
	
	if (xsp_settings_get_2(settings, "blipp", "db_host", &config.db_host) != 0) {
		xsp_info(5, "Forwarder database host not specified, using default %s", default_config.db_host);
		config.db_host = default_config.db_host;
	}
	
	if (xsp_settings_get_int_2(settings, "blipp", "db_port", &config.db_port) != 0) {
		xsp_info(5, "Forwarder database port not specified, using default %d", default_config.db_port);
		config.db_port = default_config.db_port;
	}
	
	if (!strcmp(config.store, "periscope")) {
		if (xsp_settings_get_2(settings, "blipp", "ms_instance", &config.ms_instance) != 0) {
			xsp_info(5, "MS instance not specified!");
			return -1;
		}
		
		if (xsp_settings_get_2(settings, "blipp", "unis_instance", &config.unis_instance) != 0) {
			xsp_info(5, "UNIS instance not specified!");
			return -1;
		}
		
		/* persistent connection to UNIS/MS? */
	}
	else if (!strcmp(config.store, "mongo")) {
		/* persistent mongo conn?
		   we'll connect for each insert right now */
	}
	else {
		xsp_info(5, "Unrecognized Forwarder store type!");
		return -1;
	}

	/* allocate buffer pool */
	xsp_info(5, "Creating buffer pool of size %dM with %dM allocations...", config.pool_size, config.alloc_size);
	pool = slabs_buf_create((uint64_t)config.pool_size*MB_MULT, (uint64_t)config.alloc_size*MB_MULT, 0);
	if (pool == NULL) {
		xsp_err(0, "Could not create buffer pool");
		return -1;
	}
	//slabs_buf_reset(pool);
	xsp_info(5, "done");

	/* register the buffer pool with the RDMA module, must be initialized first */
	if ((module = xsp_find_module("photon")) != NULL) {
		photonBufferPriv priv;
		xsp_info(5, "Registering forwarder buffer pool...");
		for (i = 0; i < slabs_buf_get_pcount(pool); i++) {
			priv = malloc(sizeof(struct photon_buffer_priv_t));
			if (xspd_proto_photon_register_buffer(slabs_buf_addr_ind(pool, i),
												  slabs_buf_get_psize(pool), priv) != 0) {
				xsp_err(0, "Could not register buffer pool with photon module");
				return -1;
			}
			slabs_buf_set_priv_data_ind(pool, priv, i);
		}
		xsp_info(5, "done");
	}
	
	/* load a directory of files into memory if given */
	if (strncasecmp(config.load_dir, "NULL", 4) != 0) {
		pthread_create(&loaddir_thr, NULL, __xspd_forwarder_loaddir_thread, NULL);
	}
		
	return 0;
}

int xspd_forwarder_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(0, "handling photon message of type: %d", block->type);

	*ret_block = NULL;
	return 0;
}

SLAB *xspd_forwarder_get_pool(SLAB **ret_slab) {
	if (ret_slab) {
		*ret_slab = pool;
	}
	return pool;
}

void *__xspd_forwarder_loaddir_thread(void *arg) {
	DIR *dir;
	struct dirent *dent;
	
	chdir(config.load_dir);
	dir = opendir(config.load_dir);
	if (!dir) {
		xsp_err(0, "Could not open directory \"%s\": %s", config.load_dir, strerror(errno));
		return NULL;
	}

	while((dent = readdir(dir)) != NULL) {
		if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			photonBufferPriv priv;
			struct stat filestat;
			struct passwd *pwdstat;
			void *sbuf;
			uint64_t ssize, file_size, total_read, to_read;
			int sind;
			int fd;
			ssize_t n;
			char addr[17];
			bson fmeta;
			
			xsp_info(5, "Staging file \"%s/%s", config.load_dir, dent->d_name);
			fd = open(dent->d_name, O_RDONLY);
			if (fd < 0 ) {
				xsp_err(5, "Could not open file \"%s/%s\": %s", config.load_dir,
						dent->d_name, strerror(errno));
			}
			else {
				total_read = 0;
				fstat(fd, &filestat);
				file_size = (uint64_t)filestat.st_size;
				pwdstat = getpwuid(filestat.st_uid);
				
				bson_init(&fmeta);
				bson_append_int(&fmeta, "ts", (int)time(NULL));
				bson_append_string(&fmeta, "type", "file");
				bson_append_string(&fmeta, "path", config.load_dir);
				bson_append_string(&fmeta, "filename", dent->d_name);
				bson_append_int(&fmeta, "size", (int)file_size);
				bson_append_string(&fmeta, "owner", pwdstat->pw_name);
				bson_append_start_array(&fmeta, "allocations");

				do {
					sbuf = slabs_buf_get_free(pool, &ssize, &sind);
					if (!sbuf) {
						xsp_err(0, "No more free buffers in SLABS pool!");
						return NULL;
					}

					priv = slabs_buf_get_priv_data_ind(pool, sind);

					if ((file_size - total_read) < ssize)
						to_read = (file_size - total_read);
					else
						to_read = ssize;
					
					n = read(fd, sbuf, to_read);
					if (n < 0) {
						xsp_err(5, "Error reading from file: %s", strerror(errno));
						return NULL;
					}
					
					sprintf(addr, "%016" PRIxPTR, (uintptr_t)sbuf);
					addr[16] = '\0';
					
					bson_append_start_object(&fmeta, "");
					bson_append_int(&fmeta, "offset", (int)total_read);
					bson_append_int(&fmeta, "length", (int)n);
					bson_append_string(&fmeta, "address", addr);
					if (priv) {
						sprintf(addr, "%lu", priv->key0);
						bson_append_string(&fmeta, "key0", addr);
						sprintf(addr, "%lu", priv->key1);
						bson_append_string(&fmeta, "key1", addr);
					}
					bson_append_string(&fmeta, "eid", config.eid);
					bson_append_int(&fmeta, "local_slab_index", sind);
					bson_append_finish_object(&fmeta);

					total_read += n;
				} while (total_read < file_size);

				bson_append_finish_array(&fmeta);
				bson_finish(&fmeta);
				bson_print(&fmeta);
				__xspd_forwarder_mongo_insert(&fmeta, "rdma_files");
			}
		}
	}
	
	closedir(dir);
	
	return NULL;
}

int __xspd_forwarder_mongo_insert(bson *bpp, char *collection) {
	mongo conn[1];
	char *db_path = NULL;
	int status;

	status = mongo_client(conn, config.db_host, config.db_port);

	if( status != MONGO_OK ) {
		switch ( conn->err ) {
		case MONGO_CONN_NO_SOCKET:  fprintf(stderr, "no socket\n"); return -1;
		case MONGO_CONN_FAIL:       fprintf(stderr, "connection failed\n"); return -1;
		case MONGO_CONN_NOT_MASTER: fprintf(stderr, "not master\n"); return -1;
		default: return 1;
		}
	}

	asprintf(&db_path, "%s.%s", config.db_name, collection);
	status = mongo_insert(conn, db_path, bpp, NULL);
	if (status != MONGO_OK) {
		xsp_err(5, "Could not perform mongo insert");
		return -1;
	}
	mongo_destroy(conn);

	return 0;
}
