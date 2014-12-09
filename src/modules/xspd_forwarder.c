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
#include <jansson.h>

#include "xsp_curl_context.h"
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
#define DEFAULT_CHAR_BUFF_SIZE 50
static SLAB *pool;
static pthread_t loaddir_thr;
static xspCURLContext curl_context;

static char *json_file_template = "\
{									\
    \"status\": \"ON\",							\
    \"$schema\": \"http://unis.incntre.iu.edu/schema/20140909/file#\",	\
    \"name\": \"\",							\
    \"size\": 0,							\
    \"ttl\": 600,							\
    \"created\": 0,							\
    \"modified\": 0							\
}";

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
		
struct allocation_t {
    uint64_t offset;
    uint64_t length;
    char address[DEFAULT_CHAR_BUFF_SIZE];
    char l_key[DEFAULT_CHAR_BUFF_SIZE];
    char r_key[DEFAULT_CHAR_BUFF_SIZE];
    struct allocation_t *next;
};

struct xspd_file_entry_t {
    uint64_t ts;
    uint64_t size;
    char type[DEFAULT_CHAR_BUFF_SIZE];
    char filename[DEFAULT_CHAR_BUFF_SIZE];
    char owner[DEFAULT_CHAR_BUFF_SIZE];
    struct allocation_t *allocations;
    struct xspd_file_entry_t *next_file;
};

int xspd_forwarder_init();
int xspd_forwarder_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);
void __xspd_forwarder_insert(struct xspd_file_entry_t *list);

void __xspd_forwarder_periscope_del_dup(char *filename);
int __xspd_forwarder_periscope_insert(json_t *root);
void __xspd_forwarder_periscope_converter(struct xspd_file_entry_t *file_list);
int __xspd_forwarder_mongo_insert(bson *bpp, char *collection);
void *__xspd_forwarder_loaddir_thread(void *arg);

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
	
    
	
    if (!strcmp(config.store, "periscope")) {
	if (xsp_settings_get_2(settings, "blipp", "ms_instance", &config.ms_instance) != 0) {
	    xsp_info(5, "MS instance not specified!");
	    return -1;
	}
		
	if (xsp_settings_get_2(settings, "blipp", "unis_instance", &config.unis_instance) != 0) {
	    xsp_info(5, "UNIS instance not specified!");
	    return -1;
	}
	
	curl_context.url = config.ms_instance;
        curl_context.use_ssl = 0;
        curl_context.curl_persist = 0;

        if (xsp_init_curl(&curl_context, NULL) != 0) {
	    xsp_info(0, "Could not start CURL context");
	    return -1;
        }

	/* persistent connection to UNIS/MS? */
    }
    else if (!strcmp(config.store, "mongo")) {
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

/* Collect all the information in the struct xspd_file_entry with allocation
 * Call generic function to push data to store
 * Genric function will decide current store in use
 * and will call the approriate funnction method to insert data in store
 */

void *__xspd_forwarder_loaddir_thread(void *arg) {
    DIR *dir;
    struct dirent *dent;
    struct xspd_file_entry_t *curr_file = NULL; 
    struct xspd_file_entry_t *head_file = NULL; 
    struct xspd_file_entry_t *prev_file = NULL;
    struct allocation_t *prev_alloc = NULL;
    struct allocation_t *curr_alloc = NULL;


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
    
	    curr_file = malloc(sizeof(struct xspd_file_entry_t));
	    curr_file->allocations = NULL;
	    curr_file->next_file = NULL;
			
	    if(head_file == NULL){
		head_file = curr_file;
	    }
			
	    xsp_info(5, "Staging file \"%s/%s", config.load_dir, dent->d_name);
	    fd = open(dent->d_name, O_RDONLY);
	    if (fd < 0 ) {
		xsp_err(5, "Could not open file \"%s/%s\": %s", config.load_dir,
			dent->d_name, strerror(errno));
	    }
	    else {
		total_read = 0;
		fstat(fd, &filestat);
		pwdstat = getpwuid(filestat.st_uid);
		file_size = (uint64_t)filestat.st_size;

		curr_file->ts = (int)time(NULL);
		strcpy(curr_file->type, "file");
		curr_file->size = (uint64_t)filestat.st_size;
		strcpy(curr_file->filename, dent->d_name);
		strcpy(curr_file->owner, pwdstat->pw_name);

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
					
		    sprintf(addr, "%016" PRIxPTR"\n", (uintptr_t)sbuf);
		    addr[16] = '\0';
		    
		    curr_alloc = malloc(sizeof(struct allocation_t));
		    curr_alloc->next = NULL;
		    curr_alloc->offset = total_read;
		    curr_alloc->length = n;
		    strcpy(curr_alloc->address, addr);

		    if (priv) {
			sprintf(addr, "%lu", priv->key0);
			strcpy(curr_alloc->l_key, addr);
			sprintf(addr, "%lu", priv->key1);
			strcpy(curr_alloc->r_key, addr);
		    }
	  
		    total_read += n;

		    if(prev_alloc == NULL){
			curr_file->allocations = curr_alloc;
			prev_alloc = curr_alloc;
		    }else{
			prev_alloc->next = curr_alloc;
			prev_alloc = curr_alloc;
		    }

		} while (total_read < file_size);


		if(prev_file == NULL){
		    prev_file = curr_file;
		}else{
		    prev_file->next_file = curr_file;
		    prev_file = curr_file;
		}
	    }
	}
    }
	
    closedir(dir);
	
    xsp_info(5, "Staging data in %s",config.store);
    __xspd_forwarder_insert(head_file);
    xsp_info(5, "Freeing memory");

    // Free memory
    while(head_file != NULL){
	while(head_file->allocations != NULL){
	    curr_alloc = head_file->allocations->next;
	    free(head_file->allocations);
	    head_file->allocations = curr_alloc;
	}
	curr_file = head_file->next_file;
	free(head_file);
	head_file = curr_file;
    }
    return NULL;
}

void __xspd_forwarder_insert(struct xspd_file_entry_t *list){

    if (!strcmp(config.store, "periscope")) {
	__xspd_forwarder_periscope_converter(list);
    }else if (!strcmp(config.store, "mongo")) {
	__xspd_mongo_converter_and_insert(list);
    }else {
	xsp_err(0, "No store specified");
	return;
    }
}

void __xspd_forwarder_periscope_converter(struct xspd_file_entry_t *file_list){
    
    struct xspd_file_entry_t *temp = file_list;

    while( temp != NULL){
	json_t *root;
	json_t *extents;
	json_error_t json_err;
	struct allocation_t *alloc = temp->allocations;
	int index = 0;
	
	
	root = json_loads(json_file_template, 0, &json_err);
	if (!root) {
	    xsp_err(0, "failed to decode json file template, failed at line : %d & text :%s ", json_err.line, json_err.text);
	    return;
	}

	json_object_set(root, "name", json_string(temp->filename));
	json_object_set(root, "size", json_integer(temp->size));
	json_object_set(root, "created", json_integer((int) time(NULL)));
	json_object_set(root, "modified", json_integer((int) time(NULL)));
	
	extents = json_array();
	
	while(alloc != NULL){
	    json_t *rdma;
	    json_t *extent;
	    json_t *keys;
	    	    
	    extent = json_object();
	    rdma = json_object();
	    json_object_set(rdma,"read", json_string(config.eid));
	    json_object_set(rdma,"write", json_string(config.eid));
	    json_object_set(extent, "location", rdma);
	    json_object_set(extent, "size", json_integer(alloc->length));
	    json_object_set(extent, "offset", json_integer(alloc->offset));
	    json_object_set(extent, "index", json_integer(index));
	    json_object_set(extent, "address", json_string(alloc->address));
	    
	    keys = json_array();
	    json_array_append_new(keys, json_string(alloc->l_key));
	    json_array_append_new(keys, json_string(alloc->r_key));
	    json_object_set(extent, "keys", keys);

	    json_array_append_new(extents, extent);
	    alloc = alloc->next;
	    index++;
	}

	json_object_set(root, "extents", extents);
	
	// Delete any instace of extents with same file name
	//__xspd_forwarder_periscope_del_dup(temp->filename);
	
	// push exnodes to UNIS
	if(__xspd_forwarder_periscope_insert(root) != 0){
	    xsp_err(5, "Failed to push exnode to UNIS");
	    return;
	}
	temp = temp->next_file;
    }
}


void __xspd_forwarder_periscope_del_dup(char *filename){
    json_t *json_ret;;
    json_error_t json_err;
    char *query;
    char *response;
    int num_obj;

    
    if(filename == NULL){
	xsp_err(5,"Empty filename");
	return;
    }
    
    xsp_info(5,"Finding duplicate for file : %s", filename);

    asprintf(&query, "/files?name=%s",filename);
    
    xsp_curl_get_string(&curl_context,
			query,
			NULL,
			&response);
    
    xsp_info(5,"Response from curl : %s", response);

    json_ret = json_loads(response, 0, &json_err);
    if (!json_ret) {
	xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
	xsp_err(5,"Error response : %s", response);
	return;
    }

    if((num_obj = json_array_size(json_ret)) == 0){
	xsp_info(5,"NO duplicate file found");
	return;
    }
    
    int i;
    json_t *obj;
    json_t *key;
    char *id;
    
    for(i=0; i<num_obj; i++){
	obj = json_array_get(json_ret, i);
	key = json_object_get(obj, "id");
	
	if (key){
	    id = (char *) json_string_value(key);
	    xsp_info(5, "Deleting previous file ID => %s", id);

	    asprintf(&query, "/files/%s",id);

	    xsp_curl_del(&curl_context,
			 query,
			 NULL,
			 &response);
	}
    }

    free(query);
    free(response);
}


int __xspd_forwarder_periscope_insert(json_t *root){
    json_t *json_ret;;
    json_error_t json_err;
    char *query;
    char *response;
    char *send_str;
	
    asprintf(&query, "/files");

    send_str = json_dumps(root, JSON_INDENT(2));
    if(send_str != NULL){
	xsp_info(0,"Json dump :\n %s", send_str);
    }else{
	xsp_err(0,"Failed to create json dump");
	return -1;
    }

    xsp_curl_post_json(&curl_context,
		       query,
		       send_str,
		       &response);

    json_ret = json_loads(response, 0, &json_err);
    if (!json_ret) {
	xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
	xsp_err(5,"Error response : %s", response);
	return -1;
    }

    free(query);
    free(send_str);
    free(response);
	
    return 0;
}

/*void *__xspd_forwarder_loaddir_thread(void *arg) {
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
    }*/

void __xspd_forwarder_mongodb_converter(struct xspd_file_entry_t *file_list){
    
    struct xspd_file_entry_t *temp = file_list;
    
    while( temp != NULL){
	
	struct allocation_t *alloc = temp->allocations;
	int index = 0;
	bson fmeta;
	
	
	bson_init(&fmeta);
	bson_append_int(&fmeta, "ts", (int)time(NULL));
	bson_append_string(&fmeta, "type", "file");
	bson_append_string(&fmeta, "path", config.load_dir);
	bson_append_string(&fmeta, "filename", temp->filename);
	bson_append_int(&fmeta, "size", (int)temp->size);
	bson_append_string(&fmeta, "owner", temp->owner);
	bson_append_start_array(&fmeta, "allocations");

	while(alloc != NULL){
	    	    
	    bson_append_start_object(&fmeta, "");
	    bson_append_int(&fmeta, "offset", (int)alloc->offset);
	    bson_append_int(&fmeta, "length", (int)alloc->length);
	    bson_append_string(&fmeta, "address", alloc->address);
	    bson_append_string(&fmeta, "key0", alloc->l_key);
	    bson_append_string(&fmeta, "key1", alloc->r_key);
	    bson_append_string(&fmeta, "eid", config.eid);
	    bson_append_int(&fmeta, "local_slab_index", index);
	    bson_append_finish_object(&fmeta);
	    
	    alloc = alloc->next;
	    index++;
	}
	
	bson_append_finish_array(&fmeta);
	bson_finish(&fmeta);
	bson_print(&fmeta);

	// push exnodes to mongoDB
	
	if(__xspd_forwarder_mongo_insert(&fmeta, "rdma_files") != 0){
	    xsp_err(5, "Failed to push exnode to mongoDB");
	    return;
	}
	temp = temp->next_file;
    }
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
