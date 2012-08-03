#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xsp_curl_context.h"

struct curl_http_data {
        char *ptr;
	char *lptr;
        long len;
};

static size_t read_cb(void *ptr, size_t size, size_t nmemb, void *userp);
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp);


int xsp_init_curl(xspCURLContext *cc, int *flags) {
	CURLcode res;
	int cflags;

	if (!flags)
		cflags = CURL_GLOBAL_DEFAULT;
	else
		cflags = *flags;

	res = curl_global_init(flags);
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_global_init() failed: %s\n", curl_easy_strerror(res));
		return -1;
	}

	cc->curl = curl_easy_init();
	if (!cc->curl) {
		fprintf(stderr, "Could not intialize CURL\n");
		return -1;
	}

	return 0;
}

int xsp_copy_curl_context(xspCURLContext *src, xspCURLContext *dst) {
	memcpy(dst, src, sizeof(xspCURLContext));
	return 0;
}

char *xsp_curl_json_string(xspCURLContext *cc, char *target, int curl_opt, char *send_str, char **ret_str) {
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	char *endpoint;
	long send_len;

	if (send_str)
		send_len = strlen(send_str);
	else
		send_len = 0;

	asprintf(&endpoint, "%s%s", cc->url, target);

	struct curl_http_data send_data = {
		.ptr = send_str,
		.lptr = NULL,
		.len = send_len
	};		
	
	struct curl_http_data recv_data = {
                .ptr = NULL,
		.lptr = NULL,
		.len = 0
        };

	if (cc->curl_persist)
		curl = cc->curl;
	else {
		curl = curl_easy_init();
		if (!curl) {
			fprintf(stderr, "Could not initialize CURL\n");
			goto error_exit;
		}
	}
	
	curl_easy_setopt(curl, CURLOPT_URL, endpoint);
	curl_easy_setopt(curl, curl_opt, 1L);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &send_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv_data);

	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	
	/* we need to define some content-types this little library supports
	   RESTful UNIS will need application/perfsonar+json for POSTS/PUT
	   but maybe we should have UNIS accept application/json */
	headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
	headers = curl_slist_append(headers, "Content-type': 'application/json");
	headers = curl_slist_append(headers, "Accept': 'application/json");
	
	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto error_exit;
	}

	if (!(cc->curl_persist))
		curl_easy_cleanup(curl);

	*ret_str = recv_data.ptr;
	return recv_data.ptr;

 error_exit:
	*ret_str = NULL;
	return NULL;
}

static size_t read_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct curl_http_data *data = (struct curl_http_data *)userp;

	if (size*nmemb < 1)
		return 0;

	if (data->len) {
		*(char *)ptr = data->ptr[0];
		data->ptr++;
		data->len--;
		return 1;
	}

        return 0;
}

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
        struct curl_http_data *data = (struct curl_http_data *)userp;
	long dsize = size*nmemb;
	
	if (dsize < 1)
		return 0;
	
	if (!(data->ptr)) {
		data->ptr = malloc(dsize*sizeof(char));
		data->lptr = data->ptr;
	}
	else {
		realloc(data->ptr, (dsize + data->len) * sizeof(char));
	}

	if (!(data->ptr))
		return 0;

	data->lptr = mempcpy(data->lptr, ptr, dsize);
	data->len += dsize;

	data->ptr[data->len] = '\0';

	return size*nmemb;
}
	
