#ifndef XSP_CURL_CONTEXT_H
#define XSP_CURL_CONTEXT_H

#include <curl/curl.h>

typedef struct xsp_curl_context_t {
	CURL *curl;
	char *url;
	
	int curl_persist;
	int use_ssl;

	char *keyfile;
	char *keypass;
	char *cacerts;
} xspCURLContext;

int xsp_init_curl(xspCURLContext *cc, int *flags);
int xsp_copy_curl_context(xspCURLContext *src, xspCURLContext *dst);

char *xsp_curl_json_string(xspCURLContext *cc, char *target, int curl_opt, char *send_str, char **ret_str);

#endif
