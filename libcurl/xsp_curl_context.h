/*!
 * @file xsp_curl_context.h
 * @brief Description goes here
 *
 * @author Ezra Kissel ezkissel@indiana.edu
 * @date
 * @version
 * @details curl is a command line tool for transferring data with URL syntax
 *
 */
#ifndef _GNU_SOURCE
/*! @def _GNU_SOURCE
    access to extra non-posix GNU stuff.
 */
#define _GNU_SOURCE
#endif

#ifndef XSP_CURL_CONTEXT_H
/*! @def XSP_CURL_CONTEXT_H
    Make sure not to include this file more than once.
 */
#define XSP_CURL_CONTEXT_H

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

/*!
 * @brief struct xsp_curl_context_t
 *
 * @details [detailed description]
 */
typedef struct xsp_curl_context_t {
	CURL *curl;       /**< CURL pointer */
	char *url;        /**< char pointer to URL */
	
	int curl_persist; /**< this integer is used for */
	int use_ssl;      /**< are we using SSL? */

	char *keyfile;    /**< char pointer to keyfile */
	char *keypass;    /**< char pointer to keypass */
	char *cacerts;    /**< char pointer to cacerts */
} xspCURLContext;

/*!
 * @brief struct curl_http_data
 *
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 *
 */
struct curl_http_data {
        char *ptr;       /**< char pointer to */
        char *lptr;      /**< char pointer to */
        long len;        /**< length */
};

/*!
 * @brief 
 *
 * @fn xsp_init_curl(xspCURLContext *cc, long flags)
 * @param cc
 * @param flags
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_init_curl(xspCURLContext *cc, long flags);

/*!
 * @brief 
 *
 * @fn xsp_copy_curl_context(xspCURLContext *src, xspCURLContext *dst)
 * @param src
 * @param dst
 * @return Returns an integer.
 *
 * @details [detailed description]
 */
int xsp_copy_curl_context(xspCURLContext *src, xspCURLContext *dst);

/*!
 * @brief 
 *
 * @fn xsp_curl_json_string(xspCURLContext *cc, char *target, int curl_opt, char *send_str, char **ret_str)
 * @param cc
 * @param target
 * @param curl_opt
 * @param send_str
 * @param ret_str
 * @return Returns a char pointer
 * 
 * @details 
 */
char *xsp_curl_json_string(xspCURLContext *cc, char *target, int curl_opt, char *send_str, char **ret_str);

/*!
 * @brief 
 *
 * @fn read_cb(void *ptr, size_t size, size_t nmemb, void *userp)
 * @param ptr
 * @param size
 * @param nmemb
 * @param userp
 * @return [information about return value]
 *
 * @details [detailed description]
 */
static size_t read_cb(void *ptr, size_t size, size_t nmemb, void *userp);

/*!
 * @brief [brief description]
 *
 * @fn write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
 * @param ptr
 * @param size
 * @param nmemb
 * @param userp
 * @return [information about return value]
 *
 * @details [detailed description]
 */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp);
#endif // XSP_CURL_CONTEXT_H
