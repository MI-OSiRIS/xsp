/*!
 * @file xsp_soap_context.h
 * @brief Simple Object Access Protocl (SOAP)
 *
 * @author Ezra Kissel ezkissel@indiana.edu
 * @date
 * @version
 * @details To learn more about SOAP, visit the FAQ at: 
 *          <URL:http://www.w3.org/TR/soap12-part0/>
 *
 */
#ifndef XSP_SOAP_CONTEXT_H
/*!
 * @def XSP_SOAP_CONTEXT_H
 *    Make sure not to include this file more than once.
 */
#define XSP_SOAP_CONTEXT_H

#include "stdsoap2.h"

/*!
 * @brief struct xsp_soap_context_t
 *
 * @details [detailed description]
 */
typedef struct xsp_soap_context_t {
	void *soap;                   /**<  pointer */
	char *soap_endpoint;          /**<  pointer */
	char *soap_action;            /**<  pointer */
	
	char *keyfile;                /**<  pointer */
	char *keypass;                /**<  pointer */
	char *cacerts;                /**<  pointer */
	
	char *wsse_key;               /**<  pointer */
	char *wsse_pass;              /**<  pointer */
	char *wsse_cert;              /**<  pointer */

	struct Namespace *namespaces; /**<  pointer */
} xspSoapContext;

/*!
 * @brief 
 * @fn xsp_copy_soap_context(xspSoapContext *src, xspSoapContext *dst)
 * @param
 * @param
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_copy_soap_context(xspSoapContext *src, xspSoapContext *dst);

/*!
 * @brief 
 * @fn xsp_start_soap_ssl(xspSoapContext *sc, int soap_init_flags, int soap_ssl_flags)
 * @param
 * @param
 * @param
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_start_soap_ssl(xspSoapContext *sc, int soap_init_flags, int soap_ssl_flags);

/*!
 * @brief 
 * @fn xsp_stop_soap_ssl(xspSoapContext *sc)
 * @param
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_stop_soap_ssl(xspSoapContext *sc);

/*!
 * @brief 
 * @fn xsp_start_soap(xspSoapContext *sc, int soap_init_flags)
 * @param
 * @param
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_start_soap(xspSoapContext *sc, int soap_init_flags);

/*!
 * @brief 
 * @fn xsp_stop_soap(xspSoapContext *sc)
 * @param
 * @param
 * @return Returns an integer.
 * @sa [see also section]
 * @note [any note about the function you might have]
 * @warning [any warning if necessary]
 *
 * @details [detailed description]
 */
int xsp_stop_soap(xspSoapContext *sc);

#endif // XSP_SOAP_CONTEXT_H
