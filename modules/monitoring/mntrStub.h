/* mntrStub.h
   Generated by gSOAP 2.7.9l from mntr.h
   Copyright(C) 2000-2007, Robert van Engelen, Genivia Inc. All Rights Reserved.
   This part of the software is released under one of the following licenses:
   GPL, the gSOAP public license, or Genivia's license for commercial use.
*/

#ifndef mntrStub_H
#define mntrStub_H
#ifndef WITH_NONAMESPACES
#define WITH_NONAMESPACES
#endif
#include "stdsoap2.h"
#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************\
 *                                                                            *
 * Enumerations                                                               *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Classes and Structs                                                        *
 *                                                                            *
\******************************************************************************/


#ifndef SOAP_TYPE_ns1__remove_USCOREpathResponse
#define SOAP_TYPE_ns1__remove_USCOREpathResponse (6)
/* ns1:remove_pathResponse */
struct ns1__remove_USCOREpathResponse
{
	char *remove_USCOREpathResult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns1__new_USCOREpath
#define SOAP_TYPE_ns1__new_USCOREpath (7)
/* ns1:new_path */
struct ns1__new_USCOREpath
{
	struct ns1__PathData *newpath;	/* required element of type ns1:PathData */
};
#endif

#ifndef SOAP_TYPE_ns1__status_USCOREpathResponse
#define SOAP_TYPE_ns1__status_USCOREpathResponse (10)
/* ns1:status_pathResponse */
struct ns1__status_USCOREpathResponse
{
	char *status_USCOREpathResult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns1__status_USCOREpath
#define SOAP_TYPE_ns1__status_USCOREpath (11)
/* ns1:status_path */
struct ns1__status_USCOREpath
{
	struct ns1__PathData *path;	/* required element of type ns1:PathData */
};
#endif

#ifndef SOAP_TYPE_ns1__new_USCOREpathResponse
#define SOAP_TYPE_ns1__new_USCOREpathResponse (12)
/* ns1:new_pathResponse */
struct ns1__new_USCOREpathResponse
{
	char *new_USCOREpathResult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns1__PathData
#define SOAP_TYPE_ns1__PathData (8)
/* ns1:PathData */
struct ns1__PathData
{
	char *status;	/* optional element of type xsd:string */
	char *src;	/* optional element of type xsd:string */
	char *direction;	/* optional element of type xsd:string */
	char *src_USCOREport_USCORErange;	/* optional element of type xsd:string */
	int *start_USCOREtime;	/* optional element of type xsd:int */
	char *path_USCOREid;	/* optional element of type xsd:string */
	char *dst_USCOREport_USCORErange;	/* optional element of type xsd:string */
	int *bandwidth;	/* optional element of type xsd:int */
	int *duration;	/* optional element of type xsd:int */
	char *bw_USCOREclass;	/* optional element of type xsd:string */
	char *dst;	/* optional element of type xsd:string */
	char *vlan_USCOREid;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns1__remove_USCOREpath
#define SOAP_TYPE_ns1__remove_USCOREpath (14)
/* ns1:remove_path */
struct ns1__remove_USCOREpath
{
	char *pathid;	/* required element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE___ns1__new_USCOREpath
#define SOAP_TYPE___ns1__new_USCOREpath (18)
/* Operation wrapper: */
struct __ns1__new_USCOREpath
{
	struct ns1__new_USCOREpath *ns1__new_USCOREpath;	/* optional element of type ns1:new_path */
};
#endif

#ifndef SOAP_TYPE___ns1__remove_USCOREpath
#define SOAP_TYPE___ns1__remove_USCOREpath (22)
/* Operation wrapper: */
struct __ns1__remove_USCOREpath
{
	struct ns1__remove_USCOREpath *ns1__remove_USCOREpath;	/* optional element of type ns1:remove_path */
};
#endif

#ifndef SOAP_TYPE___ns1__status_USCOREpath
#define SOAP_TYPE___ns1__status_USCOREpath (26)
/* Operation wrapper: */
struct __ns1__status_USCOREpath
{
	struct ns1__status_USCOREpath *ns1__status_USCOREpath;	/* optional element of type ns1:status_path */
};
#endif

#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (27)
/* SOAP Header: */
struct SOAP_ENV__Header
{
#ifdef WITH_NOEMPTYSTRUCT
	char dummy;	/* dummy member to enable compilation */
#endif
};
#endif

#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (28)
/* SOAP Fault Code: */
struct SOAP_ENV__Code
{
	char *SOAP_ENV__Value;	/* optional element of type xsd:QName */
	struct SOAP_ENV__Code *SOAP_ENV__Subcode;	/* optional element of type SOAP-ENV:Code */
};
#endif

#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (30)
/* SOAP-ENV:Detail */
struct SOAP_ENV__Detail
{
	int __type;	/* any type of element <fault> (defined below) */
	void *fault;	/* transient */
	char *__any;
};
#endif

#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (33)
/* SOAP-ENV:Reason */
struct SOAP_ENV__Reason
{
	char *SOAP_ENV__Text;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (34)
/* SOAP Fault: */
struct SOAP_ENV__Fault
{
	char *faultcode;	/* optional element of type xsd:QName */
	char *faultstring;	/* optional element of type xsd:string */
	char *faultactor;	/* optional element of type xsd:string */
	struct SOAP_ENV__Detail *detail;	/* optional element of type SOAP-ENV:Detail */
	struct SOAP_ENV__Code *SOAP_ENV__Code;	/* optional element of type SOAP-ENV:Code */
	struct SOAP_ENV__Reason *SOAP_ENV__Reason;	/* optional element of type SOAP-ENV:Reason */
	char *SOAP_ENV__Node;	/* optional element of type xsd:string */
	char *SOAP_ENV__Role;	/* optional element of type xsd:string */
	struct SOAP_ENV__Detail *SOAP_ENV__Detail;	/* optional element of type SOAP-ENV:Detail */
};
#endif

/******************************************************************************\
 *                                                                            *
 * Types with Custom Serializers                                              *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Typedefs                                                                   *
 *                                                                            *
\******************************************************************************/

#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (4)
typedef char *_XML;
#endif

#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (5)
typedef char *_QName;
#endif


/******************************************************************************\
 *                                                                            *
 * Typedef Synonyms                                                           *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Externals                                                                  *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Stubs                                                                      *
 *                                                                            *
\******************************************************************************/


SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__new_USCOREpath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__new_USCOREpath *ns1__new_USCOREpath, struct ns1__new_USCOREpathResponse *ns1__new_USCOREpathResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__remove_USCOREpath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__remove_USCOREpath *ns1__remove_USCOREpath, struct ns1__remove_USCOREpathResponse *ns1__remove_USCOREpathResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__status_USCOREpath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__status_USCOREpath *ns1__status_USCOREpath, struct ns1__status_USCOREpathResponse *ns1__status_USCOREpathResponse);

#ifdef __cplusplus
}
#endif

#endif

/* End of mntrStub.h */
