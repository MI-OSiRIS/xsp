// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
/* envC.c
   Generated by gSOAP 2.7.9l from env.h
   Copyright(C) 2000-2007, Robert van Engelen, Genivia Inc. All Rights Reserved.
   This part of the software is released under one of the following licenses:
   GPL, the gSOAP public license, or Genivia's license for commercial use.
*/

#include "envH.h"

#ifdef __cplusplus
extern "C" {
#endif

SOAP_SOURCE_STAMP("@(#) envC.c ver 2.7.9l 2010-05-18 13:56:37 GMT")


#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_serializeheader(struct soap *soap)
{
	if (soap->header)
		soap_serialize_SOAP_ENV__Header(soap, soap->header);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_putheader(struct soap *soap)
{
	if (soap->header)
	{	soap->part = SOAP_IN_HEADER;
		if (soap_out_SOAP_ENV__Header(soap, "SOAP-ENV:Header", 0, soap->header, NULL))
			return soap->error;
		soap->part = SOAP_END_HEADER;
	}
	return SOAP_OK;
}

SOAP_FMAC3 int SOAP_FMAC4 soap_getheader(struct soap *soap)
{
	soap->part = SOAP_IN_HEADER;
	soap->header = soap_in_SOAP_ENV__Header(soap, "SOAP-ENV:Header", NULL, NULL);
	soap->part = SOAP_END_HEADER;
	return soap->header == NULL;
}

SOAP_FMAC3 void SOAP_FMAC4 soap_header(struct soap *soap)
{
	if (!soap->header)
	{	soap->header = (struct SOAP_ENV__Header*)soap_malloc(soap, sizeof(struct SOAP_ENV__Header));
		soap_default_SOAP_ENV__Header(soap, soap->header);
	}
}

SOAP_FMAC3 void SOAP_FMAC4 soap_fault(struct soap *soap)
{
	if (!soap->fault)
	{	soap->fault = (struct SOAP_ENV__Fault*)soap_malloc(soap, sizeof(struct SOAP_ENV__Fault));
		soap_default_SOAP_ENV__Fault(soap, soap->fault);
	}
	if (soap->version == 2 && !soap->fault->SOAP_ENV__Code)
	{	soap->fault->SOAP_ENV__Code = (struct SOAP_ENV__Code*)soap_malloc(soap, sizeof(struct SOAP_ENV__Code));
		soap_default_SOAP_ENV__Code(soap, soap->fault->SOAP_ENV__Code);
	}
	if (soap->version == 2 && !soap->fault->SOAP_ENV__Reason)
	{	soap->fault->SOAP_ENV__Reason = (struct SOAP_ENV__Reason*)soap_malloc(soap, sizeof(struct SOAP_ENV__Reason));
		soap_default_SOAP_ENV__Reason(soap, soap->fault->SOAP_ENV__Reason);
	}
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serializefault(struct soap *soap)
{
	if (soap->fault)
		soap_serialize_SOAP_ENV__Fault(soap, soap->fault);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_putfault(struct soap *soap)
{
	if (soap->fault)
		return soap_put_SOAP_ENV__Fault(soap, soap->fault, "SOAP-ENV:Fault", NULL);
	return SOAP_OK;
}

SOAP_FMAC3 int SOAP_FMAC4 soap_getfault(struct soap *soap)
{
	return (soap->fault = soap_get_SOAP_ENV__Fault(soap, NULL, "SOAP-ENV:Fault", NULL)) == NULL;
}

SOAP_FMAC3 const char ** SOAP_FMAC4 soap_faultcode(struct soap *soap)
{
	soap_fault(soap);
	if (soap->version == 2)
		return (const char**)&soap->fault->SOAP_ENV__Code->SOAP_ENV__Value;
	return (const char**)&soap->fault->faultcode;
}

SOAP_FMAC3 const char ** SOAP_FMAC4 soap_faultsubcode(struct soap *soap)
{
	soap_fault(soap);
	if (soap->version == 2)
	{	if (!soap->fault->SOAP_ENV__Code->SOAP_ENV__Subcode)
		{	soap->fault->SOAP_ENV__Code->SOAP_ENV__Subcode = (struct SOAP_ENV__Code*)soap_malloc(soap, sizeof(struct SOAP_ENV__Code));
			soap_default_SOAP_ENV__Code(soap, soap->fault->SOAP_ENV__Code->SOAP_ENV__Subcode);
		}
		return (const char**)&soap->fault->SOAP_ENV__Code->SOAP_ENV__Subcode->SOAP_ENV__Value;
	}
	return (const char**)&soap->fault->faultcode;
}

SOAP_FMAC3 const char ** SOAP_FMAC4 soap_faultstring(struct soap *soap)
{
	soap_fault(soap);
	if (soap->version == 2)
		return (const char**)&soap->fault->SOAP_ENV__Reason->SOAP_ENV__Text;
	return (const char**)&soap->fault->faultstring;
}

SOAP_FMAC3 const char ** SOAP_FMAC4 soap_faultdetail(struct soap *soap)
{
	soap_fault(soap);
	if (soap->version == 1)
	{	if (!soap->fault->detail)
		{	soap->fault->detail = (struct SOAP_ENV__Detail*)soap_malloc(soap, sizeof(struct SOAP_ENV__Detail));
			soap_default_SOAP_ENV__Detail(soap, soap->fault->detail);
		}
		return (const char**)&soap->fault->detail->__any;
	}
	if (!soap->fault->SOAP_ENV__Detail)
	{	soap->fault->SOAP_ENV__Detail = (struct SOAP_ENV__Detail*)soap_malloc(soap, sizeof(struct SOAP_ENV__Detail));
		soap_default_SOAP_ENV__Detail(soap, soap->fault->SOAP_ENV__Detail);
	}
	return (const char**)&soap->fault->SOAP_ENV__Detail->__any;
}

#endif

#ifndef WITH_NOIDREF
SOAP_FMAC3 int SOAP_FMAC4 soap_getindependent(struct soap *soap)
{
	int t;
	for (;;)
		if (!soap_getelement(soap, &t))
			if (soap->error || soap_ignore_element(soap))
				break;
	if (soap->error == SOAP_NO_TAG || soap->error == SOAP_EOF)
		soap->error = SOAP_OK;
	return soap->error;
}
#endif

#ifndef WITH_NOIDREF
SOAP_FMAC3 void * SOAP_FMAC4 soap_getelement(struct soap *soap, int *type)
{
	if (soap_peek_element(soap))
		return NULL;
	if (!*soap->id || !(*type = soap_lookup_type(soap, soap->id)))
		*type = soap_lookup_type(soap, soap->href);
	switch (*type)
	{
	case SOAP_TYPE_byte:
		return soap_in_byte(soap, NULL, NULL, "xsd:byte");
	case SOAP_TYPE_int:
		return soap_in_int(soap, NULL, NULL, "xsd:int");
	case SOAP_TYPE_string:
	{	char **s;
		s = soap_in_string(soap, NULL, NULL, "xsd:string");
		return s ? *s : NULL;
	}
	default:
	{	const char *t = soap->type;
		if (!*t)
			t = soap->tag;
		if (!soap_match_tag(soap, t, "xsd:byte"))
		{	*type = SOAP_TYPE_byte;
			return soap_in_byte(soap, NULL, NULL, NULL);
		}
		if (!soap_match_tag(soap, t, "xsd:int"))
		{	*type = SOAP_TYPE_int;
			return soap_in_int(soap, NULL, NULL, NULL);
		}
		if (!soap_match_tag(soap, t, "xsd:string"))
		{	char **s;
			*type = SOAP_TYPE_string;
			s = soap_in_string(soap, NULL, NULL, NULL);
			return s ? *s : NULL;
		}
		t = soap->tag;
		if (!soap_match_tag(soap, t, "xsd:QName"))
		{	char **s;
			*type = SOAP_TYPE__QName;
			s = soap_in__QName(soap, NULL, NULL, NULL);
			return s ? *s : NULL;
		}
	}
	}
	soap->error = SOAP_TAG_MISMATCH;
	return NULL;
}
#endif

SOAP_FMAC3 int SOAP_FMAC4 soap_ignore_element(struct soap *soap)
{
	if (!soap_peek_element(soap))
	{	int t;
		if (soap->mustUnderstand && !soap->other)
			return soap->error = SOAP_MUSTUNDERSTAND;
		if (((soap->mode & SOAP_XML_STRICT) && soap->part != SOAP_IN_HEADER) || !soap_match_tag(soap, soap->tag, "SOAP-ENV:"))
		{	DBGLOG(TEST, SOAP_MESSAGE(fdebug, "REJECTING element '%s'\n", soap->tag));
			return soap->error = SOAP_TAG_MISMATCH;
		}
		if (!*soap->id || !soap_getelement(soap, &t))
		{	soap->peeked = 0;
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Unknown element '%s' (level=%u, %d)\n", soap->tag, soap->level, soap->body));
			if (soap->fignore)
				soap->error = soap->fignore(soap, soap->tag);
			else
				soap->error = SOAP_OK;
			DBGLOG(TEST, if (!soap->error) SOAP_MESSAGE(fdebug, "IGNORING element '%s'\n", soap->tag));
			if (!soap->error && soap->body)
			{	soap->level++;
				while (!soap_ignore_element(soap))
					;
				if (soap->error == SOAP_NO_TAG)
					soap->error = soap_element_end_in(soap, NULL);
			}
		}
	}
	return soap->error;
}

#ifndef WITH_NOIDREF
SOAP_FMAC3 int SOAP_FMAC4 soap_putindependent(struct soap *soap)
{
	int i;
	struct soap_plist *pp;
	if (soap->version == 1 && soap->encodingStyle && !(soap->mode & (SOAP_XML_TREE | SOAP_XML_GRAPH)))
		for (i = 0; i < SOAP_PTRHASH; i++)
			for (pp = soap->pht[i]; pp; pp = pp->next)
				if (pp->mark1 == 2 || pp->mark2 == 2)
					if (soap_putelement(soap, pp->ptr, "id", pp->id, pp->type))
						return soap->error;
	return SOAP_OK;
}
#endif

#ifndef WITH_NOIDREF
SOAP_FMAC3 int SOAP_FMAC4 soap_putelement(struct soap *soap, const void *ptr, const char *tag, int id, int type)
{
	switch (type)
	{
	case SOAP_TYPE_byte:
		return soap_out_byte(soap, tag, id, (const char *)ptr, "xsd:byte");
	case SOAP_TYPE_int:
		return soap_out_int(soap, tag, id, (const int *)ptr, "xsd:int");
	case SOAP_TYPE__QName:
		return soap_out_string(soap, "xsd:QName", id, (char*const*)&ptr, NULL);
	case SOAP_TYPE_string:
		return soap_out_string(soap, tag, id, (char*const*)&ptr, "xsd:string");
	}
	return SOAP_OK;
}
#endif

#ifndef WITH_NOIDREF
SOAP_FMAC3 void SOAP_FMAC4 soap_markelement(struct soap *soap, const void *ptr, int type)
{
	(void)soap; (void)ptr; (void)type; /* appease -Wall -Werror */
	switch (type)
	{
	case SOAP_TYPE__QName:
		soap_serialize_string(soap, (char*const*)&ptr);
		break;
	case SOAP_TYPE_string:
		soap_serialize_string(soap, (char*const*)&ptr);
		break;
	}
}
#endif

SOAP_FMAC3 void SOAP_FMAC4 soap_default_byte(struct soap *soap, char *a)
{	(void)soap; /* appease -Wall -Werror */
#ifdef SOAP_DEFAULT_byte
	*a = SOAP_DEFAULT_byte;
#else
	*a = (char)0;
#endif
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_byte(struct soap *soap, const char *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_byte);
	if (soap_out_byte(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_byte(struct soap *soap, const char *tag, int id, const char *a, const char *type)
{
	return soap_outbyte(soap, tag, id, a, type, SOAP_TYPE_byte);
}

SOAP_FMAC3 char * SOAP_FMAC4 soap_get_byte(struct soap *soap, char *p, const char *tag, const char *type)
{
	if ((p = soap_in_byte(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 char * SOAP_FMAC4 soap_in_byte(struct soap *soap, const char *tag, char *a, const char *type)
{
	return soap_inbyte(soap, tag, a, type, SOAP_TYPE_byte);
}

SOAP_FMAC3 void SOAP_FMAC4 soap_default_int(struct soap *soap, int *a)
{	(void)soap; /* appease -Wall -Werror */
#ifdef SOAP_DEFAULT_int
	*a = SOAP_DEFAULT_int;
#else
	*a = (int)0;
#endif
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_int(struct soap *soap, const int *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_int);
	if (soap_out_int(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_int(struct soap *soap, const char *tag, int id, const int *a, const char *type)
{
	return soap_outint(soap, tag, id, a, type, SOAP_TYPE_int);
}

SOAP_FMAC3 int * SOAP_FMAC4 soap_get_int(struct soap *soap, int *p, const char *tag, const char *type)
{
	if ((p = soap_in_int(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 int * SOAP_FMAC4 soap_in_int(struct soap *soap, const char *tag, int *a, const char *type)
{
	return soap_inint(soap, tag, a, type, SOAP_TYPE_int);
}

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_default_SOAP_ENV__Fault(struct soap *soap, struct SOAP_ENV__Fault *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_default__QName(soap, &a->faultcode);
	soap_default_string(soap, &a->faultstring);
	soap_default_string(soap, &a->faultactor);
	a->detail = NULL;
	a->SOAP_ENV__Code = NULL;
	a->SOAP_ENV__Reason = NULL;
	soap_default_string(soap, &a->SOAP_ENV__Node);
	soap_default_string(soap, &a->SOAP_ENV__Role);
	a->SOAP_ENV__Detail = NULL;
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_SOAP_ENV__Fault(struct soap *soap, const struct SOAP_ENV__Fault *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_serialize__QName(soap, &a->faultcode);
	soap_serialize_string(soap, &a->faultstring);
	soap_serialize_string(soap, &a->faultactor);
	soap_serialize_PointerToSOAP_ENV__Detail(soap, &a->detail);
	soap_serialize_PointerToSOAP_ENV__Code(soap, &a->SOAP_ENV__Code);
	soap_serialize_PointerToSOAP_ENV__Reason(soap, &a->SOAP_ENV__Reason);
	soap_serialize_string(soap, &a->SOAP_ENV__Node);
	soap_serialize_string(soap, &a->SOAP_ENV__Role);
	soap_serialize_PointerToSOAP_ENV__Detail(soap, &a->SOAP_ENV__Detail);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_SOAP_ENV__Fault(struct soap *soap, const struct SOAP_ENV__Fault *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_SOAP_ENV__Fault);
	if (soap_out_SOAP_ENV__Fault(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Fault(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Fault *a, const char *type)
{
	const char *soap_tmp_faultcode = soap_QName2s(soap, a->faultcode);
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, a, SOAP_TYPE_SOAP_ENV__Fault), type))
		return soap->error;
	if (soap_out__QName(soap, "faultcode", -1, (char*const*)&soap_tmp_faultcode, ""))
		return soap->error;
	if (soap_out_string(soap, "faultstring", -1, &a->faultstring, ""))
		return soap->error;
	if (soap_out_string(soap, "faultactor", -1, &a->faultactor, ""))
		return soap->error;
	if (soap_out_PointerToSOAP_ENV__Detail(soap, "detail", -1, &a->detail, ""))
		return soap->error;
	if (soap_out_PointerToSOAP_ENV__Code(soap, "SOAP-ENV:Code", -1, &a->SOAP_ENV__Code, ""))
		return soap->error;
	if (soap_out_PointerToSOAP_ENV__Reason(soap, "SOAP-ENV:Reason", -1, &a->SOAP_ENV__Reason, ""))
		return soap->error;
	if (soap_out_string(soap, "SOAP-ENV:Node", -1, &a->SOAP_ENV__Node, ""))
		return soap->error;
	if (soap_out_string(soap, "SOAP-ENV:Role", -1, &a->SOAP_ENV__Role, ""))
		return soap->error;
	if (soap_out_PointerToSOAP_ENV__Detail(soap, "SOAP-ENV:Detail", -1, &a->SOAP_ENV__Detail, ""))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

SOAP_FMAC3 struct SOAP_ENV__Fault * SOAP_FMAC4 soap_get_SOAP_ENV__Fault(struct soap *soap, struct SOAP_ENV__Fault *p, const char *tag, const char *type)
{
	if ((p = soap_in_SOAP_ENV__Fault(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Fault * SOAP_FMAC4 soap_in_SOAP_ENV__Fault(struct soap *soap, const char *tag, struct SOAP_ENV__Fault *a, const char *type)
{
	short soap_flag_faultcode = 1, soap_flag_faultstring = 1, soap_flag_faultactor = 1, soap_flag_detail = 1, soap_flag_SOAP_ENV__Code = 1, soap_flag_SOAP_ENV__Reason = 1, soap_flag_SOAP_ENV__Node = 1, soap_flag_SOAP_ENV__Role = 1, soap_flag_SOAP_ENV__Detail = 1;
	if (soap_element_begin_in(soap, tag, 0, type))
		return NULL;
	a = (struct SOAP_ENV__Fault *)soap_id_enter(soap, soap->id, a, SOAP_TYPE_SOAP_ENV__Fault, sizeof(struct SOAP_ENV__Fault), 0, NULL, NULL, NULL);
	if (!a)
		return NULL;
	soap_default_SOAP_ENV__Fault(soap, a);
	if (soap->body && !*soap->href)
	{
		for (;;)
		{	soap->error = SOAP_TAG_MISMATCH;
			if (soap_flag_faultcode && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in__QName(soap, "faultcode", &a->faultcode, ""))
				{	soap_flag_faultcode--;
					continue;
				}
			if (soap_flag_faultstring && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in_string(soap, "faultstring", &a->faultstring, "xsd:string"))
				{	soap_flag_faultstring--;
					continue;
				}
			if (soap_flag_faultactor && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in_string(soap, "faultactor", &a->faultactor, "xsd:string"))
				{	soap_flag_faultactor--;
					continue;
				}
			if (soap_flag_detail && soap->error == SOAP_TAG_MISMATCH)
				if (soap_in_PointerToSOAP_ENV__Detail(soap, "detail", &a->detail, ""))
				{	soap_flag_detail--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Code && soap->error == SOAP_TAG_MISMATCH)
				if (soap_in_PointerToSOAP_ENV__Code(soap, "SOAP-ENV:Code", &a->SOAP_ENV__Code, ""))
				{	soap_flag_SOAP_ENV__Code--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Reason && soap->error == SOAP_TAG_MISMATCH)
				if (soap_in_PointerToSOAP_ENV__Reason(soap, "SOAP-ENV:Reason", &a->SOAP_ENV__Reason, ""))
				{	soap_flag_SOAP_ENV__Reason--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Node && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in_string(soap, "SOAP-ENV:Node", &a->SOAP_ENV__Node, "xsd:string"))
				{	soap_flag_SOAP_ENV__Node--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Role && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in_string(soap, "SOAP-ENV:Role", &a->SOAP_ENV__Role, "xsd:string"))
				{	soap_flag_SOAP_ENV__Role--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Detail && soap->error == SOAP_TAG_MISMATCH)
				if (soap_in_PointerToSOAP_ENV__Detail(soap, "SOAP-ENV:Detail", &a->SOAP_ENV__Detail, ""))
				{	soap_flag_SOAP_ENV__Detail--;
					continue;
				}
			if (soap->error == SOAP_TAG_MISMATCH)
				soap->error = soap_ignore_element(soap);
			if (soap->error == SOAP_NO_TAG)
				break;
			if (soap->error)
				return NULL;
		}
		if (soap_element_end_in(soap, tag))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Fault *)soap_id_forward(soap, soap->href, (void*)a, 0, SOAP_TYPE_SOAP_ENV__Fault, 0, sizeof(struct SOAP_ENV__Fault), 0, NULL);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_default_SOAP_ENV__Reason(struct soap *soap, struct SOAP_ENV__Reason *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_default_string(soap, &a->SOAP_ENV__Text);
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_SOAP_ENV__Reason(struct soap *soap, const struct SOAP_ENV__Reason *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_serialize_string(soap, &a->SOAP_ENV__Text);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_SOAP_ENV__Reason(struct soap *soap, const struct SOAP_ENV__Reason *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_SOAP_ENV__Reason);
	if (soap_out_SOAP_ENV__Reason(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Reason(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Reason *a, const char *type)
{
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, a, SOAP_TYPE_SOAP_ENV__Reason), type))
		return soap->error;
	if (soap_out_string(soap, "SOAP-ENV:Text", -1, &a->SOAP_ENV__Text, ""))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

SOAP_FMAC3 struct SOAP_ENV__Reason * SOAP_FMAC4 soap_get_SOAP_ENV__Reason(struct soap *soap, struct SOAP_ENV__Reason *p, const char *tag, const char *type)
{
	if ((p = soap_in_SOAP_ENV__Reason(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Reason * SOAP_FMAC4 soap_in_SOAP_ENV__Reason(struct soap *soap, const char *tag, struct SOAP_ENV__Reason *a, const char *type)
{
	short soap_flag_SOAP_ENV__Text = 1;
	if (soap_element_begin_in(soap, tag, 0, type))
		return NULL;
	a = (struct SOAP_ENV__Reason *)soap_id_enter(soap, soap->id, a, SOAP_TYPE_SOAP_ENV__Reason, sizeof(struct SOAP_ENV__Reason), 0, NULL, NULL, NULL);
	if (!a)
		return NULL;
	soap_default_SOAP_ENV__Reason(soap, a);
	if (soap->body && !*soap->href)
	{
		for (;;)
		{	soap->error = SOAP_TAG_MISMATCH;
			if (soap_flag_SOAP_ENV__Text && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in_string(soap, "SOAP-ENV:Text", &a->SOAP_ENV__Text, "xsd:string"))
				{	soap_flag_SOAP_ENV__Text--;
					continue;
				}
			if (soap->error == SOAP_TAG_MISMATCH)
				soap->error = soap_ignore_element(soap);
			if (soap->error == SOAP_NO_TAG)
				break;
			if (soap->error)
				return NULL;
		}
		if (soap_element_end_in(soap, tag))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Reason *)soap_id_forward(soap, soap->href, (void*)a, 0, SOAP_TYPE_SOAP_ENV__Reason, 0, sizeof(struct SOAP_ENV__Reason), 0, NULL);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_default_SOAP_ENV__Detail(struct soap *soap, struct SOAP_ENV__Detail *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	a->__type = 0;
	a->fault = NULL;
	a->__any = NULL;
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_SOAP_ENV__Detail(struct soap *soap, const struct SOAP_ENV__Detail *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_markelement(soap, a->fault, a->__type);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_SOAP_ENV__Detail(struct soap *soap, const struct SOAP_ENV__Detail *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_SOAP_ENV__Detail);
	if (soap_out_SOAP_ENV__Detail(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Detail(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Detail *a, const char *type)
{
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, a, SOAP_TYPE_SOAP_ENV__Detail), type))
		return soap->error;
	if (soap_putelement(soap, a->fault, "fault", -1, a->__type))
		return soap->error;
	soap_outliteral(soap, "-any", &a->__any, NULL);
	return soap_element_end_out(soap, tag);
}

SOAP_FMAC3 struct SOAP_ENV__Detail * SOAP_FMAC4 soap_get_SOAP_ENV__Detail(struct soap *soap, struct SOAP_ENV__Detail *p, const char *tag, const char *type)
{
	if ((p = soap_in_SOAP_ENV__Detail(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Detail * SOAP_FMAC4 soap_in_SOAP_ENV__Detail(struct soap *soap, const char *tag, struct SOAP_ENV__Detail *a, const char *type)
{
	short soap_flag_fault = 1, soap_flag___any = 1;
	if (soap_element_begin_in(soap, tag, 0, type))
		return NULL;
	a = (struct SOAP_ENV__Detail *)soap_id_enter(soap, soap->id, a, SOAP_TYPE_SOAP_ENV__Detail, sizeof(struct SOAP_ENV__Detail), 0, NULL, NULL, NULL);
	if (!a)
		return NULL;
	soap_default_SOAP_ENV__Detail(soap, a);
	if (soap->body && !*soap->href)
	{
		for (;;)
		{	soap->error = SOAP_TAG_MISMATCH;
			if (soap_flag_fault && soap->error == SOAP_TAG_MISMATCH)
				if ((a->fault = soap_getelement(soap, &a->__type)))
				{	soap_flag_fault = 0;
					continue;
				}
			if (soap_flag___any && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_inliteral(soap, "-any", &a->__any))
				{	soap_flag___any--;
					continue;
				}
			if (soap->error == SOAP_TAG_MISMATCH)
				soap->error = soap_ignore_element(soap);
			if (soap->error == SOAP_NO_TAG)
				break;
			if (soap->error)
				return NULL;
		}
		if (soap_element_end_in(soap, tag))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Detail *)soap_id_forward(soap, soap->href, (void*)a, 0, SOAP_TYPE_SOAP_ENV__Detail, 0, sizeof(struct SOAP_ENV__Detail), 0, NULL);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_default_SOAP_ENV__Code(struct soap *soap, struct SOAP_ENV__Code *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_default__QName(soap, &a->SOAP_ENV__Value);
	a->SOAP_ENV__Subcode = NULL;
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_SOAP_ENV__Code(struct soap *soap, const struct SOAP_ENV__Code *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
	soap_serialize__QName(soap, &a->SOAP_ENV__Value);
	soap_serialize_PointerToSOAP_ENV__Code(soap, &a->SOAP_ENV__Subcode);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_SOAP_ENV__Code(struct soap *soap, const struct SOAP_ENV__Code *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_SOAP_ENV__Code);
	if (soap_out_SOAP_ENV__Code(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Code(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Code *a, const char *type)
{
	const char *soap_tmp_SOAP_ENV__Value = soap_QName2s(soap, a->SOAP_ENV__Value);
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, a, SOAP_TYPE_SOAP_ENV__Code), type))
		return soap->error;
	if (soap_out__QName(soap, "SOAP-ENV:Value", -1, (char*const*)&soap_tmp_SOAP_ENV__Value, ""))
		return soap->error;
	if (soap_out_PointerToSOAP_ENV__Code(soap, "SOAP-ENV:Subcode", -1, &a->SOAP_ENV__Subcode, ""))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

SOAP_FMAC3 struct SOAP_ENV__Code * SOAP_FMAC4 soap_get_SOAP_ENV__Code(struct soap *soap, struct SOAP_ENV__Code *p, const char *tag, const char *type)
{
	if ((p = soap_in_SOAP_ENV__Code(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Code * SOAP_FMAC4 soap_in_SOAP_ENV__Code(struct soap *soap, const char *tag, struct SOAP_ENV__Code *a, const char *type)
{
	short soap_flag_SOAP_ENV__Value = 1, soap_flag_SOAP_ENV__Subcode = 1;
	if (soap_element_begin_in(soap, tag, 0, type))
		return NULL;
	a = (struct SOAP_ENV__Code *)soap_id_enter(soap, soap->id, a, SOAP_TYPE_SOAP_ENV__Code, sizeof(struct SOAP_ENV__Code), 0, NULL, NULL, NULL);
	if (!a)
		return NULL;
	soap_default_SOAP_ENV__Code(soap, a);
	if (soap->body && !*soap->href)
	{
		for (;;)
		{	soap->error = SOAP_TAG_MISMATCH;
			if (soap_flag_SOAP_ENV__Value && (soap->error == SOAP_TAG_MISMATCH || soap->error == SOAP_NO_TAG))
				if (soap_in__QName(soap, "SOAP-ENV:Value", &a->SOAP_ENV__Value, ""))
				{	soap_flag_SOAP_ENV__Value--;
					continue;
				}
			if (soap_flag_SOAP_ENV__Subcode && soap->error == SOAP_TAG_MISMATCH)
				if (soap_in_PointerToSOAP_ENV__Code(soap, "SOAP-ENV:Subcode", &a->SOAP_ENV__Subcode, ""))
				{	soap_flag_SOAP_ENV__Subcode--;
					continue;
				}
			if (soap->error == SOAP_TAG_MISMATCH)
				soap->error = soap_ignore_element(soap);
			if (soap->error == SOAP_NO_TAG)
				break;
			if (soap->error)
				return NULL;
		}
		if (soap_element_end_in(soap, tag))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Code *)soap_id_forward(soap, soap->href, (void*)a, 0, SOAP_TYPE_SOAP_ENV__Code, 0, sizeof(struct SOAP_ENV__Code), 0, NULL);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_default_SOAP_ENV__Header(struct soap *soap, struct SOAP_ENV__Header *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_SOAP_ENV__Header(struct soap *soap, const struct SOAP_ENV__Header *a)
{
	(void)soap; (void)a; /* appease -Wall -Werror */
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_SOAP_ENV__Header(struct soap *soap, const struct SOAP_ENV__Header *a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_SOAP_ENV__Header);
	if (soap_out_SOAP_ENV__Header(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Header(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Header *a, const char *type)
{
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, a, SOAP_TYPE_SOAP_ENV__Header), type))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

SOAP_FMAC3 struct SOAP_ENV__Header * SOAP_FMAC4 soap_get_SOAP_ENV__Header(struct soap *soap, struct SOAP_ENV__Header *p, const char *tag, const char *type)
{
	if ((p = soap_in_SOAP_ENV__Header(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Header * SOAP_FMAC4 soap_in_SOAP_ENV__Header(struct soap *soap, const char *tag, struct SOAP_ENV__Header *a, const char *type)
{
	if (soap_element_begin_in(soap, tag, 0, type))
		return NULL;
	a = (struct SOAP_ENV__Header *)soap_id_enter(soap, soap->id, a, SOAP_TYPE_SOAP_ENV__Header, sizeof(struct SOAP_ENV__Header), 0, NULL, NULL, NULL);
	if (!a)
		return NULL;
	soap_default_SOAP_ENV__Header(soap, a);
	if (soap->body && !*soap->href)
	{
		for (;;)
		{	soap->error = SOAP_TAG_MISMATCH;
			if (soap->error == SOAP_TAG_MISMATCH)
				soap->error = soap_ignore_element(soap);
			if (soap->error == SOAP_NO_TAG)
				break;
			if (soap->error)
				return NULL;
		}
		if (soap_element_end_in(soap, tag))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Header *)soap_id_forward(soap, soap->href, (void*)a, 0, SOAP_TYPE_SOAP_ENV__Header, 0, sizeof(struct SOAP_ENV__Header), 0, NULL);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_PointerToSOAP_ENV__Reason(struct soap *soap, struct SOAP_ENV__Reason *const*a)
{
	if (!soap_reference(soap, *a, SOAP_TYPE_SOAP_ENV__Reason))
		soap_serialize_SOAP_ENV__Reason(soap, *a);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_PointerToSOAP_ENV__Reason(struct soap *soap, struct SOAP_ENV__Reason *const*a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_PointerToSOAP_ENV__Reason);
	if (soap_out_PointerToSOAP_ENV__Reason(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_PointerToSOAP_ENV__Reason(struct soap *soap, const char *tag, int id, struct SOAP_ENV__Reason *const*a, const char *type)
{
	id = soap_element_id(soap, tag, id, *a, NULL, 0, type, SOAP_TYPE_SOAP_ENV__Reason);
	if (id < 0)
		return soap->error;
	return soap_out_SOAP_ENV__Reason(soap, tag, id, *a, type);
}

SOAP_FMAC3 struct SOAP_ENV__Reason ** SOAP_FMAC4 soap_get_PointerToSOAP_ENV__Reason(struct soap *soap, struct SOAP_ENV__Reason **p, const char *tag, const char *type)
{
	if ((p = soap_in_PointerToSOAP_ENV__Reason(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Reason ** SOAP_FMAC4 soap_in_PointerToSOAP_ENV__Reason(struct soap *soap, const char *tag, struct SOAP_ENV__Reason **a, const char *type)
{
	if (soap_element_begin_in(soap, tag, 1, NULL))
		return NULL;
	if (!a)
		if (!(a = (struct SOAP_ENV__Reason **)soap_malloc(soap, sizeof(struct SOAP_ENV__Reason *))))
			return NULL;
	*a = NULL;
	if (!soap->null && *soap->href != '#')
	{	soap_revert(soap);
		if (!(*a = soap_in_SOAP_ENV__Reason(soap, tag, *a, type)))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Reason **)soap_id_lookup(soap, soap->href, (void**)a, SOAP_TYPE_SOAP_ENV__Reason, sizeof(struct SOAP_ENV__Reason), 0);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_PointerToSOAP_ENV__Detail(struct soap *soap, struct SOAP_ENV__Detail *const*a)
{
	if (!soap_reference(soap, *a, SOAP_TYPE_SOAP_ENV__Detail))
		soap_serialize_SOAP_ENV__Detail(soap, *a);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_PointerToSOAP_ENV__Detail(struct soap *soap, struct SOAP_ENV__Detail *const*a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_PointerToSOAP_ENV__Detail);
	if (soap_out_PointerToSOAP_ENV__Detail(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_PointerToSOAP_ENV__Detail(struct soap *soap, const char *tag, int id, struct SOAP_ENV__Detail *const*a, const char *type)
{
	id = soap_element_id(soap, tag, id, *a, NULL, 0, type, SOAP_TYPE_SOAP_ENV__Detail);
	if (id < 0)
		return soap->error;
	return soap_out_SOAP_ENV__Detail(soap, tag, id, *a, type);
}

SOAP_FMAC3 struct SOAP_ENV__Detail ** SOAP_FMAC4 soap_get_PointerToSOAP_ENV__Detail(struct soap *soap, struct SOAP_ENV__Detail **p, const char *tag, const char *type)
{
	if ((p = soap_in_PointerToSOAP_ENV__Detail(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Detail ** SOAP_FMAC4 soap_in_PointerToSOAP_ENV__Detail(struct soap *soap, const char *tag, struct SOAP_ENV__Detail **a, const char *type)
{
	if (soap_element_begin_in(soap, tag, 1, NULL))
		return NULL;
	if (!a)
		if (!(a = (struct SOAP_ENV__Detail **)soap_malloc(soap, sizeof(struct SOAP_ENV__Detail *))))
			return NULL;
	*a = NULL;
	if (!soap->null && *soap->href != '#')
	{	soap_revert(soap);
		if (!(*a = soap_in_SOAP_ENV__Detail(soap, tag, *a, type)))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Detail **)soap_id_lookup(soap, soap->href, (void**)a, SOAP_TYPE_SOAP_ENV__Detail, sizeof(struct SOAP_ENV__Detail), 0);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

#ifndef WITH_NOGLOBAL

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_PointerToSOAP_ENV__Code(struct soap *soap, struct SOAP_ENV__Code *const*a)
{
	if (!soap_reference(soap, *a, SOAP_TYPE_SOAP_ENV__Code))
		soap_serialize_SOAP_ENV__Code(soap, *a);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_PointerToSOAP_ENV__Code(struct soap *soap, struct SOAP_ENV__Code *const*a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_PointerToSOAP_ENV__Code);
	if (soap_out_PointerToSOAP_ENV__Code(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_PointerToSOAP_ENV__Code(struct soap *soap, const char *tag, int id, struct SOAP_ENV__Code *const*a, const char *type)
{
	id = soap_element_id(soap, tag, id, *a, NULL, 0, type, SOAP_TYPE_SOAP_ENV__Code);
	if (id < 0)
		return soap->error;
	return soap_out_SOAP_ENV__Code(soap, tag, id, *a, type);
}

SOAP_FMAC3 struct SOAP_ENV__Code ** SOAP_FMAC4 soap_get_PointerToSOAP_ENV__Code(struct soap *soap, struct SOAP_ENV__Code **p, const char *tag, const char *type)
{
	if ((p = soap_in_PointerToSOAP_ENV__Code(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 struct SOAP_ENV__Code ** SOAP_FMAC4 soap_in_PointerToSOAP_ENV__Code(struct soap *soap, const char *tag, struct SOAP_ENV__Code **a, const char *type)
{
	if (soap_element_begin_in(soap, tag, 1, NULL))
		return NULL;
	if (!a)
		if (!(a = (struct SOAP_ENV__Code **)soap_malloc(soap, sizeof(struct SOAP_ENV__Code *))))
			return NULL;
	*a = NULL;
	if (!soap->null && *soap->href != '#')
	{	soap_revert(soap);
		if (!(*a = soap_in_SOAP_ENV__Code(soap, tag, *a, type)))
			return NULL;
	}
	else
	{	a = (struct SOAP_ENV__Code **)soap_id_lookup(soap, soap->href, (void**)a, SOAP_TYPE_SOAP_ENV__Code, sizeof(struct SOAP_ENV__Code), 0);
		if (soap->body && soap_element_end_in(soap, tag))
			return NULL;
	}
	return a;
}

#endif

SOAP_FMAC3 void SOAP_FMAC4 soap_default__QName(struct soap *soap, char **a)
{	soap_default_string(soap, a);
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize__QName(struct soap *soap, char *const*a)
{	soap_serialize_string(soap, a);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put__QName(struct soap *soap, char *const*a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE__QName);
	if (soap_out__QName(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out__QName(struct soap *soap, const char *tag, int id, char *const*a, const char *type)
{
	return soap_outstring(soap, tag, id, a, type, SOAP_TYPE__QName);
}

SOAP_FMAC3 char ** SOAP_FMAC4 soap_get__QName(struct soap *soap, char **p, const char *tag, const char *type)
{
	if ((p = soap_in__QName(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 char * * SOAP_FMAC4 soap_in__QName(struct soap *soap, const char *tag, char **a, const char *type)
{
	return soap_instring(soap, tag, a, type, SOAP_TYPE__QName, 2, -1, -1);
}

SOAP_FMAC3 void SOAP_FMAC4 soap_default_string(struct soap *soap, char **a)
{	(void)soap; /* appease -Wall -Werror */
#ifdef SOAP_DEFAULT_string
	*a = SOAP_DEFAULT_string;
#else
	*a = (char *)0;
#endif
}

SOAP_FMAC3 void SOAP_FMAC4 soap_serialize_string(struct soap *soap, char *const*a)
{
	soap_reference(soap, *a, SOAP_TYPE_string);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_put_string(struct soap *soap, char *const*a, const char *tag, const char *type)
{
	register int id = soap_embed(soap, (void*)a, NULL, 0, tag, SOAP_TYPE_string);
	if (soap_out_string(soap, tag, id, a, type))
		return soap->error;
	return soap_putindependent(soap);
}

SOAP_FMAC3 int SOAP_FMAC4 soap_out_string(struct soap *soap, const char *tag, int id, char *const*a, const char *type)
{
	return soap_outstring(soap, tag, id, a, type, SOAP_TYPE_string);
}

SOAP_FMAC3 char ** SOAP_FMAC4 soap_get_string(struct soap *soap, char **p, const char *tag, const char *type)
{
	if ((p = soap_in_string(soap, tag, p, type)))
		if (soap_getindependent(soap))
			return NULL;
	return p;
}

SOAP_FMAC3 char * * SOAP_FMAC4 soap_in_string(struct soap *soap, const char *tag, char **a, const char *type)
{
	return soap_instring(soap, tag, a, type, SOAP_TYPE_string, 1, -1, -1);
}

#ifdef __cplusplus
}
#endif

/* End of envC.c */
