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
/* tpsStub.h
   Generated by gSOAP 2.8.1 from tpsAPI.h
   Copyright(C) 2000-2010, Robert van Engelen, Genivia Inc. All Rights Reserved.
   The generated code is released under one of the following licenses:
   GPL OR Genivia's license for commercial use.
*/

#ifndef tpsStub_H
#define tpsStub_H
#define SOAP_NAMESPACE_OF_ns2	"urn:tpsAPI/types"
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


#ifndef SOAP_TYPE_xsd__boolean
#define SOAP_TYPE_xsd__boolean (7)
/* xsd:boolean */
enum xsd__boolean {xsd__boolean__false_ = 0, xsd__boolean__true_ = 1};
#endif

/******************************************************************************\
 *                                                                            *
 * Types with Custom Serializers                                              *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Classes and Structs                                                        *
 *                                                                            *
\******************************************************************************/


#if 0 /* volatile type: do not declare here, declared elsewhere */

#endif

#ifndef SOAP_TYPE_ns2__getAllReservationsForClass
#define SOAP_TYPE_ns2__getAllReservationsForClass (8)
/* ns2:getAllReservationsForClass */
struct ns2__getAllReservationsForClass {
  struct ns2__ReservationData *ReservationData_USCORE1;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__ReservationData
#define SOAP_TYPE_ns2__ReservationData (9)
/* ns2:ReservationData */
struct ns2__ReservationData {
  LONG64 DTMinus;	/* required element of type xsd:long */
  LONG64 DTPlus;	/* required element of type xsd:long */
  struct ns2__Bandwidth *bandwidth;	/* optional element of type ns2:Bandwidth */
  char *destIp;	/* optional element of type xsd:string */
  char *destMapping;	/* optional element of type xsd:string */
  char *destName;	/* optional element of type xsd:string */
  char *destPortMax;	/* optional element of type xsd:string */
  char *destPortMin;	/* optional element of type xsd:string */
  char *destPorts;	/* optional element of type xsd:string */
  char *direction;	/* optional element of type xsd:string */
  LONG64 duration;	/* required element of type xsd:long */
  char *id;	/* optional element of type xsd:string */
  char *mapping;	/* optional element of type xsd:string */
  int modifyReservation;	/* required element of type xsd:int */
  char *protocol;	/* optional element of type xsd:string */
  char *relatedReservationIds;	/* optional element of type xsd:string */
  char *srcIp;	/* optional element of type xsd:string */
  char *srcMapping;	/* optional element of type xsd:string */
  char *srcName;	/* optional element of type xsd:string */
  char *srcPortMax;	/* optional element of type xsd:string */
  char *srcPortMin;	/* optional element of type xsd:string */
  char *srcPorts;	/* optional element of type xsd:string */
  LONG64 startTime;	/* required element of type xsd:long */
  LONG64 startTimeMax;	/* required element of type xsd:long */
  LONG64 startTimeMin;	/* required element of type xsd:long */
  char *status;	/* optional element of type xsd:string */
  LONG64 timeout;	/* required element of type xsd:long */
  char *userName;	/* optional element of type xsd:string */
  struct ns2__Who *who;	/* optional element of type ns2:Who */
};
#endif

#ifndef SOAP_TYPE_ns2__Bandwidth
#define SOAP_TYPE_ns2__Bandwidth (12)
/* ns2:Bandwidth */
struct ns2__Bandwidth {
  LONG64 bandwidth;	/* required element of type xsd:long */
  char *className;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__Who
#define SOAP_TYPE_ns2__Who (14)
/* ns2:Who */
struct ns2__Who {
  char *CA;	/* optional element of type xsd:string */
  char *DN;	/* optional element of type xsd:string */
  char *name;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__getAllReservationsForClassResponse
#define SOAP_TYPE_ns2__getAllReservationsForClassResponse (16)
/* ns2:getAllReservationsForClassResponse */
struct ns2__getAllReservationsForClassResponse {
  int __sizeresult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* sequence of elements <result> */
  struct ns2__ReservationData **result;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalCancel
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalCancel (18)
/* ns2:tpsAPI_LocalCancel */
struct ns2__tpsAPI_USCORELocalCancel {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
  char *String_USCORE3;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalCancelResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalCancelResponse (19)
/* ns2:tpsAPI_LocalCancelResponse */
struct ns2__tpsAPI_USCORELocalCancelResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalCommit
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalCommit (20)
/* ns2:tpsAPI_LocalCommit */
struct ns2__tpsAPI_USCORELocalCommit {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
  char *String_USCORE3;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalCommitResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalCommitResponse (21)
/* ns2:tpsAPI_LocalCommitResponse */
struct ns2__tpsAPI_USCORELocalCommitResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalRemove
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalRemove (22)
/* ns2:tpsAPI_LocalRemove */
struct ns2__tpsAPI_USCORELocalRemove {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
  char *String_USCORE3;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalRemoveResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalRemoveResponse (23)
/* ns2:tpsAPI_LocalRemoveResponse */
struct ns2__tpsAPI_USCORELocalRemoveResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalReserve
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalReserve (24)
/* ns2:tpsAPI_LocalReserve */
struct ns2__tpsAPI_USCORELocalReserve {
  struct ns2__ReservationData *ReservationData_USCORE1;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalReserveResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalReserveResponse (25)
/* ns2:tpsAPI_LocalReserveResponse */
struct ns2__tpsAPI_USCORELocalReserveResponse {
  struct ns2__ReservationData *result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalStart
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalStart (26)
/* ns2:tpsAPI_LocalStart */
struct ns2__tpsAPI_USCORELocalStart {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
  char *String_USCORE3;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORELocalStartResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORELocalStartResponse (27)
/* ns2:tpsAPI_LocalStartResponse */
struct ns2__tpsAPI_USCORELocalStartResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREaddRelatedReservationId
#define SOAP_TYPE_ns2__tpsAPI_USCOREaddRelatedReservationId (28)
/* ns2:tpsAPI_addRelatedReservationId */
struct ns2__tpsAPI_USCOREaddRelatedReservationId {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
  enum xsd__boolean boolean_USCORE3;	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREaddRelatedReservationIdResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREaddRelatedReservationIdResponse (29)
/* ns2:tpsAPI_addRelatedReservationIdResponse */
struct ns2__tpsAPI_USCOREaddRelatedReservationIdResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREcancel
#define SOAP_TYPE_ns2__tpsAPI_USCOREcancel (30)
/* ns2:tpsAPI_cancel */
struct ns2__tpsAPI_USCOREcancel {
  struct ns2__ReservationData *ReservationData_USCORE1;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREcancelResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREcancelResponse (31)
/* ns2:tpsAPI_cancelResponse */
struct ns2__tpsAPI_USCOREcancelResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREcommit
#define SOAP_TYPE_ns2__tpsAPI_USCOREcommit (32)
/* ns2:tpsAPI_commit */
struct ns2__tpsAPI_USCOREcommit {
  struct ns2__ReservationData *ReservationData_USCORE1;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREcommitResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREcommitResponse (33)
/* ns2:tpsAPI_commitResponse */
struct ns2__tpsAPI_USCOREcommitResponse {
  enum xsd__boolean result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:boolean */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetBandwidths
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetBandwidths (34)
/* ns2:tpsAPI_getBandwidths */
struct ns2__tpsAPI_USCOREgetBandwidths {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetBandwidthsResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetBandwidthsResponse (35)
/* ns2:tpsAPI_getBandwidthsResponse */
struct ns2__tpsAPI_USCOREgetBandwidthsResponse {
  int __sizeresult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* sequence of elements <result> */
  struct ns2__Bandwidths **result;	/* optional element of type ns2:Bandwidths */
};
#endif

#ifndef SOAP_TYPE_ns2__Bandwidths
#define SOAP_TYPE_ns2__Bandwidths (36)
/* ns2:Bandwidths */
struct ns2__Bandwidths {
  int __sizebw;	/* sequence of elements <bw> */
  struct ns2__Bandwidth **bw;	/* optional element of type ns2:Bandwidth */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetLocalBandwidths
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetLocalBandwidths (40)
/* ns2:tpsAPI_getLocalBandwidths */
struct ns2__tpsAPI_USCOREgetLocalBandwidths {
#ifdef WITH_NOEMPTYSTRUCT
  char dummy;	/* dummy member to enable compilation */
#endif
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetLocalBandwidthsResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetLocalBandwidthsResponse (41)
/* ns2:tpsAPI_getLocalBandwidthsResponse */
struct ns2__tpsAPI_USCOREgetLocalBandwidthsResponse {
  int __sizeresult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* sequence of elements <result> */
  struct ns2__Bandwidth **result;	/* optional element of type ns2:Bandwidth */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetPath
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetPath (42)
/* ns2:tpsAPI_getPath */
struct ns2__tpsAPI_USCOREgetPath {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetPathResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetPathResponse (43)
/* ns2:tpsAPI_getPathResponse */
struct ns2__tpsAPI_USCOREgetPathResponse {
  int __sizeresult;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* sequence of elements <result> */
  char **result;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetRelatedReservationIds
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetRelatedReservationIds (45)
/* ns2:tpsAPI_getRelatedReservationIds */
struct ns2__tpsAPI_USCOREgetRelatedReservationIds {
  char *String_USCORE1;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse (46)
/* ns2:tpsAPI_getRelatedReservationIdsResponse */
struct ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse {
  char *result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetReservationData
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetReservationData (47)
/* ns2:tpsAPI_getReservationData */
struct ns2__tpsAPI_USCOREgetReservationData {
  char *String_USCORE1;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREgetReservationDataResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREgetReservationDataResponse (48)
/* ns2:tpsAPI_getReservationDataResponse */
struct ns2__tpsAPI_USCOREgetReservationDataResponse {
  struct ns2__ReservationData *result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORElookupUser
#define SOAP_TYPE_ns2__tpsAPI_USCORElookupUser (49)
/* ns2:tpsAPI_lookupUser */
struct ns2__tpsAPI_USCORElookupUser {
  char *String_USCORE1;	/* optional element of type xsd:string */
  char *String_USCORE2;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCORElookupUserResponse
#define SOAP_TYPE_ns2__tpsAPI_USCORElookupUserResponse (50)
/* ns2:tpsAPI_lookupUserResponse */
struct ns2__tpsAPI_USCORElookupUserResponse {
  struct ns2__UserData *result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type ns2:UserData */
};
#endif

#ifndef SOAP_TYPE_ns2__UserData
#define SOAP_TYPE_ns2__UserData (51)
/* ns2:UserData */
struct ns2__UserData {
  LONG64 id;	/* required element of type xsd:long */
  char *info;	/* optional element of type xsd:string */
  char *passWord;	/* optional element of type xsd:string */
  char *type;	/* optional element of type xsd:string */
  char *userName;	/* optional element of type xsd:string */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREreserve
#define SOAP_TYPE_ns2__tpsAPI_USCOREreserve (53)
/* ns2:tpsAPI_reserve */
struct ns2__tpsAPI_USCOREreserve {
  struct ns2__ReservationData *ReservationData_USCORE1;	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE_ns2__tpsAPI_USCOREreserveResponse
#define SOAP_TYPE_ns2__tpsAPI_USCOREreserveResponse (54)
/* ns2:tpsAPI_reserveResponse */
struct ns2__tpsAPI_USCOREreserveResponse {
  struct ns2__ReservationData *result;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type ns2:ReservationData */
};
#endif

#ifndef SOAP_TYPE___ns1__getAllReservationsForClass
#define SOAP_TYPE___ns1__getAllReservationsForClass (58)
/* Operation wrapper: */
struct __ns1__getAllReservationsForClass {
  struct ns2__getAllReservationsForClass *ns2__getAllReservationsForClass;	/* optional element of type ns2:getAllReservationsForClass */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORELocalCancel
#define SOAP_TYPE___ns1__tpsAPI_USCORELocalCancel (62)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORELocalCancel {
  struct ns2__tpsAPI_USCORELocalCancel *ns2__tpsAPI_USCORELocalCancel;	/* optional element of type ns2:tpsAPI_LocalCancel */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORELocalCommit
#define SOAP_TYPE___ns1__tpsAPI_USCORELocalCommit (66)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORELocalCommit {
  struct ns2__tpsAPI_USCORELocalCommit *ns2__tpsAPI_USCORELocalCommit;	/* optional element of type ns2:tpsAPI_LocalCommit */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORELocalRemove
#define SOAP_TYPE___ns1__tpsAPI_USCORELocalRemove (70)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORELocalRemove {
  struct ns2__tpsAPI_USCORELocalRemove *ns2__tpsAPI_USCORELocalRemove;	/* optional element of type ns2:tpsAPI_LocalRemove */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORELocalReserve
#define SOAP_TYPE___ns1__tpsAPI_USCORELocalReserve (74)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORELocalReserve {
  struct ns2__tpsAPI_USCORELocalReserve *ns2__tpsAPI_USCORELocalReserve;	/* optional element of type ns2:tpsAPI_LocalReserve */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORELocalStart
#define SOAP_TYPE___ns1__tpsAPI_USCORELocalStart (78)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORELocalStart {
  struct ns2__tpsAPI_USCORELocalStart *ns2__tpsAPI_USCORELocalStart;	/* optional element of type ns2:tpsAPI_LocalStart */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREaddRelatedReservationId
#define SOAP_TYPE___ns1__tpsAPI_USCOREaddRelatedReservationId (82)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREaddRelatedReservationId {
  struct ns2__tpsAPI_USCOREaddRelatedReservationId *ns2__tpsAPI_USCOREaddRelatedReservationId;	/* optional element of type ns2:tpsAPI_addRelatedReservationId */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREcancel
#define SOAP_TYPE___ns1__tpsAPI_USCOREcancel (86)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREcancel {
  struct ns2__tpsAPI_USCOREcancel *ns2__tpsAPI_USCOREcancel;	/* optional element of type ns2:tpsAPI_cancel */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREcommit
#define SOAP_TYPE___ns1__tpsAPI_USCOREcommit (90)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREcommit {
  struct ns2__tpsAPI_USCOREcommit *ns2__tpsAPI_USCOREcommit;	/* optional element of type ns2:tpsAPI_commit */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREgetBandwidths
#define SOAP_TYPE___ns1__tpsAPI_USCOREgetBandwidths (94)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREgetBandwidths {
  struct ns2__tpsAPI_USCOREgetBandwidths *ns2__tpsAPI_USCOREgetBandwidths;	/* optional element of type ns2:tpsAPI_getBandwidths */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREgetLocalBandwidths
#define SOAP_TYPE___ns1__tpsAPI_USCOREgetLocalBandwidths (98)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREgetLocalBandwidths {
  struct ns2__tpsAPI_USCOREgetLocalBandwidths *ns2__tpsAPI_USCOREgetLocalBandwidths;	/* optional element of type ns2:tpsAPI_getLocalBandwidths */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREgetPath
#define SOAP_TYPE___ns1__tpsAPI_USCOREgetPath (102)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREgetPath {
  struct ns2__tpsAPI_USCOREgetPath *ns2__tpsAPI_USCOREgetPath;	/* optional element of type ns2:tpsAPI_getPath */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREgetRelatedReservationIds
#define SOAP_TYPE___ns1__tpsAPI_USCOREgetRelatedReservationIds (106)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREgetRelatedReservationIds {
  struct ns2__tpsAPI_USCOREgetRelatedReservationIds *ns2__tpsAPI_USCOREgetRelatedReservationIds;	/* optional element of type ns2:tpsAPI_getRelatedReservationIds */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREgetReservationData
#define SOAP_TYPE___ns1__tpsAPI_USCOREgetReservationData (110)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREgetReservationData {
  struct ns2__tpsAPI_USCOREgetReservationData *ns2__tpsAPI_USCOREgetReservationData;	/* optional element of type ns2:tpsAPI_getReservationData */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCORElookupUser
#define SOAP_TYPE___ns1__tpsAPI_USCORElookupUser (114)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCORElookupUser {
  struct ns2__tpsAPI_USCORElookupUser *ns2__tpsAPI_USCORElookupUser;	/* optional element of type ns2:tpsAPI_lookupUser */
};
#endif

#ifndef SOAP_TYPE___ns1__tpsAPI_USCOREreserve
#define SOAP_TYPE___ns1__tpsAPI_USCOREreserve (118)
/* Operation wrapper: */
struct __ns1__tpsAPI_USCOREreserve {
  struct ns2__tpsAPI_USCOREreserve *ns2__tpsAPI_USCOREreserve;	/* optional element of type ns2:tpsAPI_reserve */
};
#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (119)
/* SOAP Header: */
struct SOAP_ENV__Header {
#ifdef WITH_NOEMPTYSTRUCT
  char dummy;	/* dummy member to enable compilation */
#endif
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (120)
/* SOAP Fault Code: */
struct SOAP_ENV__Code {
  char *SOAP_ENV__Value;	/* optional element of type xsd:QName */
  struct SOAP_ENV__Code *SOAP_ENV__Subcode;	/* optional element of type SOAP-ENV:Code */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (122)
/* SOAP-ENV:Detail */
struct SOAP_ENV__Detail {
  char *__any;
  int __type;	/* any type of element <fault> (defined below) */
  void *fault;	/* transient */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (125)
/* SOAP-ENV:Reason */
struct SOAP_ENV__Reason {
  char *SOAP_ENV__Text;	/* optional element of type xsd:string */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (126)
/* SOAP Fault: */
struct SOAP_ENV__Fault {
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

#endif

/******************************************************************************\
 *                                                                            *
 * Typedefs                                                                   *
 *                                                                            *
\******************************************************************************/

#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (5)
typedef char *_QName;
#endif

#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (6)
typedef char *_XML;
#endif


/******************************************************************************\
 *                                                                            *
 * Externals                                                                  *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Client-Side Call Stubs                                                     *
 *                                                                            *
\******************************************************************************/


SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__getAllReservationsForClass(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__getAllReservationsForClass *ns2__getAllReservationsForClass, struct ns2__getAllReservationsForClassResponse *ns2__getAllReservationsForClassResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORELocalCancel(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORELocalCancel *ns2__tpsAPI_USCORELocalCancel, struct ns2__tpsAPI_USCORELocalCancelResponse *ns2__tpsAPI_USCORELocalCancelResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORELocalCommit(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORELocalCommit *ns2__tpsAPI_USCORELocalCommit, struct ns2__tpsAPI_USCORELocalCommitResponse *ns2__tpsAPI_USCORELocalCommitResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORELocalRemove(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORELocalRemove *ns2__tpsAPI_USCORELocalRemove, struct ns2__tpsAPI_USCORELocalRemoveResponse *ns2__tpsAPI_USCORELocalRemoveResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORELocalReserve(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORELocalReserve *ns2__tpsAPI_USCORELocalReserve, struct ns2__tpsAPI_USCORELocalReserveResponse *ns2__tpsAPI_USCORELocalReserveResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORELocalStart(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORELocalStart *ns2__tpsAPI_USCORELocalStart, struct ns2__tpsAPI_USCORELocalStartResponse *ns2__tpsAPI_USCORELocalStartResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREaddRelatedReservationId(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREaddRelatedReservationId *ns2__tpsAPI_USCOREaddRelatedReservationId, struct ns2__tpsAPI_USCOREaddRelatedReservationIdResponse *ns2__tpsAPI_USCOREaddRelatedReservationIdResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREcancel(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREcancel *ns2__tpsAPI_USCOREcancel, struct ns2__tpsAPI_USCOREcancelResponse *ns2__tpsAPI_USCOREcancelResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREcommit(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREcommit *ns2__tpsAPI_USCOREcommit, struct ns2__tpsAPI_USCOREcommitResponse *ns2__tpsAPI_USCOREcommitResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREgetBandwidths(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREgetBandwidths *ns2__tpsAPI_USCOREgetBandwidths, struct ns2__tpsAPI_USCOREgetBandwidthsResponse *ns2__tpsAPI_USCOREgetBandwidthsResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREgetLocalBandwidths(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREgetLocalBandwidths *ns2__tpsAPI_USCOREgetLocalBandwidths, struct ns2__tpsAPI_USCOREgetLocalBandwidthsResponse *ns2__tpsAPI_USCOREgetLocalBandwidthsResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREgetPath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREgetPath *ns2__tpsAPI_USCOREgetPath, struct ns2__tpsAPI_USCOREgetPathResponse *ns2__tpsAPI_USCOREgetPathResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREgetRelatedReservationIds(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREgetRelatedReservationIds *ns2__tpsAPI_USCOREgetRelatedReservationIds, struct ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse *ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREgetReservationData(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREgetReservationData *ns2__tpsAPI_USCOREgetReservationData, struct ns2__tpsAPI_USCOREgetReservationDataResponse *ns2__tpsAPI_USCOREgetReservationDataResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCORElookupUser(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCORElookupUser *ns2__tpsAPI_USCORElookupUser, struct ns2__tpsAPI_USCORElookupUserResponse *ns2__tpsAPI_USCORElookupUserResponse);

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__tpsAPI_USCOREreserve(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns2__tpsAPI_USCOREreserve *ns2__tpsAPI_USCOREreserve, struct ns2__tpsAPI_USCOREreserveResponse *ns2__tpsAPI_USCOREreserveResponse);

#ifdef __cplusplus
}
#endif

#endif

/* End of tpsStub.h */
