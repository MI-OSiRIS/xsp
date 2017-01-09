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
/*

	c14n.h

*/

/******************************************************************************\
 *                                                                            *
 * Schema Namespaces                                                          *
 *                                                                            *
\******************************************************************************/

//gsoap c14n  schema import:	http://www.w3.org/2001/10/xml-exc-c14n#
//gsoap c14n  schema elementForm:	qualified
//gsoap c14n  schema attributeForm:	unqualified

/******************************************************************************\
 *                                                                            *
 * Schema Types                                                               *
 *                                                                            *
\******************************************************************************/

typedef struct _c14n__InclusiveNamespaces {
  @char*				PrefixList;
} _c14n__InclusiveNamespaces;
