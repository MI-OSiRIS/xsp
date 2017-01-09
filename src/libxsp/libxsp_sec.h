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
#ifndef LIBXSP_SEC_H
#define LIBXSP_SEC_H

typedef struct libxsp_sec_info_t {
  char *username;
  char *password;
  char *key1;
  char *key2;
  char *keypass;
} xspSecInfo;

#endif
