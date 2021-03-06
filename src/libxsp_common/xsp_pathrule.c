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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "xsp_pathrule.h"

#include "compat.h"

xspPathRule *xsp_alloc_pathrule() {
  xspPathRule *rule;

  rule = malloc(sizeof(xspPathRule));
  if (!rule)
    goto error_exit;

  bzero(rule, sizeof(xspPathRule));

  if (pthread_mutex_init(&(rule->lock), NULL) != 0)
    goto error_exit2;

  if (pthread_cond_init(&(rule->timeout_cond), NULL) != 0)
    goto error_exit2;

  return rule;

error_exit2:
  free(rule);
error_exit:
  return NULL;
}

void xsp_free_pathrule(xspPathRule *rule) {
  pthread_mutex_destroy(&(rule->lock));
  if (rule->description)
    free(rule->description);
  if (rule->data_size && rule->data)
    free(rule->data);
  free(rule);
}
