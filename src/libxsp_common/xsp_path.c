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
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "xsp_logger.h"
#include "xsp_path.h"
#include "xsp_pathrule.h"
#include "xsp_pathrule_handler.h"

#include "hashtable.h"
#include "compat.h"

static struct hashtable *path_list;
static pthread_mutex_t path_list_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t path_id;

static unsigned int xsp_path_hash_str(const void *k1);
static int xsp_path_hash_equal(const void *k1, const void *k2);

int xsp_path_init() {
  path_list = create_hashtable(7, xsp_path_hash_str, xsp_path_hash_equal);
  if (!path_list)
    return -1;

  path_id = 0;
  xsp_pathrule_handler_init();

  return 0;
}

xspPath *xsp_alloc_path() {
  xspPath *path;

  path = malloc(sizeof(xspPath));
  if (!path)
    goto error_exit;

  bzero(path, sizeof(xspPath));

  return path;

error_exit:
  return NULL;
}

void xsp_free_path(xspPath *path) {
  if (path->rule_count)
    free(path->rules);

  free(path);
}

static unsigned int xsp_path_hash_str(const void *k1) {
  const char *c = k1;
  unsigned int retval;

  retval = 0;

  while(*c != '\0') {
    retval += (int)*c;
    c++;
  }

  return retval;
}

static int xsp_path_hash_equal(const void *k1, const void *k2) {
  const char *s1, *s2;
  int count = 0;

  s1 = (char*)k1;
  s2 = (char*)k2;

  while(*s1 != '\0' && *s2 != '\0' && *s1 == *s2) {
    s1++;
    s2++;
    count++;
  }

  if (*s1 == '\0' && *s2 == '\0')
    return 1;

  // return 0 for failure!
  return 0;
}

int xsp_get_path(xspNetPath *net_path, xspSettings *settings, xspPath **ret_path, char **ret_error_msg) {
  xspPath *path;
  xspPathRule *pathrule;
  xspPathRuleHandler *rule_handler;
  xspPathRuleHandler **handlers;
  int i;
  int desc_len = 0;
  int handler_count = 0;
  char *rule_id;
  char *error_msg;
  char *path_desc = NULL;

  handlers = malloc(net_path->rule_count * sizeof(xspPathRuleHandler *));
  if (!handlers) {
    xsp_err(0, "failed to allocate handlers array");
    goto error_exit;
  }

  for (i=0; i<net_path->rule_count; i++) {
    rule_handler = xsp_get_pathrule_handler(net_path->rules[i]->type);
    if (!rule_handler) {
      xsp_warn(0, "requested rule type has no handler: %s (skipping)", net_path->rules[i]->type);
      //goto error_exit;
      continue;
    }

    handlers[handler_count++] = rule_handler;

    rule_id = rule_handler->get_pathrule_id(net_path->rules[i], settings, &error_msg);
    if (!rule_id) {
      xsp_err(0, "error finding identifier for rule of type %s: %s", net_path->rules[i]->type, error_msg);
      if (ret_error_msg)
        *ret_error_msg = error_msg;
      goto error_exit;
    }

    path_desc = realloc(path_desc, desc_len+strlen(rule_id)+1);
    strncpy(path_desc+desc_len, rule_id, strlen(rule_id)+1);
    desc_len += strlen(rule_id);
  }

  // this XSP NE has no handlers for the specified rules
  if (!handler_count) {
    *ret_path = NULL;
    return 0;
  }
  else {
    path_desc[strlen(path_desc)] = '\0';
  }

  pthread_mutex_lock(&path_list_lock);
  {
    path = hashtable_search(path_list, path_desc);
    if (!path) {
      path = xsp_alloc_path();
      if (!path) {
        xsp_err(0, "couldn't allocated new path");
        goto error_exit;
      }

      path->rules = malloc(net_path->rule_count * sizeof(xspPathRule*));
      if (!path->rules) {
        xsp_err(0, "couldn't allocate rule list");
        goto error_exit_path;
      }

      path->rule_count = handler_count;

      for (i=0; i < handler_count; i++) {
        if (handlers[i]->allocate(net_path->rules[i], settings, &pathrule, &error_msg) != 0) {
          xsp_err(0, "couldn't create new pathrule element of type %s: %s",
                  net_path->rules[i]->type, error_msg);
          if (ret_error_msg)
            *ret_error_msg = error_msg;
          goto error_exit_unlock;
        }

        pathrule->description = handlers[i]->get_pathrule_id(net_path->rules[i],
                                settings, &error_msg);
        path->rules[i] = pathrule;
      }

      path->status = XSP_PATH_ALLOCATED;
      path->description = path_desc;
      asprintf(&(path->gri), "XSP-netPath-%d", path_id);
      path_id++;

      if (hashtable_insert(path_list, path->description, path) == 0) {
        xsp_err(0, "couldn't save reference to %s", path->description);
        if (ret_error_msg)
          *ret_error_msg = strdup("Couldn't save path reference");
        goto error_exit_path;
      }
    }
  }
  pthread_mutex_unlock(&path_list_lock);

  *ret_path = path;

  return 0;

error_exit_path:
  xsp_free_path(path);
error_exit_unlock:
  pthread_mutex_unlock(&path_list_lock);
error_exit:
  asprintf(ret_error_msg, "XSP GET PATH ERROR");
  return -1;
}

int xsp_delete_path(xspPath *path) {
  void *ret;
  ret = hashtable_remove(path_list, path->description);
  xsp_free_path(path);
  (void)ret;
  return 0;
}
