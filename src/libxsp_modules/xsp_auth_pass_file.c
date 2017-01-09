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
#include <unistd.h>

#include "xsp_auth.h"
#include "xsp_config.h"
#include "xsp_logger.h"
#include "xsp_modules.h"
#include "xsp_auth_pass.h"
#include "xsp_main_settings.h"

#include "compat.h"
#include "hashtable.h"

static int xsp_file_auth_init();
static void xsp_file_auth_read_config();
static xspPassUserInfo *file_get_user_info(const char *username);

struct xsp_file_auth_config_t {
  const char *file;
};

static struct xsp_file_auth_config_t xspFileAuthConfig = {
  .file = "passwd",
};

static xspPassBackend xsp_file_pass_backend = {
  .name = "File",
  .get_user_info = file_get_user_info,
};

static xspModule xsp_file_auth_module = {
  .desc = "File Password Authentication Module",
  .dependencies = "",
  .init = xsp_file_auth_init
};

static struct hashtable *table;

xspModule *module_info() {
  return &xsp_file_auth_module;
}

static void xsp_file_auth_read_config() {
  char *str_val;
  const xspSettings *settings;

  settings = xsp_main_settings();
  if (xsp_settings_get_2(settings,"file_auth", "passwd_file", &str_val) == 0) {
    xspFileAuthConfig.file = str_val;
  }
}

static int xsp_file_auth_htable_equal(const void *k1, const void *k2) {
  const char *c1 = k1;
  const char *c2 = k2;
  int i;

  i = 0;

  while(*c1 != '\0' && *c1 == *c2 && i < 1024) {
    i++;
  }

  if (i == 1024 || *c1 != *c2)
    return -1;

  return 0;
}

static unsigned int xsp_file_auth_htable_hash(const void *k1) {
  const char *c = k1;
  unsigned int retval;
  int i;

  retval = 0;
  i = 0;

  while(*c != 0 && i < 1024) {
    retval += *c;
    i++;
    c++;
  }

  return retval;
}

int xsp_file_auth_init() {
  FILE *f;
  char line[1024];
  int linenum;

  xsp_file_auth_read_config();

  table = create_hashtable(7, xsp_file_auth_htable_hash, xsp_file_auth_htable_equal);
  if (!table) {
    xsp_err(0, "couldn't create hash table");
    goto error_exit;
  }

  f = fopen(xspFileAuthConfig.file, "r");
  if (!f) {
    xsp_err(0, "couldn't initialize open: %s", xspFileAuthConfig.file);
    goto error_exit2;
  }

  linenum = 0;
  while(fgets(line, sizeof(line), f) != NULL) {
    char **fields;
    int field_count;
    xspPassUserInfo *ui;

    linenum++;

    fields = split(line, ",", &field_count);
    if (!fields) {
      xsp_err(0, "couldn't read line: %s:%d", xspFileAuthConfig.file, linenum);
      continue;
    }

    if (field_count != 5) {
      xsp_err(0, "invalid line: %s:%d", xspFileAuthConfig.file, linenum);
      continue;
    }

    ui = xsp_alloc_pass_user_info();
    if (!ui) {
      xsp_err(0, "couldn't allocate space to hold line: %s:%d", xspFileAuthConfig.file, linenum);
      continue;
    }

    ui->username = fields[0];
    ui->password = fields[1];
    ui->email = fields[2];
    ui->institution = fields[3];
    ui->activated = atoi(fields[4]);

    free(fields[4]);
    free(fields);

    if (!hashtable_insert(table, strdup(ui->username), ui)) {
      xsp_err(0, "couldn't add line %s:%d to the hashtable", xspFileAuthConfig.file, linenum);
      xsp_free_pass_user_info(ui);
      continue;
    }

  }

  if (xsp_set_pass_backend(&xsp_file_pass_backend)) {
    xsp_err(0, "couldn't register password backend");
    goto error_exit3;
  }

  return 0;

error_exit3:
  fclose(f);
error_exit2:
  hashtable_destroy(table, 1);
error_exit:
  return -1;
}

// internal functions
static xspPassUserInfo *file_get_user_info(const char *username) {
  xspPassUserInfo *ret_ui, *ui;

  ui = hashtable_search(table, username);
  if (!ui)
    goto error_exit;

  ret_ui = xsp_alloc_pass_user_info();
  if (!ret_ui)
    goto error_exit;

  ret_ui->username = strdup(ui->username);
  ret_ui->password = strdup(ui->password);
  ret_ui->email = strdup(ui->email);
  ret_ui->institution = strdup(ui->institution);
  ret_ui->activated = ui->activated;

  if (ret_ui->username == NULL || ret_ui->password == NULL || ret_ui->email == NULL || ret_ui->institution == NULL)
    goto error_exit2;

  return ret_ui;

error_exit2:
  xsp_free_pass_user_info(ret_ui);
error_exit:
  return NULL;
}
