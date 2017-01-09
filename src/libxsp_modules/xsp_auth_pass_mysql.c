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
#include <string.h>
#include <mysql.h>
#include <stdlib.h>

#include "xsp_auth.h"
#include "xsp_config.h"
#include "xsp_logger.h"
#include "xsp_modules.h"
#include "xsp_auth_pass.h"

static int xsp_mysql_auth_init();
static void xsp_mysql_auth_read_config();
static int connect_mysql();
static xspPassUserInfo *mysql_get_user_info(const char *username);

struct xsp_mysql_auth_config_t {
  const char *db_server;
  unsigned int db_port;
  const char *db_username;
  const char *db_password;
  const char *db_name;
  const char *db_table;
};

static struct xsp_mysql_auth_config_t xspMySQLAuthConfig = {
  .db_server = NULL,
  .db_port = 0,
  .db_username = NULL,
  .db_password = NULL,
  .db_name = "xsp",
  .db_table = "xsp_users"
};

static MYSQL *mysql;
static pthread_mutex_t mysql_lock;

static xspPassBackend xsp_mysql_pass_backend = {
  .name = "MySQL",
  .get_user_info = mysql_get_user_info,
};

static xspModule xsp_mysql_auth_module = {
  .desc = "MySQL Password Authentication Module",
  .dependencies = "",
  .init = xsp_mysql_auth_init
};

xspModule *module_info() {
  return &xsp_mysql_auth_module;
}

static int connect_mysql() {
  if (mysql_real_connect(mysql,xspMySQLAuthConfig.db_server,xspMySQLAuthConfig.db_username,xspMySQLAuthConfig.db_password,xspMySQLAuthConfig.db_name,xspMySQLAuthConfig.db_port,NULL,0) == NULL)
    return -1;

  return 0;
}

static void xsp_mysql_auth_read_config() {
  int val;
  char *str_val;

  if (xsp_main_settings_get("mysql_auth", "db_server", &str_val) == 0) {
    xspMySQLAuthConfig.db_server = str_val;
  }

  if (xsp_main_settings_get_int("mysql_auth", "db_port", &val) == 0) {
    if (val >= 0)
      xspMySQLAuthConfig.db_port = val;
  }

  if (xsp_main_settings_get("mysql_auth", "db_username", &str_val) == 0) {
    xspMySQLAuthConfig.db_username = str_val;
  }

  if (xsp_main_settings_get("mysql_auth", "db_password", &str_val) == 0) {
    xspMySQLAuthConfig.db_password = str_val;
  }

  if (xsp_main_settings_get("mysql_auth", "db_name", &str_val) == 0) {
    xspMySQLAuthConfig.db_name = str_val;
  }

  if (xsp_main_settings_get("mysql_auth", "db_table", &str_val) == 0) {
    xspMySQLAuthConfig.db_table = str_val;
  }
}

int xsp_mysql_auth_init() {
  xsp_mysql_auth_read_config();

  mysql = mysql_init(NULL);
  if (!mysql) {
    xsp_err(0, "couldn't initialize mysql structure");
    goto error_exit;
  }

  if (connect_mysql()) {
    xsp_err(0, "couldn't connect to database: %s", mysql_error(mysql));
    goto error_exit2;
  }

  if (pthread_mutex_init(&mysql_lock, NULL)) {
    xsp_err(0, "mutex initialization failed");
    goto error_exit2;
  }

  if (xsp_set_pass_backend(&xsp_mysql_pass_backend)) {
    xsp_err(0, "couldn't register password backend");
    goto error_exit3;
  }

  return 0;

error_exit3:
  pthread_mutex_destroy(&mysql_lock);
error_exit2:
  mysql_close(mysql);
error_exit:
  return -1;
}

// internal functions
static xspPassUserInfo *mysql_get_user_info(const char *username) {
  char query[2048];
  xspPassUserInfo *user_info;

  user_info = xsp_alloc_pass_user_info();
  if (!user_info)
    return NULL;

  snprintf(query, sizeof(query), "SELECT * FROM %s WHERE username='%s'",
           xspMySQLAuthConfig.db_table,
           username);

  pthread_mutex_lock(&mysql_lock);
  {
    if (mysql_real_query(mysql, query, strlen(query))) {
      xsp_err(5, "lookup failed");
      goto error_exit;
    }

    if (mysql_affected_rows(mysql) > 0) {
      MYSQL_RES *result;

      result = mysql_store_result(mysql);
      if (result) {
        MYSQL_ROW row;

        row = mysql_fetch_row(result);
        if (row) {
          user_info->username = strdup(row[0]);
          user_info->password = strdup(row[1]);
          user_info->email = strdup(row[3]);
          user_info->institution = strdup(row[4]);
          if (row[7] != NULL)
            user_info->activated = atoi(row[7]);
          else
            user_info->activated = 0;
        }

        mysql_free_result(result);
      }
    }
  }
  pthread_mutex_unlock(&mysql_lock);

  if (user_info->username == NULL || user_info->password == NULL || user_info->email == NULL || user_info->institution == NULL) {
    goto error_exit2;
  }

  return user_info;

error_exit2:
  xsp_free_pass_user_info(user_info);
error_exit:
  return NULL;
}
