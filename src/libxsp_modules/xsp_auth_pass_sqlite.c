#include <string.h>
#include <sqlite3.h>
#include <stdlib.h>

#include "xsp_auth.h"
#include "xsp_config.h"
#include "xsp_logger.h"
#include "xsp_modules.h"
#include "xsp_auth_pass.h"
#include "xsp_main_settings.h"

static int xsp_sqlite_auth_init();
static void xsp_sqlite_auth_read_config();
static xspPassUserInfo *xsp_sqlite_auth_get_user_info(const char *username);
static int xsp_sqlite_auth_cb(void *arg, int count, char **values, char **headers);

struct xsp_sqlite_auth_config_t {
	const char *db_file;
	const char *db_table;
};

static struct xsp_sqlite_auth_config_t xspSQLiteAuthConfig = {
	.db_file = "xsp.db",
	.db_table = "xsp_users"
};

static xspPassBackend xsp_sqlite_pass_backend = {
	.name = "SQLite",
	.get_user_info = xsp_sqlite_auth_get_user_info,
};

static xspModule xsp_sqlite_auth_module = {
	.desc = "SQLite Password Authentication Module",
	.dependencies = "auth_pass_file",
	.init = xsp_sqlite_auth_init
};

xspModule *module_info() {
	return &xsp_sqlite_auth_module;
}

static void xsp_sqlite_auth_read_config() {
	char *str_val;
	const xspSettings *settings;
	
	settings = xsp_main_settings();
	if (xsp_settings_get_2(settings, "sqlite_auth", "db_file", &str_val) == 0) {
		xspSQLiteAuthConfig.db_file = str_val;
	}

	if (xsp_settings_get_2(settings, "sqlite_auth", "db_table", &str_val) == 0) {
		xspSQLiteAuthConfig.db_table = str_val;
	}
}

int xsp_sqlite_auth_init() {
	char query[2048];
	char *errmsg;
	sqlite3 *sql_conn;
	int create_table;
	int n;

	xsp_sqlite_auth_read_config();

	if (sqlite3_open(xspSQLiteAuthConfig.db_file, &sql_conn) != SQLITE_OK) {
		xsp_err(0, "couldn't open SQLite database");
		goto error_exit;
	}

	create_table = 0;
	snprintf(query, sizeof(query), "SELECT * FROM %s", xspSQLiteAuthConfig.db_table);
	n = sqlite3_exec(sql_conn, query, NULL, NULL, &errmsg);
	if (n == SQLITE_ERROR) {
		create_table = 1;
	} else if (n != SQLITE_OK) {
		xsp_err(0, "error verifying database state: %s", errmsg);
		free(errmsg);
		goto error_exit2;
	}

	if (create_table) {
		snprintf(query, sizeof(query), "CREATE TABLE %s (username VARCHAR(30), password VARCHAR(30), email VARCHAR(30), institution VARCHAR(255), activated BOOL)", xspSQLiteAuthConfig.db_table);
		if (sqlite3_exec(sql_conn, query, NULL, NULL, &errmsg)) {
			xsp_err(0, "couldn't create statistics table: %s", errmsg);
			free(errmsg);
			goto error_exit2;
		}
	}

	sqlite3_close(sql_conn);

	if (xsp_set_pass_backend(&xsp_sqlite_pass_backend)) {
		xsp_err(0, "couldn't register password backend");
		goto error_exit2;
	}

	return 0;

error_exit2:
	sqlite3_close(sql_conn);
error_exit:
	return -1;
}

// internal functions
static xspPassUserInfo *xsp_sqlite_auth_get_user_info(const char *username) {
	xspPassUserInfo *user_info = NULL;
	char query[2048];
	char *errmsg;
	static sqlite3 *sql_conn;

	if (sqlite3_open(xspSQLiteAuthConfig.db_file, &sql_conn) != SQLITE_OK) {
		xsp_err(0, "Couldn't open SQLite database");
		goto error_exit;
	}

	snprintf(query, sizeof(query), "SELECT * FROM %s WHERE username='%s'",
			xspSQLiteAuthConfig.db_table,
			username);

	if (sqlite3_exec(sql_conn, query, xsp_sqlite_auth_cb, &user_info, &errmsg) != SQLITE_OK) {
		xsp_err(0, "Error running database query \"%s\": %s", query, errmsg);
		goto error_exit;
	}

	sqlite3_close(sql_conn);

	return user_info;

error_exit:
	return NULL;
}

static int xsp_sqlite_auth_cb(void *arg, int count, char **values, char **headers) {
	int i;
	xspPassUserInfo **retptr = arg;
	xspPassUserInfo *user_info;

	user_info = xsp_alloc_pass_user_info();
	if (!user_info) {
		goto error_exit;
	}

	for(i = 0; i < count; i++) {
		if (strcmp(headers[i], "username") == 0) {
			user_info->username = strdup(values[i]);
		} else if (strcmp(headers[i], "password") == 0) {
			user_info->password= strdup(values[i]);
		} else if (strcmp(headers[i], "email") == 0) {
			user_info->email = strdup(values[i]);
		} else if (strcmp(headers[i], "institution") == 0) {
			user_info->institution = strdup(values[i]);
		} else if (strcmp(headers[i], "activated") == 0) {
			user_info->activated = atoi(values[i]);
		}
	}

	if (!user_info->username || !user_info->password || !user_info->email || !user_info->institution) {
		xsp_err(0, "partially filled user info structure");
		goto error_exit2;
	}

	*retptr = user_info;

	return 0;

error_exit2:
	xsp_free_pass_user_info(user_info);
error_exit:
	return -1;
}
