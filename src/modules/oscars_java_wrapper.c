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
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "oscars.h"

static int oscars_signal_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *signal, const char *id, int refresh_count, char ***results, int *nresults, char **ret_orig, char **error_msg);
static int oscars_get_classpath(const char *axis_home, const char *client_dir, char **ret_path);
static int push_char(char c, char **buf, int *length, int *tail);
static char **split_inline(char *string, char *delimiters, int skip_empty, int *count);
static int exec_child(const char *dir, const char *file, ...);

int oscars_reserve_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *src, int tagged_src, const char *dst, int tagged_dst, time_t stime, time_t etime, uint32_t bandwidth, int32_t vlan_id, const char *desc, char **ret_id, char **error_msg) {
	char *classpath;
	int n;
	char id[32];
	char status[32];
	char *buf;
	char **fields;
	int count;
	char stime_str[32];
	char etime_str[32];
	char tagged_src_str[32];
	char tagged_dst_str[32];
	char bandwidth_str[32];
	uint64_t etime64, stime64;
	char repo_dir[1024];
	char vlan_tag_str[32];
	char *orig;
	const char *java = NULL;

	printf("oscars_reserve_path\n");

	if (oscars_get_classpath(axis_path, client_dir, &classpath) != 0) {
		*error_msg = strdup("Internal server classpath error");
		return -1;
	}

	stime64 = stime;
//	stime64 *= 1000;

	etime64 = etime;
//	etime64 *= 1000;

	sprintf(stime_str, "%llu", stime64);
	sprintf(etime_str, "%llu", etime64);
	sprintf(bandwidth_str, "%d", bandwidth);
	sprintf(tagged_src_str, "%d", tagged_src);
	sprintf(tagged_dst_str, "%d", tagged_dst);
	if (vlan_id == -1) {
		sprintf(vlan_tag_str, "any");
	} else {
		snprintf(vlan_tag_str, sizeof(vlan_tag_str), "%d", vlan_id);
	}
	if (client_dir[strlen(client_dir) - 1] != '/')
		sprintf(repo_dir, "%s/repo", client_dir);
	else
		sprintf(repo_dir, "%srepo", client_dir);

	if (java_path)
		java = java_path;
	else
		java = "java";
	
	n = exec_child(client_dir, java,
		       "-cp", classpath,
		       "CreateReservationCLI",
		       "-repo", repo_dir,
		       "-url", url,
		       "-l2source", src,
		       "-tagSource", tagged_src_str,
		       "-l2dest", dst,
		       "-tagDest", tagged_dst_str,
		       "-start", stime_str,
		       "-end", etime_str,
		       "-bwidth", bandwidth_str,
		       "-vlan", vlan_tag_str,
		       "-pathsetup", "timer-automatic",
		       "-desc", desc, NULL,
		       "", &buf);
	
	bzero(status, sizeof(status));
	bzero(id, sizeof(id));

	if (n == 0) {
		orig = strdup(buf);
		if (orig) {
			fields = split_inline(buf, "\n", 1, &count);

			if (!fields) {
				free(orig);
			} else {
				int i;
				for(i = 1; i < count; i++) {
					if (strncmp(fields[i], "GRI:", 4) == 0) {
						if (sscanf(fields[i], "GRI: %s", id) != 1) {
							id[0] = '\0';
						}

					} else if (strncmp(fields[i], "Status:", 7) == 0) {
						if (sscanf(fields[i], "Status: %s", status) != 1) {
							status[0] = '\0';
						}
					}
				}

				free(fields);
			}
		}
	}

	if (strcmp(status, "") == 0 || strcmp(id, "") == 0) {
		*error_msg = orig;
		printf("Returning error 1 ");
		return -1;
	}

	if (strcmp(status, "ACCEPTED") != 0) {
		*error_msg = orig;
		printf("Returning error 2 ");
		return -1;
	}

	*ret_id = strdup(id);
	if (!*ret_id) {
		printf("Returning error 3 ");
		return -1;
	}

	free(orig);

	return 0;
}

int oscars_create_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *id, char **error_msg) {
	int i, n, count;
	char **fields;
	char recv_id[32];
	char status[32];
	char *orig;

	printf("oscars_create_path\n");

	n = oscars_signal_path(java_path, axis_path, url, client_dir, "create", id, 0, &fields, &count, &orig, error_msg);
	if (n != 0) {
		return -1;
	}

	bzero(status, sizeof(status));
	bzero(recv_id, sizeof(recv_id));

	for(i = 0; i < count; i++) {
		printf("fields: %s\n", fields[i]);
		const char *id_str = "Global Reservation Id:";
		const char *status_str = "Create Status:";
		if (strncmp(fields[i], id_str, strlen(id_str)) == 0) {
			if (sscanf(fields[i], "Global Reservation Id: %s", recv_id) != 1) {
				recv_id[0] = '\0';
			}
		} else if (strncmp(fields[i], status_str, strlen(status_str)) == 0) {
			if (sscanf(fields[i], "Create Status: %s", status) != 1) {
				status[0] = '\0';
			}
		}
	}

	if (fields)
		free(fields);

	if (strcmp(status, "") == 0 || strcmp(recv_id, "") == 0 || strcmp(id, recv_id) != 0 || strcmp(status, "ACTIVE") != 0) {
		*error_msg = orig;
		return -1;
	}

	free(orig);

	return 0;
}

int oscars_refresh_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *id, char **error_msg) {
	int i, n, count;
	char **fields;
	char recv_id[32];
	char status[32];
	char *orig;

	n = oscars_signal_path(java_path, axis_path, url, client_dir, "refresh", id, 1, &fields, &count, &orig, error_msg);
	if (n != 0) {
		return -1;
	}

	bzero(status, sizeof(status));
	bzero(recv_id, sizeof(recv_id));

/*
Result Global Reservation Id: hopi-11537-131
Result Create Status: ACTIVE
*/
	for(i = 0; i < count; i++) {
		printf("fields: %s\n", fields[i]);
		const char *id_str = "Global Reservation Id:";
		const char *status_str = "Refresh Status:";
		if (strncmp(fields[i], id_str, strlen(id_str)) == 0) {
			if (sscanf(fields[i], "Global Reservation Id: %s", recv_id) != 1) {
				recv_id[0] = '\0';
			}
		} else if (strncmp(fields[i], status_str, strlen(status_str)) == 0) {
			if (sscanf(fields[i], "Refresh Status: %s", status) != 1) {
				status[0] = '\0';
			}
		}
	}

	if (fields)
		free(fields);

	if (strcmp(status, "") == 0 || strcmp(recv_id, "") == 0 || strcmp(id, recv_id) != 0 || strcmp(status, "ACTIVE") != 0) {
		*error_msg = orig;
		return -1;
	}

	free(orig);

	return 0;
}

int oscars_query_path_status(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *id, char **ret_status, char **error_msg) {
	char *classpath;
	int n;
	char status[32];
	char *buf;
	char **fields;
	int count;
	char repo_dir[1024];
	char *orig;
	const char *java;

	printf("oscars_query_path\n");

	if (oscars_get_classpath(axis_path, client_dir, &classpath) != 0) {
		printf("no classpath found\n");
		*error_msg = strdup("Internal server classpath error");
		return -1;
	}

	if (client_dir[strlen(client_dir) - 1] != '/')
		sprintf(repo_dir, "%s/repo", client_dir);
	else
		sprintf(repo_dir, "%srepo", client_dir);

	if (java_path)
		java = java_path;
	else
		java = "java";

	n = exec_child(client_dir, java,
			"-cp", classpath,
			"QueryReservationCLI",
			"-repo", repo_dir,
			"-url", url,
			"-gri", id,
			NULL,
			"", &buf);

	bzero(status, sizeof(status));

	if (n == 0) {
		orig = strdup(buf);
		if (orig) {
			fields = split_inline(buf, "\n", 1, &count);
			if (!fields) {
				free(fields);
			} else {
				int i;
				for(i = 0; i < count; i++) {
					if (strncmp(fields[i], "Status:", 7) == 0) {
						if (sscanf(fields[i], "Status: %s", status) != 1) {
							status[0] = '\0';
						}
					}
				}

				free(fields);
			}
		}
	}

	if (strcmp(status, "") == 0) {
		*error_msg = orig;
		return -1;
	}

	*ret_status = strdup(status);
	if (!*ret_status)
		return -1;

	return 0;
}

int oscars_close_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *id, char **error_msg) {
	char *classpath;
	int n;
	char ret_status[32];
	char *buf;
	char **fields;
	int count;
	char repo_dir[1024];
	char string[1024];
	const char *java = NULL;

	printf("oscars_close_path\n");

	if (oscars_get_classpath(axis_path, client_dir, &classpath) != 0) {
		*error_msg = strdup("Internal server classpath error");
		printf("no classpath found\n");
		return -1;
	}

	if (client_dir[strlen(client_dir) - 1] != '/')
		snprintf(repo_dir, sizeof(repo_dir), "%s/repo", client_dir);
	else
		snprintf(repo_dir, sizeof(repo_dir), "%srepo", client_dir);

	if (java_path)
		java = java_path;
	else
		java = "java";

	n = exec_child(client_dir, java,
			"-cp", classpath,
			"CancelReservationCLI",
			"-repo", repo_dir,
			"-url", url,
			"-gri", id,
			NULL,
			"", &buf);

	bzero(ret_status, sizeof(ret_status));
	bzero(string, sizeof(string));

	if (n == 0) {
		fields = split_inline(buf, "\n", 1, &count);
		if (fields) {
			int i;
			for(i = 0; i < count; i++) {
				if (strncmp(fields[i], "STATUS:", 7) == 0) {
					if (sscanf(fields[i], "STATUS: %s", ret_status) != 1) {
						ret_status[0] = '\0';
					}
				}

				strlcat(string, fields[i], sizeof(string));
			}

			free(fields);
		}
	}

	free(buf);

	if (strcmp(ret_status, "PRECANCEL") == 0 || strcmp(ret_status, "CANCELLED") == 0) {
		return 0;
	}

	*error_msg = strdup(string);

	return -1;
}

static int oscars_signal_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *signal, const char *id, int refresh_count, char ***results, int *nresults, char **ret_orig, char **error_msg) {
	char *classpath;
	char *buf;
	int n;
	char refresh_str[32];
	int retval;
	char **fields;
	int count;
	char repo_dir[1024];
	char *orig;
	const char *java;

	if (oscars_get_classpath(axis_path, client_dir, &classpath) != 0) {
		*error_msg = strdup("Internal server classpath error");
		return -1;
	}

	sprintf(refresh_str, "%d", refresh_count);
	if (client_dir[strlen(client_dir) - 1] != '/')
		sprintf(repo_dir, "%s/repo", client_dir);
	else
		sprintf(repo_dir, "%srepo", client_dir);


	if (java_path)
		java = java_path;
	else
		java = "java";

	n = exec_child(client_dir, java, "-cp", classpath, "SignalClient",
				repo_dir,
				url,
				id,
				refresh_str,
				signal,
				NULL,
				"", &buf);

	if (n < 0) {
		*error_msg = strdup("Internal error executing OSCARS client");
		return -1;
	}

	// keep a copy of the original output
	orig = strdup(buf);
	if (!orig) {
		*error_msg = strdup("Internal error");
		goto error_exit;
	}

	fields = split_inline(buf, "\n", 1, &count);
	if (!fields) {
		*error_msg = strdup("Internal error");
		goto error_exit_orig;
		free(orig);
		return -1;
	}

	*results = fields;
	*nresults = count;
	*ret_orig = orig;

	return 0;

error_exit_orig:
	free(orig);
error_exit:
	return -1;
}

static int push_char(char c, char **buf, int *length, int *tail) {
	char *new_buf;

	if (*length == 0) {
		new_buf = malloc(10);
		if (!new_buf)
			return -1;

		*buf = new_buf;
		*length = 10;
	} else if (*tail == *length) {
		new_buf = realloc(*buf, *length * 2);
		if (!new_buf)
			return -1;

		*buf = new_buf;
		*length *= 2;
	}

	(*buf)[*tail] = c;
	(*tail)++;

	return 0;
}

static int oscars_get_classpath(const char *axis_home, const char *client_dir, char **ret_path) {
	char oscars_classpath[8192];
	char axis_lib_path[255];
	DIR *dirp;
	struct dirent entry;
	struct dirent *state;
	const char *axis_path;

	oscars_classpath[0] = '\0';
	strcat(oscars_classpath, ".");

	axis_path = axis_home;
	if (!axis_path) {
		axis_path = getenv("AXIS2_HOME");
		if (axis_path == NULL) {
			return -1;
		}
	}

	sprintf(axis_lib_path, "%s/lib", axis_path);
	dirp = opendir(axis_lib_path);
	while (readdir_r(dirp, &entry, &state) == 0 && state != NULL) {
		int n = strlen(entry.d_name);
		if (entry.d_name[n - 4] == '.' && entry.d_name[n - 3] == 'j' && entry.d_name[n - 2] == 'a' && entry.d_name[n - 1] == 'r') {
			strcat(oscars_classpath, ":");
			strcat(oscars_classpath, axis_lib_path);
			strcat(oscars_classpath, "/");
			strcat(oscars_classpath, entry.d_name);
		}
	}
	closedir(dirp);

	strcat(oscars_classpath, ":");
	strcat(oscars_classpath, client_dir);
	if (client_dir[strlen(client_dir) - 1] != '/')
		strcat(oscars_classpath, "/");
	strcat(oscars_classpath, "OSCARS-client-api.jar");
	strcat(oscars_classpath, ":");
	strcat(oscars_classpath, client_dir);
	if (client_dir[strlen(client_dir) - 1] != '/')
		strcat(oscars_classpath, "/");
	strcat(oscars_classpath, "OSCARS-client-examples.jar");

	*ret_path = strdup(oscars_classpath);

	if (!*ret_path)	{
		return -1;
	}

	return 0;
}

static int exec_child(const char *dir, const char *file, ...) {
	pid_t pid;
	int request_fds[2];
	int response_fds[2];
	char *args[32];
	va_list ap;
	int i;
	char **ret_buf;
	char *send_buf;
	char *buf;
	int length = 0;
	int tail = 0;
	int n;
	char c;
	int child_status;

	if (dir != NULL) {
		if (chdir(dir) != 0) {
			return -1;
		}
	}

	args[0] = file;
	printf("%s", args[0]);
	va_start(ap, file);
	for(i = 1; i < 32; i++) {
		args[i] = va_arg(ap, char *);

		if (args[i] == NULL)
			break;
		printf(" %s", args[i]);
	}
	printf("\n");

	send_buf = va_arg(ap, char *);
	ret_buf = va_arg(ap, char **);

	pipe(request_fds);
	pipe(response_fds);

	pid = fork();
	if (pid == 0) {
		close(response_fds[0]);
		dup2(response_fds[1], 1);
		dup2(response_fds[1], 2);
		close(request_fds[1]);
		dup2(request_fds[0], 0);

		execvp(file, args);

		exit(-1);
	}

	close(response_fds[1]);
	close(request_fds[0]);

	if (strlen(send_buf) > 0) {
		write(request_fds[1], send_buf, strlen(send_buf));
	}

	while((n = read(response_fds[0], &c, 1)) != 0) {
		push_char(c, &buf, &length, &tail);
	}

	push_char(0, &buf, &length, &tail);

	waitpid(pid, &child_status, 0);

	*ret_buf = buf;

//	printf("Results: \"%s\"", buf);

	if (child_status < 0)
		return -1;

	return 0;
}

static char **split_inline(char *string, char *delimiters, int skip_empty, int *count) {
	char **retval;
	char **new_retval;
	int i, j;
	char *str_start;
	int curr_spot;

	retval = malloc(sizeof(char *));
	if (!retval) {
		goto error_exit;
	}

	curr_spot = 0;

	str_start = string;

	for(i = 0; string[i] != '\0'; i++) {
		for(j = 0; j < strlen(delimiters); j++) {
			if (string[i] == delimiters[j]) {
				string[i] = '\0';

				if (!skip_empty || (skip_empty && strlen(str_start)) > 0) {
					new_retval = realloc(retval, sizeof(char *) * (curr_spot + 1));
					if (new_retval == NULL)
						goto error_exit2;

					retval = new_retval;

					retval[curr_spot] = str_start;

					curr_spot++;
				}

				str_start = string + i + 1;

				break;
			}
		}
	}

	if (!skip_empty || (skip_empty && strlen(str_start) > 0)) {
		new_retval = realloc(retval, sizeof(char *) * (curr_spot + 1));
		if (new_retval == NULL)
			goto error_exit2;

		retval = new_retval;

		retval[curr_spot] = str_start;

		curr_spot++;
	}

	*count = curr_spot;

	return retval;

error_exit2:
	free(retval);
error_exit:
	*count = 0;
	return NULL;
}
