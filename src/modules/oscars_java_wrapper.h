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
#ifndef OSCARS_H
#define OSCARS_H

#include <stdint.h>

int oscars_reserve_path(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *src, int tagged_src, const char *dst, int tagged_dst, time_t stime, time_t etime, uint32_t bandwidth, int32_t vlan_id, const char *desc, char **ret_id, char **error_msg);
int oscars_create_path(const char *java_path, const char *axis_path, const char *url, const char *repo_dir, const char *id, char **error_msg);
int oscars_refresh_path(const char *java_path, const char *axis_path, const char *url, const char *repo_dir, const char *id, char **error_msg);
int oscars_close_path(const char *java_path, const char *axis_path, const char *url, const char *repo_dir, const char *id, char **error_msg);
int oscars_query_path_status(const char *java_path, const char *axis_path, const char *url, const char *client_dir, const char *id, char **ret_status, char **error_msg);

#endif
