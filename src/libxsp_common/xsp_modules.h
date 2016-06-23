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
#ifndef XSP_MODULES_H
#define XSP_MODULES_H

int xsp_modules_init();
int xsp_load_modules();
int xsp_load_module(char *module_name);

typedef struct xsp_module_t {
	void *handle;
	char *filename;
	char *name;
	char *desc;
	char *dependencies;

	int (*init)();
	int (*opt_handler)();
} xspModule;

xspModule *xsp_find_module(char *module_name);
xspModule *module_info();

#endif
