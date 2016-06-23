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
package xsp;

public class Constants {
	public static final int PF_XSP = 30;
	public static final int AF_XSP = 30;
	public static final char XSP_STAT_OK = 0x0000;
	public static final char XSP_STAT_NOROUTE  = 0x0001;
	public static final char XSP_STAT_CANT_CONNECT = 0x0002;
	public static final char XSP_STAT_CLOSING = 0xFFFE;
	public static final char XSP_STAT_ERROR	= 0xFFFF;

	public static final int XSP_MAX_LENGTH = 65536;

	public static final int XSP_HOPID_LEN = 60;
	public static final int XSP_SESSIONID_LEN = 16;
	public static final int XSP_PROTO_NAME_LEN = 10;
	public static final int XSP_AUTH_NAME_LEN = 10;

	
	/* the XSP socket layer */
	public static final int XSP_SOCKET = 2;
	
	
	public static final int LIBXSP_PROTO_BINARY_ID = 0;
	public static final int XSP_HOP_NATIVE = 1;
	public static final int SHA_DIGEST_LENGTH = 20;
	
}


