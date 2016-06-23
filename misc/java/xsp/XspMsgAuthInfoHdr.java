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

public class XspMsgAuthInfoHdr extends XspBase {
	public byte [] name;

	public static final int size = Constants.XSP_AUTH_NAME_LEN;

	XspMsgAuthInfoHdr()
	{
		name = new byte[Constants.XSP_AUTH_NAME_LEN];
	}
	
    public byte[] getBytes() {    	    	    	
    	return name;    	
	}
	
    XspMsgAuthInfoHdr(byte [] binData)
    {
    	System.arraycopy(binData, 0, name, 0, Constants.XSP_AUTH_NAME_LEN); 	
    } 
}
