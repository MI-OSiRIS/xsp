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

public class XspAuthType extends XspBase {
	byte [] name;
	
	public static final int size = Constants.XSP_AUTH_NAME_LEN;
	
	XspAuthType()
	{
		name = new byte[Constants.XSP_AUTH_NAME_LEN];
	}
	
    public byte[] getBytes() {    	
    	return name;
	}
	
    XspAuthType(byte [] binData)
    {	
    	if(name==null)
    		name = new byte[Constants.XSP_AUTH_NAME_LEN];
    	System.out.println(name.length + " " + binData.length);
    	System.arraycopy(binData, 0, name, 0, Xsp.min(name.length, binData.length));    	    
    }  
}
