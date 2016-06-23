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

public class XspMsgSessNackHdr extends XspBase {
	public int length;	
	public static final int size = 4 ;

	XspMsgSessNackHdr()
	{
		
	}
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size]; 
    	System.arraycopy(Xsp.intToByteArray(length), 0, binData, 0, 4);    		    		
    	return binData;    	
	}
	
    XspMsgSessNackHdr(byte [] binData)
    {
    	length=Xsp.byteArrayToInt(binData);
    } 
}
