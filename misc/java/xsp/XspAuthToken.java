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

public class XspAuthToken extends XspBase {
	int token_length;
	byte [] token;
	
	XspAuthToken()
	{
		token_length=0;
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
    	if(token_length<=0)
    	{    	
    		binData=new byte[4];
    		System.arraycopy(Xsp.intToByteArray(token_length), 0, binData, 0, 4);
    		return binData;
    	}
    	else
    	{
    		binData=new byte[4+token_length];
    		System.arraycopy(Xsp.intToByteArray(token_length), 0, binData, 0, 4);
    		System.arraycopy(token, 0, binData, 4, token_length);    	  
    		return binData;
    	}
	}
	
    XspAuthToken(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, intByte, 0, 4);
    	token_length=Xsp.byteArrayToInt(intByte);
    	if(token_length>=0)
    	{    	
    		System.arraycopy(binData, 4, token, 0, token_length);
    	}    	
    }   
}
