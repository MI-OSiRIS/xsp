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

public class XspBlockHeaderHdr extends XspBase {
	public short type;
	public short sport;
	public int length;
		
	public static final int size = 2 + 2 + 4;
	
	XspBlockHeaderHdr()
	{
		
	}
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[8];    	
    	System.arraycopy(Xsp.shortToByteArray(type), 0, binData, 0, 2);
    	System.arraycopy(Xsp.shortToByteArray(sport), 0, binData, 2, 2);
    	System.arraycopy(Xsp.intToByteArray(length), 0, binData, 4, 4);    		    		
    	return binData;    	
	}
	
    XspBlockHeaderHdr(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	byte [] shortByte;
    	shortByte=new byte[2];
    	
    	System.arraycopy(binData, 0, shortByte, 0, 2);
    	type=Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 2, shortByte, 0, 2);
    	sport=Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 4, intByte, 0, 4);
    	length=Xsp.byteArrayToInt(intByte);
 	
    }  
}
