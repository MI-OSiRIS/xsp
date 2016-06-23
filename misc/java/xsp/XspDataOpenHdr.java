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

public class XspDataOpenHdr extends XspBase {
	short flags;
	byte [] hop_id;
	byte [] proto;
	
	public static final int size = 2 + Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN;
	
	XspDataOpenHdr()
	{
		hop_id=new byte[Constants.XSP_HOPID_LEN];
		proto =new byte[Constants.XSP_PROTO_NAME_LEN];
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	
    	System.arraycopy(Xsp.shortToByteArray(flags), 0, binData, 0, 2);
    	System.arraycopy(hop_id, 0, binData, 2, Constants.XSP_HOPID_LEN);
    	System.arraycopy(proto, 0, binData, Constants.XSP_HOPID_LEN+2, Constants.XSP_PROTO_NAME_LEN);    		    		
    	return binData;    	
	}
	
    XspDataOpenHdr(byte [] binData)
    {
    	byte [] shortByte;
    	shortByte=new byte[2];
    	
    	System.arraycopy(binData, 0, shortByte, 0, 2);
    	flags=Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 2, hop_id, 0, Constants.XSP_HOPID_LEN);    	
    	System.arraycopy(binData, 2+Constants.XSP_HOPID_LEN, proto, 0, Constants.XSP_PROTO_NAME_LEN); 	
    } 
}
