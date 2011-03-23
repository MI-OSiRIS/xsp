package xsp;

public class XspMsgDataOpenHdr {
	public int flags;
	public byte [] hop_id;
	public byte [] proto;
	
	public static final int size = 4 + Constants.XSP_HOPID_LEN  + Constants.XSP_PROTO_NAME_LEN;

	XspMsgDataOpenHdr()
	{
		hop_id = new byte[Constants.XSP_HOPID_LEN];
		proto = new byte[Constants.XSP_PROTO_NAME_LEN];
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	
    	System.arraycopy(Xsp.intToByteArray(flags), 0, binData, 0, 4);
    	System.arraycopy(hop_id, 0, binData, 4, Constants.XSP_HOPID_LEN);
    	System.arraycopy(proto, 0, binData, Constants.XSP_HOPID_LEN+4, Constants.XSP_PROTO_NAME_LEN);    		    		
    	return binData;    	
	}
	
    XspMsgDataOpenHdr(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, intByte, 0, 4);
    	flags=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, 4, hop_id, 0, Constants.XSP_HOPID_LEN);    	
    	System.arraycopy(binData, 4+Constants.XSP_HOPID_LEN, proto, 0, Constants.XSP_PROTO_NAME_LEN); 	
    } 
}
