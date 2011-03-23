package xsp;

public class XspHopHdr {
	public byte [] id;
	public byte [] protocol;
	public int flags;
	public short child_count;

	public static final int size = Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN + 4 + 2;
	
	XspHopHdr()
	{
		id = new byte[Constants.XSP_HOPID_LEN];
		protocol = new byte[Constants.XSP_PROTO_NAME_LEN];
	}
	
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	    	
    	System.arraycopy(id, 0, binData, 0, Constants.XSP_HOPID_LEN);
    	System.arraycopy(protocol, 0, binData, Constants.XSP_HOPID_LEN, Constants.XSP_PROTO_NAME_LEN);
    	System.arraycopy(Xsp.intToByteArray(flags), 0, binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN, 4);
    	System.arraycopy(Xsp.shortToByteArray(child_count), 0, binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN + 4, 2);
    	return binData;    	
	}
	
    XspHopHdr(byte [] binData)
    {
    	byte [] shortByte;
    	shortByte=new byte[2];
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, id, 0, Constants.XSP_HOPID_LEN);    	
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN, protocol, 0, Constants.XSP_PROTO_NAME_LEN); 	
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN, intByte, 0, 4);    	
    	flags=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN+4, shortByte, 0, 2);    	
    	child_count=Xsp.byteArrayToShort(shortByte);    	
    } 
}