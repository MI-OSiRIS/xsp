package xsp;

public class XspMsgHdr {
	public short length;
	public byte version;
	public byte type;
	public byte [] sess_id;

	public static final int size = 2 + 1 + 1 + Constants.XSP_SESSIONID_LEN;
	
	XspMsgHdr()
	{
		sess_id =new byte[Constants.XSP_SESSIONID_LEN];
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size]; 
    	System.arraycopy(Xsp.shortToByteArray(length), 0, binData, 0, 2);
    	binData[2]=version;
    	binData[3]=type;
    	System.arraycopy(sess_id, 0, binData, 4, Constants.XSP_SESSIONID_LEN);    		    		
    	return binData;    	
	}
	
    XspMsgHdr(byte [] binData)
    {
    	byte [] shortByte;
    	shortByte=new byte[4];
    	
    	System.arraycopy(binData, 0, shortByte, 0, 2);
    	length=Xsp.byteArrayToShort(shortByte);

    	version=binData[2];
    	type=binData[3];
    	System.arraycopy(binData, 4, sess_id, 0, Constants.XSP_SESSIONID_LEN); 	
    } 
}
