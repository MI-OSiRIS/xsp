package xsp;

public class XspMsgAuthInfoHdr {
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