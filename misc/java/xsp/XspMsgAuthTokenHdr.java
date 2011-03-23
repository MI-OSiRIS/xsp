package xsp;

public class XspMsgAuthTokenHdr {
	public int token_length;
	public static final int size = 4;
	
	XspMsgAuthTokenHdr()
	{
		
	}
    public byte[] getBytes() {    	
    	return Xsp.intToByteArray(token_length);    	
	}
	
    XspMsgAuthTokenHdr(byte [] binData)
    {
    	token_length=Xsp.byteArrayToInt(binData); 	
    } 

}
