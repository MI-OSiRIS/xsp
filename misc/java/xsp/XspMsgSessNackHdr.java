package xsp;

public class XspMsgSessNackHdr {
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
