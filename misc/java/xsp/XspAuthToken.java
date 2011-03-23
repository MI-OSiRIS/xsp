package xsp;

public class XspAuthToken {
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
