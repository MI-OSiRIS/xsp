package xsp;

public class XspAuthType {
	byte [] name;
	
	public static final int size = Constants.XSP_AUTH_NAME_LEN;
	
	XspAuthType()
	{
		name = new byte[Constants.XSP_AUTH_NAME_LEN];
	}
	
    public byte[] getBytes() {    	
    	return name;
	}
	
    XspAuthType(byte [] binData)
    {	
    		System.arraycopy(binData, 0, name, 0, Constants.XSP_AUTH_NAME_LEN);    	    
    }  
}
