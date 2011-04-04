package xsp;

public class XspAuthType extends XspBase {
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
    	if(name==null)
    		name = new byte[Constants.XSP_AUTH_NAME_LEN];
    	System.out.println(name.length + " " + binData.length);
    	System.arraycopy(binData, 0, name, 0, Xsp.min(name.length, binData.length));    	    
    }  
}
