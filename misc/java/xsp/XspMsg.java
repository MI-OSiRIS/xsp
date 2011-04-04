package xsp;

public class XspMsg extends XspBase {
	public byte type;
	public byte version;
	public byte [] sess_id;
	public byte [] msg_body;
	public XspBase msg_object;
	
	public static final int size = 1 + 1 + Constants.XSP_SESSIONID_LEN*2;
	
	XspMsg()
	{
		sess_id =new byte[Constants.XSP_SESSIONID_LEN*2];
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size]; 
    	binData[0]=type;
    	binData[1]=version;
    	System.arraycopy(sess_id, 0, binData, 2, Constants.XSP_SESSIONID_LEN*2);    		    		
    	return binData;    	
	}
	
    XspMsg(byte [] binData)
    {
    	type=binData[0];
    	version=binData[1];
    	System.arraycopy(binData, 2, sess_id, 0, Constants.XSP_SESSIONID_LEN*2); 	
    } 
}