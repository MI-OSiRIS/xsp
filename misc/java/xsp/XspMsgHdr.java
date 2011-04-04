package xsp;

public class XspMsgHdr extends XspBase {
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
    	//System.out.println("XspMsgHdr.getbytes()=> binData : "+binData[4]);//new String(Xsp.byteToCharArray(binData)));
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
    	if(sess_id==null)
    		sess_id=new byte[Constants.XSP_SESSIONID_LEN];
    	System.arraycopy(binData, 4, sess_id, 0, Constants.XSP_SESSIONID_LEN); 	
    	System.out.println("XspMsgHdr => length  : "+length);
    	System.out.println("XspMsgHdr => version : "+version);
    	System.out.println("XspMsgHdr => type    : "+type);
    	System.out.println("XspMsgHdr => sess_id : "+sess_id[2]);
    } 
}
