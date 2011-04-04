package xsp;

public class XspSessHdr extends XspBase {
	public byte [] sess_id;
	public byte [] src_id;
	public int sess_flags;
	public int hop_flags;	
	
	public static final int size = Constants.XSP_SESSIONID_LEN + Constants.XSP_HOPID_LEN + 4 + 4;

	XspSessHdr()
	{
		sess_id = new byte[Constants.XSP_SESSIONID_LEN];
		src_id = new byte[Constants.XSP_HOPID_LEN];
	}
	
	@Override
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	    	
    	System.arraycopy(sess_id, 0, binData, 0, Constants.XSP_SESSIONID_LEN);
    	System.arraycopy(src_id, 0, binData, Constants.XSP_SESSIONID_LEN, Constants.XSP_HOPID_LEN);
    	System.arraycopy(Xsp.intToByteArray(sess_flags), 0, binData, Constants.XSP_SESSIONID_LEN+Constants.XSP_HOPID_LEN, 4);
    	System.arraycopy(Xsp.intToByteArray(hop_flags), 0, binData, Constants.XSP_SESSIONID_LEN+Constants.XSP_HOPID_LEN + 4, 4);
    	return binData;    	
	}
	
    XspSessHdr(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, sess_id, 0, Constants.XSP_SESSIONID_LEN);    	
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN, src_id, 0, Constants.XSP_HOPID_LEN); 	
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN+Constants.XSP_HOPID_LEN, intByte, 0, 4);    	
    	sess_flags=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_SESSIONID_LEN+4, intByte, 0, 4);    	
    	hop_flags=Xsp.byteArrayToShort(intByte);    	
    } 
}