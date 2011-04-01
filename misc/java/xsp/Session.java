package xsp;

import java.util.Arrays;
import java.util.Vector;

public class Session {
	byte [] sess_id;

	byte [] src_id;

	int sess_flags;

	int hop_flags;
	int child_count;
	
	Vector<Hop> child;

	public static final int size=Constants.XSP_SESSIONID_LEN+Constants.XSP_HOPID_LEN+12;
	
	Session()
	{
		sess_id = new byte[Constants.XSP_SESSIONID_LEN];
		src_id = new byte[Constants.XSP_HOPID_LEN];
		sess_flags = 0;
		hop_flags = 0;
		child_count = 0 ;		
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	    
    	System.arraycopy(sess_id, 0, binData, 0, Constants.XSP_SESSIONID_LEN);
    	System.arraycopy(src_id, 0, binData, Constants.XSP_SESSIONID_LEN, Constants.XSP_HOPID_LEN);
    	System.arraycopy(Xsp.intToByteArray(sess_flags), 0, binData, Constants.XSP_SESSIONID_LEN+ Constants.XSP_HOPID_LEN, 4);
    	System.arraycopy(Xsp.intToByteArray(hop_flags), 0, binData, Constants.XSP_SESSIONID_LEN+ Constants.XSP_HOPID_LEN+4, 4);
    	System.arraycopy(Xsp.intToByteArray(child_count), 0, binData, Constants.XSP_SESSIONID_LEN+ Constants.XSP_HOPID_LEN+8, 4);
    	return binData;    	
	}
	
    Session(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	System.arraycopy(binData, 0, sess_id, 0, Constants.XSP_SESSIONID_LEN); 	
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN, src_id, 0, Constants.XSP_HOPID_LEN);    	    	    	
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_SESSIONID_LEN, intByte, 0, 4);    	
    	sess_flags=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_SESSIONID_LEN+4, intByte, 0, 4);    	
    	hop_flags=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_SESSIONID_LEN+8, intByte, 0, 4);    	
    	child_count=Xsp.byteArrayToInt(intByte);
    } 
    
	boolean xsp_sesscmp(Session s1) 
	{
		return Arrays.equals(sess_id, s1.sess_id);
	}
	
	int xsp_sess_addhop(Hop hop) {
		child.add(hop);

		child_count = child.size();

		hop.session = this;

		return 0;
	}
}
