package xsp;

public class SlabsRecordHdr {
    public byte [] sess_id;
    public int offset;
    public int length;
    public int crc;
 
    public static final int size = Constants.XSP_SESSIONID_LEN + 4 + 4 + 4;
    
    SlabsRecordHdr()
    {
    	sess_id = new byte[Constants.XSP_SESSIONID_LEN];
    } 
    
    public byte[] getBytes() {
    	byte [] binData;
    	binData=new byte[size];
    	System.arraycopy(sess_id, 0, binData, 0, Constants.XSP_SESSIONID_LEN);
    	System.arraycopy(Xsp.intToByteArray(offset), 0, binData, Constants.XSP_SESSIONID_LEN, 4);
    	System.arraycopy(Xsp.intToByteArray(length), 0, binData, Constants.XSP_SESSIONID_LEN+4, 4);
    	System.arraycopy(Xsp.intToByteArray(crc), 0, binData, Constants.XSP_SESSIONID_LEN+4+4, 4);
    	  
    	return binData;	
	}
	
    SlabsRecordHdr(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, sess_id, 0, Constants.XSP_SESSIONID_LEN);
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN, intByte, 0, 4);
    	offset=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN+4, intByte, 0, 4);
    	length=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, Constants.XSP_SESSIONID_LEN+4+4, intByte, 0, 4);
    	crc=Xsp.byteArrayToInt(intByte);    	
    }    
}
