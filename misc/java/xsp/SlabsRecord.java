package xsp;

public class SlabsRecord  extends XspBase{	 
	byte [] sess_id; //[XSP_SESSIONID_LEN * 2 + 1];
    int offset;
    int length;
    int crc;
     
    public static final int size = Constants.XSP_SESSIONID_LEN + 4 + 4 + 4;
     
    SlabsRecord()
    {
    	sess_id = new byte[Constants.XSP_SESSIONID_LEN];
    }
    
    public byte[] getBytes() {    	     	
    	byte [] binData;
  
     	binData=new byte[size]; 
     	System.arraycopy(sess_id, 0, binData, 0, Constants.XSP_SESSIONID_LEN);
     	System.arraycopy(Xsp.intToByteArray(offset), 0, binData, Constants.XSP_SESSIONID_LEN, 4);
     	System.arraycopy(Xsp.intToByteArray(length), 0, binData, Constants.XSP_SESSIONID_LEN+4, 4);
     	System.arraycopy(Xsp.intToByteArray(crc), 0, binData, Constants.XSP_SESSIONID_LEN+8, 4);

     	return binData;    	
 	}
 	
    SlabsRecord(byte [] binData)
     {  
    	 byte [] intByte;
    	 intByte=new byte[4];
    	 System.arraycopy(binData, 0, sess_id, 0, Constants.XSP_SESSIONID_LEN);
    	 System.arraycopy(binData, Constants.XSP_SESSIONID_LEN, intByte, 0, 4);
    	 offset=Xsp.byteArrayToInt(intByte);
    	 System.arraycopy(binData, Constants.XSP_SESSIONID_LEN + 4, intByte, 0, 4);
    	 length=Xsp.byteArrayToInt(intByte);
    	 System.arraycopy(binData, Constants.XSP_SESSIONID_LEN + 8, intByte, 0, 4);
    	 crc=Xsp.byteArrayToInt(intByte);     	
     } 
}
