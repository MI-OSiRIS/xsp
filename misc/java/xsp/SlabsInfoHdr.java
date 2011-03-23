package xsp;

public class SlabsInfoHdr {
    public int length;
    public int rec_count;
    
    public static final int size = 8;
    
    SlabsInfoHdr()
    {}
    
    public byte[] getBytes() {
    	byte [] binData;
    	binData=new byte[8];
    	
    	System.arraycopy(Xsp.intToByteArray(length), 0, binData, 0, 4);
    	System.arraycopy(Xsp.intToByteArray(rec_count), 0, binData, 4, 4);
	      
    	return binData;	
	}
	
    SlabsInfoHdr(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	System.arraycopy(binData, 0, intByte, 0, 4);
    	length=Xsp.byteArrayToInt(intByte);
    	System.arraycopy(binData, 4, intByte, 0, 4);
    	rec_count=Xsp.byteArrayToInt(intByte);
    	
    }    
}
