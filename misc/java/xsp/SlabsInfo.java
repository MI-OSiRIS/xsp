package xsp;

import java.util.Vector;

public class SlabsInfo {
	int length;
    int rec_count;
    Vector<SlabsRecord> entries;
    
    public static final int size = 8;
    SlabsInfo()
    {    	
    }
    
    public byte[] getBytes() {    	     	
    	byte [] binData;
  
     	binData=new byte[size]; 
     	System.arraycopy(Xsp.intToByteArray(length), 0, binData, 0, 4);
     	System.arraycopy(Xsp.intToByteArray(rec_count), 0, binData, 4, 4);

     	return binData;    	
 	}
 	
    SlabsInfo(byte [] binData)
     {  
    	 byte [] intByte;
    	 intByte=new byte[4];
    	 System.arraycopy(binData, 0, intByte, 0, 4);
    	 length=Xsp.byteArrayToInt(intByte);
    	 System.arraycopy(binData, 4, intByte, 0, 4);
    	 rec_count=Xsp.byteArrayToInt(intByte);    	
     } 
}
