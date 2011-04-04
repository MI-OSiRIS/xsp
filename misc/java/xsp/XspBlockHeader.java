package xsp;

public class XspBlockHeader extends XspBase {
	short type;
	short sport;
	int length;
	byte [] blob;
	
	XspBlockHeader()
	{
		super();
		length=0;
	}
	
	@Override
    public byte[] getBytes()  {    	
    	byte [] binData;
    	if(length<=0)
    	{    	
    		binData=new byte[8];
    		System.arraycopy(Xsp.shortToByteArray(type), 0, binData, 0, 2);
    		System.arraycopy(Xsp.shortToByteArray(sport), 0, binData, 2, 2);
    		System.arraycopy(Xsp.intToByteArray(length), 0, binData, 4, 4);    		    		
    		return binData;
    	}
    	else
    	{
    		binData=new byte[8+length];
    		System.arraycopy(Xsp.shortToByteArray(type), 0, binData, 0, 2);
    		System.arraycopy(Xsp.shortToByteArray(sport), 0, binData, 2, 2);
    		System.arraycopy(Xsp.intToByteArray(length), 0, binData, 4, 4);
    		System.arraycopy(blob, 0, binData, 8, length);    		
    		return binData;
    	}
	}
	
    XspBlockHeader(byte [] binData)
    {
    	byte [] intByte;
    	intByte=new byte[4];
    	byte [] shortByte;
    	shortByte=new byte[2];
    	
    	System.arraycopy(binData, 0, shortByte, 0, 2);
    	type=Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 2, shortByte, 0, 2);
    	sport=Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 4, intByte, 0, 4);
    	length=Xsp.byteArrayToInt(intByte);
    	blob=new byte[length];
    	if(length>=0)
    	{    	
    		System.arraycopy(binData, 8, blob, 0, length);
    	}    	
    }  
}
