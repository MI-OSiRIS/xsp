package xsp;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class Xsp {
	public static final int XSP_MSG_NOWAIT = 0x01;

	public static final int XSP_SESS_SAVE_STREAM = 0x01;
	public static final int XSP_SESS_LSRR = 0x02;

	public static final int XSP_HOP_NATIVE = 0x01;
	public static final int XSP_UNNECESSARY = 0x02;

	public static final int XSP_MSG_INVALID		  =	0;
	public static final int XSP_MSG_SESS_OPEN	  = 1;
	public static final int XSP_MSG_SESS_ACK	  = 2;
	public static final int XSP_MSG_SESS_CLOSE	  = 3;
	public static final int XSP_MSG_BLOCK_HEADER  = 4;
	public static final int XSP_MSG_AUTH_TYPE	  = 8;
	public static final int XSP_MSG_AUTH_TOKEN	  = 9;
	public static final int XSP_MSG_SESS_NACK	  = 10;
	public static final int XSP_MSG_PING		  = 11;
	public static final int XSP_MSG_PONG		  = 12;
	public static final int XSP_MSG_DATA_OPEN     = 13;
	public static final int XSP_MSG_DATA_CLOSE    = 14;
	public static final int XSP_MSG_PATH_OPEN     = 15;
	public static final int XSP_MSG_PATH_CLOSE    = 16;
	public static final int XSP_MSG_APP_DATA      = 17;
	public static final int XSP_MSG_SLAB_INFO     = 18;
	
	public static final byte[] intToByteArray(int value) 
	{
		return new byte[] {
				(byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
                };
	}

	public static final byte[] shortToByteArray(short value) 
	{
		return new byte[] {
				(byte)(value >>> 8),
                (byte)value
                };
	}
	
	public static final int byteArrayToInt(byte [] b) {
        return (b[0] << 24)
                + ((b[1] & 0xFF) << 16)
                + ((b[2] & 0xFF) << 8)
                + (b[3] & 0xFF);
	}
	
	public static final short byteArrayToShort(byte [] b) {
        return (short) ((b[0] << 8)
                + (b[1] & 0xFF));
	}
	  public static void main(String[] args) throws Exception {
	    Properties prop = new Properties();
	    String fileName = "app.config";
	    InputStream is = new FileInputStream(fileName);

	    prop.load(is);

	    System.out.println(prop.getProperty("app.name"));
	    System.out.println(prop.getProperty("app.version"));

	    System.out.println(prop.getProperty("app.vendor", "Java"));
	  }
	
	 
}
