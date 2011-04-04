package xsp;

import java.io.IOException;

public abstract class XspProtoHandler extends XspBase {
	public byte max_msg_type;
	public static final int size = 1 ;

	public abstract int parse_INVALID (byte [] buf, int remainder, XspBase msg_object);
	public abstract int parse_SESS_OPEN	(byte [] buf, int remainder, XspBase msg_object) throws IOException;
	public abstract int parse_SESS_ACK (byte [] buf, int remainder, XspBase msg_object); 
	public abstract int parse_SESS_CLOSE (byte [] buf, int remainder, XspBase msg_object);	
	public abstract int parse_BLOCK_HEADER (byte [] buf, int remainder, XspBase msg_object);
	public abstract int parse_AUTH_TYPE	(byte [] buf, int remainder, XspBase msg_object); 
	public abstract int parse_AUTH_TOKEN (byte [] buf, int remainder, XspBase msg_object);	 
	public abstract int parse_SESS_NACK	(byte [] buf, int remainder, XspBase msg_object); 
	public abstract int parse_PING (byte [] buf, int remainder, XspBase msg_object);	 
	public abstract int parse_PONG (byte [] buf, int remainder, XspBase msg_object);	 
	public abstract int parse_DATA_OPEN (byte [] buf, int remainder, XspBase msg_object);
	public abstract int parse_DATA_CLOSE (byte [] buf, int remainder, XspBase msg_object);
	public abstract int parse_PATH_OPEN (byte [] buf, int remainder, XspBase msg_object); 
	public abstract int parse_PATH_CLOSE (byte [] buf, int remainder, XspBase msg_object);
	public abstract int parse_APP_DATA (byte [] buf, int remainder, XspBase msg_object);  
	public abstract int parse_SLAB_INFO (byte [] buf, int remainder, XspBase msg_object); 
	
	public abstract int writeout_INVALID (XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_SESS_OPEN	(XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_SESS_ACK (XspBase msg_object, byte [] buf, int remainder); 
	public abstract int writeout_SESS_CLOSE (XspBase msg_object, byte [] buf, int remainder);	
	public abstract int writeout_BLOCK_HEADER (XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_AUTH_TYPE	(XspBase msg_object, byte [] buf, int remainder); 
	public abstract int writeout_AUTH_TOKEN (XspBase msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_SESS_NACK	(XspBase msg_object, byte [] buf, int remainder); 
	public abstract int writeout_PING (XspBase msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_PONG (XspBase msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_DATA_OPEN (XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_DATA_CLOSE (XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_PATH_OPEN (XspBase msg_object, byte [] buf, int remainder); 
	public abstract int writeout_PATH_CLOSE (XspBase msg_object, byte [] buf, int remainder);
	public abstract int writeout_APP_DATA (XspBase msg_object, byte [] buf, int remainder);  
	public abstract int writeout_SLAB_INFO (XspBase msg_object, byte [] buf, int remainder); 
}
