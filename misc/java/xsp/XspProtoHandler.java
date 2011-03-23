package xsp;

import java.io.IOException;

public abstract class XspProtoHandler {
	public byte max_msg_type;
	public static final int size = 1 ;

	public abstract int parse_INVALID (byte [] buf, int remainder, Object msg_object);
	public abstract int parse_SESS_OPEN	(byte [] buf, int remainder, Object msg_object) throws IOException;
	public abstract int parse_SESS_ACK (byte [] buf, int remainder, Object msg_object); 
	public abstract int parse_SESS_CLOSE (byte [] buf, int remainder, Object msg_object);	
	public abstract int parse_BLOCK_HEADER (byte [] buf, int remainder, Object msg_object);
	public abstract int parse_AUTH_TYPE	(byte [] buf, int remainder, Object msg_object); 
	public abstract int parse_AUTH_TOKEN (byte [] buf, int remainder, Object msg_object);	 
	public abstract int parse_SESS_NACK	(byte [] buf, int remainder, Object msg_object); 
	public abstract int parse_PING (byte [] buf, int remainder, Object msg_object);	 
	public abstract int parse_PONG (byte [] buf, int remainder, Object msg_object);	 
	public abstract int parse_DATA_OPEN (byte [] buf, int remainder, Object msg_object);
	public abstract int parse_DATA_CLOSE (byte [] buf, int remainder, Object msg_object);
	public abstract int parse_PATH_OPEN (byte [] buf, int remainder, Object msg_object); 
	public abstract int parse_PATH_CLOSE (byte [] buf, int remainder, Object msg_object);
	public abstract int parse_APP_DATA (byte [] buf, int remainder, Object msg_object);  
	public abstract int parse_SLAB_INFO (byte [] buf, int remainder, Object msg_object); 
	
	public abstract int writeout_INVALID (Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_SESS_OPEN	(Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_SESS_ACK (Object msg_object, byte [] buf, int remainder); 
	public abstract int writeout_SESS_CLOSE (Object msg_object, byte [] buf, int remainder);	
	public abstract int writeout_BLOCK_HEADER (Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_AUTH_TYPE	(Object msg_object, byte [] buf, int remainder); 
	public abstract int writeout_AUTH_TOKEN (Object msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_SESS_NACK	(Object msg_object, byte [] buf, int remainder); 
	public abstract int writeout_PING (Object msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_PONG (Object msg_object, byte [] buf, int remainder);	 
	public abstract int writeout_DATA_OPEN (Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_DATA_CLOSE (Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_PATH_OPEN (Object msg_object, byte [] buf, int remainder); 
	public abstract int writeout_PATH_CLOSE (Object msg_object, byte [] buf, int remainder);
	public abstract int writeout_APP_DATA (Object msg_object, byte [] buf, int remainder);  
	public abstract int writeout_SLAB_INFO (Object msg_object, byte [] buf, int remainder); 
}
