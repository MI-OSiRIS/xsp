// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
package xsp;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Vector;

public class XspClient{
	byte [] sess_id;
	byte [] src_id;

	int sess_flags;
	int hop_flags;

	Vector<Hop> child;
	int child_count;

	// the above is "inherited" from xspSess

	Socket sock;
	Socket data_sock;
	
	int connected;
	int data_connected;
	int sock_desc;

	byte [] data_hop;

	List<XspClient> sessions;

	int mtu;
	int debug;
	int nodelay;
	int reuseaddr;
	int recv_bufsize;
	int send_bufsize;
	int recv_timeout;
	int send_timeout;

	InetAddress address;
	
	Hop prev_added_child;
	
	Xsp xsp;
	
	public static final int XSP_MSG_NOWAIT=0x01;
	
	XspClient()
	{
		sess_id=new byte[Constants.XSP_SESSIONID_LEN];
		src_id=new byte[Constants.XSP_HOPID_LEN];
		sess_flags=0;
		hop_flags=0;
		child_count=0;
		
		child=new Vector<Hop>();
		
		sock=new Socket();
		data_sock=new Socket();
		connected=0;
		data_connected=0;
		sock_desc=0;
		
		data_hop=new byte[Constants.XSP_HOPID_LEN];
		mtu=0;
		debug=0;
		nodelay=0;
		reuseaddr=0;
		recv_bufsize=0;
		send_bufsize=0;
		recv_timeout=0;
		send_timeout=0;
		xsp=new Xsp((byte) Constants.LIBXSP_PROTO_BINARY_ID);
	}
	
	int xsp_sess_appendchild(byte [] child_name, int flags) 
	{
		Hop hop;

		hop = new Hop();
		hop.xsp_hop_setid(child_name);
	
		hop.session.sess_id=sess_id.clone();
		
		hop.session.src_id=src_id.clone();
		hop.session.sess_flags=sess_flags;
		hop.session.hop_flags=hop_flags;
		hop.session.child_count=child_count;
		
		hop.flags = (short) flags;

		if (prev_added_child == null) 
		{
			System.out.println("xsp_sess_appendchild(): adding first child: " + new String(Xsp.byteToCharArray(child_name)));
			child.add(hop);					
		}		
		else if (((int)prev_added_child.flags & Constants.XSP_HOP_NATIVE) == 0) 
		{
			System.out.println("xsp_sess_appendchild(): error: trying to add a child to a non-xsp speaking node\n");
			return -1;
		} 
		else 
		{
			System.out.println("xsp_sess_appendchild(): adding "+child_name.toString()+" as child of " + prev_added_child.hop_id.toString());
			
			prev_added_child.child.add(hop);
			prev_added_child.child_count = 1;
		}

		prev_added_child = hop;

		return 0;
	}
	
	int xsp_addchild_helper(Hop curr_node, byte [] parent, Hop new_child) 
	{
		int i;
		int retval = -1;
		if(Arrays.equals(parent, curr_node.hop_id))
		{
			Vector<Hop> new_list=new Vector<Hop>();

			if (((int)curr_node.flags & Constants.XSP_HOP_NATIVE) == 0) {
				System.out.println("xsp_addchild_helper(): attempting to add "+new_child.hop_id+" as child of non-xsp node "+ parent);
				return -1;
			}

			curr_node.child = new_list;
			curr_node.child.add(new_child);
			curr_node.child_count++;

			return 1;
		}

		for(i = 0; i < curr_node.child_count; i++) {
			retval = xsp_addchild_helper(curr_node.child.elementAt(i), parent, new_child);
			if (retval == 1 || retval < 0)
				break;
		}

		return retval;
	}

	int xsp_sess_addchild(byte [] parent, byte [] childname, short flags) 
	{
		Hop hop=new Hop();
		int i;
		int retval = -1;
		Vector<Hop> new_list=new Vector<Hop>();

		hop.hop_id=childname.clone();
		
		hop.session.sess_id = sess_id.clone();
		hop.session.src_id = src_id.clone();
		hop.session.sess_flags = sess_flags;
		hop.session.hop_flags = hop_flags;
		hop.session.child_count = child_count;
		hop.flags = flags;

		if (parent.length == 0) 
		{
			child = new_list;
			child.add(hop);
			child_count++;
			return 1;
		}

		for(i = 0; i < child_count; i++) {
			retval = xsp_addchild_helper(child.elementAt(i), parent, hop);

			if (retval < 0 || retval == 1)
				break;
		}

		if (retval == 1)
			prev_added_child = hop;
		
		return retval;
	}
	
	int xsp_put_msg(byte version, byte type, byte [] sess_id, XspBase msg_body) 
	{			
		byte [] msg_buf;
		int msg_buf_len;
		int msg_len;

		msg_buf = new byte [65536];
		msg_buf_len = 65536;
		System.out.println("xsp_put_msg => version: "+version+" -- type :"+type );
		msg_len=xsp.protocol.xsp_writeout_msg(msg_buf, msg_buf_len, version, type, sess_id, msg_body);
		System.out.println("xsp_put_msg => msg_len : "+msg_len);
		System.out.println("xsp_put_msg=>"+msg_buf[8]);//new String(Xsp.byteToCharArray(msg_buf)));
		if (msg_len < 0)
			return -1;

		OutputStream out;
		try {
			out = sock.getOutputStream();
			System.out.println("xsp_put_msg => msg_buf[0]: "+msg_buf[22]); 
			out.write(msg_buf, 0, msg_len);
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}
		return msg_len;
	}	
	
	XspMsg xsp_get_msg(int flags) {
		byte [] hdr_buf;
		hdr_buf=new byte[32];
		byte [] buf = null;
		int amt_read, rd, remainder;
		XspMsg msg;
		XspMsgHdr hdr;
		InputStream in;
		System.out.println("xsp_get_msg ------------------------------------------");
		try {
			in = sock.getInputStream();
		
			// if they don't want to wait, check to see if everything can be read in without waiting
			// if not, return an error stating as such
			if ((flags & XSP_MSG_NOWAIT)!=0) {		    

				// read in the buffer using MSG_PEEK so as to not actually remove the data from the stream
				rd=in.read(hdr_buf,0,XspMsgHdr.size);
			
				if (rd < (XspMsgHdr.size )) {
					return null;
				}
				
				hdr = new XspMsgHdr(hdr_buf);
				System.out.println("xsp_get_msg => length : "+hdr.length);
				// grab the remainder
				remainder = hdr.length;
				if (remainder < 0 || remainder > Constants.XSP_MAX_LENGTH)
					return null;

				// if there is a remainder, allocate a buffer and try to read into that
				if (remainder > 0) {
					buf = new byte[remainder + XspMsgHdr.size];
					rd=in.read(buf, 0, buf.length);
						
					if (rd < (XspMsgHdr.size + remainder)) {
						return null;
					}
				}
			}

			// read the header in
			amt_read = in.read(hdr_buf, 0, XspMsgHdr.size);
		
			if (amt_read < XspMsgHdr.size) {
				return null;
			}

			hdr = new XspMsgHdr(hdr_buf);

			// obtain the length of the message and verify that it fits in bounds
			remainder = hdr.length;
			System.out.println("xsp_get_msg => length : "+hdr.length);
			if (remainder < 0 || remainder > Constants.XSP_MAX_LENGTH)
				return null;
			
			if (remainder > 0) {
				// allocate space for the remainder
				buf = new byte[remainder];
				// grab the remainder
				amt_read =in.read(buf, 0, remainder);			
				System.out.println("xsp_get_msg => buf : "+buf[2]);
				if (amt_read < remainder)
					return null;
			}

			// allocate a message to return
			msg = new XspMsg();
			// fill in the message
			msg.type = hdr.type;
			msg.version = hdr.version;
			msg.sess_id=hdr.sess_id.clone();

			// fill in the message body
			if (xsp.protocol.xsp_parse_msgbody(msg, buf, remainder, msg.msg_object)!=0)
				return null;
		} 
		catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return msg;
	}
 
    public static byte [] SHA1(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException  
    { 
    	MessageDigest md;
    	md = MessageDigest.getInstance("SHA-1");
    	byte[] sha1hash = new byte[Constants.SHA_DIGEST_LENGTH];
    	md.update(text.getBytes("iso-8859-1"), 0, text.length());
    	sha1hash = md.digest();
    	return sha1hash;
    } 

    int xsp_signal_path(String path_type) {
    	XspMsg msg;
    	XspBlockHeader block=new XspBlockHeader();
    	String path;

    	if (path_type.equals("TERAPATHS") || path_type.equals("OSCARS")) 
    	{    		
    		path = new String(path_type);
    		block.type = 0;
    		block.sport = 0;
    		block.length = path.length() + 1;
    		block.blob = Xsp.charToByteArray(path.toCharArray());

    		if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_PATH_OPEN, sess_id, block) < 0) {
    			System.out.println("xsp_signal_path(): error: failed to send session path message");
    			return -1;
    		}
    		
    		msg = xsp_get_msg(0);
    		if (msg==null) {
    			System.out.println("xsp_signal_path(): error: did not receive a valid response");
    			return -1;
    		}
    		
    		if (msg.type == (byte)Xsp.XSP_MSG_SESS_NACK) 
    		{
    			System.out.println("xsp_signal_path(): could not setup path, error received: \n"+ new String(Xsp.byteToCharArray(msg.msg_body)));
    			return -1;
    		}
    		else if (msg.type != (byte)Xsp.XSP_MSG_SESS_ACK) 
    		{	    		
    			System.out.println("xsp_signal_path(): error: did not receive a path sess ACK");    			
    			return -1;    			
    		}		

    	}
    	else 
    	{
    		System.out.println("xsp_signal_path(): error: XSP_CIRCUIT="+path_type+" is not a valid path type");
    		return -1;
    	}

    	return 0;
    }

    int xsp_connect() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		InetAddress[] nexthop_addrs;
		int connected;
		Hop next_hop;
		Socket socket=null;
		// generate a random session id
		Random rand=new Random(23842734);
		
		rand.nextBytes(sess_id);
		
		System.out.println("xsp_connect(): new session id: "+ new String(Xsp.byteToCharArray(sess_id)));

		if (child_count > 1) {
			System.out.println("xsp_connect(): error: can't send to multiple hosts yet");			
			return -1;
		}

		next_hop = child.elementAt(0);
		String [] serverStr=new String[2];
		String hopStr=new String(next_hop.hop_id);
		System.out.println("hopStr: "+hopStr);
		
		if (Xsp.xsp_parse_hopid(hopStr, serverStr) < 0) {
			System.out.println("hop parsing failed: "+ hopStr);
			return -1;
		}
		System.out.println(serverStr[0] + " " + serverStr[1]);
		try {
			nexthop_addrs = Xsp.xsp_lookuphop(serverStr[0]);
		} catch (UnknownHostException e1) {			
			e1.printStackTrace();
			return -1;
		}
		if (nexthop_addrs==null) {
			System.out.println("hop lookup failed for: "+hopStr);
			return -1;
		}
		System.out.println("okuz musun "+serverStr[0]+ " "+serverStr[1] );
		System.out.println(serverStr[0].length()+ " " + serverStr[1].length());
		int servPort=Integer.parseInt(serverStr[1]);
		connected = 0;
		for(int i=0; i<nexthop_addrs.length && connected==0; i++) 
		{
			try {
				socket = new Socket(serverStr[0], servPort);
			} catch (UnknownHostException e) {				
				e.printStackTrace();
				return -1;
			} catch (IOException e) {				
				e.printStackTrace();
				return -1;
			}			
			connected = 1;
		}

		if (connected == 0) 
		{
			System.out.println("xsp_connect(): couldn't connect to destination host");
			return -1;
		}
		
		sock = socket;
		if (((int)next_hop.flags & Constants.XSP_HOP_NATIVE) != 0) {
			XspMsg msg;
			XspAuthType auth_type = new XspAuthType();
			XspAuthToken token,ret_token;
			token=new XspAuthToken();
			ret_token=new XspAuthToken();
			
			if (System.getenv("XSP_USERNAME")!=null && System.getenv("XSP_PASSWORD")!=null) {
				auth_type=new XspAuthType();
				auth_type.name=Xsp.charToByteArray("PASS".toCharArray());
				
				if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_AUTH_TYPE, sess_id, auth_type) < 0) {
					System.out.println("xsp_connect(): error: PASS authorization failed: couldn't send auth type");					
					try {
						sock.close();
					} catch (IOException e) {						
						e.printStackTrace();
					}
					return -1;
				}

				token.token = Xsp.charToByteArray(System.getenv("XSP_USERNAME").toCharArray());
				token.token_length = System.getenv("XSP_USERNAME").length();

				if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_AUTH_TOKEN, sess_id, token) < 0) {
					System.out.println("xsp_connect(): error: PASS authorization failed: couldn't send username");
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					return -1;
				}

				msg = xsp_get_msg(0);
				if (msg==null || msg.type != Xsp.XSP_MSG_AUTH_TOKEN) {
					System.out.println("xsp_connect(): error: PASS authorization failed: received invalid rxsponse");					
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					return -1;
				}

				ret_token = new XspAuthToken(msg.msg_body);

				if (ret_token.token_length != Constants.SHA_DIGEST_LENGTH) {					
					System.out.println("xsp_connect(): error: PASS authorization failed: received invalid rxsponse(not a sha1 hash)");
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					return -1;
				}

				token.token = SHA1(System.getenv("XSP_PASSWORD"));
				token.token_length = Constants.SHA_DIGEST_LENGTH;

				if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_AUTH_TOKEN, sess_id, token) < 0) {
					System.out.println("xsp_connect(): error: PASS authorization failed: couldn't send password hash");					
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					return -1;
				}
			} else {
				System.out.println("xsp_connect() : authorization in process");
				auth_type.name=Xsp.charToByteArray("ANON".toCharArray()).clone();				
				if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_AUTH_TYPE, sess_id, auth_type) < 0) {
					System.out.println("xsp_connect(): error: authorization failed");					
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}

			next_hop.session.sess_id=sess_id.clone();
			System.out.println("--------------------------------------------------------1");
			//System.out.println("xsp_connect => "+new String(src_id));
			//System.out.println("xsp_connect => "+new String(next_hop.session.sess_id));
			if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_SESS_OPEN, sess_id, next_hop) < 0) {
				System.out.println("xsp_connect(): error: failed to send session open message");
				try {
					sock.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				return -1;
			}
			System.out.println("--------------------------------------------------------2");
			if (System.getenv("XSP_CIRCUIT") != null) {
				System.out.println("xsp_connect(): found XSP_CIRCUIT, using " + System.getenv("XSP_CIRCUIT"));
				if (xsp_signal_path(System.getenv("XSP_CIRCUIT")) != 0) {
					System.out.println("xsp_connect(): could not signal XSP_CIRCUIT");
				}
			}
			System.out.println("--------------------------------------------------------3");
			msg = xsp_get_msg(0);
			if (msg==null) {
				System.out.println("xsp_connect(): error: did not receive a valid response");
				try {
					sock.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				return -1;
			}

			if (msg.type == (byte)Xsp.XSP_MSG_SESS_NACK) {
				System.out.println("xsp_connect(): could not connect to destination using XSP, error received: "+new String(Xsp.byteToCharArray(msg.msg_body)));
				try {
					sock.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				return -1;
			} else if (msg.type != (byte)Xsp.XSP_MSG_SESS_ACK) {
				System.out.println("xsp_connect(): error: did not receive a session ACK");
				try {
					sock.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				return -1;
			}
		}
		
		System.out.println("xsp_connect(): session connected");
		connected = 1;

		return 0;
	}
    
    int xsp_data_connect() 
    {
    	InetAddress [] nexthop_addrs = null;
        Socket socket = null;
        
        int connected;     
		String [] serverStr = new String[2];
		String hopStr=new String(data_hop);
		if (Xsp.xsp_parse_hopid(hopStr, serverStr) < 0) {
			System.out.println("hop parsing failed: "+ hopStr);
			return -1;
		}
		
		try {
			nexthop_addrs = Xsp.xsp_lookuphop(serverStr[0]);
		} catch (UnknownHostException e1) {			
			e1.printStackTrace();
			return -1;
		}
		if (nexthop_addrs==null) {
			System.out.println("hop lookup failed for: "+hopStr);
			return -1;
		}  
		
		int serverPort=Integer.parseInt(serverStr[1]);
		connected = 0;
		for(int i=0; i<nexthop_addrs.length && connected==0 ; i++)
		{
			try {
				socket=new Socket(serverStr[0],serverPort);			

				if (nodelay!=0) 
				{	
					System.out.println("xsp_connect(): setting tcp_nodelay");
					socket.setTcpNoDelay(true);               
				}
				if(reuseaddr!=0)
				{
					System.out.println("xsp_connect(): setting so_reuseaddr");			
					socket.setReuseAddress(true);
				}
			
				if (recv_timeout != 0) 
				{
					System.out.println("xsp_connect(): setting recv timeout: "+recv_timeout);
					socket.setSoTimeout(recv_timeout);				
				}			
             
				if (send_bufsize != 0) 
				{
					System.out.println("xsp_connect(): setting send buffer: "+send_bufsize);
					socket.setSendBufferSize(send_bufsize);
				}
             
				if (recv_bufsize != 0) 
				{
					System.out.println("xsp_connect(): setting recv buffer: "+recv_bufsize);
					socket.setReceiveBufferSize(recv_bufsize);
				}
			
				connected = 1;		
			} 
			catch (UnknownHostException e) 
			{
				e.printStackTrace();
				return -1;
			} 
			catch (IOException e) 
			{
				e.printStackTrace();
				return -1;
			}
		}
         
		if (connected == 0) 
		{
			System.out.println("xsp_connect(): couldn't connect to destination host");
			return -1;            
		}

		data_sock = socket;
        data_connected = 1;

        return 0;
    }
    

    int xsp_send_msg(byte [] buf, int len, int opt_type) {
    	XspBlockHeader block=new XspBlockHeader();
    	int ret;
    	System.out.println("xsp_send_msg-------------------------------------------------------"); 
    	
    	block.type = (short)opt_type;
    	block.sport = 0;
    	block.length = len;
    	block.blob = buf.clone();
    	System.out.println("xsp_send_msg => msg : "+new String(block.blob));
    	
    	if ((ret = xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_APP_DATA, sess_id, block)) < 0) {
    		System.out.println("xsp_send_msg(): error: failed to send message");
    		return 0;
    	}

    	return ret;
    }

    int xsp_recv_msg(byte [] ret_buf, int len, Integer ret_type) {
    	XspMsg msg;
    	XspBlockHeader block;
    	System.out.println("xsp_recv_msg-------------------------------------------------------"); 
    	msg = xsp_get_msg(0);
    	
    	if (msg==null) {
    		System.out.println("xsp_recv_msg(): error: did not receive message");
    		return 0;
    	}
    	if (msg.type != Xsp.XSP_MSG_APP_DATA) {
    		System.out.println("xsp_recv_msg(): error: did not receive XSP_MSG_APP_DATA message");
    		return 0;
    	}
    	
    	block = new XspBlockHeader(msg.msg_body);

    	if (block.length <=0 ) {
    	    System.out.println("xsp_recv_msg(): error: no block data!");
    	    return 0;
    	}

    	ret_buf = new byte[block.length];
    
    	ret_buf=block.blob.clone();
    	
    	ret_type = new Integer(block.type);
    	
    	return block.length;

    }
    
    int xsp_close() {
		try {
			if (data_connected!=0)
				data_sock.close();		
    	
			if (connected!=0)
				sock.close();
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
    	return 0;
    }

    int xsp_close2() {
    	try { 	   		  
    		if (connected!=0) 
    		{
    			if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_SESS_CLOSE, sess_id, null) < 0) {
    				System.out.println("xsp_close(): error: failed to send session close message");
    				return -1;
    			}
    			sock.close();
    		}
    	
    		if (data_connected!=0)
    			data_sock.close();
    	}
		catch (IOException e) 
		{
			e.printStackTrace();
		}
    	return 0;
    }

    int xsp_recv(byte [] buf, int len, int flags) throws IOException {

    	if (connected==0) {
    		return -1;
    	}
        InputStream in = sock.getInputStream();
        return in.read(buf, 0, len);
    }

    int xsp_send(byte [] buf, int len, int flags) throws IOException {

    	if (connected==0) {
    		return -1;
    	}

    	OutputStream out = sock.getOutputStream();
    	out.write(buf, 0, len);
    	return len;
    }

    void xsp_shutdown(int how) throws IOException {
    	if (connected==0) {
    		return;
    	}
    	if(how==1)
    		sock.shutdownInput();
    	else if(how==2)
    		sock.shutdownOutput();
    	else if(how==3)
    	{
    		sock.shutdownInput();    	
    		sock.shutdownOutput();
    	}
    }

    int xsp_set_session_socket(Socket new_sd) {
    	if (connected==1) 
    	{
    		sock = new_sd;
    		return 0;
    	} 
    	else {
    		return -1;
    	}
    }

    Socket xsp_get_session_socket() {
    	if (connected==1) {
    		return sock;
    	} else {
    		return null;
    	}
    }

    // since we can externally set the session socket,
    // allow session to be "connected" as well
    int xsp_set_session_connected() {
    	connected = 1;
    	return 0;
    }

    int xsp_send_ping() {
    	if (xsp_put_msg((byte)0, (byte)Xsp.XSP_MSG_PING, sess_id, null) < 0) {
    		System.out.println("xsp_ping(): error: failed to send ping message");
    		return -1;
    	}
    	return 0;
    }

    int xsp_recv_ping() {
    	XspMsg msg;
    	
    	msg = xsp_get_msg(0);
    	if (msg==null) {
    		System.out.println("xsp_ping(): error: did not receive a valid rxsponse");
    		return -1;
    	}

    	if (msg.type == Xsp.XSP_MSG_PONG) {
    		System.out.println("xsp_recv_ping(): PONG");
    		return 0;
    	}
    	else {
    		System.out.println("xsp_ping(): invalid message type");
    		return -1;
    	}
    }
}
