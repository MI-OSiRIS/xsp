package xsp;

public class ProtoBinary extends XspProtoHandler{

	Hop xsp_parsehop(Session sess, byte [] buf, int remainder, String size) {
		Hop new_hop = null;
		XspHopHdr hdr = null;
		int orig_remainder = 0;
		short child_count = 0;		
		String child_size = Integer.toString(0);
		int i = 0;

		// verify that we have enough remaining to have a hop
		if (remainder < XspHopHdr.size) {
			System.out.println("Bad Remainder: " + remainder + " " + XspHopHdr.size);
			return null;
		}

		orig_remainder = remainder;

		// allocate a new hop
		new_hop = new Hop();
		
		new_hop.session = sess;

		hdr = new  XspHopHdr(buf);
		
		// grab the hop id and NULL terminate it
		System.arraycopy(hdr.id, 0, new_hop.hop_id, 0, Constants.XSP_HOPID_LEN);
		//new_hop.hop_id[Constants.XSP_HOPID_LEN] = '\0';

		System.out.println("Parsing: " + new_hop.hop_id.toString());

		System.arraycopy(hdr.protocol, 0, new_hop.protocol, 0, Constants.XSP_PROTO_NAME_LEN);		
		//new_hop.protocol[Constants.XSP_PROTO_NAME_LEN] = '\0';

		// grab the flags for the given hop
		new_hop.flags = (short)hdr.flags;

		// grab the number of children to be read in
		child_count = hdr.child_count;

		byte [] buf2;
		buf2=new byte[buf.length - XspHopHdr.size];
		System.arraycopy(buf, XspHopHdr.size, buf2, 0, buf.length - XspHopHdr.size);
		
		remainder -= XspHopHdr.size;

		if (child_count == 0) 
		{
			new_hop.child = null;
			new_hop.child_count = 0;
		} 
		else 
		{
			new_hop.child_count = 0;

			// try to parse each child
			for(i = 0; i < child_count; i++) {
				Hop tempHop; //=new_hop.child.elementAt(i);
				tempHop = this.xsp_parsehop(sess, buf2, remainder, child_size);
				new_hop.child.add(i, tempHop);
				
				if(Integer.parseInt(child_size) > 0 )
				{
					byte [] buf3;
					buf3=new byte[buf2.length - Integer.parseInt(child_size)];
					System.arraycopy(buf2, Integer.parseInt(child_size), buf3, 0, buf2.length-Integer.parseInt(child_size));
					buf2=null;
					buf2=new byte[buf3.length];
					System.arraycopy(buf3, 0, buf2, 0, buf2.length);
					remainder -= Integer.parseInt(child_size);
				}
				new_hop.child_count++;
			}
		}

		size = Integer.toString(orig_remainder - remainder);

		return new_hop;
	}
	
	public int parse_INVALID (byte [] buf, int remainder, Object msg_object) { return 0; }

	public int parse_SESS_OPEN(byte [] buf, int remainder, Object msg_object) 
	{ 	
		XspSessHdr hdr;
		Hop next_hop;
		Session ret_sess=(Session)msg_object;
		if(ret_sess==null)
			ret_sess = new Session();
		
		hdr = new XspSessHdr(buf);
		hdr.sess_id=buf.clone();

		System.out.println("Remainder: " + remainder);

		if(remainder<XspSessHdr.size)
			return -1;
		
		System.arraycopy(hdr.sess_id, 0, ret_sess.sess_id, 0, Constants.XSP_SESSIONID_LEN);
		System.arraycopy(hdr.src_id, 0, ret_sess.src_id, 0, Constants.XSP_HOPID_LEN);
		
		System.out.println("src: " + ret_sess.src_id.toString());

		ret_sess.sess_flags = hdr.sess_flags;
		ret_sess.hop_flags = hdr.hop_flags;

		byte [] buf2;
		buf2=new byte[buf.length - XspSessHdr.size];
		System.arraycopy(buf, XspHopHdr.size, buf2, 0, buf.length - XspSessHdr.size);
		
		remainder -= XspSessHdr.size;	

		while (remainder > 0) 
		{			
			String hop_size=Integer.toString(0);
				
			System.out.println("Grabbing next hop info\n");

			next_hop = xsp_parsehop(ret_sess, buf2, remainder, hop_size);
			if (next_hop == null)
				return -1;
		
			ret_sess.xsp_sess_addhop(next_hop);

			System.out.println("HOP SIZE: " + hop_size);

			byte [] buf3;
			buf3=new byte[buf2.length - Integer.parseInt(hop_size)];
			
			System.arraycopy(buf2, Integer.parseInt(hop_size), buf3, 0, buf.length - Integer.parseInt(hop_size));					
			remainder -= Integer.parseInt(hop_size);
			if(remainder>0)
			{
				buf2=null;
				buf2=new byte[buf3.length];
				System.arraycopy(buf3, 0, buf2, 0, buf3.length);
			}			
		}
		return 0;
	}
		
	public int parse_SESS_ACK (byte [] buf, int remainder, Object msg_object){ return 0; } 
	public int parse_SESS_CLOSE (byte [] buf, int remainder, Object msg_object){ return 0; }	
	
	public int parse_BLOCK_HEADER (byte [] buf, int remainder, Object msg_object)
	{
		XspBlockHeaderHdr hdr;
		XspBlockHeader new_header=(XspBlockHeader)msg_object;
		if(new_header==null)
			new_header = new XspBlockHeader();
		
		if (remainder < XspBlockHeaderHdr.size)
			return -1;
		
		hdr = new  XspBlockHeaderHdr(buf);		
		
		new_header.type = hdr.type;
		new_header.sport = hdr.sport;
		new_header.length = hdr.length;

		remainder -= XspBlockHeaderHdr.size;

	        // validate the blob size
	        
		if (new_header.length > 16777216 || new_header.length > remainder) 
			return -1;
	     
	        
		// allocate space for the blob
		new_header.blob = new byte[new_header.length];


		// copy the blob from the message	    
		System.arraycopy(buf, XspBlockHeaderHdr.size, new_header.blob, 0, new_header.length);
		
		return 0; 
		
	}
	
	public int parse_AUTH_TYPE	(byte [] buf, int remainder, Object msg_object)
	{ 
		XspMsgAuthInfoHdr hdr;
		XspAuthType new_auth_type=(XspAuthType)msg_object;

		if (new_auth_type==null)
			new_auth_type = new XspAuthType();
		
		if (remainder < XspMsgAuthInfoHdr.size)
			return -1;

		
		hdr = new  XspMsgAuthInfoHdr(buf);

		// read in the only entry so far in the header
		System.arraycopy(hdr.name, 0, new_auth_type.name, 0, Constants.XSP_AUTH_NAME_LEN);
		
		// return success
		return 0;
	} 
	
	public int parse_AUTH_TOKEN (byte [] buf, int remainder, Object msg_object)
	{ 
		XspMsgAuthTokenHdr hdr;
		XspAuthToken new_token=(XspAuthToken)msg_object;

		if(new_token==null)
			new_token = new XspAuthToken();
		
		if (remainder < XspMsgAuthTokenHdr.size)
			return -1;

		hdr = new  XspMsgAuthTokenHdr(buf);
		
		new_token.token_length = hdr.token_length;

		remainder -= XspMsgAuthTokenHdr.size;

		// validate the token
		if(new_token.token_length > 16777216 || new_token.token_length > remainder)
			return -1;
			
		// allocate space for the token
		new_token.token = new byte[new_token.token_length];

		// copy the token from the message
		System.arraycopy(buf, XspMsgAuthTokenHdr.size, new_token.token, 0, new_token.token_length);
	
		// return success
		return 0;
	}	 
	
	public int parse_SESS_NACK	(byte [] buf, int remainder, Object msg_object)
	{ 
		XspMsgSessNackHdr hdr;
		short len;		
		byte [] error_message=(byte [])msg_object;
		
		if (remainder < XspMsgSessNackHdr.size)
			return -1;

		
		hdr = new  XspMsgSessNackHdr(buf);
		
		len = (short)hdr.length;

		remainder -= XspMsgSessNackHdr.size;
		
		byte [] buf2;
		buf2=new byte[buf.length - XspMsgSessNackHdr.size];
		System.arraycopy(buf, XspMsgSessNackHdr.size, buf2, 0, buf.length - XspMsgSessNackHdr.size);
		
		// validate the token
		if (len > remainder) {
			return -1;
		}

		System.arraycopy(buf2, 0, error_message, 0, len);
		
		return 0; 
		
	} 
	public int parse_PING (byte [] buf, int remainder, Object msg_object){ return 0; }	 
	public int parse_PONG (byte [] buf, int remainder, Object msg_object){ return 0; }
	
	public int parse_DATA_OPEN (byte [] buf, int remainder, Object msg_object)
	{ 
		XspMsgDataOpenHdr hdr;
		XspDataOpenHdr new_hdr=(XspDataOpenHdr)msg_object;

		if(new_hdr==null)
			new_hdr =new XspDataOpenHdr();
		
		if (remainder < XspMsgDataOpenHdr.size)
			return -1;

		hdr = new  XspMsgDataOpenHdr(buf);
		
		System.arraycopy(hdr.hop_id, 0, new_hdr.hop_id, 0, Constants.XSP_HOPID_LEN);
		new_hdr.flags = (short) hdr.flags;
		
		return 0; 		
	}
	
	public int parse_DATA_CLOSE (byte [] buf, int remainder, Object msg_object){ return 0; }
	public int parse_PATH_OPEN (byte [] buf, int remainder, Object msg_object)
	{ 
		XspBlockHeaderHdr hdr;
		XspBlockHeader new_header=(XspBlockHeader)msg_object;
		if(new_header==null)
			new_header = new XspBlockHeader();
		
		if (remainder < XspBlockHeaderHdr.size)
			return -1;
		
		hdr = new  XspBlockHeaderHdr(buf);		
		
		new_header.type = hdr.type;
		new_header.sport = hdr.sport;
		new_header.length = hdr.length;

		remainder -= XspBlockHeaderHdr.size;

	        // validate the blob size
	        
		if (new_header.length > 16777216 || new_header.length > remainder) 
			return -1;
	     
	        
		// allocate space for the blob
		new_header.blob = new byte[new_header.length];


		// copy the blob from the message	    
		System.arraycopy(buf, XspBlockHeaderHdr.size, new_header.blob, 0, new_header.length);
		
		return 0; 
	} 
	public int parse_PATH_CLOSE (byte [] buf, int remainder, Object msg_object){ return 0; }
	public int parse_APP_DATA (byte [] buf, int remainder, Object msg_object)
	{
		XspBlockHeaderHdr hdr;
		XspBlockHeader new_header=(XspBlockHeader)msg_object;
		if(new_header==null)
			new_header = new XspBlockHeader();
		
		if (remainder < XspBlockHeaderHdr.size)
			return -1;
	
		hdr = new  XspBlockHeaderHdr(buf);		
		
		new_header.type = hdr.type;
		new_header.sport = hdr.sport;
		new_header.length = hdr.length;

		remainder -= XspBlockHeaderHdr.size;

	        // validate the blob size
	        
		if (new_header.length > 16777216 || new_header.length > remainder) 
			return -1;
	     
	        
		// allocate space for the blob
		new_header.blob = new byte[new_header.length];


		// copy the blob from the message	    
		System.arraycopy(buf, XspBlockHeaderHdr.size, new_header.blob, 0, new_header.length);
		
		return 0; 
	}  
	
	SlabsRecord xsp_parse_slab_record(byte [] buf, int remainder, String size) {
        SlabsRecord new_rec;
        SlabsRecordHdr in;
        int orig_remainder;

        orig_remainder = remainder;

        new_rec = new SlabsRecord();
        
        in = new SlabsRecordHdr(buf);

        System.arraycopy(in.sess_id, 0, new_rec.sess_id, 0, Constants.XSP_SESSIONID_LEN);
        new_rec.offset = in.offset;
        new_rec.length = in.length;
        new_rec.crc = in.crc;

        remainder -= SlabsRecordHdr.size;

        size = Integer.toString(orig_remainder - remainder);

        return new_rec;
    }
	
	public int parse_SLAB_INFO (byte [] buf, int remainder, Object msg_object)
	{ 
	    SlabsInfo new_info;
        SlabsInfoHdr in;
        int i;
        String rec_size = Integer.toString(0);

        if (remainder < SlabsInfoHdr.size)
        	return -1;        

        new_info = new SlabsInfo();

        in = new SlabsInfoHdr(buf);

        new_info.length = in.length;
        new_info.rec_count = in.rec_count;

        byte [] buf2;
        buf2 = new byte[buf.length - SlabsInfoHdr.size];
        System.arraycopy(buf, SlabsInfoHdr.size, buf2, 0, buf2.length);
        
        if (new_info.rec_count == 0)
        {                
        	new_info.entries = null;
        }
        else 
        {                
        	for (i=0; i<new_info.rec_count; i++) 
        	{
        		SlabsRecord tempRec;
        		tempRec=this.xsp_parse_slab_record(buf2, remainder, rec_size);
        		if(tempRec==null)
        			return -1;
        		new_info.entries.add(tempRec);
                                        
        		byte [] buf3;
        		buf3=new byte[buf2.length - Integer.parseInt(rec_size)];
        		System.arraycopy(buf2, Integer.parseInt(rec_size), buf3, 0, buf3.length);
        		buf2=null;
        		buf2=new byte[buf3.length];
        		buf2=buf3.clone();
        		
        		remainder -= Integer.parseInt(rec_size);
        	}
        }
        return 0;
	} 
	
	int xsp_writeouthop(Hop hop, byte [] buf, int remainder,int written) 
	{
		int i;
		int orig_remainder;
		XspHopHdr hdr;
		int child_size;

		if (remainder < XspHopHdr.size)
			return -1;

		if (hop==null) {
			System.out.println("Error: specified writeout of NULL hop");
			return -1;
		}

		orig_remainder = remainder;

		System.out.println("Writing " + hop.hop_id.toString() + " hop information");
		
		hdr=new XspHopHdr();
		
		System.arraycopy(hop.hop_id, 0, hdr.id, 0, Constants.XSP_HOPID_LEN);
		System.arraycopy(hop.protocol, 0, hdr.protocol, 0, Constants.XSP_PROTO_NAME_LEN);
		hdr.flags=hop.flags;
		hdr.child_count=(short) hop.child_count;
		
		System.arraycopy(hdr.getBytes(), 0, buf, written, XspHopHdr.size);
		remainder -= XspHopHdr.size;
		written += XspHopHdr.size;
		
		for(i = 0; i < hop.child_count; i++) {
			child_size = xsp_writeouthop(hop.child.elementAt(i), buf, remainder,written);
			if (child_size < 0)
				return -1;

			written += child_size;
			remainder -= child_size;
		}

		return orig_remainder - remainder;
	}
	
	public int writeout_INVALID (Object msg_object, byte [] buf, int remainder){ return 0; }
	
	public int writeout_SESS_OPEN (Object msg_object, byte [] buf, int remainder)
	{ 
		int orig_remainder;
		
		Hop hop = (Hop) msg_object;
		XspSessHdr sess_hdr=new XspSessHdr();
		int i;
		int child_size;

		orig_remainder = remainder;

		if (remainder < XspSessHdr.size)
			return -1;

		System.arraycopy(hop.session.sess_id, 0, sess_hdr.sess_id, 0, Constants.XSP_SESSIONID_LEN);
		System.arraycopy(hop.session.src_id, 0, sess_hdr.src_id, 0, Constants.XSP_HOPID_LEN);

		sess_hdr.sess_flags = hop.session.sess_flags;
		sess_hdr.hop_flags = hop.flags;
		
		remainder -= XspSessHdr.size;
		
		System.arraycopy(sess_hdr.getBytes(), 0, buf, 0, XspSessHdr.size);
		
		byte [] buf2;
		buf2=new byte[remainder];
		
		int written=0;
		
		for(i = 0; i < hop.child_count; i++) {

			child_size = xsp_writeouthop(hop.child.elementAt(i), buf2, remainder,written);
			if (child_size < 0)
				return -1;

			written += child_size;
			remainder -= child_size;
		}

		System.arraycopy(buf2, 0, buf, XspSessHdr.size, buf2.length);
		return orig_remainder - remainder;		
	}
	
	public int writeout_SESS_ACK (Object msg_object, byte [] buf, int remainder){ return 0; } 
	public int writeout_SESS_CLOSE (Object msg_object, byte [] buf, int remainder){ return 0; }	
	
	public int writeout_BLOCK_HEADER (Object msg_object, byte [] buf, int remainder)
	{ 	
		XspBlockHeader block = (XspBlockHeader)msg_object;
		XspBlockHeaderHdr hdr = new XspBlockHeaderHdr();

		// if there isn't enough room to write the structure, don't do it
		if (remainder < XspBlockHeaderHdr.size)
			return -1;		

		// writeout the block header structure in network byte order
		hdr.type = block.type;
		hdr.sport = block.sport;
		hdr.length = block.length;

		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspBlockHeaderHdr.size);
		remainder -= XspBlockHeaderHdr.size;

		if (remainder < block.length)
			return -1;

		System.arraycopy(block.blob, 0, buf, XspBlockHeaderHdr.size, block.length);
		
		return XspBlockHeaderHdr.size + block.length;
	}
	
	public int writeout_AUTH_TYPE	(Object msg_object, byte [] buf, int remainder){ return 0; } 
	
	public int writeout_AUTH_TOKEN (Object msg_object, byte [] buf, int remainder)
	{ 
		XspAuthToken xsp_token = (XspAuthToken)msg_object;
		XspMsgAuthTokenHdr hdr=new XspMsgAuthTokenHdr();

		// if there isn't enough room to write the structure, don't do it
		if (remainder < XspMsgAuthTokenHdr.size)			
			return -1;
		
		// writeout the auth_token token structure in network byte order
		hdr.token_length = xsp_token.token_length;

		remainder -= XspMsgAuthTokenHdr.size;

		if (remainder < xsp_token.token_length)
			return -1;

		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspMsgAuthTokenHdr.size);
		System.arraycopy(xsp_token.token, 0, buf, XspMsgAuthTokenHdr.size, xsp_token.token_length);

		return XspMsgAuthTokenHdr.size + xsp_token.token_length;	
	}	
	
	public int writeout_SESS_NACK (Object msg_object, byte [] buf, int remainder)
	{ 
		String error_msg = (String)msg_object;
		XspMsgSessNackHdr hdr = new XspMsgSessNackHdr();

		// if there isn't enough room to write the structure, don't do it
		if (remainder < XspMsgSessNackHdr.size)
			return -1;	

		// writeout the auth_token token structure in network byte order
		hdr.length = error_msg.length();

		remainder -= XspMsgSessNackHdr.size;
		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspMsgSessNackHdr.size);

		if (remainder < error_msg.length())
			return -1;

		System.arraycopy(error_msg.getBytes(), 0, buf, XspMsgSessNackHdr.size, error_msg.length());
		
		return XspMsgSessNackHdr.size + error_msg.length();		
	}
	
	public int writeout_PING (Object msg_object, byte [] buf, int remainder){ return 0; }	 
	public int writeout_PONG (Object msg_object, byte [] buf, int remainder){ return 0; }	 
	
	public int writeout_DATA_OPEN (Object msg_object, byte [] buf, int remainder)
	{ 
		XspDataOpenHdr dopen = (XspDataOpenHdr)msg_object;
		XspMsgDataOpenHdr hdr = new XspMsgDataOpenHdr();

		if (remainder < XspMsgDataOpenHdr.size)
			return -1;		
		       
		//hdr = (xspDataOpen_HDR *) buf;
		
		hdr.flags = dopen.flags;
		System.arraycopy(dopen.hop_id, 0, hdr.hop_id, 0, Constants.XSP_HOPID_LEN);		
		System.arraycopy(dopen.proto, 0, hdr.proto, 0, Constants.XSP_PROTO_NAME_LEN);
		
		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspMsgDataOpenHdr.size);
		remainder -= XspMsgDataOpenHdr.size;
		
		return XspMsgDataOpenHdr.size;
	}
	public int writeout_DATA_CLOSE (Object msg_object, byte [] buf, int remainder){ return 0; }
	
	public int writeout_PATH_OPEN (Object msg_object, byte [] buf, int remainder)
	{ 
		XspBlockHeader block = (XspBlockHeader)msg_object;
		XspBlockHeaderHdr hdr = new XspBlockHeaderHdr();

		// if there isn't enough room to write the structure, don't do it
		if (remainder < XspBlockHeaderHdr.size)
			return -1;		

		// writeout the block header structure in network byte order
		hdr.type = block.type;
		hdr.sport = block.sport;
		hdr.length = block.length;

		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspBlockHeaderHdr.size);
		remainder -= XspBlockHeaderHdr.size;

		if (remainder < block.length)
			return -1;

		System.arraycopy(block.blob, 0, buf, XspBlockHeaderHdr.size, block.length);
		
		return XspBlockHeaderHdr.size + block.length;	
	} 
	
	public int writeout_PATH_CLOSE (Object msg_object, byte [] buf, int remainder){ return 0; }
	
	public int writeout_APP_DATA (Object msg_object, byte [] buf, int remainder)
	{ 
		XspBlockHeader block = (XspBlockHeader)msg_object;
		XspBlockHeaderHdr hdr = new XspBlockHeaderHdr();

		// if there isn't enough room to write the structure, don't do it
		if (remainder < XspBlockHeaderHdr.size)
			return -1;		

		// writeout the block header structure in network byte order
		hdr.type = block.type;
		hdr.sport = block.sport;
		hdr.length = block.length;

		System.arraycopy(hdr.getBytes(), 0, buf, 0, XspBlockHeaderHdr.size);
		remainder -= XspBlockHeaderHdr.size;

		if (remainder < block.length)
			return -1;

		System.arraycopy(block.blob, 0, buf, XspBlockHeaderHdr.size, block.length);
		
		return XspBlockHeaderHdr.size + block.length;	
	}  

	int xsp_writeout_slab_record(SlabsRecord rec, byte [] buf, int remainder, int written) {
        int orig_remainder;
        SlabsRecordHdr out=new SlabsRecordHdr();
        if (remainder < SlabsRecordHdr.size)
        	return -1;	
        
        orig_remainder = remainder;

        System.arraycopy(rec.sess_id, 0, out.sess_id, 0, Constants.XSP_SESSIONID_LEN); 
        out.offset = rec.offset;
        out.length = rec.length;
        out.crc = rec.crc;

        System.arraycopy(out.getBytes(), 0, buf, 0, SlabsRecordHdr.size);
        remainder -= SlabsRecordHdr.size;

        return orig_remainder - remainder;
	}
	
	public int writeout_SLAB_INFO (Object msg_object, byte [] buf, int remainder)
	{ 
        int orig_remainder;
        SlabsInfo info = (SlabsInfo) msg_object;
        SlabsInfoHdr out = new SlabsInfoHdr();
        int i;
        int rec_size;

        orig_remainder = remainder;

        if (remainder < SlabsInfoHdr.size)
        	return -1;        

        out.length = info.length;
        out.rec_count = info.rec_count;

        remainder -= SlabsInfoHdr.size;
        System.arraycopy(out.getBytes(), 0, buf, 0, SlabsInfoHdr.size);
                
		byte [] buf2;
		buf2=new byte[remainder];
		
		int written=0;
		
        for (i=0; i<info.rec_count; i++) {
        	rec_size = xsp_writeout_slab_record(info.entries.elementAt(i), buf2, remainder,written);
        	if (rec_size < 0)
        		return -1;
        	
        	remainder -= rec_size;
        }	
        System.arraycopy(buf2, 0, buf, SlabsInfoHdr.size, buf2.length);
        return orig_remainder - remainder;
	} 
}
