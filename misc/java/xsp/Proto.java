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
import java.util.Vector;

public class Proto  extends XspBase{
	public Vector<XspProtoHandler> proto_list;
	
	Proto()
	{
		proto_list=new Vector<XspProtoHandler>();
	}

	public int xsp_add_proto_handler(byte version, XspProtoHandler handler) {
		proto_list.add(version, handler);
		return 0;
	}

	int xsp_writeout_msgbody(byte [] buf, int length, byte version, byte type, XspBase msg_body) {
		if (proto_list.get(version) == null || proto_list.get(version).max_msg_type < type) {
			System.out.println("couldn't write: " + (proto_list.get(version) == null) + " " +type + " " + proto_list.get(version).max_msg_type);
			return -1;
		}
		System.out.println("xsp_writeout_msgbody=> length : "+length+", version : "+version+", type : "+type);

		switch(type)
		{
		case Xsp.XSP_MSG_INVALID:
			return proto_list.get(version).writeout_INVALID(msg_body, buf, length);
		case Xsp.XSP_MSG_SESS_OPEN:
			return proto_list.get(version).writeout_SESS_OPEN(msg_body, buf, length);
		case Xsp.XSP_MSG_SESS_ACK:
			return proto_list.get(version).writeout_SESS_ACK(msg_body, buf, length);
		case Xsp.XSP_MSG_SESS_CLOSE:
			return proto_list.get(version).writeout_SESS_CLOSE(msg_body, buf, length);
		case Xsp.XSP_MSG_BLOCK_HEADER:
			return proto_list.get(version).writeout_BLOCK_HEADER(msg_body, buf, length);
		case Xsp.XSP_MSG_AUTH_TYPE:
			System.out.println("xsp_writeout_msgbody2=> length : "+length+", version : "+version+", type : "+type);
			return proto_list.get(version).writeout_AUTH_TYPE(msg_body, buf, length);
		case Xsp.XSP_MSG_AUTH_TOKEN:
			return proto_list.get(version).writeout_AUTH_TOKEN(msg_body, buf, length);
		case Xsp.XSP_MSG_SESS_NACK:
			return proto_list.get(version).writeout_SESS_NACK(msg_body, buf, length);
		case Xsp.XSP_MSG_PING:
			return proto_list.get(version).writeout_PING(msg_body, buf, length);
		case Xsp.XSP_MSG_PONG:
			return proto_list.get(version).writeout_PONG(msg_body, buf, length);
		case Xsp.XSP_MSG_DATA_OPEN:
			return proto_list.get(version).writeout_DATA_OPEN(msg_body, buf, length);
		case Xsp.XSP_MSG_DATA_CLOSE:
			return proto_list.get(version).writeout_DATA_CLOSE(msg_body, buf, length);
		case Xsp.XSP_MSG_PATH_OPEN:
			return proto_list.get(version).writeout_PATH_OPEN(msg_body, buf, length);
		case Xsp.XSP_MSG_PATH_CLOSE:
			return proto_list.get(version).writeout_PATH_CLOSE(msg_body, buf, length);
		case Xsp.XSP_MSG_APP_DATA:
			return proto_list.get(version).writeout_APP_DATA(msg_body, buf, length);
		case Xsp.XSP_MSG_SLAB_INFO:
			return proto_list.get(version).writeout_SLAB_INFO(msg_body, buf, length);
		}
		return -1;
	}
	
	public int xsp_writeout_msg(byte [] buf, int length, byte version, byte type, byte [] sess_id, XspBase msg_body) {
		XspMsgHdr hdr = new XspMsgHdr();
		byte [] msg_buf;
		int body_length;
		int remainder;
		
		if (length < XspMsgHdr.size)
			return -1;
			
		hdr.type = type;
		hdr.version = version;
	
		hdr.sess_id=sess_id.clone();
		System.out.println("xsp_writeout_msg=> sess_id : "+new String(hdr.sess_id));
		remainder = length - XspMsgHdr.size;
		//System.out.println("xsp_writeout_msg=> length : "+length+", version : "+version+", type : "+type+", remainder :" + remainder);
		// fill in the message body
		msg_buf=new byte[remainder];
		body_length = xsp_writeout_msgbody(msg_buf, remainder, version, type, msg_body);
		
		if (body_length < 0)
			return -1;
		
		System.arraycopy(msg_buf, 0, buf, XspMsgHdr.size, body_length);
		hdr.length = (short)body_length;

		System.out.println("body_length: " + body_length + " " + hdr.length);
		System.out.println("header_length: " + XspMsgHdr.size);
		System.arraycopy(hdr.getBytes(),0,buf,0, XspMsgHdr.size);
		System.out.println("xsp_writeout_msg=> msg_buf : "+msg_buf[2]+" "+msg_buf.length);//new String(Xsp.byteToCharArray(hdr.)));
		//System.out.println("xsp_writeout_msg"+new String(Xsp.byteToCharArray(msg_buf)));
		return (XspMsgHdr.size + body_length);

	}
	


	int xsp_parse_msgbody(XspMsg hdr, byte [] buf, int length, XspBase msg_object) throws IOException {
		int retval=-1;

		if (proto_list.get(hdr.version) == null || proto_list.get(hdr.version).max_msg_type < hdr.type) {
		    System.out.println("bad message type: \n" + hdr.type);
			retval = -1;
		} 
		else {
			switch(hdr.type)
			{
			case Xsp.XSP_MSG_INVALID:
				return proto_list.get(hdr.version).parse_INVALID(buf, length, msg_object);
			case Xsp.XSP_MSG_SESS_OPEN:
				return proto_list.get(hdr.version).parse_SESS_OPEN(buf, length, msg_object);
			case Xsp.XSP_MSG_SESS_ACK:
				return proto_list.get(hdr.version).parse_SESS_ACK(buf, length, msg_object);
			case Xsp.XSP_MSG_SESS_CLOSE:
				return proto_list.get(hdr.version).parse_SESS_CLOSE(buf, length, msg_object);
			case Xsp.XSP_MSG_BLOCK_HEADER:
				return proto_list.get(hdr.version).parse_BLOCK_HEADER(buf, length, msg_object);
			case Xsp.XSP_MSG_AUTH_TYPE:
				return proto_list.get(hdr.version).parse_AUTH_TYPE(buf, length, msg_object);
			case Xsp.XSP_MSG_AUTH_TOKEN:
				return proto_list.get(hdr.version).parse_AUTH_TOKEN(buf, length, msg_object);
			case Xsp.XSP_MSG_SESS_NACK:
				return proto_list.get(hdr.version).parse_SESS_NACK(buf, length, msg_object);
			case Xsp.XSP_MSG_PING:
				return proto_list.get(hdr.version).parse_PING(buf, length, msg_object);
			case Xsp.XSP_MSG_PONG:
				return proto_list.get(hdr.version).parse_PONG(buf, length, msg_object);
			case Xsp.XSP_MSG_DATA_OPEN:
				return proto_list.get(hdr.version).parse_DATA_OPEN(buf, length, msg_object);
			case Xsp.XSP_MSG_DATA_CLOSE:
				return proto_list.get(hdr.version).parse_DATA_CLOSE(buf, length, msg_object);
			case Xsp.XSP_MSG_PATH_OPEN:
				return proto_list.get(hdr.version).parse_PATH_OPEN(buf, length, msg_object);
			case Xsp.XSP_MSG_PATH_CLOSE:
				return proto_list.get(hdr.version).parse_PATH_CLOSE(buf, length, msg_object);
			case Xsp.XSP_MSG_APP_DATA:
				return proto_list.get(hdr.version).parse_APP_DATA(buf, length, msg_object);
			case Xsp.XSP_MSG_SLAB_INFO:
				return proto_list.get(hdr.version).parse_SLAB_INFO(buf, length, msg_object);
			}
		}

		return retval;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return null;
	}

}
