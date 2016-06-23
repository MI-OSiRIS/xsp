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
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class Xsp {
	public Proto protocol;
	
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
	
	Xsp()
	{
		protocol=new Proto();
	}
	
	Xsp(byte type)
	{
		
		protocol=new Proto();
		if(type==Constants.LIBXSP_PROTO_BINARY_ID);
		{
			ProtoBinary protoBin=new ProtoBinary();
			protocol.xsp_add_proto_handler((byte)Constants.LIBXSP_PROTO_BINARY_ID, protoBin);
		}
				
	}
	
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
	
	public static int min(int a, int b)
	{
		if(a<b)
			return a;
		else
			return b;
	}

	public static int xsp_parse_hopid(String hop_id, String [] serverStr) 
	{
		int slashIdx=hop_id.indexOf('/');
		System.out.println("slashIdx : "+slashIdx);
		if(slashIdx<0)
		{
			System.out.println("No / in the hop_id");
			return -1;
		}
		serverStr[0]=hop_id.substring(0, slashIdx);
		serverStr[1]=hop_id.substring(slashIdx+1, hop_id.length());
		System.out.println(serverStr[0] + " " + serverStr[1]);
		return 0;
	}

	public static InetAddress[] xsp_lookuphop(String server) throws UnknownHostException {		
		InetAddress[] res=InetAddress.getAllByName(server);
		return res;
	}

	public static Socket xsp_make_connection(char [] hop_id) {
		InetAddress [] hop_addrs;
		Socket socket = null;
		short connected;		
		String [] serverStr = new String[2];
		String hopStr=new String(hop_id);
		if (xsp_parse_hopid(hopStr, serverStr) < 0) {
			System.out.println("hop parsing failed: "+ new String(hop_id));
			return null;
		}
		
		try {
			hop_addrs = xsp_lookuphop(serverStr[0]);
		} catch (UnknownHostException e1) {			
			e1.printStackTrace();
			return null;
		}
		if (hop_addrs==null) {
			System.out.println("hop lookup failed for: "+new String(hop_id));
			return null;
		}
		int servPort=Integer.parseInt(serverStr[1]);
		connected = 0;
		for(int i=0; i<hop_addrs.length && connected==0; i++) 
		{
			try {
				socket = new Socket(serverStr[0], servPort);
			} catch (UnknownHostException e) {				
				e.printStackTrace();
				return null;
			} catch (IOException e) {				
				e.printStackTrace();
				return null;
			}			
			connected = 1;
		}

		if (connected==0)
			return null;

		return socket;
	}
	
	public static byte[] charToByteArray(char [] c)
	{
		byte [] b;
		b=new byte[c.length];
		for(int i=0;i<c.length;i++)
			b[i]=(byte)c[i];
		
		return b;
	}
	
	public static char [] byteToCharArray(byte [] b)
	{
		char [] c;
		c=new char[b.length];
		for(int i=0;i<b.length;i++)
			c[i]=(char)b[i];
		
		return c;
	}	
	 
}
