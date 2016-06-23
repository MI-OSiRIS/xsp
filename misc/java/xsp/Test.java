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

public class Test {
	  public static void main(String[] args) throws Exception {  
		  XspClient client=new XspClient();
		  client.xsp_sess_appendchild(Xsp.charToByteArray("localhost/5006".toCharArray()), Xsp.XSP_HOP_NATIVE);
		  client.xsp_connect();		  		  
		  
		  String str = "This is a test";
		  byte [] ret_buf;
		  ret_buf=new byte[30];
		  

		  client.xsp_send_msg(Xsp.charToByteArray(str.toCharArray()), str.length(), 0x30);
		  client.xsp_recv_msg(ret_buf, 100, 0x30);

			
		  System.out.println("got message: "+ new String(Xsp.byteToCharArray(ret_buf)));

		  client.xsp_close();
	  }
}
