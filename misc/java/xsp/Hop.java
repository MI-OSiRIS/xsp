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

import java.util.Vector;
import java.util.Arrays;

public class Hop extends XspBase{
	public char opt_type;
	public short flags;
	public byte [] hop_id;

	public byte [] protocol;
	public int child_count;
	public Session session;

	public Vector<Hop> child;
	
	public static final int size = 2+2+Constants.XSP_HOPID_LEN+Constants.XSP_PROTO_NAME_LEN+4;
	public Hop()
	{
		opt_type = 0;
		flags = 0;
		hop_id = new byte[Constants.XSP_HOPID_LEN];
		protocol = new byte[Constants.XSP_PROTO_NAME_LEN];
		session = new Session();
		child_count = 0;
		child=new Vector<Hop>();
	}
	
    public byte[] getBytes() {    	
    	byte [] binData;
 
    	binData=new byte[size];    	    
    	System.arraycopy(Xsp.shortToByteArray((short)opt_type), 0, binData, 0, 2);
    	System.arraycopy(Xsp.shortToByteArray(flags), 0, binData, 2, 2);
    	//System.out.println("Hop.getBytes()=> lengths : "+hop_id.length+ " "+binData.length);
    	System.arraycopy(hop_id, 0, binData, 4, hop_id.length);
    	System.arraycopy(protocol, 0, binData, Constants.XSP_HOPID_LEN+4, Constants.XSP_PROTO_NAME_LEN);
    	System.arraycopy(Xsp.intToByteArray(child_count), 0, binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN+4, 4);
    	return binData;    	
	}
	
    Hop(byte [] binData)
    {
    	byte [] shortByte;
    	shortByte=new byte[2];
    	byte [] intByte;
    	intByte=new byte[4];
    	
    	System.arraycopy(binData, 0, shortByte, 0, 2);
    	opt_type=(char)Xsp.byteArrayToShort(shortByte);
    	System.arraycopy(binData, 2, shortByte, 0, 2);
    	flags=Xsp.byteArrayToShort(shortByte);    	
    	if(hop_id==null)
    		hop_id=new byte[Constants.XSP_HOPID_LEN];
    	System.arraycopy(binData, 4, hop_id, 0, Constants.XSP_HOPID_LEN);
    	if(protocol==null)
    		protocol=new byte[Constants.XSP_PROTO_NAME_LEN];    	
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN+4, protocol, 0, Constants.XSP_PROTO_NAME_LEN); 	
    	System.arraycopy(binData, Constants.XSP_HOPID_LEN + Constants.XSP_PROTO_NAME_LEN+4, intByte, 0, 4);    	
    	child_count=Xsp.byteArrayToInt(intByte);    	
    } 
    
	public int xsp_hop_merge_children(Hop dst, Hop src) {
		int i;
		if (src.child_count == 0)
			return 0;
		for(i=0;i<src.child.size();i++)
		{
			dst.child.add(src.child.get(i));			
		}
		dst.child_count=dst.child.size();
		
		return 0;
	}

	public int xsp_hop_add_child(Hop chld) {
		child.add(chld);
		child_count = child.size();
		return 0;
	}

	public byte [] xsp_hop_getid()
	{
		return hop_id;
	}
	
	public void xsp_hop_setid(byte [] id)
	{
		hop_id=id.clone();
	}
	
	public void xsp_hop_set_flag(short flag) {
		flags = flag;
	}

	public int xsp_hop_check_flag(char flag) {
		return (flags & flag);
	}
	
	public int xsp_path_merge_duplicates() {
		int i, curr;

		curr = 0;

		do 
		{
			// find a duplicate
			for(i = curr + 1; i < child_count; i++) 
			{
				if (Arrays.equals(child.elementAt(curr).hop_id, child.elementAt(i).hop_id))
					break;
			}

			if (i < child_count) {
				// if we find a duplicate entry, merge the children together
				if (this.xsp_hop_merge_children(this.child.elementAt(curr), this.child.elementAt(i)) == 0)
				{
					return -1;
				}

				//xsp_free_hop(root->child[i], 0);

				// move the final hop down to replace the removed node
				child.remove(i);
				child_count--;
			} else {
				// no duplicate found, check the subtree below this hop
				if (child.elementAt(curr).xsp_path_merge_duplicates() == 1){
					return -1;
				}

				curr++;
			}

		} while (curr < child_count);

		return 0;
	}

}
