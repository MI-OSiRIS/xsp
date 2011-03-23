package xsp;

import java.util.Vector;
import java.util.Arrays;

public class Hop {
	char opt_type;
	short flags;
	byte [] hop_id;

	byte [] protocol;

	Session session;

	Vector<Hop> child;
	int child_count;
	
	Hop()
	{
		opt_type = 0;
		flags = 0;
		hop_id = new byte[Constants.XSP_HOPID_LEN];
		protocol = new byte[Constants.XSP_PROTO_NAME_LEN];
		session = new Session();
		child_count = 0;
	}
	
	int xsp_hop_merge_children(Hop dst, Hop src) {
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

	int xsp_hop_add_child(Hop chld) {
		child.add(chld);
		child_count = child.size();
		return 0;
	}

	byte [] xsp_hop_getid()
	{
		return hop_id;
	}
	
	void xsp_hop_setid(byte [] id)
	{
		int i;
		for(i=0;i<hop_id.length;i++)
			hop_id[i] = id[i];
	}
	
	void xsp_hop_set_flag(short flag) {
		flags = flag;
	}

	int xsp_hop_check_flag(char flag) {
		return (flags & flag);
	}
	
	int xsp_path_merge_duplicates() {
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
