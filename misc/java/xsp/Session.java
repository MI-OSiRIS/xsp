package xsp;

import java.util.Arrays;
import java.util.Vector;

public class Session {
	byte [] sess_id;

	byte [] src_id;

	int sess_flags;

	int hop_flags;

	Vector<Hop> child;
	int child_count;

	Session()
	{
		sess_id = new byte[Constants.XSP_SESSIONID_LEN];
		src_id = new byte[Constants.XSP_HOPID_LEN];
		sess_flags = 0;
		hop_flags = 0;
		child_count = 0 ;		
	}
	
	boolean xsp_sesscmp(Session s1) 
	{
		return Arrays.equals(sess_id, s1.sess_id);
	}
	
	int xsp_sess_addhop(Hop hop) {
		child.add(hop);

		child_count = child.size();

		hop.session = this;

		return 0;
	}
}
