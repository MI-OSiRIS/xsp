# =============================================================================
#  DAMSL (xsp)
#
#  Copyright (c) 2010-2016, Trustees of Indiana University,
#  All rights reserved.
#
#  This software may be modified and distributed under the terms of the BSD
#  license.  See the COPYING file for details.
#
#  This software was created at the Indiana University Center for Research in
#  Extreme Scale Technologies (CREST).
# =============================================================================
"""
Client/server library for the eXtensible Session Protocol (XSP).
"""
__author__ = "Ezra Kissel <kissel@cis.udel.edu>, Dan Gunter <dkgunter@lbl.gov>"
__rcsid__ = "$Id: xsplib.py 27238 2011-02-24 23:45:43Z dang $"

import asyncore
import binascii
import random
import socket
import struct
import sys
import time

from netlogger.nllog import DoesLogging, get_logger

XSP_v0=0
XSP_v1=1

XSP_HOPID_LEN=64
XSP_MAX_LENGTH=65536
XSP_DEF_FLAGS=0
XSP_DEF_SPORT=1
XSP_RESERVED=0

"""
XSP Message types
"""
XSP_MSG_SESS_OPEN=1
XSP_MSG_SESS_ACK=2
XSP_MSG_SESS_CLOSE=3
XSP_MSG_BLOCK_HEADER=4
XSP_MSG_AUTH_TYPE=5
XSP_MSG_PING=8
XSP_MSG_PONG=9
XSP_MSG_APP_DATA=12
XSP_MSG_AUTH_SIZE=10
XSP_MSG_BLOCK_HDR_SIZE=8
XSP_MSG_OPEN_SIZE_V0=88
XSP_MSG_OPEN_SIZE_V1=20
XSP_MSG_HDR_SIZE_V0=20
XSP_MSG_HDR_SIZE_V1=168

"""
XSP_MSG_APP_DATA option types
"""
XSP_MSG_OPT_HOP = 1 # NEW HOP BLOCK
XSP_MSG_OPT_AUTH_TYP = 2 # AUTH TYPE BLOCK
XSP_MSG_XIO_NEW_XFER  = 48 # Beginning of transfer
XSP_MSG_XIO_END_XFER  = 49 # End of transfer
XSP_MSG_XIO_UPDATE_XFER = 50 # Intermediate xfer info, eg NL-Calipers summaries
XSP_MSG_XIO_MIN = 48 # Lowest XSP+XIO event
XSP_MSG_XIO_MAX = 50 # Highest XSP+XIO event
XSP_MSG_NLMI_DATA=32 # Monitoring data from Blipp (formerly: NLMI)

"""
XSP header formats
"""
fmt_XSPv     = '!B'
fmt_v0MsgHdr = '!BBH16s'
fmt_v0BlkHdr = 'HHI'
fmt_v1MsgHdr = '!BBHHH72s72s16s'
fmt_v1BlkHdr = 'HHHH'


def msg_has_data(t):
    return (t == XSP_MSG_APP_DATA)

def block_has_data(t):
    return ((t >= XSP_MSG_XIO_MIN and t <= XSP_MSG_XIO_MAX)
            or (t == XSP_MSG_NLMI_DATA))

class XSPSessionEOF(Exception):
    pass

def readn(sock, sz, tmout=2.0):
    """Read 'sz' bytes fro2 socket.
    Raise XSPSessionEOF if we get 0 bytes before sz.
    """
    log = get_logger("nl_xsp_recv.readn")
    log.info("start", sz=sz)
    t0 = time.time()
    buf = ""
    while len(buf) < sz:
        b = ""
        try:
            b = sock.recv(sz - len(buf))
        except socket.error, (errno, errmsg):
            stopnow = True
            if errno == 11:
                dt = time.time() - t0
                if dt < tmout:
                    stopnow = False
            if stopnow:
                log.warn("socket.error", msg=errmsg, errno=errno)
                break
            else:
                time.sleep(0.1)
        #print("xsp hdr len={len:d}".format(len=len(xsp_hdr)))
        if len(b) == 0:
            dt = time.time() - t0
            if dt > tmout:
                log.warn("readn.eof")
                break
            else:
                time.sleep(0.1)
        else:
            buf += b
    # If we stopped getting data, consider this session over
    if len(buf) < sz:
        log.info("end", sz=sz, n=len(buf), status=-1)
        raise XSPSessionEOF()
    log.info("end", sz=sz, n=len(buf), status=0)
    return buf

class XSPSession(DoesLogging):
    """A connection to an XSP sender/receiver.
    """
    id = ""

    def __init__(self, sock=None):
        self.s = sock or socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.version = XSP_v1
        DoesLogging.__init__(self)

    def connect(self, host, port):
        self.s.connect((host, port))
        random.seed()
        self.id = "%032X" % random.getrandbits(128)
        self.send_auth()
        self.send_open()
        self.s.recv(XSP_MSG_HDR_SIZE_V1)
        # just ignore ACK, woo!

    def send_msg(self, data, length, type_):
        """Send a message to an XSP server.

        Args:
          data - Data portion, uninterpreted
          length - Length of the data
          type_ - Message type
        """

        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr + fmt_v0BlkHdr + str(length) + 's'
            block_len = XSP_MSG_BLOCK_HDR_SIZE + int(length)
            block_msg = struct.pack(fmt, self.version, XSP_MSG_APP_DATA,
                                    block_len, binascii.a2b_hex(self.id),
                                    int(type_), XSP_DEF_SPORT, int(length), data)

        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr + fmt_v1BlkHdr + str(length) + 's'
            block_len = int(length)
            block_msg = struct.pack(fmt, self.version, XSP_DEF_FLAGS, XSP_MSG_APP_DATA,
                                    1, XSP_RESERVED, "", "", binascii.a2b_hex(self.id),
                                    int(type_), XSP_DEF_SPORT,
                                    int(length), XSP_RESERVED, data)
                  
        self.s.send(block_msg)

    def send_auth(self, name="ANON"):
        """Send an <auth> message to an XSP server.
        Uses 'self.id' as the key.

        Args:
          name - Authorization name.
        """

        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr + str(XSP_MSG_AUTH_SIZE) + 's'
            msg = struct.pack(fmt, self.version, XSP_MSG_AUTH_TYPE,
                              XSP_MSG_AUTH_SIZE,
                              binascii.a2b_hex(self.id), name)

        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr + fmt_v1BlkHdr + str(XSP_MSG_AUTH_SIZE) + 's'
            msg = struct.pack(fmt, self.version, XSP_DEF_FLAGS, XSP_MSG_AUTH_TYPE,
                              1, XSP_RESERVED, "", "", binascii.a2b_hex(self.id),
                              XSP_MSG_OPT_AUTH_TYP, XSP_DEF_SPORT,
                              XSP_MSG_AUTH_SIZE, XSP_RESERVED, name)
            
        self.s.send(msg)

    def send_open(self, host='localhost'):
        """Send an <open> message to an XSP server.

        Args:
          host - Sending host name (default 'localhost')
        """
        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr + '16s' + str(XSP_HOPID_LEN) + 'sII'
            msg = struct.pack(fmt, self.version, XSP_MSG_SESS_OPEN,
                              XSP_MSG_OPEN_SIZE_V0, binascii.a2b_hex(self.id),
                              binascii.a2b_hex(self.id),
                              'localhost', 0, 0)
            
        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr + fmt_v1BlkHdr + '16sI'
            msg = struct.pack(fmt, self.version, XSP_DEF_FLAGS, XSP_MSG_SESS_OPEN,
                              1, XSP_RESERVED, "", "", binascii.a2b_hex(self.id),
                              XSP_MSG_OPT_HOP, XSP_DEF_SPORT, XSP_MSG_OPEN_SIZE_V1,
                              XSP_RESERVED, binascii.a2b_hex(self.id), 0)
            
        self.s.send(msg)

    def send_close(self):
        """Send a <close> message to an XSP server.
        """
        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr
            msg = struct.pack(fmt, self.version, XSP_MSG_SESS_CLOSE,
                              0, binascii.a2b_hex(self.id))

        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr
            msg = struct.pack(fmt, self.version, 0, XSP_MSG_SESS_CLOSE,
                              0, 0, "", "", binascii.a2b_hex(self.id))
            
        self.s.send(msg)

    def send_ack(self):
        """ACK a message
        """
        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr
            ack_msg = struct.pack(fmt, self.version, XSP_MSG_SESS_ACK, 0,
                                  binascii.a2b_hex(self.id))

        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr
            ack_msg = struct.pack(fmt, self.version, 0, XSP_MSG_SESS_ACK,
                                  0, 0, "", "", binascii.a2b_hex(self.id))

        self.s.send(ack_msg)

    def recv_msg(self):
        xsp_ver = readn(self.s, 1)
        ver = struct.unpack(fmt_XSPv, xsp_ver)

        if ver[0] == XSP_v0:
            xsp_hdr = readn(self.s, XSP_MSG_HDR_SIZE_V0-1)
            hdr = struct.unpack('!' + fmt_v0MsgHdr[2:], xsp_hdr)
            if not msg_has_data(hdr[0]):
                _ = readn(self.s, hdr[1])
                return hdr[0], 0, None

            block_msg = readn(self.s, hdr[1])
            #print("@@ got msg len={0:d} expect={1:d}".format(len(block_msg), hdr[0]))
            fmt = '!' + fmt_v0BlkHdr + str(hdr[1] - XSP_MSG_BLOCK_HDR_SIZE) + 's'
            #print("@@ struct fmt={0}".format(fmt))
            block = struct.unpack(fmt, block_msg)
            return block[0], block[2], block[3]

        elif ver[0] == XSP_v1:
            hdr_bytes = readn(self.s, XSP_MSG_HDR_SIZE_V1-1)
            hdr = struct.unpack('!' + fmt_v1MsgHdr[2:], hdr_bytes)
            msg_type, msg_data = hdr[1], hdr[2]

            # Set version when session opens
            if msg_type == XSP_MSG_SESS_OPEN:
                self.version = XSP_v1

            # If there is no message data, stop and return message type
            if not msg_data:
                return msg_type, 0, None

            # Read message data
            block_bytes = readn(self.s, XSP_MSG_BLOCK_HDR_SIZE)
            block_type, _, block_len, _ = struct.unpack('!' + fmt_v1BlkHdr, block_bytes)

            # If this type of block has no data, consume any
            # additional parts and return the message type
            if not block_has_data(block_type):
                _ = readn(self.s, block_len)
                return msg_type, 0, None

            # Otherwise, read the data and return it along with
            # the block (or option) type

            block_bytes = readn(self.s, block_len)
            return block_type, block_len, block_bytes

    def close(self):
        self.send_close()

    def ping(self):
        fmt = ''
        if self.version == XSP_v0:
            fmt = fmt_v0MsgHdr
            ping_msg = struct.pack(fmt, self.version, XSP_MSG_PING,
                                   0, binascii.a2b_hex(self.id))
            
        elif self.version == XSP_v1:
            fmt = fmt_v1MsgHdr
            ping_msg = struct.pack(fmt, self.version, 0, XSP_MSG_PING,
                                  0, 0, "", "", binascii.a2b_hex(self.id))

        self.s.send(ping_msg)

        if self.version == XSP_v0:
            xsp_hdr = self.s.recv(XSP_MSG_HDR_SIZE_V0)

        elif self.version == XSP_v1:
            xsp_hdr = self.s.recv(XSP_MSG_HDR_SIZE_V1)
            
        if (len(xsp_hdr) > 0):
            hdr = struct.unpack(fmt, xsp_hdr)
        else:
            return -1

        hdr = struct.unpack(fmt, xsp_hdr)
        
        if (hdr[self.version + 1] == XSP_MSG_PONG):
            return 0
        else:
            return -1

class XSPServer(asyncore.dispatcher, DoesLogging):
    """Asyncore-based XSP message server.

    This class accepts connections then hands them off
    to instances of XSPHandler.
    """
    def __init__(self, host, port, data_fn=None, cb_map={ }):
        """Create new server listening on local socket.

        Args:
          host - socket host addr
          port - socket port
          data_fn - callback function passed to XSPHandler
        """
        DoesLogging.__init__(self)
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        if cb_map:
            self._callback = cb_map
        else:
            self._callback = data_fn

    def handle_accept(self):
        """Accept a new connection.
        """
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            self.log.info("connection.new", addr=repr(addr))
            handler = XSPHandler(sock, self._callback)

    def loop(self, **kw):
        asyncore.loop(**kw)

class XSPHandler(asyncore.dispatcher_with_send, DoesLogging):
    """Handle new connections from XSPServer.
    """
    def __init__(self, sock, callback):
        """Create an XSPSession with the given socket.

        Args:
          sock - Socket
          callback - If a single callable, invoked as callback(data),
                     where 'data' is a buffer of BSON-encoded info.
                     If a dictionary, then a mapping of <type>:<fn> for
                     various XSP message types.
        """
        DoesLogging.__init__(self)
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.sess = XSPSession(sock)
        if callable(callback):
            self._cb = callback
            self._handler = self._handle_data
        else:
            self._cb_map = callback
            self._handler = self._handle_mapped

    def handle_read(self):
        """Read a message, maybe send an ack.
        """
        if self._dbg:
            self.log.debug("read.start")
        length = 0
        try:
            type_, length, data = self.sess.recv_msg()
        except XSPSessionEOF:
            self.log.info("read.eof")
            self.handle_close()
            return
        self._handler(type_, length, data)
        if self._dbg:
            self.log.debug("read.end", length=length)

    def _handle_data(self, type_, length, data):
        """Handle a message in 'data' mode.
        """
        if type_ == XSP_MSG_SESS_OPEN:
            if self._dbg: self.log.debug("ack.start", type=type_)
            self.sess.send_ack()
            if self._dbg: self.log.debug("ack.end", type=type_)
        elif data is not None:
            if self._dbg: self.log.debug("callback.start", data__len=len(data))
            self._cb(data)
            if self._dbg: self.log.debug("callback.end")

    def _handle_mapped(self, type_, length, data):
        """Handle a message to a map of callbacks.
        """
        if type_ == XSP_MSG_SESS_OPEN:
            if self._dbg: self.log.debug("ack.start", type=type_)
            self.sess.send_ack()
            if self._dbg: self.log.debug("ack.end", type=type_)
        func = self._cb_map.get(type_, None)
        if func is not None:
            if self._dbg:
                self.log.debug("callback.start", type=type_, func=func.__name__)
            func(data=data)
            if self._dbg:
                self.log.debug("callback.end", type=type_, func=func.__name__)
        elif self._cb_map.has_key(None):
            func = self._cb_map[None]
            if self._dbg:
                self.log.debug("mapped.default-callback.start", type=type_,
                               func=func.__name__)
            func(type_=type_, data=data)
            if self._dbg:
                self.log.debug("mapped.default-callback.end", type=type_,
                               func=func.__name__)
        else:
            if self._dbg:
                self.log.debug("callback.noop", type=type_)

    def handle_close(self):
        """Close XSP session and underlying socket.
        """
        self.log.info("close.start")
        # can't send close if EOF
        #self.sess.close()
        self.close()
        self.log.info("close.end")


def __test():

    sess = XSPSession()
    sess.connect('localhost', 5006)

    my_msg = "This is a test"
    my_type = 0x20

    print '\nSending message [%d,%d]: %s' % (my_type, len(my_msg), my_msg)
    sess.send_msg(my_msg, len(my_msg), my_type)

    (type, length, data) = sess.recv_msg()
    print '\nReceived message [%d,%d]: %s' % (type, length, data)

    # might want pings to keep the session alive
    for i in range(5):
        time.sleep(1)
        ret = sess.ping()

        if (not ret):
            print "got pong"
        else:
            print "did not get pong"

    sess.close()

if __name__ == "__main__":
    __test()
