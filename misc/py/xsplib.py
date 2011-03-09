"""
Client/server library for the eXtensible Session Protocol (XSP).
"""
__author__ = "Ezra Kissel <kissel@cis.udel.edu>, Dan Gunter <dkgunter@lbl.gov>"
__rcsid__ = "$Id: xsplib.py 27238 2011-02-24 23:45:43Z dang $"

import asyncore
import socket
import struct
import random
import binascii
import time

from netlogger.nllog import DoesLogging, get_logger

XSP_VERSION=0
XSP_MAX_LENGTH=65536

XSP_MSG_SESS_OPEN=1
XSP_MSG_SESS_ACK=2
XSP_MSG_SESS_CLOSE=3
XSP_MSG_BLOCK_HEADER=4
XSP_MSG_AUTH_TYPE=8
XSP_MSG_PING=11
XSP_MSG_PONG=12
XSP_MSG_APP_DATA=17
XSP_MSG_XIO_MIN = 48
XSP_MSG_XIO_MAX = 50
XSP_MSG_NLMI_DATA=32

XSP_MSG_OPEN_SIZE=84
XSP_MSG_AUTH_SIZE=10
XSP_MSG_BLOCK_SIZE=8
XSP_MSG_HDR_SIZE=20

def msg_has_data(t):
    return (t in (XSP_MSG_APP_DATA, XSP_MSG_NLMI_DATA) or
            (t >= XSP_MSG_XIO_MIN and t <= XSP_MSG_XIO_MAX))

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
        DoesLogging.__init__(self)

    def connect(self, host, port):
        self.s.connect((host, port))

        random.seed()
        self.id = "%X" % random.getrandbits(128)

        auth_msg = struct.pack('!hBB16s10s', XSP_MSG_AUTH_SIZE, XSP_VERSION,
                               XSP_MSG_AUTH_TYPE,
                               binascii.a2b_hex(self.id), "ANON")

        open_msg = struct.pack('!hBB16s16s60sii',
                               XSP_MSG_OPEN_SIZE, XSP_VERSION,
                               XSP_MSG_SESS_OPEN, binascii.a2b_hex(self.id),
                               binascii.a2b_hex(self.id),
                               'localhost', 0, 0)

        self.s.send(auth_msg)
        self.s.send(open_msg)
        self.s.recv(XSP_MSG_HDR_SIZE)
        # just ignore ACK, woo!

    def send_msg(self, data, length, type_):
        fmt = '!hBB16shhi' + str(length) + 's'
        block_len = XSP_MSG_BLOCK_SIZE + int(length)
        block_msg = struct.pack(fmt, block_len, XSP_VERSION,
                                XSP_MSG_APP_DATA, binascii.a2b_hex(self.id),
                                int(type_), 0, int(length), data)

        self.s.send(block_msg)

    def send_ack(self):
        fmt = '!hBB16s'
        ack_msg = struct.pack(fmt, 0, XSP_VERSION,
                              XSP_MSG_SESS_ACK, binascii.a2b_hex(self.id))
        self.s.send(ack_msg)


    def recv_msg(self):
        xsp_hdr = readn(self.s, XSP_MSG_HDR_SIZE)
        hdr = struct.unpack('!hBB16s', xsp_hdr)
        #print("xsp body type={code:d}".format(code=hdr[2]))
        if not msg_has_data(hdr[2]):
            _ = readn(self.s, hdr[0])
            return hdr[2], 0, None

        block_msg = readn(self.s, hdr[0])
        #print("@@ got msg len={0:d} expect={1:d}".format(len(block_msg), hdr[0]))
        fmt = '!hhi' + str(hdr[0] - XSP_MSG_BLOCK_SIZE) + 's'
        #print("@@ struct fmt={0}".format(fmt))
        block = struct.unpack(fmt, block_msg)
        return block[0], block[2], block[3]

    def close(self):
        close_msg = struct.pack('!hBB16s', 0, XSP_VERSION,
                                XSP_MSG_SESS_CLOSE, binascii.a2b_hex(self.id))
        self.s.send(close_msg)

    def ping(self):
        ping_msg = struct.pack('!hBB16s', 0, XSP_VERSION,
                                XSP_MSG_PING, binascii.a2b_hex(self.id))
        self.s.send(ping_msg)
        xsp_hdr = self.s.recv(XSP_MSG_HDR_SIZE)

        if (len(xsp_hdr) > 0):
            hdr = struct.unpack('!hBB16s', xsp_hdr)
        else:
            return -1

        if (hdr[2] == XSP_MSG_PONG):
            return 0
        else:
            return -1

class XSPServer(asyncore.dispatcher, DoesLogging):
    """Asyncore-based XSP message server.
    
    This class accepts connections then hands them off
    to instances of XSPHandler.
    """
    def __init__(self, host, port, data_fn=None):
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
          callback - Callback function, invoked as callback(data),
                     where 'data' is a buffer of BSON-encoded info.
        """
        DoesLogging.__init__(self)
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.sess = XSPSession(sock)
        self._cb = callback
        
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
        if type_ == XSP_MSG_SESS_OPEN:
            if self._dbg: self.log.debug("ack.start", type=type_)
            self.sess.send_ack()
            if self._dbg: self.log.debug("ack.end", type=type_)
        elif data is not None:
            if self._dbg: self.log.debug("callback.start", data__len=len(data))
            self._cb(data)
            if self._dbg: self.log.debug("callback.end")
        if self._dbg:
            self.log.debug("read.end", length=length)

    def handle_close(self):
        """Close XSP session and underlying socket.
        """
        self.log.info("close.start")
        self.sess.close()
        self.close()
        self.log.info("close.end")


def __test():

    sess = XSPSession()
    sess.connect('localhost', 5006)

    my_msg = "This is a test"
    my_type = 0x30
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
