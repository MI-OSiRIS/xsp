import socket
import struct
import random
import binascii
import time

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

XSP_MSG_OPEN_SIZE=84
XSP_MSG_AUTH_SIZE=10
XSP_MSG_BLOCK_SIZE=8
XSP_MSG_HDR_SIZE=20

class xspSess:

    id = ""

    def connect(self, host, port):
        self.s.connect((host, port))
        
        random.seed()
        self.id = "%X" % random.getrandbits(128)

        auth_msg = struct.pack('!hBB16s10s', XSP_MSG_AUTH_SIZE, XSP_VERSION,
                               XSP_MSG_AUTH_TYPE, binascii.a2b_hex(self.id), "ANON")
        
        open_msg = struct.pack('!hBB16s16s60sii', XSP_MSG_OPEN_SIZE, XSP_VERSION,
                               XSP_MSG_SESS_OPEN, binascii.a2b_hex(self.id),
                               binascii.a2b_hex(self.id),
                               'localhost', 0, 0)

        self.s.send(auth_msg)
        self.s.send(open_msg)
        self.s.recv(XSP_MSG_HDR_SIZE)
        # just ignore ACK, woo!
        
    def send_msg(self, data, length, type):
        fmt = '!hBB16shhi' + str(length) + 's'
        block_len = XSP_MSG_BLOCK_SIZE + int(length)
        block_msg = struct.pack(fmt, block_len, XSP_VERSION,
                                XSP_MSG_APP_DATA, binascii.a2b_hex(self.id),
                                int(type), 0, int(length), data)

        self.s.send(block_msg)

    def recv_msg(self):
        xsp_hdr = self.s.recv(XSP_MSG_HDR_SIZE)
        hdr = struct.unpack('!hBB16s', xsp_hdr)
        
        if (hdr[3] != XSP_MSG_APP_DATA):
            self.s.recv(hdr[0])
            return hdr[0], 0, None

        block_msg = self.s.recv(hdr[0])
        fmt = '!hhi' + str(hdr[0] - XSP_MSG_BLOCK_SIZE) + 's'
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
                                                        
    def __init__(self, sock):
        self.s = sock
    
    
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sess = xspSess(sock)
    sess.connect('localhost', 5006)
    
    my_msg = "This is a test"
    my_type = 0x34
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
    main()


