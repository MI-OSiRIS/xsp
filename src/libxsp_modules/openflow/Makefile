INCLUDE_DIR = -I./include
LIB_DIR = -L. -L./lib

#LIBS = ./lib/command-line.o \
#       ./lib/hash.o \
#       ./lib/queue.o \
#       ./lib/util.o \
#       ./lib/daemon.o \
#       ./lib/learning-switch.o \
#       ./lib/rconn.o \
#       ./lib/vconn.o \
#       ./lib/fault.o \
#       ./lib/ofpbuf.o \
#       ./lib/stp.o \
#       ./lib/vlog.o \
#       ./lib/flow.o \
#       ./lib/poll-loop.o \
#       ./lib/timeval.o \
#       ./lib/vlog-socket.o

test: test.c libcontroller.so
	gcc -Wall $(INCLUDE_DIR) $(LIB_DIR) -lcontroller -lopenflow -lpthread test.c -o test

libcontroller.so: controller.c
	gcc -Wall $(INCLUDE_DIR) -fPIC -c controller.c
	gcc -shared -Wl,-soname,libcontroller.so.1 -o libcontroller.so.1.0 controller.o
	ln -sf libcontroller.so.1.0 libcontroller.so
	ln -sf libcontroller.so.1.0 libcontroller.so.1

clean:
	rm *.o
	rm *.so*
	rm test
