AM_CPPFLAGS = -I@top_srcdir@/src/libxsp        \
	      -I@top_srcdir@/include           \
	      -I@top_srcdir@/compat            \
	      -I@top_srcdir@/libconfig

noinst_LTLIBRARIES = libxsp.la

noinst_HEADERS = libxsp.h                      \
	         libxsp_hop.h                  \
	         libxsp_block.h                \
		 libxsp_path.h                 \
	  	 libxsp_net_path.h             \
		 libxsp_session.h              \
		 libxsp_protocol_settings.h    \
		 libxsp_proto_binary_v0.h      \
		 libxsp_proto_binary_v1.h      \
		 libxsp_proto.c libxsp_proto.h \
		 libxsp_sec.h 

libxsp_la_SOURCES = libxsp.c                   \
		    libxsp_proto.c             \
		    libxsp_hop.c               \
		    libxsp_block.c             \
		    libxsp_path.c              \
		    libxsp_net_path.c          \
		    libxsp_session.c           \
		    libxsp_protocol_settings.c \
		    libxsp_proto_binary_v0.c   \
		    libxsp_proto_binary_v1.c

libxsp_la_LIBADD  = @top_builddir@/compat/libcompat.la
