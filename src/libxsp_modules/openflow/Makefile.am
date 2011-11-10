noinst_LIBRARIES = libofcontrol.a
noinst_PROGRAMS = openflow_client

libofcontrol_a_SOURCES = controller.c ctrl_table.c

openflow_client_SOURCES = openflow_client.c
openflow_client_LDADD = libofcontrol.a lib/libopenflow.a $(SSL_LIBS) $(THREAD_LIBS)

AUTOMAKE_OPTIONS = foreign -Wno-syntax subdir-objects
ACLOCAL_AMFLAGS = -I m4
#SUBDIRS = datapath
SUBDIRS =

AM_CPPFLAGS = $(SSL_CFLAGS) -g
AM_CPPFLAGS += -I $(srcdir)/include
AM_CPPFLAGS += -I $(srcdir)/lib

AM_CFLAGS = -Wstrict-prototypes

CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

ro_c = echo '/* -*- mode: c; buffer-read-only: t -*- */'

include lib/automake.mk
