AC_PREREQ([2.63])
AC_INIT([libxsp], [2.1], [xsp@crest.iu.edu])
AC_CONFIG_SRCDIR([include/config.h.in])
AM_CONFIG_HEADER([include/config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.9 dist-bzip2 subdir-objects foreign tar-ustar -Wall -Werror])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
LT_PREREQ([2.2.6])
LT_INIT

# keep track of modules we build, these are the default
xsp_modules="tcp auth_anon auth_pass auth_pass_file auth_trust logger_file logger_stdout logger_syslog"

AC_GNU_SOURCE
AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_AS

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h float.h inttypes.h malloc.h netdb.h netinet/in.h netinet/in_systm.h stdint.h stdlib.h string.h strings.h sys/param.h sys/queue.h sys/socket.h sys/time.h unistd.h values.h sys/sendfile.h machine/endian.h byteswap.h libkern/OSByteOrder.h linux/unistd.h splice.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen], DL_LIBS="$DL_LIBS -ldl")
AC_CHECK_LIB([m], [ceilf])
AC_CHECK_LIB([pthread], [pthread_mutex_init], THREAD_LIBS="$THREAD_LIBS -lpthread")
AC_CHECK_LIB([c_r], [pthread_mutex_init], THREAD_LIBS="$THREAD_LIBS -pthread -lc_r")
AC_CHECK_LIB([rt], [sem_init], use_rt=yes)

AM_CONDITIONAL(HAVE_LIBRT, test x$use_rt = xyes)

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([atoll atoq bzero gethostbyaddr gethostbyname gethostname gettimeofday inet_ntoa memset select socket strcasecmp strchr strdup strerror strlcat strlcpy strstr strtoul strtoll inet_ntop])

AH_TEMPLATE(SOCKLEN_T, The native socklen_t type used on the platform)
AC_DEFINE_UNQUOTED(SOCKLEN_T, socklen_t)

XSP_CONFIG_LIBUNIS([contrib/libunis-c], [libunis])

AC_ARG_ENABLE(debug,
	[  --enable-debug          turn on debugging],
	[CFLAGS="-g -O0 -Wall -DDEBUG ${CFLAGS}"],
	[CFLAGS="-O2 -Wall ${CFLAGS}"])

AC_ARG_ENABLE(netlogger,
	[  --enable-netlogger	  turn on netlogger],
	[CFLAGS="-g -Wall -DNETLOGGER ${CFLAGS}" NL_LIBS="-lnl -lnlio"])
		
AC_ARG_ENABLE(globus,
        [  --enable-globus     turn on globus],
        [CFLAGS="-DHAVE_GLOBUS ${CFLAGS}"])		

AC_ARG_ENABLE(client,
        AC_HELP_STRING([--enable-client], [enable xsp client [default=yes]]),
        [enable_client=$enableval],
        [enable_client=yes])

AM_CONDITIONAL(ENABLE_CLIENT, test x$enable_client = xyes)

AC_ARG_ENABLE(dragon,
        AC_HELP_STRING([--enable-dragon], [enable dragon support [default=no]]),
        [enable_dragon=$enableval],
        [enable_dragon=no])

AM_CONDITIONAL(ENABLE_DRAGON, test x$enable_dragon = xyes)

AC_ARG_ENABLE(libunis,
        AC_HELP_STRING([--enable-libunis], [enable libunis support [default=yes]]),
        [enable_libunis=$enableval],
        [enable_libunis=yes])

AM_CONDITIONAL(HAVE_LIBUNIS, test x$enable_libunis = xyes)

AC_ARG_ENABLE(blipp,
        AC_HELP_STRING([--enable-blipp], [enable BLIPP module [default=no]]),
        [enable_blipp=$enableval],
        [enable_blipp=no])

AM_CONDITIONAL(ENABLE_BLIPP, test x$enable_blipp = xyes)

AC_ARG_ENABLE(speedometer,
        AC_HELP_STRING([--enable-speedometer], [enable speed-o-meter module [default=no]]),
        [enable_speedometer=$enableval],
        [enable_speedometer=no])

AM_CONDITIONAL(ENABLE_SPEEDOMETER, test x$enable_speedometer = xyes)

AC_ARG_ENABLE(openflow,
        AC_HELP_STRING([--enable-openflow], [enable openflow module [default=no]]),
        [enable_openflow=$enableval],
        [enable_openflow=no])

AM_CONDITIONAL(ENABLE_OPENFLOW, test x$enable_openflow = xyes)

AC_ARG_ENABLE(floodlight,
        AC_HELP_STRING([--enable-floodlight], [enable floodlight (OF) module [default=no]]),
        [enable_floodlight=$enableval],
        [enable_floodlight=no])

AM_CONDITIONAL(ENABLE_FLOODLIGHT, test x$enable_floodlight = xyes)

AC_ARG_ENABLE(flange,
        AC_HELP_STRING([--enable-flange], [enable Flange module [default=no]]),
        [enable_flange=$enableval],
        [enable_flange=no])

AM_CONDITIONAL(ENABLE_FLANGE, test x$enable_flange = xyes)

AC_ARG_ENABLE(oess,
        AC_HELP_STRING([--enable-oess], [enable oess (AL2S) module [default=no]]),
        [enable_oess=$enableval],
        [enable_oess=no])

AM_CONDITIONAL(ENABLE_OESS, test x$enable_oess = xyes)

AC_ARG_ENABLE(linuxnet,
        AC_HELP_STRING([--enable-linuxnet], [enable linuxnet module [default=no]]),
        [enable_linuxnet=$enableval],
        [enable_linuxnet=no])

AM_CONDITIONAL(ENABLE_LINUXNET, test x$enable_linuxnet = xyes)

dnl Check for Web100
AC_ARG_ENABLE(web100, AC_HELP_STRING([--disable-web100], [disable web100 support (default is autodetect)]),,enable_web100=try)
if test "$enable_web100" != "no" ; then
  
	AC_PATH_PROG([web100_config], [web100-config], [no]) 
  
	AC_MSG_CHECKING(for Web100) 
  
	if test "$web100_config" != "no"; then
		WEB100_CFLAGS=`$web100_config --cflags`
		WEB100_LIBS=`$web100_config --libs`
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
		if test "$enable_web100" = "yes"; then
			AC_MSG_ERROR(web100 not found)
		fi
	fi 

	AC_SUBST(WEB100_CFLAGS)
	AC_SUBST(WEB100_LIBS)
fi

AM_CONDITIONAL(HAVE_WEB100, test "${WEB100_CFLAGS}" != "")

dnl Check for LibXML
AC_PATH_PROG([xml2_config], [xml2-config], [no]) 
  
AC_MSG_CHECKING(for LibXML) 
  
if test "$xml2_config" != "no"; then
	LIBXML_CFLAGS=`$xml2_config --cflags`
	LIBXML_LIBS=`$xml2_config --libs`
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi 

AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)

AM_CONDITIONAL(HAVE_LIBXML, test "${LIBXML_CFLAGS}" != "")

dnl End check for Web100

dnl Check for prctl
AH_TEMPLATE(HAVE_SYS_PRCTL_H, Whether or not prctl is available)

dnl Check for Netfilter
AH_TEMPLATE(HAVE_NETFILTER, Whether or not netfilter is used on the system)

AC_ARG_ENABLE(netfilter, [  --enable-netfilter      use netfilter for transparency [default=yes]], enable_netfilter=$enableval, enable_netfilter=try)

if test "$enable_netfilter" = "yes" -o "$enable_netfilter" = "try"; then
	AC_CHECK_HEADER(linux/netfilter.h, netfilter_header=yes, [], [ #include <netinet/in.h> ])
	if test "$netfilter_header" == "yes"; then
		AC_DEFINE(HAVE_NETFILTER)
		xsp_modules+=" transparent"
	elif test "$enable_netfilter" = "yes"; then
		AC_MSG_ERROR(netfilter.h not found)
	fi
fi

AM_CONDITIONAL(HAVE_NETFILTER, test "$netfilter_header" == "yes")
dnl End check for Netfilter

dnl Check for MySQL
AH_TEMPLATE(HAVE_MYSQL, Whether or not mysql is used on the system)

AC_ARG_WITH([mysql], [  --with-mysql[=DIR]          use mysql in DIR], [], [with_mysql=try])

if test "$with_mysql" != "no"
then	
	mysql_header="no"
	AC_CHECK_HEADER(mysql/mysql.h, mysql_header=yes, [], [])

	if test "$with_mysql" = "yes" -o "$with_mysql" = "try"; then
		AC_PATH_PROG(mysql_path, mysql_config)
		if test "$mysql_path" != ""; then
			MYSQL_LIBS=`$mysql_path --libs`
			MYSQL_CFLAGS=`$mysql_path --cflags`
		fi
	else
		if test -x $with_mysql/mysql_config; then
			MYSQL_LIBS=`$with_mysql/mysql_config --libs`
			MYSQL_CFLAGS=`$with_mysql/mysql_config --cflags`
		elif test -x $with_mysql/bin/mysql_config; then
			MYSQL_LIBS=`$with_mysql/bin/mysql_config --libs`
			MYSQL_CFLAGS=`$with_mysql/bin/mysql_config --cflags`
		fi
	fi

	if test "$MYSQL_CFLAGS" == "" -a "$mysql_header" == "no" ; then
		if test "$with_mysql" != "try"; then
		  if test "$mysql_header" == "no"; then
			  AC_MSG_ERROR(mysql.h not found)
			else
			  AC_MSG_ERROR(mysql_config not found or not executable)
			fi
		fi
	else
		xsp_modules+=" auth_pass_mysql"
	fi
fi

AM_CONDITIONAL(HAVE_MYSQL, test "$MYSQL_CFLAGS" != "")
AC_SUBST(MYSQL_CFLAGS)
AC_SUBST(MYSQL_LIBS)
AC_SUBST(HAVE_MYSQL)

dnl Check for SQLite
AH_TEMPLATE(HAVE_SQLITE, Whether or not sqlite is used on the system)

AC_MSG_CHECKING(for SQLite)
AC_ARG_WITH(sqlite, [  --with-sqlite[=DIR]          use sqlite in DIR], , with_sqlite=try)
if test "$with_sqlite" != "no"
then
	if test "$with_sqlite" == "yes" -o "$with_sqlite" == "try"
	then
		if test -f /usr/include/sqlite3.h; then
	 		SQLITE_LIBS="-lsqlite3"
 			SQLITE_CFLAGS=""
		elif test -f /usr/local/include/sqlite3.h; then
	 		SQLITE_LIBS="-lsqlite3"
 			SQLITE_CFLAGS=""
		else
			AC_MSG_RESULT(no)
			if test "$with_sqlite" == "yes"; then
				AC_ERROR(sqlite3.h not found)
			fi
		fi
	elif test "$with_sqlite" != "no"
	then
		if test -f $with_sqlite/include/sqlite3.h; then
			SQLITE_LIBS="-L$with_sqlite/lib -lsqlite3"
			SQLITE_CFLAGS="-I$with_sqlite/include"
		else
			AC_MSG_RESULT(no)
			AC_ERROR(sqlite3.h not found)
		fi
	fi
fi
 
if test "$SQLITE_LIBS" != ""
then
 	AC_MSG_RESULT(yes)
	xsp_modules+=" auth_pass_sqlite"
fi

AM_CONDITIONAL(HAVE_SQLITE, test "$SQLITE_LIBS" != "")
AC_SUBST(SQLITE_CFLAGS)
AC_SUBST(SQLITE_LIBS)

dnl Check for Photon
AC_MSG_CHECKING(for Photon)
AC_ARG_WITH(photon, [  --with-photon[=DIR]          use Photon in DIR], , with_photon=try)
if test "$with_photon" != "no"
then
	if test "$with_photon" == "yes" -o "$with_photon" == "try"
	then
		if test -f /usr/include/photon_xsp_forwarder.h; then
	 		PHOTON_LIBS="-lphoton"
 			PHOTON_CFLAGS=""
		elif test -f /usr/local/include/photon_xsp_forwarder.h; then
	 		PHOTON_LIBS="-lphoton"
 			PHOTON_CFLAGS=""
		else
			AC_MSG_RESULT(no)
			if test "$with_photon" == "yes"; then
				AC_ERROR(photon_xsp_forwarder.h not found)
			fi
		fi
	elif test "$with_photon" != "no"
	then
		if test -f $with_photon/include/photon_xsp_forwarder.h; then
			PHOTON_LIBS="-L$with_photon/lib -lphoton"
			PHOTON_CFLAGS="-I$with_photon/include"
		else
			AC_MSG_RESULT(no)
			AC_ERROR(photon_xsp_forwarder.h not found)
		fi
	fi
fi
 
if test "$PHOTON_LIBS" != ""
then
 	AC_MSG_RESULT(yes)
	xsp_modules+=" photon"
fi

AM_CONDITIONAL(ENABLE_PHOTON, test "$PHOTON_LIBS" != "")
AC_SUBST(PHOTON_CFLAGS)
AC_SUBST(PHOTON_LIBS)

dnl Check for libssh2
AC_ARG_ENABLE(ssh, AC_HELP_STRING([--disable-ssh],
		   [disable SSH2 connection support (default is autodetect)]),
		   [enable_ssh=$enableval],
		   [enable_ssh=try])

if test "$enable_ssh" != "no" ; then
        AH_TEMPLATE(HAVE_SSH, Whether or not libssh2 is installed on the system)
        AC_CHECK_LIB(ssh2, main, [
                AC_CHECK_HEADERS(libssh/ssh2.h, [
                        SSH_LIBS="-lssh2"
                        AC_SUBST(SSH_LIBS)
                        have_ssh=yes
                ])
        ])

        if test "$have_ssh" == "yes"; then
                AC_DEFINE(HAVE_SSH,, Build with SSH2 support)
        fi
fi

AM_CONDITIONAL(HAVE_SSH, test x$have_ssh = xyes)

dnl Check for RDMA (infiniband verbs)
AC_ARG_ENABLE(rdma, AC_HELP_STRING([--disable-rdma],
		    [disable RDMA (IBV) support (default is autodetect)]),
		    [enable_rdma=$enableval],
		    [enable_rdma=try])

if test "$enable_rdma" != "no" ; then
        AH_TEMPLATE(HAVE_RDMA, Whether or not ibverbs and rdma_cma is installed on the system)
        AC_CHECK_LIB(ibverbs, main, [
                AC_CHECK_HEADERS([infiniband/verbs.h rdma/rdma_cma.h], [
                        RDMA_LIBS="-libverbs -lrdmacm"
                        AC_SUBST(RDMA_LIBS)
                        have_rdma=yes
                ])
        ])

        if test "$have_rdma" == "yes"; then
                AC_DEFINE(HAVE_RDMA,, Build with RDMA support)
        fi
fi

AM_CONDITIONAL(HAVE_RDMA, test x$have_rdma = xyes)

dnl Check for OpenSSL
AC_ARG_ENABLE(openssl, AC_HELP_STRING([--disable-openssl],
		       [disable OpenSSL support (default is autodetect)]),
		       [enable_openssl=$enableval],
		       [enable_openssl=try])

if test "$enable_openssl" != "no" ; then
	AH_TEMPLATE(HAVE_OPENSSL, Whether or not OpenSSL is installed on the system)
	AC_CHECK_LIB(ssl, main, [
		AC_CHECK_HEADERS(openssl/ssl.h, [
			SSL_LIBS="-lssl -lcrypto"
			AC_SUBST(SSL_LIBS)
			have_openssl=yes
		])
	])

	if test "$have_openssl" == "yes"; then
		AC_DEFINE(HAVE_OPENSSL,, Build with OpenSSL support)
		xsp_modules+=" auth_ssl"
	fi
fi

AM_CONDITIONAL(HAVE_OPENSSL, test x$have_openssl = xyes)

dnl Check for curl
AC_ARG_ENABLE(curl, AC_HELP_STRING([--disable-curl], [disable curl support (default is autodetect)]),
		    [enable_curl=$enableval],
		    [enable_curl=try])

if test "$enable_curl" != "no" ; then
        AH_TEMPLATE(HAVE_CURL, Whether or not libcurl is installed on the system)
        AC_CHECK_LIB(curl, main, [
                AC_CHECK_HEADERS(curl/curl.h, [
                        CURL_LIBS="-lcurl"
                        AC_SUBST(CURL_LIBS)
                        have_curl=yes
        		])
        ])

        if test "$have_curl" == "yes"; then
                AC_DEFINE(HAVE_CURL,, Build with curl support)
        fi
fi

AM_CONDITIONAL(HAVE_CURL, test x$have_curl = xyes)

dnl Check for json
AC_ARG_ENABLE(json, AC_HELP_STRING([--disable-json], [disable json support (default is autodetect)]),
                    [enable_json=$enableval],
                    [enable_json=try])

if test "$enable_json" != "no" ; then
        AH_TEMPLATE(HAVE_JSON, Whether or not jansson (json lib) is installed on the system)
        AC_CHECK_LIB(jansson, main, [
                AC_CHECK_HEADERS(jansson.h, [
                        JSON_LIBS="-ljansson"
                        AC_SUBST(JSON_LIBS)
                        have_json=yes
                        ])
        ])

        if test "$have_json" == "yes"; then
                AC_DEFINE(HAVE_JSON,, Build with json support)
        fi
fi

AM_CONDITIONAL(HAVE_JSON, test x$have_json = xyes)

AC_ARG_ENABLE(terapaths,
        AC_HELP_STRING([--enable-terapaths], [enable terapaths module [default=no]]),
        [enable_terapaths=$enableval],
        [enable_terapaths=no])

AM_CONDITIONAL(ENABLE_TERAPATHS, test x$enable_terapaths = xyes -a x$have_openssl = xyes)

AC_ARG_ENABLE(oscars,
        AC_HELP_STRING([--enable-oscars], [enable oscars module [default=no]]),

        [enable_oscars=$enableval],
        [enable_oscars=no])

AM_CONDITIONAL(ENABLE_OSCARS, test x$enable_oscars = xyes -a x$have_openssl = xyes)

dnl Check for Globus                                                            
AM_CONDITIONAL(HAVE_GLOBUS, test "${GLOBUS_INCLUDES}" != "")
dnl End check for Globus        

dnl Check for libconfig (required)
AC_CHECK_HEADERS(libconfig.h, [
			CONFIG_LIBS="-lconfig"
			AC_SUBST(CONFIG_LIBS)
		],
		AC_MSG_ERROR([libconfig.h not found (try installing libconfig-dev)]))

XSP_DO_AM_CONDITIONALS

# Substitute the variables required for libtool linking of libhpx internally.
AC_SUBST(LIBXSP_CPPFLAGS)
AC_SUBST(LIBXSP_CFLAGS)
AC_SUBST(LIBXSP_CXXFLAGS)
AC_SUBST(LIBXSP_LDFLAGS)
AC_SUBST(LIBXSP_LIBADD)
AC_SUBST(LIBXSP_LIBS)

CONFIG_FILE=$sysconfdir/xspd.conf
AC_SUBST(CONFIG_FILE)
moduledir=$libdir/libxsp
AC_SUBST(moduledir)
AC_SUBST(THREAD_LIBS)
AC_SUBST(DL_LIBS)
AC_SUBST(NL_LIBS)

AC_OUTPUT(
	Makefile
	compat/Makefile
	contrib/Makefile
	libslabs/Makefile
	libradix/Makefile
	libmongo_client/Makefile
	libgsoap/Makefile
	src/libxsp/Makefile
	src/xspd/Makefile
	src/modules/Makefile
	src/libxsp_common/Makefile
	src/libxsp_modules/Makefile
	src/libxsp_modules/terapaths/Makefile
	src/libxsp_modules/oscars/Makefile
	src/libxsp_modules/monitoring/Makefile
	src/libxsp_modules/openflow/Makefile
	src/libxsp_client/Makefile
	src/libxsp_rdma/Makefile
	misc/subsys/Makefile
        scripts/Makefile
	test/Makefile
	)

# figure out what additional modules will be built
if test "$enable_oscars" = "yes" -a "$have_openssl" = "yes"; then
   xsp_modules+=" oscars"
fi
if test "$enable_terapaths" = "yes" -a "$have_openssl" = "yes"; then
   xsp_modules+=" terapaths"
fi
if test "$enable_blipp" = "yes"; then
   xsp_modules+=" blipp"
fi
if test "$enable_openflow" = "yes"; then
   xsp_modules+=" openflow"
fi
if test "$enable_floodlight" = "yes" -a "$have_curl" = "yes" -a "$have_json" = "yes"; then
   xsp_modules+=" floodlight"
fi
if test "$have_libunis" = "yes"; then
   xsp_modules+=" unis"
fi
if test "$have_libunis" = "yes" -a "$enable_oess" = "yes"; then
   xsp_modules+=" auth_cosign oess"
fi
if test "$enable_linuxnet" = "yes"; then
   xsp_modules+=" linuxnet"
fi
if test "$enable_dragon" = "yes"; then
   xsp_modules+=" dragon"
fi
if test "$enable_flange" = "yes"; then
   xsp_modules+=" flange"
fi

if test "$have_ssh" = "yes"; then
   ssh_yn="yes"
else
   ssh_yn="no"
fi

cat << EOF

Config files successfully generated by ./configure $ac_configure_args !

  Install prefix     : $prefix
  SSH client support : $ssh_yn
    
  Building modules:
`for m in $xsp_modules; do echo -e \\\t$m; done`

  To build and install, run:
     $ make
     $ make install

EOF
