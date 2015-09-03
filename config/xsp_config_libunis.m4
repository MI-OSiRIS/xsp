# -*- autoconf -*---------------------------------------------------------------
# XSP_CONFIG_LIBUNIS([src-path])
#
# Make sure that a compatible installation of libunis can be found.
#
# Sets
#   enable_libunis
#   with_libunis
#   have_libunis
#   build_libunis
#
# Appends
#   LIBXSP_CPPFLAGS
#   LIBXSP_LIBADD
#   LIBXSP_LIBS
#   XSP_PC_PRIVATE_PKGS
#   XSP_PC_PRIVATE_LIBS
#
# Defines
#   HAVE_LIBUNIS
# ------------------------------------------------------------------------------
AC_ARG_VAR([LIBUNIS_CARGS], [Additional arguments passed to libunis contrib])

AC_DEFUN([_HAVE_LIBUNIS], [
  AC_DEFINE([HAVE_LIBUNIS], [1], [libunis support available])
  have_libunis=yes
])

AC_DEFUN([_XSP_CONFIG_LIBUNIS], [
 contrib=$1
 
 # configure and build the included libunis library
 XSP_MERGE_STATIC_SHARED([LIBUNIS_CARGS])
 ACX_CONFIGURE_DIR([$contrib], [$contrib], ["$LIBUNIS_CARGS"])
 _HAVE_LIBUNIS
 LIBXSP_CPPFLAGS="$LIBXSP_CPPFLAGS -I\$(top_srcdir)/$1/include"
 LIBXSP_LIBADD="$LIBXSP_LIBADD \$(top_builddir)/$1/src/libunis-c.la"
 XSP_PC_PRIVATE_PKGS="$XSP_PC_PRIVATE_PKGS -lunis-c"
])

AC_DEFUN([_XSP_PKG_LIBUNIS], [
 pkg=$1
 
 # search for a libunis pkg-config package
 PKG_CHECK_MODULES([LIBUNIS], [$pkg],
   [_HAVE_LIBUNIS
    LIBXSP_CFLAGS="$LIBXSP_CFLAGS $LIBUNIS_CFLAGS"
    LIBXSP_LIBS="$LIBXSP_LIBS $LIBUNIS_LIBS"
    XSP_PC_PRIVATE_PKGS="$XSP_PC_PRIVATE_PKGS $pkg"])
])

AC_DEFUN([_XSP_LIB_LIBUNIS], [
 # look for libunis in the path
 AC_CHECK_HEADER([libunis.h],
   [AC_CHECK_LIB([libunis], [libunis_init],
     [_HAVE_LIBUNIS
      LIBXSP_LIBS="$LIBXSP_LIBS -llibunis"
      XSP_PC_PRIVATE_LIBS="$XSP_PC_PRIVATE_LIBS -llibunis"])])
])

AC_DEFUN([_XSP_WITH_LIBUNIS], [
 pkg=$1
 
 # handle the with_libunis option, if enable_libunis is selected
 AS_CASE($with_libunis,
   [no], [AC_MSG_ERROR([--enable-libunis=$enable_libunis excludes --without-libunis])],
   
   # contrib means we should just go ahead and build the library
   [contrib], [build_libunis=yes],
   [yes], [build_libunis=yes],
   
   # system means that we look for a library in the system path, or a
   # default-named pkg-config package
   [system], [_XSP_LIB_LIBUNIS
              AS_IF([test "x$with_libunis" != xyes], [_XSP_PKG_LIBUNIS($pkg)])],

   # any other string is interpreted as a custom pkg-config package
   [_XSP_PKG_LIBUNIS($with_libunis)])
])

AC_DEFUN([XSP_CONFIG_LIBUNIS], [
 contrib=$1
 pkg=$2
 
 # Allow the user to override the way we try and find libunis.
 AC_ARG_ENABLE([libunis],
   [AS_HELP_STRING([--enable-libunis],
                   [Enable the libunis network @<:@default=no@:>@])],
   [], [enable_libunis=no])

 AC_ARG_WITH(libunis,
   [AS_HELP_STRING([--with-libunis{=contrib,system,PKG}],
                   [How we find libunis @<:@default=contrib@:>@])],
   [], [with_libunis=contrib])

 AS_IF([test "x$enable_libunis" != xno], [_XSP_WITH_LIBUNIS($pkg)])
 AS_IF([test "x$build_libunis" == xyes], [_XSP_CONFIG_LIBUNIS($contrib)])
])
