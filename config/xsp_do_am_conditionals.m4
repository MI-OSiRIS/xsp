# -*- autoconf -*---------------------------------------------------------------
# XSP_DO_AM_CONDITIONALS
#
# Set automake conditionals for use in Makefile.am settings, HWLOC-style.
# ------------------------------------------------------------------------------
AC_DEFUN([XSP_DO_AM_CONDITIONALS], [

 AM_CONDITIONAL([OS_LINUX], [[[[ "x$host_os" = xlinux* ]]]])
 AM_CONDITIONAL([OS_DARWIN], [[[[ "x$host_os" = xdarwin* ]]]])
 AM_CONDITIONAL([CPU_X86_64], [test "x$host_cpu" = xx86_64])
 AM_CONDITIONAL([CPU_ARM], [test "x$host_cpu" = xarmv7l])
 AM_CONDITIONAL([CPU_AARCH64], [test "x$host_cpu" = xaarch64])

 AM_CONDITIONAL([GNU_PE_ENV], [test "x$hpx_pe_env" = xGNU])
 AM_CONDITIONAL([CRAY_PE_ENV], [test "x$hpx_pe_env" = xCRAY])
 AM_CONDITIONAL([PGI_PE_ENV], [test "x$hpx_pe_env" = xPGI])
 AM_CONDITIONAL([INTEL_PE_ENV], [test "x$hpx_pe_env" = xINTEL])

 AM_CONDITIONAL([BUILD_LIBUNIS], [test "x$build_libunis" == xyes])

 AM_CONDITIONAL([HAVE_LIBUNIS], [test "x$have_libunis" == xyes])
])
