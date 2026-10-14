AC_INIT(src/main.c)
AM_INIT_AUTOMAKE(aerod, 1.0.0)

AM_CONFIG_HEADER([config.h])

PKG_PROG_PKG_CONFIG
AC_PROG_INSTALL

AC_HEADER_STDC

AC_CHECK_HEADERS([net/if.h netdb.h arpa/inet.h netinet/ip.h netinet/icmp6.h linux/socket.h sys/utsname.h])
AC_CHECK_HEADERS([getopt.h])

AC_TYPE_PID_T
AC_FUNC_MALLOC

AC_CHECK_FUNCS([ioctl getopt_long syslog fcntl])

AC_MSG_CHECKING(if 1=2)
AC_MSG_RESULT(no)

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])

AC_ARG_ENABLE(
        [aero-mode],
        [AS_HELP_STRING([--enable-aero-mode], [enable aero-mode support @<:@default=no@:>@])],
        ,
        [enable_aero_mode="no"]
)

AC_ARG_ENABLE(
	[aero-dpdk],
	[AS_HELP_STRING([--enable-aero-dpdk], [enable aero-dpdk support @<:@default=no@:>@])],
	,
	[enable_aero_dpdk="no"]
)

PKG_CHECK_MODULES([DPDK],[libdpdk])
PKG_CHECK_MODULES([LIBJSON],[jansson])
test "${enable_aero_mode}" = "yes" && AC_DEFINE([AERO], [1], [Enable aero mode support])
test "${enable_aero_dpdk}" = "yes" && AC_DEFINE([AERO_DPDK], [1], [Enable aero dpdk support])
AC_SUBST([DPDK_CFLAGS]) 
AC_SUBST([DPDK_LIBS])
AC_OUTPUT


