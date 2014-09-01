#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([tomahawk], [1.2.0], [xiche@verizon.net])
AC_CONFIG_SRCDIR([tomahawk.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pcap],[pcap_open_offline])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa memmove memset select socket strerror strtol strtoul])

if test -n "$GCC"; then
    CFLAGS="$CFLAGS -Wall"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
