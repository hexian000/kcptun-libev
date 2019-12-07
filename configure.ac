#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([kcptun-libev], [1.0.0-beta], , , [https://github.com/hexian000/kcptun-libev])
AC_CONFIG_SRCDIR([aead.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB([ev], [ev_run])
#AC_CHECK_LIB([m], [fmod])
#AC_CHECK_LIB([pthread], [pthread_create])
#AC_CHECK_LIB([sodium], [sodium_init])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime floor gettimeofday localtime_r memmove memset pow socket sqrt strerror strrchr strtoul])

AC_OUTPUT
