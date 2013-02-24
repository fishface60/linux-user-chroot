AC_PREREQ([2.63])
AC_INIT([linux-user-chroot], [2013.1], [walters@verbum.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign no-define tar-ustar no-dist-gzip dist-xz])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_SYS_LARGEFILE

AC_PROG_CC
AM_PROG_CC_C_O

changequote(,)dnl
if test "x$GCC" = "xyes"; then
  WARN_CFLAGS="-Wall -Werror=missing-prototypes"
fi
changequote([,])dnl
AC_SUBST(WARN_CFLAGS)

# Initialize libtool
LT_PREREQ([2.2.4])
LT_INIT([disable-static])

AC_CHECK_HEADER([linux/securebits.h],
	        [AC_DEFINE([HAVE_LINUX_SECUREBITS_H], [1],
		 [Define to 1 if we have securebits.h])])

AC_ARG_ENABLE(documentation,
              AC_HELP_STRING([--enable-documentation],
                             [build documentation]),,
              enable_documentation=yes)
AM_CONDITIONAL(BUILD_DOCUMENTATION, test x$enable_documentation = xyes)

AC_ARG_ENABLE(newnet-helper,
              AC_HELP_STRING([--enable-newnet-helper],
                             [build newnet helper (see README.newnet)]),,
              enable_newnet_helper=no)
AM_CONDITIONAL(BUILD_NEWNET_HELPER, test x$enable_newnet_helper = xyes)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
