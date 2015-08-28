/* Seccomp rules, originally from xdg-app, which looks clearly influenced
 * by sandstorm-io/sandstorm/src/standstorm/supervisor.c++
 *
 * Copyright (C) 2014 Alexander Larsson
 * Copyright (C) 2015 Colin Walters <walters@verbum.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"
/* Core libc/linux-headers stuff */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sched.h>

/* Seccomp */
#include <seccomp.h>

#define N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))

#include "setup-seccomp.h"

static void
die_with_error (const char *format, ...)
{
  va_list args;
  int errsv;

  errsv = errno;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, ": %s\n", strerror (errsv));

  exit (1);
}

static void
die (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, "\n");

  exit (1);
}

static void
die_oom (void)
{
  die ("Out of memory");
}

/*
 * We're calling this filter "v0" - any future additions or changes
 * should become new versions.  This helps ensure backwards
 * compatibility for build systems.
 */
void
setup_seccomp_v0 (void)
{
  scmp_filter_ctx seccomp;
  /**** BEGIN NOTE ON CODE SHARING
   *
   * There are today a number of different Linux container
   * implementations.  That will likely continue for long into the
   * future.  But we can still try to share code, and it's important
   * to do so because it affects what library and application writers
   * can do, and we should support code portability between different
   * container tools.
   *
   * This syscall blacklist is copied from xdg-app, which was in turn
   * clearly influenced by the Sandstorm.io blacklist.
   *
   * If you make any changes here, I suggest sending the changes along
   * to other sandbox maintainers.  Using the libseccomp list is also
   * an appropriate venue:
   * https://groups.google.com/forum/#!topic/libseccomp
   *
   * A non-exhaustive list of links to container tooling that might
   * want to share this blacklist:
   *
   *  https://github.com/sandstorm-io/sandstorm
   *    in src/sandstorm/supervisor.c++
   *  http://cgit.freedesktop.org/xdg-app/xdg-app/
   *    in lib/xdg-app-helper.c
   *  https://git.gnome.org/browse/linux-user-chroot
   *    in src/setup-seccomp.c
   *
   **** END NOTE ON CODE SHARING
   */
  struct {
    int scall;
    struct scmp_arg_cmp *arg;
  } syscall_blacklist[] = {
    /* Block dmesg */
    {SCMP_SYS(syslog)},
    /* Useless old syscall */
    {SCMP_SYS(uselib)},
    /* Don't allow you to switch to bsd emulation or whatnot */
    {SCMP_SYS(personality)},
    /* Don't allow disabling accounting */
    {SCMP_SYS(acct)},
    /* 16-bit code is unnecessary in the sandbox, and modify_ldt is a
       historic source of interesting information leaks. */
    {SCMP_SYS(modify_ldt)},
    /* Don't allow reading current quota use */
    {SCMP_SYS(quotactl)},

    /* Scary VM/NUMA ops */
    {SCMP_SYS(move_pages)},
    {SCMP_SYS(mbind)},
    {SCMP_SYS(get_mempolicy)},
    {SCMP_SYS(set_mempolicy)},
    {SCMP_SYS(migrate_pages)},

    /* Don't allow subnamespace setups: */
    {SCMP_SYS(unshare)},
    {SCMP_SYS(mount)},
    {SCMP_SYS(pivot_root)},
    {SCMP_SYS(clone), &SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)},

    /* Utterly terrifying profiling operations */
    {SCMP_SYS(perf_event_open)}
  };
  /* Blacklist all but unix, inet, inet6 and netlink */
  int socket_family_blacklist[] = {
    AF_AX25,
    AF_IPX,
    AF_APPLETALK,
    AF_NETROM,
    AF_BRIDGE,
    AF_ATMPVC,
    AF_X25,
    AF_ROSE,
    AF_DECnet,
    AF_NETBEUI,
    AF_SECURITY,
    AF_KEY,
    AF_NETLINK + 1, /* Last gets CMP_GE, so order is important */
  };
  int i, r;
  struct utsname uts;

  seccomp = seccomp_init(SCMP_ACT_ALLOW);
  if (!seccomp)
    return die_oom ();

  /* Add in all possible secondary archs we are aware of that
   * this kernel might support. */
#if defined(__i386__) || defined(__x86_64__)
  r = seccomp_arch_add (seccomp, SCMP_ARCH_X86);
  if (r < 0 && r != -EEXIST)
    die_with_error ("Failed to add x86 architecture to seccomp filter");

  r = seccomp_arch_add (seccomp, SCMP_ARCH_X86_64);
  if (r < 0 && r != -EEXIST)
    die_with_error ("Failed to add x86_64 architecture to seccomp filter");

  r = seccomp_arch_add (seccomp, SCMP_ARCH_X32);
  if (r < 0 && r != -EEXIST)
    die_with_error ("Failed to add x32 architecture to seccomp filter");
#endif

  /* TODO: Should we filter the kernel keyring syscalls in some way?
   * We do want them to be used by desktop apps, but they could also perhaps
   * leak system stuff or secrets from other apps.
   */

  for (i = 0; i < N_ELEMENTS (syscall_blacklist); i++)
    {
      int scall = syscall_blacklist[i].scall;
      if (syscall_blacklist[i].arg)
        r = seccomp_rule_add (seccomp, SCMP_ACT_ERRNO(EPERM), scall, 1, *syscall_blacklist[i].arg);
      else
        r = seccomp_rule_add (seccomp, SCMP_ACT_ERRNO(EPERM), scall, 0);
      if (r < 0 && r == -EFAULT /* unknown syscall */)
        die_with_error ("Failed to block syscall %d", scall);
    }

  /* Socket filtering doesn't work on x86 */
  if (uname (&uts) == 0 && strcmp (uts.machine, "i686") != 0)
    {
      for (i = 0; i < N_ELEMENTS (socket_family_blacklist); i++)
	{
	  int family = socket_family_blacklist[i];
	  if (i == N_ELEMENTS (socket_family_blacklist) - 1)
	    r = seccomp_rule_add (seccomp, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_GE, family));
	  else
	    r = seccomp_rule_add (seccomp, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_EQ, family));
	  if (r < 0)
	    die_with_error ("Failed to block socket family %d", family);
	}
    }

  r = seccomp_load (seccomp);
  if (r < 0)
    die_with_error ("Failed to install seccomp audit filter: ");

  seccomp_release (seccomp);
}
