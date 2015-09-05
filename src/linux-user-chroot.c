/* -*- mode: c; tab-width: 2; indent-tabs-mode: nil -*-
 *
 * linux-user-chroot: A setuid program for non-root users to safely create containers
 *
 * This program is primarily intended for use by build systems.
 *
 * Let me elaborate on "safely": I believe that this program, when
 * deployed as setuid on a typical "distribution" such as RHEL or
 * Debian, does not, even when used in combination with typical
 * software installed on that distribution, allow privilege
 * escalation.  See the README for more details.
 *
 * Copyright 2011,2012,2015 Colin Walters <walters@verbum.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>

#include "setup-seccomp.h"
#include "setup-dev.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS	38
#endif

/* Totally arbitrary; we're just trying to mitigate somewhat against
 * DoS attacks.  In practice uids can typically spawn multiple
 * processes, so this isn't effective.  What is needed is for the
 * kernel to understand we're creating bind mounts on behalf of a
 * given uid.  Most likely this will happen if the kernel obsoletes
 * this tool by allowing processes with PR_SET_NO_NEW_PRIVS to create
 * private mounts or chroot.
 */
#define MAX_BIND_MOUNTS 1024

static void fatal (const char *message, ...) __attribute__ ((noreturn)) __attribute__ ((format (printf, 1, 2)));
static void fatal_errno (const char *message) __attribute__ ((noreturn));

static void
fatal (const char *fmt,
       ...)
{
  va_list args;
  
  va_start (args, fmt);

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  
  va_end (args);
  exit (1);
}

static void
fatal_errno (const char *message)
{
  perror (message);
  exit (1);
}

typedef enum {
  MOUNT_SPEC_BIND,
  MOUNT_SPEC_READONLY,
  MOUNT_SPEC_PROCFS,
  MOUNT_SPEC_DEVAPI
} MountSpecType;

typedef struct _MountSpec MountSpec;
struct _MountSpec {
  MountSpecType type;

  const char *source;
  const char *dest;
  
  MountSpec *next;
};

static MountSpec *
reverse_mount_list (MountSpec *mount)
{
  MountSpec *prev = NULL;

  while (mount)
    {
      MountSpec *next = mount->next;
      mount->next = prev;
      prev = mount;
      mount = next;
    }

  return prev;
}

/**
 * fsuid_chdir:
 * @uid: User id we should use
 * @path: Path string
 *
 * Like chdir() except we use the filesystem privileges of @uid.
 */
static int
fsuid_chdir (uid_t       uid,
             const char *path)
{
  int errsv;
  int ret;
  /* Note we don't check errors here because we can't, basically */
  (void) setfsuid (uid);
  ret = chdir (path);
  errsv = errno;
  (void) setfsuid (0);
  errno = errsv;
  return ret;
}

static inline int
raw_clone (unsigned long flags, void *child_stack)
{
#if defined(__s390__) || defined(__CRIS__)
  /* On s390 and cris the order of the first and second arguments
   * of the raw clone() system call is reversed. */
  return (int) syscall(__NR_clone, child_stack, flags);
#else
  return (int) syscall(__NR_clone, flags, child_stack);
#endif
}

int
main (int      argc,
      char   **argv)
{
  const char *argv0;
  const char *chroot_dir;
  const char *chdir_target = "/";
  const char *program;
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  int after_mount_arg_index;
  unsigned int n_mounts = 0;
  const unsigned int max_mounts = MAX_BIND_MOUNTS;
  char **program_argv;
  MountSpec *bind_mounts = NULL;
  MountSpec *bind_mount_iter;
  int unshare_ipc = 0;
  int unshare_net = 0;
  int unshare_pid = 0;
  int seccomp_profile_version = -1;
  int clone_flags = 0;
  int child_status = 0;
  pid_t child;

  if (argc <= 0)
    return 1;

  argv0 = argv[0];
  argc--;
  argv++;

  if (argc < 1)
    fatal ("ROOTDIR argument must be specified");

  after_mount_arg_index = 0;
  while (after_mount_arg_index < argc)
    {
      const char *arg = argv[after_mount_arg_index];
      MountSpec *mount = NULL;

      if (n_mounts >= max_mounts)
        fatal ("Too many mounts (maximum of %u)", n_mounts);
      n_mounts++;

      if (strcmp (arg, "--help") == 0)
        {
          printf ("%s\n", "See \"man linux-user-chroot\"");
          exit (0);
        }
      else if (strcmp (arg, "--version") == 0)
        {
          printf ("%s\n", PACKAGE_STRING);
          exit (0);
        }
      else if (strcmp (arg, "--mount-bind") == 0)
        {
          if ((argc - after_mount_arg_index) < 3)
            fatal ("--mount-bind takes two arguments");

          mount = malloc (sizeof (MountSpec));
          mount->type = MOUNT_SPEC_BIND;
          mount->source = argv[after_mount_arg_index+1];
          mount->dest = argv[after_mount_arg_index+2];
          mount->next = bind_mounts;
          
          bind_mounts = mount;
          after_mount_arg_index += 3;
        }
      else if (strcmp (arg, "--mount-readonly") == 0)
        {
          MountSpec *mount;

          if ((argc - after_mount_arg_index) < 2)
            fatal ("--mount-readonly takes one argument");

          mount = malloc (sizeof (MountSpec));
          mount->type = MOUNT_SPEC_READONLY;
          mount->source = NULL;
          mount->dest = argv[after_mount_arg_index+1];
          mount->next = bind_mounts;
          
          bind_mounts = mount;
          after_mount_arg_index += 2;
        }
      else if (strcmp (arg, "--mount-proc") == 0)
        {
          MountSpec *mount;

          if ((argc - after_mount_arg_index) < 2)
            fatal ("--mount-proc takes one argument");

          mount = malloc (sizeof (MountSpec));
          mount->type = MOUNT_SPEC_PROCFS;
          mount->source = NULL;
          mount->dest = argv[after_mount_arg_index+1];
          mount->next = bind_mounts;
          
          bind_mounts = mount;
          after_mount_arg_index += 2;
        }
      else if (strcmp (arg, "--mount-devapi") == 0)
        {
          MountSpec *mount;

          if ((argc - after_mount_arg_index) < 2)
            fatal ("--mount-devapi takes one argument");

          mount = malloc (sizeof (MountSpec));
          mount->type = MOUNT_SPEC_DEVAPI;
          mount->source = NULL;
          mount->dest = argv[after_mount_arg_index+1];
          mount->next = bind_mounts;
          
          bind_mounts = mount;
          after_mount_arg_index += 2;
        }
      else if (strcmp (arg, "--unshare-ipc") == 0)
        {
          unshare_ipc = 1;
          after_mount_arg_index += 1;
        }
      else if (strcmp (arg, "--unshare-pid") == 0)
        {
          unshare_pid = 1;
          after_mount_arg_index += 1;
        }
      else if (strcmp (arg, "--unshare-net") == 0)
        {
          unshare_net = 1;
          after_mount_arg_index += 1;
        }
      else if (strcmp (arg, "--chdir") == 0)
        {
          if ((argc - after_mount_arg_index) < 2)
            fatal ("--chdir takes one argument");

          chdir_target = argv[after_mount_arg_index+1];
          after_mount_arg_index += 2;
        }
      else if (strcmp (arg, "--seccomp-profile-version") == 0)
        {
          if ((argc - after_mount_arg_index) < 2)
            fatal ("--seccomp-profile-version takes one argument");

          seccomp_profile_version = atoi(argv[after_mount_arg_index+1]);
          after_mount_arg_index += 2;
        }
      else
        break;
    }
        
  bind_mounts = reverse_mount_list (bind_mounts);

  if ((argc - after_mount_arg_index) < 2)
    fatal ("usage: %s [--unshare-ipc] [--unshare-pid] [--unshare-net] [--mount-proc DIR] [--mount-readonly DIR] [--mount-bind SOURCE DEST] [--chdir DIR] ROOTDIR PROGRAM ARGS...", argv0);
  chroot_dir = argv[after_mount_arg_index];
  program = argv[after_mount_arg_index+1];
  program_argv = argv + after_mount_arg_index + 1;

  if (getresgid (&rgid, &egid, &sgid) < 0)
    fatal_errno ("getresgid");
  if (getresuid (&ruid, &euid, &suid) < 0)
    fatal_errno ("getresuid");

  if (rgid == 0)
    rgid = ruid;

  /* CLONE_NEWNS makes it so that when we create bind mounts below,
   * we're only affecting our children, not the entire system.  This
   * way it's harmless to bind mount e.g. /proc over an arbitrary
   * directory.
   */
  clone_flags = SIGCHLD | CLONE_NEWNS;
  /* CLONE_NEWIPC and CLONE_NEWUTS are avenues of communication that
   * might leak outside the container; any IPC can be done by setting
   * up a bind mount and using files or sockets there, if desired.
   */
  if (unshare_ipc)
    clone_flags |= (CLONE_NEWIPC | CLONE_NEWUTS);
  /* CLONE_NEWPID helps ensure random build or test scripts don't kill
   * processes outside of the container.
   */
  if (unshare_pid)
    clone_flags |= CLONE_NEWPID;

  /* Isolated networking */
  if (unshare_net)
    clone_flags |= CLONE_NEWNET;

  if ((child = raw_clone (clone_flags, NULL)) < 0)
    fatal_errno ("clone");

  if (child == 0)
    {
      /*
       * First, we attempt to use PR_SET_NO_NEW_PRIVS, since it does
       * exactly what we want - ensures the child can not gain any
       * privileges, even attempting to execute setuid binaries.
       *
       * http://lwn.net/Articles/504879/
       *
       * Following the belt-and-suspenders model, we also make a
       * MS_NOSUID bind mount below.  I don't think this is strictly
       * necessary, but at least we doubly ensure we're not going to
       * be executing any setuid binaries from the host's /.  It
       * doesn't help if there are any other mount points with setuid
       * binaries, but `PR_SET_NO_NEW_PRIVS` fixes that.
       */
      if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        fatal_errno ("prctl (PR_SET_NO_NEW_PRIVS)");

      /* This is necessary to undo the damage "sandbox" creates on Fedora
       * by making / a shared mount instead of private.  This isn't
       * totally correct because the targets for our bind mounts may still
       * be shared, but really, Fedora's sandbox is broken.
       */
      if (mount (NULL, "/", "none", MS_PRIVATE | MS_REC, NULL) < 0)
        fatal_errno ("mount(/, MS_PRIVATE | MS_REC)");

      /* I had thought that SECBIT_NOROOT was enough to be safe, but Serge E. Hallyn
       * pointed out that setuid binaries still change uid to 0.  So let's just
       * disallow them at the rootfs level.
       */
      if (mount (NULL, "/", "none", MS_PRIVATE | MS_REMOUNT | MS_NOSUID, NULL) < 0)
        fatal_errno ("mount(/, MS_PRIVATE | MS_REC | MS_NOSUID)");

      /* Now let's set up our bind mounts */
      for (bind_mount_iter = bind_mounts; bind_mount_iter; bind_mount_iter = bind_mount_iter->next)
        {
          char *dest;
          
          asprintf (&dest, "%s%s", chroot_dir, bind_mount_iter->dest);
          
          if (bind_mount_iter->type == MOUNT_SPEC_READONLY)
            {
              if (mount (dest, dest,
                         NULL, MS_BIND | MS_PRIVATE, NULL) < 0)
                fatal_errno ("mount (MS_BIND)");
              if (mount (dest, dest,
                         NULL, MS_BIND | MS_PRIVATE | MS_REMOUNT | MS_RDONLY, NULL) < 0)
                fatal_errno ("mount (MS_BIND | MS_RDONLY)");
            }
          else if (bind_mount_iter->type == MOUNT_SPEC_BIND)
            {
              if (fsuid_chdir (ruid, bind_mount_iter->source) < 0)
                fatal ("Couldn't chdir to bind mount source");
              if (mount (".", dest,
                         NULL, MS_BIND | MS_PRIVATE, NULL) < 0)
                fatal_errno ("mount (MS_BIND)");
            }
          else if (bind_mount_iter->type == MOUNT_SPEC_PROCFS)
            {
              if (mount ("proc", dest,
                         "proc", MS_MGC_VAL | MS_PRIVATE, NULL) < 0)
                fatal_errno ("mount (\"proc\")");
            }
          else if (bind_mount_iter->type == MOUNT_SPEC_DEVAPI)
            {
              if (setup_dev (dest) < 0)
                fatal_errno ("setting up devapi");
            }
          else
            assert (0);
          free (dest);
        }

      if (fsuid_chdir (ruid, chroot_dir) < 0)
        fatal_errno ("chdir");

      if (mount (".", ".", NULL, MS_BIND | MS_PRIVATE, NULL) < 0)
        fatal_errno ("mount (MS_BIND)");

      /* Only move if we're not actually just using / */
      if (strcmp (chroot_dir, "/") != 0)
        {
          if (mount (chroot_dir, "/", NULL, MS_MOVE, NULL) < 0)
            fatal_errno ("mount (MS_MOVE)");

          if (chroot (".") < 0)
            fatal_errno ("chroot");
        }
      
      /* Switch back to the uid of our invoking process.  These calls are
       * irrevocable - see setuid(2) */
      if (setgid (rgid) < 0)
        fatal_errno ("setgid");
      if (setuid (ruid) < 0)
        fatal_errno ("setuid");

      if (chdir (chdir_target) < 0)
        fatal_errno ("chdir");

      /* Add the seccomp filters just before we exec */
      if (seccomp_profile_version == 0)
        setup_seccomp_v0 ();
      else if (seccomp_profile_version == -1)
        ;
      else
        fatal ("Unknown --seccomp-profile-version");

      if (execvp (program, program_argv) < 0)
        fatal_errno ("execv");
    }

  /* Let's also setuid back in the parent - there's no reason to stay uid 0, and
   * it's just better to drop privileges. */
  if (setgid (rgid) < 0)
    fatal_errno ("setgid");
  if (setuid (ruid) < 0)
    fatal_errno ("setuid");

  /* Kind of lame to sit around blocked in waitpid, but oh well. */
  if (waitpid (child, &child_status, 0) < 0)
    fatal_errno ("waitpid");
  
  if (WIFEXITED (child_status))
    return WEXITSTATUS (child_status);
  else
    return 1;
}
