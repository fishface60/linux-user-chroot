/* -*- mode: c; tab-width: 2; indent-tabs-mode: nil -*-
 *
 * newnet-suid: Allow allocating a new empty network namespace as
 * non-root.  This program is just a workaround for the kernel
 * requiring large-order allocations (e.g. 4 pages) per network
 * namespace.
 *
 * Copyright 2012 Colin Walters <walters@verbum.org>
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>

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


int
main (int      argc,
      char   **argv)
{
  const char *program;
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  char **program_argv;
  int child_status = 0;
  pid_t child;

  if (argc <= 0)
    return 1;

  argc--;
  argv++;

  if (argc < 1)
    fatal ("PROGRAM argument must be specified");

  program = argv[0];
  program_argv = argv;

  if (getresgid (&rgid, &egid, &sgid) < 0)
    fatal_errno ("getresgid");
  if (getresuid (&ruid, &euid, &suid) < 0)
    fatal_errno ("getresuid");

  if (rgid == 0)
    rgid = ruid;

  if ((child = syscall (__NR_clone, SIGCHLD | CLONE_NEWNET, NULL)) < 0)
    perror ("clone");

  if (child == 0)
    {
      /* Switch back to the uid of our invoking process.  These calls are
       * irrevocable - see setuid(2) */
      if (setgid (rgid) < 0)
        fatal_errno ("setgid");
      if (setuid (ruid) < 0)
        fatal_errno ("setuid");

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
