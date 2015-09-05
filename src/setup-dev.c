/* 
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
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sched.h>

#include "setup-dev.h"
#include "cleanup.h"

#define N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))

int
setup_dev (const char  *dest_devdir)
{
  _cleanup_fd_close_ int src_fd = -1;
  _cleanup_fd_close_ int dest_fd = -1;
  struct stat stbuf;
  unsigned int i;
  static const char *const devnodes[] = { "null", "zero", "full", "random", "urandom", "tty" };

  src_fd = openat (AT_FDCWD, "/dev", O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC | O_NOCTTY);
  if (src_fd == -1)
    return -1;

  if (mount ("tmpfs", dest_devdir,
	     "tmpfs", MS_MGC_VAL | MS_PRIVATE | MS_NOSUID, "mode=0755") < 0)
    return -1;

  dest_fd = openat (AT_FDCWD, dest_devdir, O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC | O_NOCTTY);
  if (dest_fd == -1)
    return -1;

  for (i = 0; i < N_ELEMENTS (devnodes); i++)
    {
      const char *nodename = devnodes[i];
      
      if (fstatat (src_fd, nodename, &stbuf, 0) == -1)
	return -1;
      if (mknodat (dest_fd, nodename, stbuf.st_mode, stbuf.st_rdev) != 0)
        return -1;
      if (fchmodat (dest_fd, nodename, stbuf.st_mode, 0) != 0)
        return -1;
    }

  if (symlinkat ("/proc/self/fd/0", dest_fd, "stdin") < 0)
    return -1;
  if (symlinkat ("/proc/self/fd/1", dest_fd, "stdout") < 0)
    return -1;
  if (symlinkat ("/proc/self/fd/2", dest_fd, "stderr") < 0)
    return -1;

  return 0;
}

