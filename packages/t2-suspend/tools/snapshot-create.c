/* SPDX-License-Identifier: MIT
 * Laboratory boundary test: create and discard a kernel snapshot.
 * Never save, restore, or power off. Closing /dev/snapshot cancels the image
 * and thaws processes, including on any ioctl error.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/suspend_ioctls.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static int create_and_discard(__kernel_loff_t *size)
{
  int fd;
  int created = -1;
  int error = 0;

  if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
    return errno;
  sync();
  fd = open("/dev/snapshot", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    error = errno;
    munlockall();
    return error;
  }

  /* No logging, allocation, or filesystem I/O while userspace is frozen. */
  if (ioctl(fd, SNAPSHOT_FREEZE, 0) < 0)
    error = errno;
  else if (ioctl(fd, SNAPSHOT_CREATE_IMAGE, &created) < 0)
    error = errno;
  else if (created != 1)
    error = EPROTO;
  else if (ioctl(fd, SNAPSHOT_GET_IMAGE_SIZE, size) < 0)
    error = errno;
  else if (*size <= 0)
    error = ENODATA;

  /* release frees the image and thaws; never retry close after an error. */
  if (close(fd) < 0 && !error)
    error = errno;
  munlockall();
  return error;
}

int main(int argc, char **argv)
{
  __kernel_loff_t size = 0;
  int error;

  if (argc != 2 || strcmp(argv[1], "--create-and-discard")) {
    fprintf(stderr, "Usage: %s --create-and-discard\n", argv[0]);
    return 2;
  }
  if (geteuid() != 0) {
    fprintf(stderr, "This hardware diagnostic requires root.\n");
    return 1;
  }
  error = create_and_discard(&size);
  if (error) {
    fprintf(stderr, "Snapshot creation/discard failed: %s\n", strerror(error));
    return 1;
  }
  printf("Snapshot created and discarded: %lld bytes; no image restore or power-off attempted.\n",
         (long long)size);
  return 0;
}
