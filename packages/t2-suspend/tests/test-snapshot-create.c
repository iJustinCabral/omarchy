/* Offline fault injection; no real PM or snapshot operations. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/suspend_ioctls.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static int phase, failure, closes, unlocks;
static int fake_mlockall(int flags)
{
  assert(phase++ == 0);
  assert(flags == (MCL_CURRENT | MCL_FUTURE));
  if (failure == 1) { errno = ENOMEM; return -1; }
  return 0;
}
static void fake_sync(void) { assert(phase++ == 1); }
static int fake_open(const char *name, int flags)
{
  assert(phase++ == 2);
  assert(!strcmp(name, "/dev/snapshot"));
  assert(flags == (O_RDONLY | O_CLOEXEC));
  if (failure == 2) { errno = EBUSY; return -1; }
  return 42;
}
static int fake_ioctl(int fd, unsigned long request, void *argument)
{
  assert(fd == 42);
  assert(!closes);
  if (phase == 3) assert(request == SNAPSHOT_FREEZE);
  else if (phase == 4) assert(request == SNAPSHOT_CREATE_IMAGE);
  else if (phase == 5) assert(request == SNAPSHOT_GET_IMAGE_SIZE);
  else assert(0);
  phase++;
  if (failure == phase - 1) { errno = EIO; return -1; }
  if (request == SNAPSHOT_CREATE_IMAGE)
    *(int *)argument = failure == 6 ? 0 : 1;
  if (request == SNAPSHOT_GET_IMAGE_SIZE)
    *(__kernel_loff_t *)argument = failure == 7 ? 0 : 4096;
  return 0;
}
static int fake_close(int fd)
{
  assert(fd == 42);
  assert(!closes++);
  if (failure == 8) { errno = EIO; return -1; }
  return 0;
}
static int fake_munlockall(void) { unlocks++; return 0; }

#define mlockall fake_mlockall
#define sync fake_sync
#define open fake_open
#define ioctl fake_ioctl
#define close fake_close
#define munlockall fake_munlockall
#define main snapshot_tool_main
#include "../tools/snapshot-create.c"
#undef main

int main(void)
{
  for (failure = 0; failure <= 8; failure++) {
    __kernel_loff_t size = 0;
    int result;
    phase = closes = unlocks = 0;
    result = create_and_discard(&size);
    assert((result == 0) == (failure == 0));
    assert(closes == (failure != 1 && failure != 2));
    assert(unlocks == (failure != 1));
    if (!failure) assert(size == 4096);
  }
  puts("PASS: snapshot creation order, cancellation, and all failure cleanup paths");
  return 0;
}
