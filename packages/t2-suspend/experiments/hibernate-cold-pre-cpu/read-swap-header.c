// SPDX-License-Identifier: GPL-2.0
// Read only: never opens a device for writing or changes a swap signature.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define COLD_PAGE_SIZE 4096

static int cold_decimal(const char *text, uint64_t *value)
{
  uint64_t result = 0;
  const unsigned char *cursor = (const unsigned char *)text;

  if (!*cursor || (*cursor == '0' && cursor[1]))
    return -1;
  while (*cursor) {
    unsigned int digit;
    if (*cursor < '0' || *cursor > '9')
      return -1;
    digit = *cursor++ - '0';
    if (result > (UINT64_MAX - digit) / 10)
      return -1;
    result = result * 10 + digit;
  }
  *value = result;
  return 0;
}

static const char *cold_classify(const unsigned char page[COLD_PAGE_SIZE])
{
  const unsigned char *signature = page + COLD_PAGE_SIZE - 10;

  if (!memcmp(signature, "S1SUSPEND\0", 10))
    return "PENDING";
  // Existing flags/map fields are historical after swsusp_check resets magic.
  if (!memcmp(signature, "SWAPSPACE2", 10) && page[1024] == 1 &&
      page[1025] == 0 && page[1026] == 0 && page[1027] == 0)
    return "NORMAL";
  return NULL;
}

static int cold_read_header(const char *device, uint64_t pages,
                            unsigned int expected_major, unsigned int expected_minor,
                            unsigned char page[COLD_PAGE_SIZE])
{
  struct stat opened, named;
  uint64_t size;
  uint64_t offset;
  char *resolved;
  int descriptor;
  int result = -1;
  ssize_t count;

  if (pages > ((uint64_t)INT64_MAX - COLD_PAGE_SIZE) / COLD_PAGE_SIZE)
    return -1;
  offset = pages * COLD_PAGE_SIZE;
  // /dev/mapper/root is normally a symlink; open only its resolved block node.
  resolved = realpath(device, NULL);
  if (!resolved)
    return -1;
  descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  free(resolved);
  if (descriptor < 0)
    return -1;
  if (fstat(descriptor, &opened) || !S_ISBLK(opened.st_mode) ||
      major(opened.st_rdev) != expected_major || minor(opened.st_rdev) != expected_minor)
    goto Close;
  if (stat(device, &named) || !S_ISBLK(named.st_mode) ||
      named.st_rdev != opened.st_rdev)
    goto Close;
  if (ioctl(descriptor, BLKGETSIZE64, &size) || offset > size ||
      size - offset < COLD_PAGE_SIZE)
    goto Close;
  count = pread(descriptor, page, COLD_PAGE_SIZE, (off_t)offset);
  // Interrupted or short reads are inconclusive; do not retry a partial read.
  if (count != COLD_PAGE_SIZE)
    goto Close;
  result = 0;
Close:
  if (close(descriptor))
    result = -1;
  return result;
}

int main(int argc, char **argv)
{
  uint64_t pages, major_value, minor_value;
  unsigned char page[COLD_PAGE_SIZE];
  const char *classification;

  if (argc != 5 || strcmp(argv[1], "/dev/mapper/root") ||
      cold_decimal(argv[2], &pages) || !pages ||
      cold_decimal(argv[3], &major_value) || major_value > UINT_MAX ||
      cold_decimal(argv[4], &minor_value) || minor_value > UINT_MAX)
    return 2;
  if (cold_read_header(argv[1], pages, (unsigned int)major_value,
                       (unsigned int)minor_value, page))
    return 3;
  classification = cold_classify(page);
  if (!classification)
    return 4;
  if (printf("%s\n", classification) < 0)
    return 5;
  return 0;
}
