// SPDX-License-Identifier: GPL-2.0
/* Disposable QEMU/OVMF guest entry point; never install or execute on the host. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define VARIABLE "/sys/firmware/efi/efivars/OmarchyT2FtraceEntryProbe-9f946df0-1b9c-4af5-97e8-bc322a728241"
#define PARAMETER(name) "/sys/module/mba_hibernate_efi_ftrace_marker/parameters/" name

static void finish(const char *result)
{
  printf("MBA_VM_RESULT=%s\n", result);
  fflush(stdout);
  sync();
  reboot(RB_POWER_OFF);
  _exit(1);
}

static ssize_t read_value(const char *path, void *buffer, size_t size)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  ssize_t count;

  if (fd < 0)
    return -1;
  count = read(fd, buffer, size);
  close(fd);
  return count;
}

static bool write_value(const char *path, const void *buffer, size_t size, int flags)
{
  int fd = open(path, O_WRONLY | O_CLOEXEC | flags, 0600);
  ssize_t count;

  if (fd < 0)
    return false;
  count = write(fd, buffer, size);
  close(fd);
  return count == (ssize_t)size;
}

static bool selected(const char *path, const char *expected)
{
  char buffer[64] = { 0 };
  ssize_t count = read_value(path, buffer, sizeof(buffer) - 1);

  return count > 0 && strcmp(buffer, expected) == 0;
}

int main(void)
{
  static const unsigned char stage0[] = {
    7, 0, 0, 0, 'M', 'B', 'F', 'E',
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0,
  };
  static const char nonce[] = "00112233445566778899aabb\n";
  char vendor[64] = { 0 };
  char command_line[2048] = { 0 };
  unsigned char marker[sizeof(stage0)] = { 0 };
  ssize_t count;
  int fd;

  setvbuf(stdout, NULL, _IONBF, 0);
  mkdir("/proc", 0755);
  mkdir("/sys", 0755);
  mkdir("/dev", 0755);
  if (mount("proc", "/proc", "proc", 0, NULL) ||
      mount("sysfs", "/sys", "sysfs", 0, NULL) ||
      mount("devtmpfs", "/dev", "devtmpfs", 0, NULL))
    finish("mount-failed");

  if (read_value("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor) - 1) <= 0 ||
      read_value("/proc/cmdline", command_line, sizeof(command_line) - 1) <= 0 ||
      strncmp(vendor, "QEMU", 4) ||
      !strstr(command_line, "mba_vm_ftrace=1"))
    finish("refused-non-qemu");

  if (mkdir("/sys/firmware/efi/efivars", 0755) && errno != EEXIST)
    finish("no-efi-runtime");
  if (mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, NULL))
    finish("no-efivarfs");
  if (access(VARIABLE, F_OK) == 0)
    finish("stale-efi-variable");

  fd = open("/module.ko", O_RDONLY | O_CLOEXEC);
  if (fd < 0 || syscall(SYS_finit_module, fd, "", 0))
    finish("module-load-failed");
  close(fd);
  if (!write_value(VARIABLE, stage0, sizeof(stage0), O_CREAT | O_EXCL))
    finish("efi-stage0-failed");
  if (!write_value(PARAMETER("entry_nonce"), nonce, sizeof(nonce) - 1, 0) ||
      !selected(PARAMETER("entry_armed"), "Y\n"))
    finish("module-arm-failed");

  if (!write_value("/sys/power/pm_test", "freezer\n", 8, 0) ||
      !write_value("/sys/power/disk", "shutdown\n", 9, 0))
    finish("pm-mode-failed");
  printf("MBA_VM_FREEZER_ENTER\n");
  if (!write_value("/sys/power/state", "disk\n", 5, 0))
    finish("freezer-transition-failed");
  printf("MBA_VM_FREEZER_RETURN\n");

  count = read_value(VARIABLE, marker, sizeof(marker));
  printf("MBA_VM_OBSERVED marker_length=%zd marker_stage=%u\n", count, marker[20]);
  if (count != sizeof(marker) || memcmp(marker, stage0, 20) || marker[20] != 1 ||
      !selected(PARAMETER("entry_stage"), "1\n") ||
      !selected(PARAMETER("entry_efi_status"), "0\n") ||
      !selected(PARAMETER("entry_armed"), "N\n"))
    finish("marker-mismatch");
  finish("pass");
}
