// SPDX-License-Identifier: GPL-2.0
/* Disposable QEMU/OVMF cold-boot check of the post-write EFI marker. */

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
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define EFI_VARIABLE "/sys/firmware/efi/efivars/OmarchyT2PostwriteStage-47a2fceb-87bc-4e58-8d83-23f62ffb3393"
#define ARM_PARAMETER "/sys/module/mba_hibernate_efi_postwrite_marker/parameters/arm_vector"
#define SWAP_DEVICE "/dev/vda"

static const unsigned char stage0[] = {
  7, 0, 0, 0, 'M', 'B', 'P', 'W',
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
  0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0,
};
static const char vector[] =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";

static void finish(const char *result)
{
  printf("MBA_VM_POSTWRITE_RESULT=%s\n", result);
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

static bool load_module(void)
{
  int fd = open("/marker.ko", O_RDONLY | O_CLOEXEC);
  int status;

  if (fd < 0)
    return false;
  status = syscall(SYS_finit_module, fd, "", 0);
  close(fd);
  return status == 0;
}

int main(void)
{
  char command_line[2048] = { 0 };
  char vendor[64] = { 0 };
  char resume_device[64];
  unsigned char marker[sizeof(stage0)] = { 0 };
  struct stat device;
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
      strncmp(vendor, "QEMU", 4) || !strstr(command_line, "mba_vm_postwrite=1"))
    finish("refused-non-qemu");
  if (mkdir("/sys/firmware/efi/efivars", 0755) && errno != EEXIST)
    finish("no-efi-runtime");
  if (mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, NULL))
    finish("no-efivarfs");

  if (strstr(command_line, "mba_vm_postwrite_verify=1")) {
    count = read_value(EFI_VARIABLE, marker, sizeof(marker));
    if (count != sizeof(marker) || memcmp(marker, stage0, sizeof(stage0) - 1) ||
        marker[sizeof(marker) - 1] != 3)
      finish("marker-not-stage-3-after-cold-boot");
    printf("MBA_VM_POSTWRITE_OBSERVED=3\n");
    finish("pass");
  }

  if (access(EFI_VARIABLE, F_OK) == 0)
    finish("stale-efi-variable");
  if (stat(SWAP_DEVICE, &device) || !S_ISBLK(device.st_mode) ||
      swapon(SWAP_DEVICE, 0))
    finish("swap-unavailable");
  if (snprintf(resume_device, sizeof(resume_device), "%u:%u\n",
               major(device.st_rdev), minor(device.st_rdev)) >= (int)sizeof(resume_device) ||
      !write_value("/sys/power/resume", resume_device, strlen(resume_device), 0))
    finish("resume-device-failed");
  if (!load_module() ||
      !write_value(EFI_VARIABLE, stage0, sizeof(stage0), O_CREAT | O_EXCL) ||
      !write_value(ARM_PARAMETER, vector, sizeof(vector) - 1, 0) ||
      !write_value("/sys/power/pm_test", "none\n", 5, 0) ||
      !write_value("/sys/power/disk", "shutdown\n", 9, 0))
    finish("arm-or-mode-failed");

  printf("MBA_VM_POSTWRITE_ENTER\n");
  fd = open("/sys/power/state", O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    finish("state-open-failed");
  count = write(fd, "disk\n", 5);
  close(fd);
  printf("MBA_VM_POSTWRITE_UNEXPECTED_RETURN=%zd\n", count);
  finish("unexpected-return");
}
