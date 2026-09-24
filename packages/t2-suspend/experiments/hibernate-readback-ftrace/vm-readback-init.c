// SPDX-License-Identifier: GPL-2.0
/* Disposable QEMU/OVMF test of full image I/O and the readback abort hook. */

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

#define EFI_VARIABLE "/sys/firmware/efi/efivars/OmarchyT2HibernateStage-96234839-90c9-4cd5-97b2-7ba690f0af02"
#define MARKER_PARAMETER(name) "/sys/module/mba_hibernate_efi_ftrace_marker/parameters/" name
#define ABORT_PARAMETER(name) "/sys/module/mba_hibernate_readback_abort/parameters/" name
#define SWAP_DEVICE "/dev/vda"

static void finish(const char *result)
{
  printf("MBA_VM_READBACK_RESULT=%s\n", result);
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
  char value[128] = { 0 };
  ssize_t count = read_value(path, value, sizeof(value) - 1);

  return count > 0 && strcmp(value, expected) == 0;
}

static bool load_module(const char *path)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  int status;

  if (fd < 0)
    return false;
  status = syscall(SYS_finit_module, fd, "", 0);
  close(fd);
  return status == 0;
}

int main(void)
{
  static const unsigned char stage0[] = {
    7, 0, 0, 0, 'M', 'B', 'A', '9',
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0,
  };
  static const char vector[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
  char vendor[64] = { 0 };
  char command_line[2048] = { 0 };
  char resume_device[64];
  unsigned char marker[sizeof(stage0)] = { 0 };
  unsigned char swap_header[4096];
  struct stat device;
  ssize_t count;
  int fd;
  int state_error;

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
      strncmp(vendor, "QEMU", 4) || !strstr(command_line, "mba_vm_readback=1"))
    finish("refused-non-qemu");
  if (mkdir("/sys/firmware/efi/efivars", 0755) && errno != EEXIST)
    finish("no-efi-runtime");
  if (mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, NULL))
    finish("no-efivarfs");
  if (access(EFI_VARIABLE, F_OK) == 0)
    finish("stale-efi-variable");
  if (stat(SWAP_DEVICE, &device) || !S_ISBLK(device.st_mode))
    finish("missing-swap-device");
  if (swapon(SWAP_DEVICE, 0))
    finish("swapon-failed");
  if (snprintf(resume_device, sizeof(resume_device), "%u:%u\n",
               major(device.st_rdev), minor(device.st_rdev)) >= (int)sizeof(resume_device))
    finish("resume-device-overflow");
  if (!write_value("/sys/power/resume", resume_device, strlen(resume_device), 0) ||
      !selected("/sys/power/resume", resume_device) ||
      !selected("/sys/power/resume_offset", "0\n"))
    finish("resume-device-failed");
  if (!load_module("/marker.ko") || !load_module("/abort.ko"))
    finish("module-load-failed");
  if (!selected(ABORT_PARAMETER("armed"), "0\n") ||
      !selected(ABORT_PARAMETER("interceptions"), "0\n") ||
      !selected(MARKER_PARAMETER("arm_vector"), "0\n"))
    finish("module-not-disarmed");
  if (!write_value(EFI_VARIABLE, stage0, sizeof(stage0), O_CREAT | O_EXCL) ||
      !write_value(MARKER_PARAMETER("arm_vector"), vector, sizeof(vector) - 1, 0) ||
      !selected(MARKER_PARAMETER("arm_vector"), "1\n") ||
      !write_value(ABORT_PARAMETER("armed"), "Y\n", 2, 0) ||
      !selected(ABORT_PARAMETER("armed"), "1\n"))
    finish("module-arm-failed");
  if (!write_value("/sys/power/pm_test", "none\n", 5, 0) ||
      !write_value("/sys/power/disk", "test_resume\n", 12, 0))
    finish("pm-mode-failed");

  printf("MBA_VM_READBACK_ENTER\n");
  fd = open("/sys/power/state", O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    finish("state-open-failed");
  count = write(fd, "disk\n", 5);
  state_error = errno;
  close(fd);
  printf("MBA_VM_READBACK_RETURN rc=%zd errno=%d\n", count, state_error);
  if (count >= 0 || (state_error != ECANCELED && state_error != EIO))
    finish("transition-not-aborted");
  count = read_value(EFI_VARIABLE, marker, sizeof(marker));
  if (count != sizeof(marker) || memcmp(marker, stage0, 20) || marker[20] != 2 ||
      !selected(MARKER_PARAMETER("stage"), "2\n") ||
      !selected(MARKER_PARAMETER("last_efi_status"), "0\n") ||
      !selected(ABORT_PARAMETER("interceptions"), "1\n") ||
      !selected(ABORT_PARAMETER("armed"), "0\n"))
    finish("marker-or-abort-mismatch");
  fd = open(SWAP_DEVICE, O_RDONLY | O_CLOEXEC);
  if (fd < 0 || pread(fd, swap_header, sizeof(swap_header), 0) != sizeof(swap_header))
    finish("swap-header-read-failed");
  close(fd);
  if (memcmp(swap_header + sizeof(swap_header) - 10, "SWAPSPACE2", 10))
    finish("swap-signature-not-restored");
  printf("MBA_VM_READBACK_OBSERVED marker_stage=2 interceptions=1 normal_swap_signature=1\n");
  finish("pass");
}
