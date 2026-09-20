#!/usr/bin/env python3
"""Exercise the quiesce-only diagnostic path offline; never suspend anything."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()

setup = re.search(
    r"static int __init hibernate_quiesce_probe_setup\(char \*value\)\n\{.*?\n\}",
    source,
    re.S,
)
restore = re.search(
    r"int hibernation_restore\(int platform_mode\)\n\{.*?\n\}", source, re.S
)
load = re.search(r"static int load_image_and_restore\(void\)\n\{.*?\n\}", source, re.S)
assert setup and restore and load
assert '__setup("hibernate_quiesce_probe=", hibernate_quiesce_probe_setup);' in source

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define __init
#define HIBERNATION_TEST_RESUME 7
#define SF_PLATFORM_MODE 1
#define PMSG_QUIESCE 10
#define PMSG_RECOVER 11
#define pm_pr_dbg(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_notice(...) (markers++)
#define BUG_ON(condition) assert(!(condition))
static bool hibernate_readback_probe;
static bool hibernate_quiesce_probe;
static int hibernation_mode, suspend_error, bitmap_error, read_error;
static int locked, closes, reads, target_resumes, freed, bitmap_freed;
static int markers, swap_freed, console_prepared, console_suspended;
static int console_resumed, console_restored, recoveries;
static void pm_prepare_console(void) { console_prepared++; }
static void console_suspend_all(void) { console_suspended++; }
static int dpm_suspend_start(int message) {
  assert(message == PMSG_QUIESCE); return suspend_error;
}
static int resume_target_kernel(int platform) {
  assert(platform == SF_PLATFORM_MODE); target_resumes++; return -EAGAIN;
}
static void dpm_resume_end(int message) {
  assert(message == PMSG_RECOVER); recoveries++;
}
static void console_resume_all(void) { console_resumed++; }
static void pm_restore_console(void) { console_restored++; }
static void lock_device_hotplug(void) { assert(!locked); locked = 1; }
static void unlock_device_hotplug(void) { assert(locked); locked = 0; }
static int create_basic_memory_bitmaps(void) { return bitmap_error; }
static void swsusp_close(void) { closes++; }
static int swsusp_read(unsigned int *flags) { reads++; *flags = 3; return read_error; }
static void swsusp_free(void) { freed++; }
static void free_basic_memory_bitmaps(void) { bitmap_freed++; }
static void swsusp_free_test_image(void) { swap_freed++; }
'''
harness += setup.group(0) + "\n" + restore.group(0) + "\n" + load.group(0)
harness += r'''
static void reset_counts(void) {
  locked = closes = reads = target_resumes = freed = bitmap_freed = 0;
  markers = swap_freed = console_prepared = console_suspended = 0;
  console_resumed = console_restored = recoveries = 0;
}
int main(void) {
  assert(!hibernate_quiesce_probe);
  assert(hibernate_quiesce_probe_setup("0") == 0);
  assert(hibernate_quiesce_probe_setup("invalid") == 0);
  assert(!hibernate_quiesce_probe);
  assert(hibernate_quiesce_probe_setup("1") == 1);
  assert(hibernate_quiesce_probe);

  for (int enabled = 0; enabled < 2; enabled++) {
    for (int test_mode = 0; test_mode < 2; test_mode++) {
      hibernate_quiesce_probe = enabled;
      hibernate_readback_probe = false;
      hibernation_mode = test_mode ? HIBERNATION_TEST_RESUME : 0;
      suspend_error = bitmap_error = read_error = 0;
      reset_counts();
      int result = load_image_and_restore();
      assert(result == ((enabled && test_mode) ? -ECANCELED : -EAGAIN));
      assert(!locked && closes == 1 && reads == 1);
      assert(freed == 1 && bitmap_freed == 1);
      assert(swap_freed == (enabled && test_mode));
      assert(markers == (enabled && test_mode));
      assert(target_resumes == !(enabled && test_mode));
      assert(console_prepared == 1 && console_suspended == 1);
      assert(console_resumed == 1 && console_restored == 1 && recoveries == 1);
    }
  }

  hibernate_quiesce_probe = true;
  hibernation_mode = HIBERNATION_TEST_RESUME;
  suspend_error = -EIO;
  bitmap_error = read_error = 0;
  reset_counts();
  assert(load_image_and_restore() == -EIO);
  assert(!target_resumes && !markers);
  assert(recoveries == 1 && console_resumed == 1 && console_restored == 1);
  assert(swap_freed == 1 && freed == 1 && bitmap_freed == 1);

  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-quiesce-probe-") as directory:
    root = Path(directory)
    (root / "test.c").write_text(harness)
    subprocess.run(
        [
            "cc",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(root / "test.c"),
            "-o",
            str(root / "test"),
        ],
        check=True,
    )
    subprocess.run([str(root / "test")], check=True)

print("PASS: quiesce probe is opt-in/test-resume-only and unwinds before memory restore")
