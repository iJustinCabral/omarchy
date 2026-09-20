#!/usr/bin/env python3
"""Exercise the patched kernel function offline; never load or suspend anything."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
function = re.search(r'static int load_image_and_restore\(void\)\n\{.*?\n\}', source, re.S)
setup = re.search(r'static int __init hibernate_readback_probe_setup\(char \*value\)\n\{.*?\n\}', source, re.S)
assert function and setup
assert '__setup("hibernate_readback_probe=", hibernate_readback_probe_setup);' in source
harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define __init
#define HIBERNATION_TEST_RESUME 7
#define SF_PLATFORM_MODE 1
#define pm_pr_dbg(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_notice(...) (markers++)
static bool hibernate_readback_probe;
static int hibernation_mode, bitmap_error, read_error;
static int locked, closes, reads, restores, freed, bitmap_freed, markers;
static void lock_device_hotplug(void) { assert(!locked); locked = 1; }
static void unlock_device_hotplug(void) { assert(locked); locked = 0; }
static int create_basic_memory_bitmaps(void) { return bitmap_error; }
static void swsusp_close(void) { closes++; }
static int swsusp_read(unsigned int *flags) { reads++; *flags = 3; return read_error; }
static int hibernation_restore(unsigned int platform) {
  assert(platform == SF_PLATFORM_MODE); assert(closes == 1); restores++; return -EAGAIN;
}
static void swsusp_free(void) { freed++; }
static void free_basic_memory_bitmaps(void) { bitmap_freed++; }
'''
harness += setup.group(0) + '\n' + function.group(0)
harness += r'''
int main(void) {
  assert(!hibernate_readback_probe);
  assert(hibernate_readback_probe_setup("0") == 0);
  assert(hibernate_readback_probe_setup("invalid") == 0);
  assert(!hibernate_readback_probe);
  assert(hibernate_readback_probe_setup("1") == 1);
  assert(hibernate_readback_probe);
  for (int enabled = 0; enabled < 2; enabled++) {
    for (int test_mode = 0; test_mode < 2; test_mode++) {
      for (int failure = 0; failure < 3; failure++) {
        hibernate_readback_probe = enabled;
        hibernation_mode = test_mode ? HIBERNATION_TEST_RESUME : 0;
        bitmap_error = failure == 1 ? -ENOMEM : 0;
        read_error = failure == 2 ? -EIO : 0;
        locked = closes = reads = restores = freed = bitmap_freed = markers = 0;
        int result = load_image_and_restore();
        assert(!locked && closes == 1);
        if (bitmap_error) {
          assert(result == -ENOMEM && !reads && !restores && !freed && !bitmap_freed && !markers);
        } else {
          assert(reads == 1 && freed == 1 && bitmap_freed == 1);
          if (read_error) {
            assert(result == -EIO && !restores && !markers);
          } else if (enabled && test_mode) {
            assert(result == -ECANCELED && !restores && markers == 1);
          } else {
            assert(result == -EAGAIN && restores == 1 && !markers);
          }
        }
      }
    }
  }
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='t2-readback-probe-') as directory:
  root = Path(directory)
  (root / 'test.c').write_text(harness)
  subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(root / 'test.c'),
                  '-o', str(root / 'test')], check=True)
  subprocess.run([str(root / 'test')], check=True)
print('PASS: readback-only probe is opt-in/test-resume-only; errors and cleanup preserved')
