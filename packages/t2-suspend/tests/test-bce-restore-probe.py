#!/usr/bin/env python3
"""Offline test for the optional restore-abort diagnostic, never loads a module."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
match = re.search(r'static int t2bce_image_restore\(struct device \*dev\)\n\{.*?\n\}', source, re.S)
assert match, 'missing diagnostic restore wrapper'
assert 'module_param(hibernate_restore_abort, bool, 0444)' in source
assert '.restore = t2bce_image_restore' in source
for operation, callback in [('suspend', 't2bce_suspend'), ('resume', 't2bce_resume'),
                            ('freeze', 't2bce_suspend'), ('thaw', 't2bce_resume')]:
  assert re.search(r'\.' + operation + r'\s*=\s*' + callback, source)

harness = '''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
struct device { int unused; };
static bool hibernate_restore_abort;
static int calls;
static int t2bce_resume(struct device *dev) { assert(dev); calls++; return -EAGAIN; }
#define pr_err(...) ((void)0)
'''
harness += match.group(0)
harness += '''
int main(void) {
  struct device dev = {0};
  assert(t2bce_image_restore(&dev) == -EAGAIN);
  assert(calls == 1);
  hibernate_restore_abort = true;
  assert(t2bce_image_restore(&dev) == -ECANCELED);
  assert(calls == 1);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='t2-bce-probe-test-') as directory:
  root = Path(directory)
  (root / 'test.c').write_text(harness)
  subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(root / 'test.c'),
                  '-o', str(root / 'test')], check=True)
  subprocess.run([str(root / 'test')], check=True)
print('PASS: default restore forwards status; opt-in abort never invokes firmware resume')
