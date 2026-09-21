#!/usr/bin/env python3
"""Exercise the post-relocation return-probe decision offline."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
entry = re.search(r"static int relocate_entry\(.*?\n\}", source, re.S)
returned = re.search(r"static int relocate_return\(.*?\n\}", source, re.S)
assert entry and returned
assert '.kp.symbol_name = "relocate_restore_code"' in source
assert "if (armed)\n    return -EPERM;" in source

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define pr_notice(...) (markers++)
struct pt_regs { long result; };
struct kretprobe_instance { char *data; };
struct post_relocate_probe_state { bool intercept; };
static bool armed;
static unsigned int interceptions;
static int markers;
static long regs_return_value(struct pt_regs *regs) { return regs->result; }
static void regs_set_return_value(struct pt_regs *regs, long value) { regs->result = value; }
'''
harness += entry.group(0) + "\n" + returned.group(0)
harness += r'''
int main(void) {
  struct post_relocate_probe_state state = {0};
  struct kretprobe_instance instance = {.data = (char *)&state};
  struct pt_regs regs = {.result = 0};

  assert(relocate_entry(&instance, &regs) == 0 && !state.intercept);
  assert(relocate_return(&instance, &regs) == 0);
  assert(regs.result == 0 && interceptions == 0 && markers == 0);

  armed = true;
  assert(relocate_entry(&instance, &regs) == 0 && state.intercept);
  regs.result = -ENOMEM;
  assert(relocate_return(&instance, &regs) == 0);
  assert(regs.result == -ENOMEM && interceptions == 0 && markers == 1);

  regs.result = 0;
  assert(relocate_entry(&instance, &regs) == 0 && state.intercept);
  assert(relocate_return(&instance, &regs) == 0);
  assert(regs.result == -ECANCELED && interceptions == 1 && markers == 2);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-post-relocate-kretprobe-") as directory:
  root = Path(directory)
  (root / "test.c").write_text(harness)
  subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-O2", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)

print("PASS: post-relocation probe preserves failures and cancels only armed success")
