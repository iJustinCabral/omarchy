#!/usr/bin/env python3
"""Exercise the running-kernel quiesce return probe offline."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
entry = re.search(r"static int dpm_suspend_start_entry\(.*?\n\}", source, re.S)
returned = re.search(r"static int dpm_suspend_start_return\(.*?\n\}", source, re.S)
assert entry and returned
assert '.kp.symbol_name = "dpm_suspend_start"' in source
assert "if (armed)\n    return -EPERM;" in source

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#define PM_EVENT_QUIESCE 8
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define pr_notice(...) (markers++)
struct pt_regs { unsigned long argument; long result; };
struct kretprobe_instance { char *data; };
struct quiesce_probe_state { bool intercept; };
static bool armed;
static unsigned int interceptions;
static int markers;
static unsigned long regs_get_kernel_argument(struct pt_regs *regs, int index) {
  assert(index == 0); return regs->argument;
}
static long regs_return_value(struct pt_regs *regs) { return regs->result; }
static void regs_set_return_value(struct pt_regs *regs, long value) { regs->result = value; }
'''
harness += entry.group(0) + "\n" + returned.group(0)
harness += r'''
int main(void) {
  struct quiesce_probe_state state = {0};
  struct kretprobe_instance instance = {.data = (char *)&state};
  struct pt_regs regs = {.argument = PM_EVENT_QUIESCE, .result = 0};

  assert(dpm_suspend_start_entry(&instance, &regs) == 0 && !state.intercept);
  armed = true;
  regs.argument = 1;
  assert(dpm_suspend_start_entry(&instance, &regs) == 0 && !state.intercept);
  regs.argument = PM_EVENT_QUIESCE;
  assert(dpm_suspend_start_entry(&instance, &regs) == 0 && state.intercept);

  regs.result = -EIO;
  assert(dpm_suspend_start_return(&instance, &regs) == 0);
  assert(regs.result == -EIO && interceptions == 0 && markers == 1);

  regs.result = 0;
  assert(dpm_suspend_start_return(&instance, &regs) == 0);
  assert(regs.result == -ECANCELED && interceptions == 1 && markers == 2);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-quiesce-kretprobe-") as directory:
  root = Path(directory)
  (root / "test.c").write_text(harness)
  subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-O2", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)

print("PASS: quiesce return probe is armed and event scoped; success alone is canceled")
