#!/usr/bin/env python3
"""Exercise the post-syscore return-probe decision offline."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
entry = re.search(r"static int syscore_suspend_entry\(.*?\n\}", source, re.S)
returned = re.search(r"static int syscore_suspend_return\(.*?\n\}", source, re.S)
assert entry and returned
assert '.kp.symbol_name = "syscore_suspend"' in source
assert "if (armed)\n    return -EPERM;" in source

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define pr_info(...) (markers++)
#define pr_notice(...) (markers++)
struct pt_regs { long result; };
struct kretprobe_instance { char *data; };
struct post_syscore_probe_state { bool intercept; };
static bool armed;
static unsigned int successful_calls;
static unsigned int interceptions;
static int markers;
static int resumes;
static long regs_return_value(struct pt_regs *regs) { return regs->result; }
static void regs_set_return_value(struct pt_regs *regs, long value) { regs->result = value; }
static void syscore_resume(void) { resumes++; }
'''
harness += entry.group(0) + "\n" + returned.group(0)
harness += r'''
int main(void) {
  struct post_syscore_probe_state state = {0};
  struct kretprobe_instance instance = {.data = (char *)&state};
  struct pt_regs regs = {.result = 0};

  assert(syscore_suspend_entry(&instance, &regs) == 0 && !state.intercept);
  assert(syscore_suspend_return(&instance, &regs) == 0);
  assert(regs.result == 0 && successful_calls == 0 && interceptions == 0);

  armed = true;
  assert(syscore_suspend_entry(&instance, &regs) == 0 && state.intercept);
  regs.result = -EIO;
  assert(syscore_suspend_return(&instance, &regs) == 0);
  assert(regs.result == -EIO && successful_calls == 0 && interceptions == 0);

  regs.result = 0;
  assert(syscore_suspend_entry(&instance, &regs) == 0 && state.intercept);
  assert(syscore_suspend_return(&instance, &regs) == 0);
  assert(regs.result == 0 && successful_calls == 1 && interceptions == 0);

  regs.result = 0;
  assert(syscore_suspend_entry(&instance, &regs) == 0 && state.intercept);
  assert(syscore_suspend_return(&instance, &regs) == 0);
  assert(regs.result == -ECANCELED && successful_calls == 2 && interceptions == 1 && resumes == 1);

  regs.result = 0;
  assert(syscore_suspend_entry(&instance, &regs) == 0 && state.intercept);
  assert(syscore_suspend_return(&instance, &regs) == 0);
  assert(regs.result == 0 && successful_calls == 3 && interceptions == 1 && resumes == 1);
  assert(markers == 3);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-post-syscore-kretprobe-") as directory:
  root = Path(directory)
  (root / "test.c").write_text(harness)
  subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-O2", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)

print("PASS: post-syscore probe passes creation and cancels only restore success")
