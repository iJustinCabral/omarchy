#!/usr/bin/env python3
"""Check the pre-image-write ftrace probe and pinned hibernation error path."""

from pathlib import Path
import re
import sys


module = Path(sys.argv[1]).read_text()
replacement = re.search(r"static int notrace mba_hibernate_skip_image_write\(unsigned int flags\)\n\{.*?\n\}", module, re.S)
hook = re.search(r"static void notrace mba_hibernate_pre_write_hook\(.*?\n\}", module, re.S)
assert replacement and hook
assert '#define TARGET_FUNCTION "swsusp_write"' in module
assert "return -ECANCELED;" in replacement.group(0)
assert "interceptions" in replacement.group(0)
assert "if (READ_ONCE(armed))" in hook.group(0)
assert "ftrace_regs_set_instruction_pointer" in hook.group(0)
assert "if (armed)\n    return -EPERM;" in module
assert "FTRACE_OPS_FL_IPMODIFY" in module

if len(sys.argv) > 2:
  hibernate = Path(sys.argv[2]).read_text()
  snapshot = hibernate.index("error = hibernation_snapshot(hibernation_mode == HIBERNATION_PLATFORM);")
  image_write = hibernate.index("error = swsusp_write(flags);", snapshot)
  image_free = hibernate.index("swsusp_free();", image_write)
  power_off = hibernate.index("if (!error) {", image_free)
  assert snapshot < image_write < image_free < power_off
  assert "power_down();" in hibernate[power_off:power_off + 180]
  assert "thaw_processes();" in hibernate[image_write:]

print("PASS: armed probe skips image write after snapshot; stock path unwinds on error")
