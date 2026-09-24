#!/usr/bin/python3
"""Check the readback abort hook and, optionally, pinned kernel ordering."""

from pathlib import Path
import re
import sys


source = Path(sys.argv[1]).read_text()
hook = re.search(r"static void notrace mba_readback_hook\(.*?\n\}", source, re.S)
replacement = re.search(r"static int notrace mba_skip_atomic_restore\(.*?\n\}", source, re.S)
setter = re.search(r"static int mba_set_armed\(.*?\n\}", source, re.S)
assert hook and replacement and setter
assert '#define TARGET_FUNCTION "hibernation_restore"' in source
assert "FTRACE_OPS_FL_IPMODIFY" in source
assert "ftrace_regs_set_instruction_pointer" in hook.group(0)
assert "cmpxchg(&interceptions, 0, 1)" in hook.group(0)
assert "WRITE_ONCE(armed, false);" in hook.group(0)
assert "return -ECANCELED;" in replacement.group(0)
assert "!READ_ONCE(registered)" in setter.group(0)
assert "READ_ONCE(interceptions) != 0" in setter.group(0)
assert "if (READ_ONCE(armed))\n    return -EPERM;" in source

if len(sys.argv) > 2:
  hibernate = Path(sys.argv[2]).read_text()
  load = hibernate.split("static int load_image_and_restore(void)", 1)[1].split("#define COMPRESSION_ALGO_LZO", 1)[0]
  assert load.index("error = swsusp_read(&flags);") < load.index("swsusp_close();", load.index("error = swsusp_read(&flags);"))
  assert load.index("swsusp_close();", load.index("error = swsusp_read(&flags);")) < load.index("error = hibernation_restore(flags & SF_PLATFORM_MODE);")
  assert load.index("error = hibernation_restore(flags & SF_PLATFORM_MODE);") < load.index("swsusp_free();")
  test_resume = hibernate.split("int hibernate(void)", 1)[1]
  assert test_resume.index("error = swsusp_write(flags);") < test_resume.index("error = swsusp_check(false);") < test_resume.index("error = load_image_and_restore();")

if len(sys.argv) > 3:
  swap = Path(sys.argv[3]).read_text()
  check = swap.split("int swsusp_check(bool exclusive)", 1)[1].split("void swsusp_close(void)", 1)[0]
  assert check.index("memcpy(swsusp_header->sig, swsusp_header->orig_sig, 10);") < check.index("REQ_OP_WRITE | REQ_SYNC")

if len(sys.argv) > 4:
  swapfile = Path(sys.argv[4]).read_text()
  selection = swapfile.split("static int __find_hibernation_swap_type", 1)[1].split("int pin_hibernation_swap_type", 1)[0]
  assert "device == sis->bdev->bd_dev" in selection
  assert "se->start_block == offset" in selection

print("PASS: readback abort is one-use and precedes atomic restore in the pinned kernel")
