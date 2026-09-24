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

if len(sys.argv) > 2 and sys.argv[2]:
  hibernate = Path(sys.argv[2]).read_text()
  load = hibernate.split("static int load_image_and_restore(void)", 1)[1].split("#define COMPRESSION_ALGO_LZO", 1)[0]
  assert load.index("error = swsusp_read(&flags);") < load.index("swsusp_close();", load.index("error = swsusp_read(&flags);"))
  assert load.index("swsusp_close();", load.index("error = swsusp_read(&flags);")) < load.index("error = hibernation_restore(flags & SF_PLATFORM_MODE);")
  assert load.index("error = hibernation_restore(flags & SF_PLATFORM_MODE);") < load.index("swsusp_free();")
  test_resume = hibernate.split("int hibernate(void)", 1)[1]
  assert test_resume.index("error = swsusp_write(flags);") < test_resume.index("error = swsusp_check(false);") < test_resume.index("error = load_image_and_restore();")

if len(sys.argv) > 3 and sys.argv[3]:
  swap = Path(sys.argv[3]).read_text()
  check = swap.split("int swsusp_check(bool exclusive)", 1)[1].split("void swsusp_close(void)", 1)[0]
  assert check.index("memcpy(swsusp_header->sig, swsusp_header->orig_sig, 10);") < check.index("REQ_OP_WRITE | REQ_SYNC")

if len(sys.argv) > 4 and sys.argv[4]:
  swapfile = Path(sys.argv[4]).read_text()
  selection = swapfile.split("static int __find_hibernation_swap_type", 1)[1].split("int pin_hibernation_swap_type", 1)[0]
  assert "device == sis->bdev->bd_dev" in selection
  assert "se->start_block == offset" in selection

if len(sys.argv) > 5:
  vm_init = Path(sys.argv[5]).read_text()
  assert 'strncmp(vendor, "QEMU", 4)' in vm_init and '"mba_vm_readback=1"' in vm_init
  assert vm_init.index("swapon(SWAP_DEVICE, 0)") < vm_init.index('write_value("/sys/power/resume"')
  assert vm_init.index('write_value(EFI_VARIABLE, stage0') < vm_init.index('write_value(ABORT_PARAMETER("armed"), "Y\\n"')
  assert vm_init.index('write_value(ABORT_PARAMETER("armed"), "Y\\n"') < vm_init.index('open("/sys/power/state"')
  assert 'selected(ABORT_PARAMETER("interceptions"), "1\\n")' in vm_init
  assert '"SWAPSPACE2"' in vm_init

if len(sys.argv) > 6:
  vm_runner = Path(sys.argv[6]).read_text()
  assert "mktemp -d /tmp/mba-readback-vm." in vm_runner
  assert 'if=virtio,format=raw,file="$work/swap.img"' in vm_runner
  assert 'mba_vm_readback=1' in vm_runner
  assert '28e13ee2a660c590d0d66988c0af9d768aa5a37e2e2ed52624215f624b149f32' in vm_runner
  assert '1d524ff4ca53980be38654f3f872fe3d82b725baac5fd6c9dbc86306db9aba39' in vm_runner

print("PASS: readback abort is one-use and precedes atomic restore in the pinned kernel")
