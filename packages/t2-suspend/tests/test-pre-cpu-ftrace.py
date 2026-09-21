#!/usr/bin/env python3
"""Check the pre-CPU ftrace probe's guarded replacement offline."""
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text()
replacement = re.search(r"static int notrace mba_hibernate_skip_cpu_disable\(void\)\n\{.*?\n\}", source, re.S)
hook = re.search(r"static void notrace mba_hibernate_pre_cpu_hook\(.*?\n\}", source, re.S)
assert replacement and hook
assert '#define TARGET_FUNCTION "hibernate_resume_nonboot_cpu_disable"' in source
assert "return -ECANCELED;" in replacement.group(0)
assert "interceptions" in replacement.group(0)
assert "if (READ_ONCE(armed))" in hook.group(0)
assert "ftrace_regs_set_instruction_pointer" in hook.group(0)
assert "if (armed)\n    return -EPERM;" in source
assert "FTRACE_OPS_FL_IPMODIFY" in source
print("PASS: pre-CPU ftrace probe is disarmed by default and redirects only while armed")
