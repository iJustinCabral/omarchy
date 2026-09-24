#!/usr/bin/python3
"""Check that the external EFI marker stays opt-in and uses nonblocking APIs."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1] / "experiments"
module = (root / "hibernate-efi-ftrace-marker/mba_hibernate_efi_ftrace_marker.c").read_text()
original = (root / "hibernate-efi-stage-marker/marker.py").read_text()
kernel_patch = (root / "0012-hibernate-efi-stage-marker.patch").read_text()

assert 'L"OmarchyT2HibernateStage"' in module
assert 'EFI_GUID(0x96234839, 0x90c9, 0x4cd5, 0x97, 0xb2, 0x7b, 0xa6, 0x90, 0xf0, 0xaf, 0x02)' in module
assert 'OmarchyT2HibernateStage-96234839-90c9-4cd5-97b2-7ba690f0af02' in original
assert 'EFI_GUID(0x96234839, 0x90c9, 0x4cd5, 0x97, 0xb2, 0x7b, 0xa6, 0x90, 0xf0, 0xaf, 0x02)' in kernel_patch
assert re.search(r'#define MARKER_SIZE 17\b', module)
assert re.search(r'hex2bin\(expected \+ 4, value, 12\)', module)
assert 'memcmp(actual, expected, sizeof(actual))' in module
assert 'attrs != MARKER_ATTRS' in module and 'size != sizeof(actual)' in module
assert 'efivar_get_variable(marker_name, &marker_guid, &attrs, &size, actual)' in module
assert 'efivar_trylock()' in module
assert re.search(r'efivar_set_variable_locked\(marker_name, &marker_guid,\s*MARKER_ATTRS, sizeof\(value\), value, true\)', module)
assert 'efivar_unlock();' in module
assert 'efi.set_variable_nonblocking' in module and 'efi.query_variable_info_nonblocking' in module
assert 'WRITE_ONCE(armed, false);' in module
assert 'module_param_cb(arm_vector, &arm_vector_ops, NULL, 0600)' in module
assert re.search(r'\{ \.function = "hibernate", \.value = 1 \},\s*\{ \.function = "swsusp_write", \.value = 2 \}', module)
assert 'FTRACE_OPS_FL_IPMODIFY' not in module
assert 'kernel_power_off' not in module and 'power_down' not in module
assert 'MODULE_IMPORT_NS("EFIVAR")' in module

print("PASS: stock-kernel EFI marker is guarded, nonblocking and source-boundary-only")
