#!/usr/bin/python3
"""Check a one-use in-kernel EFI write protocol without touching real EFI."""

import importlib.util
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/kernel_probe.py"
spec = importlib.util.spec_from_file_location("t2_efi_kernel_probe", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SOURCE = "53dcba62-0eb1-4623-b5c7-68e343cdd689"
RETURN = "c3e62542-7bf9-48ab-af0f-80dcf4001de8"


def refused(action, message):
  try:
    action()
  except (OSError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe kernel EFI probe operation was accepted")


def fixture(root):
  (root / probe.VARIABLE).parent.mkdir(parents=True)
  (root / probe.STATE).parent.mkdir(parents=True)
  (root / probe.COMMON.BOOT_ID).parent.mkdir(parents=True)
  (root / probe.COMMON.BOOT_ID).write_text(SOURCE + "\n")


def module_parameters(root, consumed="0", status="0"):
  path = root / probe.MODULE / "parameters"
  path.mkdir(parents=True)
  (root / probe.MODULE / "srcversion").write_text(probe.MODULE_SRCVERSION + "\n")
  for name, value in (("probe_consumed", consumed), ("probe_efi_status", status),
                      ("arm_vector", "0"), ("stage", "0")):
    (path / name).write_text(value + "\n")


def remove_module(root):
  path = root / probe.MODULE / "parameters"
  for item in path.iterdir():
    item.unlink()
  path.rmdir()
  (root / probe.MODULE / "srcversion").unlink()
  (root / probe.MODULE).rmdir()


refused(lambda: probe.require_scope(Path("/"), False), "explicit allow_live=True")

with tempfile.TemporaryDirectory(prefix="t2-efi-kernel-probe-") as temporary:
  root = Path(temporary)
  fixture(root)
  extra = (root / probe.VARIABLE).parent / "UnrelatedVariable-d963eecc-8654-47d4-bc1c-456d7b776a86"
  extra.write_bytes(b"unrelated")
  prepared = probe.prepare(root)
  arm, stage0, stage1 = probe.load_arm(root)
  assert prepared["source_boot_id"] == SOURCE
  assert (root / probe.VARIABLE).read_bytes() == stage0
  assert (root / probe.STATE).stat().st_mode & 0o777 == 0o700
  assert (root / probe.STATE / "armed.json").stat().st_mode & 0o777 == 0o600
  refused(lambda: probe.prepare(root), "already exists")
  module_parameters(root)
  refused(lambda: probe.record_write(root), "not consumed")
  (root / probe.VARIABLE).write_bytes(stage1)
  probe.parameter(root, "probe_consumed").write_text("Y\n")
  written = probe.record_write(root)
  assert written["success"] is True and written["observed_stage"] == 1
  refused(lambda: probe.record_write(root), "File exists")
  refused(lambda: probe.verify_return(root), "Same-boot")
  remove_module(root)
  (root / probe.COMMON.BOOT_ID).write_text(RETURN + "\n")
  returned = probe.verify_return(root)
  assert returned["persisted"] is True and returned["observed_stage"] == 1
  assert probe.clear(root) is True
  assert not (root / probe.VARIABLE).exists()
  assert extra.read_bytes() == b"unrelated"
  assert (root / probe.STATE / "cleared.json").is_file()
  refused(lambda: probe.clear(root), "Only an exact")

with tempfile.TemporaryDirectory(prefix="t2-efi-kernel-probe-failed-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.prepare(root)
  module_parameters(root, consumed="Y", status="9223372036854775814")
  written = probe.record_write(root)
  assert written["success"] is False and written["observed_stage"] == 0
  remove_module(root)
  (root / probe.COMMON.BOOT_ID).write_text(RETURN + "\n")
  assert probe.verify_return(root)["persisted"] is False
  refused(lambda: probe.clear(root), "Only an exact")

with tempfile.TemporaryDirectory(prefix="t2-efi-kernel-probe-armed-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.prepare(root)
  module_parameters(root)
  probe.parameter(root, "arm_vector").write_text("1\n")
  refused(lambda: probe.execute(root), "not disarmed and unused")
  assert not (root / probe.STATE / "write-result.json").exists()
  assert probe.stage(root, *probe.load_arm(root)[1:]) == 0

with tempfile.TemporaryDirectory(prefix="t2-efi-kernel-probe-stale-") as temporary:
  root = Path(temporary)
  fixture(root)
  (root / probe.VARIABLE).write_bytes(b"stale")
  refused(lambda: probe.prepare(root), "already exists")
  assert not (root / probe.STATE).exists()

module = (script.parent / "mba_hibernate_efi_ftrace_marker.c").read_text()
assert 'L"OmarchyT2KernelEfiProbe"' in module
assert 'EFI_GUID(0xd963eecc, 0x8654, 0x47d4, 0xbc, 0x1c, 0x45, 0x6d, 0x7b, 0x77, 0x6a, 0x86)' in module
assert "module_param_cb(probe_nonce, &probe_nonce_ops, NULL, 0600)" in module
assert "READ_ONCE(probe_consumed) || READ_ONCE(armed)" in module
assert "READ_ONCE(arm_consumed) ||" in module
assert "status = mba_write_variable(probe_name, &probe_guid, expected);" in module
assert "WRITE_ONCE(probe_consumed, true);" in module
assert "MODULE_IMPORT_NS(\"EFIVAR\")" in module

print("PASS: in-kernel EFI probe is distinct, one-use and mutually exclusive with S4 arming")
