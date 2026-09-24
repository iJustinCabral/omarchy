#!/usr/bin/python3
"""Check guarded freezer-depth ftrace entry behavior on synthetic sysfs."""

import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/entry_probe.py"
spec = importlib.util.spec_from_file_location("t2_efi_ftrace_entry_probe", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SOURCE = "ef7a623b-53e4-4531-a6d6-5451182ed94c"
RETURN = "698ae76d-c186-4eb5-a285-cad409bb7e48"


def refused(action, message):
  try:
    action()
  except (OSError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe ftrace entry operation was accepted")


def fixture(root):
  (root / probe.VARIABLE).parent.mkdir(parents=True)
  (root / probe.STATE).parent.mkdir(parents=True)
  (root / probe.COMMON.BOOT_ID).parent.mkdir(parents=True)
  (root / probe.COMMON.BOOT_ID).write_text(SOURCE + "\n")
  power = root / "sys/power"
  power.mkdir(parents=True)
  (power / "pm_test").write_text("[none] freezer devices platform processors core\n")
  (power / "disk").write_text("[platform] shutdown reboot test_resume\n")


def fake_module(root):
  path = root / probe.MODULE / "parameters"
  path.mkdir(parents=True)
  (root / probe.MODULE / "srcversion").write_text(probe.MODULE_SRCVERSION + "\n")
  for name, value in (("entry_consumed", "N"), ("entry_armed", "N"),
                      ("entry_stage", "0"), ("entry_efi_status", "0"),
                      ("arm_vector", "0"), ("probe_consumed", "N"),
                      ("stage", "0"), ("entry_nonce", "")):
    (path / name).write_text(value + "\n")


def fake_arm(root, value):
  arm, _, _ = probe.load_arm(root)
  assert value == (arm["nonce_hex"] + "\n").encode()
  probe.module_parameter(root, "entry_nonce").write_bytes(value)
  probe.module_parameter(root, "entry_consumed").write_text("Y\n")
  probe.module_parameter(root, "entry_armed").write_text("Y\n")


def remove_fake_module(root):
  parameters = root / probe.MODULE / "parameters"
  for item in parameters.iterdir():
    item.unlink()
  parameters.rmdir()
  (root / probe.MODULE / "srcversion").unlink()
  (root / probe.MODULE).rmdir()


def fake_return(root):
  guard = probe.COMMON.load_json(root / probe.STATE / "pm-attempted.json", root)
  assert guard["source_boot_id"] == SOURCE
  assert guard["command"][-4:] == ["--disk-mode", "shutdown", "--no-sudo-prompt", "--yes"]
  _, stage0, stage1 = probe.load_arm(root)
  assert probe.stage(root, stage0, stage1) == 0
  (root / probe.VARIABLE).write_bytes(stage1)
  probe.module_parameter(root, "entry_armed").write_text("N\n")
  probe.module_parameter(root, "entry_stage").write_text("1\n")
  return 0, "freezer returned"


refused(lambda: probe.require_scope(Path("/"), False), "explicit allow_live=True")
assert probe.HELPER.is_file()
assert probe.COMMON.sha256_file(probe.HELPER) == probe.HELPER_SHA256
assert "require_recovery_acceptance" in probe.require_live_preflight.__code__.co_names

with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-recovery-") as temporary:
  root = Path(temporary)
  fixture(root)
  acceptance_path = root / probe.RECOVERY_ACCEPTANCE
  refused(lambda: probe.require_recovery_acceptance(root), "explicit operator-attended")
  acceptance_path.parent.mkdir(parents=True)
  accepted = {
    "kind": "ftrace-entry-freezer-recovery-acceptance-v1",
    "source_boot_id": SOURCE,
    "module_sha256": probe.MODULE_SHA256,
    "helper_sha256": probe.HELPER_SHA256,
    "production_uki_sha256": probe.COMMON.PRODUCTION_UKI_SHA256,
    "production_limine_sha256": probe.COMMON.PRODUCTION_LIMINE_SHA256,
    "method": "operator-attended-cold-power",
    "accepted": True,
  }
  for change in ({"source_boot_id": RETURN}, {"module_sha256": "0" * 64},
                 {"method": "smart-plug"}, {"accepted": False}):
    acceptance_path.write_text(json.dumps({**accepted, **change}))
    refused(lambda: probe.require_recovery_acceptance(root), "does not bind")
  acceptance_path.write_text(json.dumps(accepted))
  assert probe.require_recovery_acceptance(root) == accepted

with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-entry-") as temporary:
  root = Path(temporary)
  fixture(root)
  extra = (root / probe.VARIABLE).parent / "UnrelatedVariable-9f946df0-1b9c-4af5-97e8-bc322a728241"
  extra.write_bytes(b"unrelated")
  prepared = probe.prepare(root)
  arm, stage0, stage1 = probe.load_arm(root)
  assert prepared["source_boot_id"] == SOURCE
  assert (root / probe.VARIABLE).read_bytes() == stage0
  assert (root / probe.STATE).stat().st_mode & 0o777 == 0o700
  assert (root / probe.STATE / "armed.json").stat().st_mode & 0o777 == 0o600
  refused(lambda: probe.prepare(root), "already exists")
  fake_module(root)
  result = probe.arm_module(root, write_parameter=fake_arm)
  assert result["source_boot_id"] == SOURCE
  assert probe.parameter_value(root, "entry_armed") == "Y"
  returned = probe.execute_freezer(root, transition=fake_return)
  assert returned["success"] is True
  assert returned["observed_stage"] == 1
  assert returned["pm_test_after"] == "none" and returned["disk_after"] == "platform"
  assert extra.read_bytes() == b"unrelated"
  refused(lambda: probe.execute_freezer(root, transition=fake_return), "does not match")
  remove_fake_module(root)
  (root / probe.COMMON.BOOT_ID).write_text(RETURN + "\n")
  captured = probe.capture_return(root)
  assert captured["marker_persisted"] is True
  assert captured["source_returned_successfully"] is True
  assert probe.clear(root) is True
  assert not (root / probe.VARIABLE).exists()
  assert extra.read_bytes() == b"unrelated"
  refused(lambda: probe.clear(root), "Only an exact")

with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-entry-hang-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.prepare(root)
  arm, stage0, stage1 = probe.load_arm(root)
  fake_module(root)
  probe.arm_module(root, write_parameter=fake_arm)
  probe.COMMON.atomic_new_json(root / probe.STATE / "pm-attempted.json", {
    "kind": "ftrace-entry-freezer-probe-v1-pm-attempted",
    "source_boot_id": SOURCE,
    "module_sha256": probe.MODULE_SHA256,
    "stage0_sha256": arm["stage0_sha256"],
  })
  (root / probe.VARIABLE).write_bytes(stage1)
  remove_fake_module(root)
  (root / probe.COMMON.BOOT_ID).write_text(RETURN + "\n")
  captured = probe.capture_return(root)
  assert captured["marker_persisted"] is True
  assert captured["source_returned_successfully"] is False
  refused(lambda: probe.clear(root), "Only an exact")
  assert (root / probe.VARIABLE).read_bytes() == stage1

with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-entry-stale-") as temporary:
  root = Path(temporary)
  fixture(root)
  (root / probe.VARIABLE).write_bytes(b"stale")
  refused(lambda: probe.prepare(root), "already exists")
  assert not (root / probe.STATE).exists()

module = (script.parent / "mba_hibernate_efi_ftrace_marker.c").read_text()
assert 'L"OmarchyT2FtraceEntryProbe"' in module
assert 'EFI_GUID(0x9f946df0, 0x1b9c, 0x4af5, 0x97, 0xe8, 0xbc, 0x32, 0x2a, 0x72, 0x82, 0x41)' in module
assert 'module_param_cb(entry_nonce, &entry_nonce_ops, NULL, 0600)' in module
assert 'hook->value == 1 && READ_ONCE(entry_armed)' in module
assert 'status = mba_write_entry_stage();' in module
assert 'WRITE_ONCE(entry_consumed, true);' in module
assert 'READ_ONCE(entry_consumed) ||' in module
assert 'WRITE_ONCE(entry_armed, false);' in module

print("PASS: one-use freezer ftrace entry probe is separate, guarded and returns before S4")
