#!/usr/bin/python3
"""Exercise the one-use EFI persistence probe on a synthetic efivarfs."""

import importlib.util
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/persistence_probe.py"
spec = importlib.util.spec_from_file_location("t2_efi_persistence_probe", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SOURCE = "ef1bc90d-7cce-4c1d-aea8-404e3b53c5b7"
RETURN = "a7f030a8-a041-488c-bd68-20b7d44c573a"


def refused(action, message):
  try:
    action()
  except (OSError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe EFI probe operation was accepted")


def fixture(root):
  (root / probe.VARIABLE).parent.mkdir(parents=True)
  (root / probe.STATE).parent.mkdir(parents=True)
  (root / probe.BOOT_ID).parent.mkdir(parents=True)
  (root / probe.BOOT_ID).write_text(SOURCE + "\n")


refused(lambda: probe.require_scope(Path("/"), False), "explicit allow_live=True")


with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-probe-") as temporary:
  root = Path(temporary)
  fixture(root)
  extra = (root / probe.VARIABLE).parent / "UnrelatedVariable-0dc7b0e2-3b57-4e62-9159-caa993087e72"
  extra.write_bytes(b"unrelated")
  result = probe.arm(root)
  variable = root / probe.VARIABLE
  armed = probe.load_json(root / probe.STATE / "armed.json", root)
  assert variable.read_bytes() == probe.expected_value(armed)
  assert result["source_boot_id"] == SOURCE
  assert (root / probe.STATE).stat().st_mode & 0o777 == 0o700
  assert (root / probe.STATE / "armed.json").stat().st_mode & 0o777 == 0o600
  refused(lambda: probe.arm(root), "already exists")
  refused(lambda: probe.verify(root), "Same-boot")
  assert not (root / probe.STATE / "verified.json").exists()
  (root / probe.BOOT_ID).write_text(RETURN + "\n")
  verified = probe.verify(root)
  assert verified["persisted"] is True
  assert verified["source_boot_id"] == SOURCE and verified["return_boot_id"] == RETURN
  refused(lambda: probe.verify(root), "File exists")
  assert probe.clear(root) is True
  assert not variable.exists()
  assert extra.read_bytes() == b"unrelated"
  assert (root / probe.STATE / "clear-intent.json").is_file()
  assert (root / probe.STATE / "cleared.json").is_file()
  refused(lambda: probe.clear(root), "changed after verification")

with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-changed-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.arm(root)
  (root / probe.BOOT_ID).write_text(RETURN + "\n")
  assert probe.verify(root)["persisted"] is True
  variable = root / probe.VARIABLE
  variable.write_bytes(probe.ATTRIBUTES + probe.MAGIC + b"y" * 12)
  refused(lambda: probe.clear(root), "changed after verification")
  assert variable.is_file()
  assert not (root / probe.STATE / "clear-intent.json").exists()

with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-mismatch-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.arm(root)
  variable = root / probe.VARIABLE
  variable.write_bytes(probe.ATTRIBUTES + probe.MAGIC + b"x" * 12)
  (root / probe.BOOT_ID).write_text(RETURN + "\n")
  assert probe.verify(root)["persisted"] is False
  refused(lambda: probe.clear(root), "Only an exact")
  assert variable.is_file()

with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-absent-") as temporary:
  root = Path(temporary)
  fixture(root)
  probe.arm(root)
  (root / probe.VARIABLE).unlink()
  (root / probe.BOOT_ID).write_text(RETURN + "\n")
  result = probe.verify(root)
  assert result["persisted"] is False and result["observed_sha256"] is None
  refused(lambda: probe.clear(root), "Only an exact")

with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-symlink-") as temporary:
  root = Path(temporary)
  fixture(root)
  (root / probe.VARIABLE).symlink_to(root / probe.BOOT_ID)
  refused(lambda: probe.arm(root), "Too many levels of symbolic links")
  assert not (root / probe.STATE).exists()

with tempfile.TemporaryDirectory(prefix="t2-efi-persistence-stale-") as temporary:
  root = Path(temporary)
  fixture(root)
  (root / probe.STATE).mkdir()
  refused(lambda: probe.arm(root), "File exists")
  assert not (root / probe.VARIABLE).exists()

print("PASS: disposable EFI probe is one-use, cross-boot, exact-value and cleanup-guarded")
