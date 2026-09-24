#!/usr/bin/python3
"""Check the separate one-use forced-power EFI variable protocol offline."""

import importlib.util
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/forced_power_probe.py"
spec = importlib.util.spec_from_file_location("t2_forced_power_probe", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SOURCE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RETURN = "11111111-2222-3333-4444-555555555555"


def refused(action, message):
  try:
    action()
  except (OSError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe forced-power probe operation was accepted")


with tempfile.TemporaryDirectory(prefix="t2-forced-power-probe-") as temporary:
  root = Path(temporary)
  (root / probe.CORE.VARIABLE).parent.mkdir(parents=True)
  (root / probe.CORE.STATE).parent.mkdir(parents=True)
  (root / probe.CORE.BOOT_ID).parent.mkdir(parents=True)
  (root / probe.CORE.BOOT_ID).write_text(SOURCE + "\n")
  refused(lambda: probe.arm(root), "attending operator")
  assert not (root / probe.CORE.STATE).exists()
  result = probe.arm(root, operator_attended=True)
  assert result["source_boot_id"] == SOURCE
  assert probe.CORE.MAGIC == b"MBFP"
  assert probe.CORE.VARIABLE != Path("sys/firmware/efi/efivars/OmarchyT2EfiPersistenceProbe-0dc7b0e2-3b57-4e62-9159-caa993087e72")
  assert probe.require_intent(root)["value_sha256"] == result["value_sha256"]
  refused(lambda: probe.arm(root, operator_attended=True), "already exists")
  refused(lambda: probe.verify(root), "Same-boot")
  (root / probe.CORE.BOOT_ID).write_text(RETURN + "\n")
  verified = probe.verify(root)
  assert verified["persisted"] is True
  assert verified["power_cut_proven_by_software"] is False
  assert probe.clear(root) is True
  assert not (root / probe.CORE.VARIABLE).exists()
  assert (root / probe.CORE.STATE / "armed.json").is_file()
  assert (root / probe.CORE.STATE / "forced-power-intent.json").is_file()
  assert (root / probe.CORE.STATE / "verified.json").is_file()
  assert (root / probe.CORE.STATE / "cleared.json").is_file()
  refused(lambda: probe.clear(root), "changed after verification")

print("PASS: forced-power EFI probe is distinct, attended, one-use and exact-value guarded")
