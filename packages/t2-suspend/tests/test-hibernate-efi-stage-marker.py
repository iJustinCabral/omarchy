#!/usr/bin/python3
"""Test EFI marker layout and no-repeat behavior on synthetic efivarfs."""

import importlib.util
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-stage-marker/marker.py"
spec = importlib.util.spec_from_file_location("hibernate_efi_stage_marker", script)
marker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(marker)
VECTOR = "5b72eb22c88cf50a5938b52da02ffee9c94f5cf9468e212a961098c4bf04b230"


def refused(action, message):
  try:
    action()
  except (OSError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe EFI marker operation was accepted")


with tempfile.TemporaryDirectory(prefix="t2-efi-stage-marker-") as temporary:
  root = Path(temporary)
  variable = marker.marker_path(root)
  variable.parent.mkdir(parents=True)
  parameter = marker.parameter_path(root)
  parameter.parent.mkdir(parents=True)
  assert marker.inspect(root, VECTOR) is None
  refused(lambda: marker.prearm(root, VECTOR), "no T2 EFI stage-marker parameter")
  parameter.write_text("N\n")
  refused(lambda: marker.prearm(root, VECTOR), "not enabled")
  marker.enable(root)
  assert parameter.read_text() == "Y"
  refused(lambda: marker.payload("X" * 64, 0), "lowercase SHA-256")
  refused(lambda: marker.payload(VECTOR, 3), "Unsupported")
  armed = marker.prearm(root, VECTOR)
  assert armed == str(variable)
  assert variable.read_bytes() == marker.ATTRIBUTES + b"MBA9" + bytes.fromhex(VECTOR[:24]) + b"\x00"
  assert marker.inspect(root, VECTOR) == 0
  refused(lambda: marker.prearm(root, VECTOR), "already exists")
  refused(lambda: marker.inspect(root, "0" * 64), "another vector")
  variable.write_bytes(marker.ATTRIBUTES + marker.payload(VECTOR, 1))
  assert marker.inspect(root, VECTOR) == 1
  variable.write_bytes(marker.ATTRIBUTES + marker.payload(VECTOR, 2))
  assert marker.inspect(root, VECTOR) == 2
  refused(lambda: marker.prearm(root, VECTOR), "already exists")
  variable.write_bytes(b"\x00" * 4 + marker.payload(VECTOR, 0))
  refused(lambda: marker.inspect(root, VECTOR), "attributes or size")
  variable.write_bytes(marker.ATTRIBUTES + marker.payload(VECTOR, 0)[:-1])
  refused(lambda: marker.inspect(root, VECTOR), "attributes or size")
  variable.unlink()
  variable.symlink_to(parameter)
  refused(lambda: marker.prearm(root, VECTOR), "already exists")
  refused(lambda: marker.inspect(root, VECTOR), "symlink")
  variable.unlink()
  parameter.unlink()
  parameter.symlink_to(variable)
  refused(lambda: marker.prearm(root, VECTOR), "no T2 EFI stage-marker parameter")

print("PASS: EFI marker binds guarded vector and refuses stale, corrupt or symlinked evidence")
