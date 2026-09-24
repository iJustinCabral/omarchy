#!/usr/bin/python3
"""Exercise the external S4 breadcrumb backend without touching host EFI or PM."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/s4_backend.py"
spec = importlib.util.spec_from_file_location("t2_ftrace_s4_backend", script)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
VECTOR = "a" * 64
BOOT_ID = "11111111-2222-3333-4444-555555555555"
SRCVERSION = "693755E32EFAB59747D2ED1"


def refused(action, message):
  try:
    action()
  except (OSError, RuntimeError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe EFI ftrace S4 operation was accepted")


with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-s4-") as temporary:
  temporary = Path(temporary)
  root = temporary / "host"
  module_file = temporary / "marker.ko"
  module_file.write_bytes(b"exact synthetic marker module")
  module_hash = hashlib.sha256(module_file.read_bytes()).hexdigest()
  (root / "sys/power").mkdir(parents=True)
  (root / "sys/power/pm_trace").write_text("0\n")
  variable = backend.MARKER.marker_path(root)
  variable.parent.mkdir(parents=True)
  attempt_directory = root / "var/lib/pair/s4-vectors" / VECTOR / "attempts" / BOOT_ID
  attempt_directory.mkdir(parents=True)
  guard = attempt_directory.parent.parent / "s4-attempted"
  guard.write_text(BOOT_ID + "\n")
  (attempt_directory / "attempt.json").write_text(json.dumps({
    "boot_id": BOOT_ID,
    "transition_vector": VECTOR,
    "state": "guard-consumed",
  }))
  events = []

  def fake_command(arguments):
    events.append(tuple(arguments))
    if arguments[:3] == ("modinfo", "-F", "vermagic"):
      return "7.2.6-arch2-Watanare-T2-2-t2 SMP preempt\n"
    if arguments[:3] == ("modinfo", "-F", "srcversion"):
      return SRCVERSION + "\n"
    if arguments[0] == "insmod":
      parameters = root / backend.PARAMETERS
      parameters.mkdir(parents=True)
      for name, value in (("arm_vector", "0"), ("stage", "0"),
                          ("probe_consumed", "N"), ("entry_consumed", "N")):
        (parameters / name).write_text(value + "\n")
      return ""
    if arguments == ("rmmod", backend.MODULE_NAME):
      parameters = root / backend.PARAMETERS
      for path in parameters.iterdir():
        path.unlink()
      parameters.rmdir()
      parameters.parent.rmdir()
      return ""
    raise AssertionError("Unexpected command: " + repr(arguments))

  def fake_arm(host, vector):
    assert host == root and vector == VECTOR
    (root / backend.PARAMETERS / "arm_vector").write_text("1\n")

  marker = backend.FtraceEfiBackend(
    module_file, module_hash, SRCVERSION, command=fake_command,
    kernel_release="7.2.6-arch2-Watanare-T2-2-t2", parameter_writer=fake_arm,
  )
  assert marker.EXECUTION_QUALIFIED is False
  assert marker.MIN_RETURN_STAGE == 2
  assert marker.PM_TRACE_VALUE == "0"
  marker.require_kernel_available(root)
  marker.cleanup(root, VECTOR, BOOT_ID, attempt_directory)
  refused(lambda: marker.enable(root), "no consumed attempt identity")
  guard.write_text("different-boot\n")
  refused(lambda: marker.before_arm(root, VECTOR, BOOT_ID, attempt_directory), "exact consumed pair guard")
  guard.write_text(BOOT_ID + "\n")
  marker.before_arm(root, VECTOR, BOOT_ID, attempt_directory)
  assert (attempt_directory / "ftrace-efi-identity.json").exists()
  refused(lambda: marker.before_arm(root, VECTOR, BOOT_ID, attempt_directory), "File exists")
  marker.enable(root)
  assert marker.prearm(root, VECTOR) == str(variable)
  assert marker.inspect(root, VECTOR) == 0
  refused(lambda: marker.prearm(root, VECTOR), "already exists")
  variable.write_bytes(backend.MARKER.ATTRIBUTES + backend.MARKER.payload(VECTOR, 1))
  assert marker.inspect(root, VECTOR) == 1
  variable.write_bytes(backend.MARKER.ATTRIBUTES + backend.MARKER.payload(VECTOR, 2))
  assert marker.inspect(root, VECTOR) == 2
  marker.cleanup(root, VECTOR, BOOT_ID, attempt_directory)
  assert not marker.loaded(root)
  assert marker.inspect(root, VECTOR) == 2
  assert guard.read_text() == BOOT_ID + "\n"
  refused(lambda: marker.cleanup(root, "b" * 64, BOOT_ID, attempt_directory), "differs")
  assert ("rmmod", backend.MODULE_NAME) in events

print("PASS: external EFI S4 backend preserves one-use guard and stage evidence offline")
