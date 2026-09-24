#!/usr/bin/python3
"""Check the post-write EFI adapter using only a disposable filesystem."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-postwrite-marker/s4_backend.py"
spec = importlib.util.spec_from_file_location("postwrite_efi_s4_backend", script)
backend_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend_module)
VECTOR = "0123456789abcdef" * 4
BOOT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RELEASE = "7.2.6-arch2-Watanare-T2-2-t2"
SRCVERSION = "ECA3A5319ADB6686DD0BD88"


def write(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(value)


with tempfile.TemporaryDirectory(prefix="t2-postwrite-backend-") as temporary:
  root = Path(temporary)
  module = root / "marker.ko"
  module.write_bytes(b"private-test-module")
  module_hash = hashlib.sha256(module.read_bytes()).hexdigest()
  write(root / "sys/power/pm_trace", "0\n")
  (root / backend_module.VARIABLE).parent.mkdir(parents=True)
  parameters = root / backend_module.PARAMETERS
  calls = []

  def command(arguments):
    calls.append(tuple(arguments))
    if arguments[:3] == ("modinfo", "-F", "vermagic"):
      return RELEASE + " SMP preempt mod_unload\n"
    if arguments[:3] == ("modinfo", "-F", "srcversion"):
      return SRCVERSION + "\n"
    if arguments == ("insmod", str(module)):
      write(parameters / "arm_vector", "0\n")
      write(parameters / "stage", "0\n")
      write(parameters / "last_efi_status", "0\n")
      return ""
    if arguments == ("rmmod", backend_module.MODULE_NAME):
      for path in parameters.iterdir():
        path.unlink()
      parameters.rmdir()
      return ""
    raise AssertionError("Unexpected command: " + repr(arguments))

  def arm(_root, identity):
    assert identity == VECTOR
    write(parameters / "arm_vector", "1\n")

  backend = backend_module.PostwriteEfiBackend(
    module, module_hash, SRCVERSION, command=command,
    kernel_release=RELEASE, parameter_writer=arm,
  )
  backend.require_kernel_available(root)
  assert backend.inspect(root, VECTOR) is None
  acceptance_path = root / backend_module.ACCEPTANCE
  production = "a" * 64
  try:
    backend.require_operator_acceptance(root, VECTOR, BOOT_ID, production)
    raise AssertionError("Missing recovery acceptance was accepted")
  except ValueError as error:
    assert "acceptance is missing" in str(error)
  acceptance = {
    "kind": "postwrite-efi-attended-s4-v1",
    "boot_id": BOOT_ID,
    "transition_vector": VECTOR,
    "module_sha256": module_hash,
    "production_uki_sha256": production,
    "method": "operator-attended-cold-power",
    "accepted": True,
  }
  write(acceptance_path, json.dumps(acceptance))
  acceptance_path.chmod(0o600)
  assert backend.require_operator_acceptance(root, VECTOR, BOOT_ID, production) == hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
  try:
    backend.require_operator_acceptance(root, VECTOR, "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", production)
    raise AssertionError("Acceptance from another boot was accepted")
  except ValueError as error:
    assert "differs" in str(error)
  try:
    backend.prearm(root, VECTOR)
    raise AssertionError("Post-write backend armed without a consumed pair guard")
  except ValueError as error:
    assert "differs from its loaded attempt" in str(error)

  attempt_directory = root / "var/lib/pair/s4-vectors" / VECTOR / "attempts" / BOOT_ID
  guard = attempt_directory.parent.parent / "s4-attempted"
  write(guard, BOOT_ID + "\n")
  attempt = attempt_directory / "attempt.json"
  write(attempt, json.dumps({"transition_vector": VECTOR, "boot_id": BOOT_ID}))
  backend.before_arm(root, VECTOR, BOOT_ID, attempt_directory)
  identity = json.loads((attempt_directory / "postwrite-efi-identity.json").read_text())
  assert identity["module_sha256"] == module_hash
  assert identity["recovery"] == "operator-attended-cold-power"
  assert backend.inspect(root, VECTOR) is None
  backend.enable(root)
  marker_path = Path(backend.prearm(root, VECTOR))
  assert backend.inspect(root, VECTOR) == 0
  assert marker_path.read_bytes() == backend_module.ATTRIBUTES + backend_module.MAGIC + bytes.fromhex(VECTOR[:24]) + b"\x00"
  assert calls[-1] == ("insmod", str(module))
  try:
    backend.prearm(root, VECTOR)
    raise AssertionError("Post-write stage 0 was overwritten")
  except ValueError as error:
    assert "already exists" in str(error)
  marker_path.write_bytes(marker_path.read_bytes()[:-1] + b"\x03")
  assert backend.inspect(root, VECTOR) == 3
  try:
    backend.inspect(root, "f" * 64)
    raise AssertionError("Foreign post-write marker was accepted")
  except ValueError as error:
    assert "does not match" in str(error)
  backend.cleanup(root, VECTOR, BOOT_ID, attempt_directory)
  assert not backend.loaded(root)
  assert backend.inspect(root, VECTOR) == 3

  wrong = backend_module.PostwriteEfiBackend(module, "0" * 64, SRCVERSION, command=command, kernel_release=RELEASE)
  try:
    wrong.require_kernel_available(root)
    raise AssertionError("Changed module hash was accepted")
  except ValueError as error:
    assert "differs" in str(error)

with tempfile.TemporaryDirectory(prefix="t2-postwrite-restore-backend-") as temporary:
  root = Path(temporary)
  source_module = root / "source-marker.ko"
  restore_module = root / "restore-marker.ko"
  source_module.write_bytes(b"new-source-marker")
  restore_module.write_bytes(b"new-restore-marker")
  source_hash = hashlib.sha256(source_module.read_bytes()).hexdigest()
  restore_hash = hashlib.sha256(restore_module.read_bytes()).hexdigest()
  restore_srcversion = "3119365A09AED2D4CD65DD6"
  write(root / "sys/power/pm_trace", "0\n")
  (root / backend_module.VARIABLE).parent.mkdir(parents=True)
  parameters = root / backend_module.PARAMETERS

  def command(arguments):
    if arguments[:3] == ("modinfo", "-F", "vermagic"):
      return RELEASE + " SMP preempt mod_unload\n"
    if arguments[:3] == ("modinfo", "-F", "srcversion"):
      return (restore_srcversion if arguments[3] == str(restore_module) else SRCVERSION) + "\n"
    if arguments == ("insmod", str(source_module)):
      write(parameters / "arm_vector", "0\n")
      write(parameters / "stage", "0\n")
      write(parameters / "last_efi_status", "0\n")
      return ""
    if arguments == ("rmmod", backend_module.MODULE_NAME):
      for path in parameters.iterdir():
        path.unlink()
      parameters.rmdir()
      return ""
    raise AssertionError("Unexpected command: " + repr(arguments))

  def arm(_root, identity):
    assert identity == VECTOR
    write(parameters / "arm_vector", "1\n")

  backend = backend_module.PostwriteRestoreEfiBackend(
    source_module, source_hash, SRCVERSION,
    restore_module, restore_hash, restore_srcversion,
    command=command, kernel_release=RELEASE, parameter_writer=arm,
  )
  backend.require_kernel_available(root)
  assert backend.inspect(root, VECTOR) is None
  acceptance_path = root / backend_module.ACCEPTANCE
  production = "a" * 64
  acceptance = {
    "kind": "postwrite-restore-efi-attended-s4-v1",
    "boot_id": BOOT_ID,
    "transition_vector": VECTOR,
    "module_sha256": source_hash,
    "restore_module_sha256": restore_hash,
    "production_uki_sha256": production,
    "method": "operator-attended-cold-power",
    "accepted": True,
  }
  write(acceptance_path, json.dumps(acceptance))
  acceptance_path.chmod(0o600)
  assert backend.require_operator_acceptance(root, VECTOR, BOOT_ID, production) == hashlib.sha256(acceptance_path.read_bytes()).hexdigest()

  attempt_directory = root / "var/lib/pair/s4-vectors" / VECTOR / "attempts" / BOOT_ID
  write(attempt_directory.parent.parent / "s4-attempted", BOOT_ID + "\n")
  write(attempt_directory / "attempt.json", json.dumps({"transition_vector": VECTOR, "boot_id": BOOT_ID}))
  backend.before_arm(root, VECTOR, BOOT_ID, attempt_directory)
  identity = json.loads((attempt_directory / "restore-efi-identity.json").read_text())
  assert identity["module_sha256"] == restore_hash
  assert identity["efi_variable"] == backend_module.RESTORE_VARIABLE.name
  backend.enable(root)
  source_path = Path(backend.prearm(root, VECTOR))
  restore_path = root / backend_module.RESTORE_VARIABLE
  assert source_path.read_bytes() == backend_module.ATTRIBUTES + backend_module.MAGIC + bytes.fromhex(VECTOR[:24]) + b"\x00"
  assert restore_path.read_bytes() == backend_module.ATTRIBUTES + backend_module.RESTORE_MAGIC + bytes.fromhex(VECTOR[:24]) + b"\x00"
  assert backend.restore_marker_path == str(restore_path)
  assert backend.inspect_restore(root, VECTOR) == 0
  restore_path.write_bytes(restore_path.read_bytes()[:-1] + b"\x07")
  source_path.write_bytes(source_path.read_bytes()[:-1] + b"\x04")
  assert backend.inspect(root, VECTOR) == 4
  assert backend.inspect_restore(root, VECTOR) == 7
  backend.cleanup(root, VECTOR, BOOT_ID, attempt_directory)
  assert not backend.loaded(root)
  assert restore_path.is_file()

  wrong = backend_module.PostwriteRestoreEfiBackend(
    source_module, source_hash, SRCVERSION,
    restore_module, "0" * 64, restore_srcversion,
    command=command, kernel_release=RELEASE,
  )
  try:
    wrong.require_kernel_available(root)
    raise AssertionError("Changed restore module hash was accepted")
  except ValueError as error:
    assert "Restore EFI module differs" in str(error)

print("PASS: post-write EFI backend binds exact module, consumed guard, stage and attended recovery")
