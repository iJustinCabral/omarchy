#!/usr/bin/python3
"""Exercise the RTC S4 backend against a disposable synthetic sysfs tree."""

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile


source = Path(__file__).resolve().parents[1] / "experiments/hibernate-rtc-stage-marker/runtime.py"
spec = importlib.util.spec_from_file_location("t2_rtc_runtime_tested", source)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
VECTOR = "a" * 64
BOOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MARKER_DATE = "2048-05-13"
MARKER_TIME = "00:00:01"


def write(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(value)


def fixture(base):
  root = base / "root"
  module = base / "mba_hibernate_rtc_stage_marker.ko"
  module.parent.mkdir(parents=True)
  module.write_bytes(b"synthetic marker module")
  module_hash = hashlib.sha256(module.read_bytes()).hexdigest()
  write(root / "sys/power/pm_trace", "0\n")
  for destination, original in (
    (runtime.RECOVERY_UNIT, source.parent / "codex-mba-rtc-return.service"),
    (runtime.RECOVERY_SCRIPT, source.parent / "boot_recovery.py"),
    (runtime.MARKER_SCRIPT, source.parent / "marker.py"),
  ):
    write(root / destination, original.read_text())
  now = datetime.now(timezone.utc)
  write(root / "sys/class/rtc/rtc0/date", now.strftime("%Y-%m-%d") + "\n")
  write(root / "sys/class/rtc/rtc0/time", now.strftime("%H:%M:%S") + "\n")
  attempt_directory = root / runtime.RECOVERY.STATE / "s4-vectors" / VECTOR / "attempts" / BOOT
  write(attempt_directory / "attempt.json", json.dumps({"transition_vector": VECTOR, "boot_id": BOOT}))
  write(attempt_directory.parent.parent / "s4-attempted", BOOT + "\n")
  state = {"synchronized": True, "service": True, "raw_marker": False, "loaded": False}

  def command(arguments):
    args = tuple(arguments)
    if args[:3] == ("modinfo", "-F", "vermagic"):
      return "test-kernel SMP preempt\n"
    if args[:2] == ("systemctl", "is-enabled"):
      return "enabled\n" if state["service"] else "disabled\n"
    if args[:2] == ("timedatectl", "show"):
      return "yes\n" if state["synchronized"] else "no\n"
    if args[:1] == ("insmod",):
      write(root / runtime.PARAMETERS / "armed", "0\n")
      write(root / runtime.PARAMETERS / "stage", "0\n")
      write(root / runtime.PARAMETERS / "rtc_repaired", "0\n")
      state["loaded"] = True
      return ""
    if args[:1] == ("rmmod",):
      shutil.rmtree(root / runtime.PARAMETERS)
      state["loaded"] = False
      return ""
    if args[:2] == ("hwclock", "--directisa"):
      if "--systohc" in args:
        state["raw_marker"] = False
        return ""
      if "--show" in args:
        if state["raw_marker"] or (state["loaded"] and (root / runtime.PARAMETERS / "armed").read_text().strip() == "1"):
          state["raw_marker"] = True
          date, time = MARKER_DATE, MARKER_TIME
        else:
          now = datetime.now(timezone.utc)
          date, time = now.strftime("%Y/%m/%d"), now.strftime("%H:%M:%S")
        return "Time read from Hardware Clock: " + date.replace("-", "/") + " " + time + "\n"
    raise AssertionError("Unexpected command " + repr(args))

  backend = runtime.RTCBackend(module, module_hash, command=command, kernel_release="test-kernel")
  return root, module, attempt_directory, backend, state


def rejects(action, phrase):
  try:
    action()
    raise AssertionError("Unexpected success: " + phrase)
  except (RuntimeError, ValueError) as error:
    assert phrase in str(error), str(error)


with tempfile.TemporaryDirectory(prefix="t2-rtc-runtime-") as temporary:
  base = Path(temporary)
  root, module, attempt, backend, state = fixture(base / "success")
  backend.require_kernel_available(root)
  rejects(lambda: backend.before_arm(root, VECTOR, BOOT, attempt / "wrong"), "does not match")
  backend.before_arm(root, VECTOR, BOOT, attempt)
  assert runtime.RECOVERY.load_active(root)[0]["module_sha256"] == backend.expected_sha256
  assert json.loads((attempt / "rtc-baseline.json").read_text())["module_sha256"] == backend.expected_sha256
  rejects(lambda: backend.require_kernel_available(root), "already exists")
  backend.enable(root)
  assert backend.prearm(root, VECTOR).endswith("/parameters/armed")
  assert backend.inspect(root, VECTOR) == 0
  backend.cleanup(root, VECTOR, BOOT, attempt)
  assert not state["loaded"]
  assert runtime.RECOVERY.load_active(root) is None
  assert (attempt / "rtc-active.closed.json").is_file()
  assert json.loads((attempt / "rtc-source.json").read_text())["raw_rtc_magic"] == "0:928:0"

  root, module, attempt, backend, state = fixture(base / "bad-hash")
  module.write_bytes(b"changed module")
  rejects(lambda: backend.require_kernel_available(root), "hash differs")
  assert not (root / runtime.RECOVERY.ACTIVE).exists()

  root, module, attempt, backend, state = fixture(base / "missing-return-service")
  state["service"] = False
  rejects(lambda: backend.require_kernel_available(root), "not enabled")

  root, module, attempt, backend, state = fixture(base / "readback-failure")
  backend.require_kernel_available(root)
  backend.before_arm(root, VECTOR, BOOT, attempt)
  backend.enable(root)
  original_inspect = backend.inspect
  backend.inspect = lambda _root, _vector: None
  rejects(lambda: backend.prearm(root, VECTOR), "readback did not match")
  backend.inspect = original_inspect
  assert (root / runtime.RECOVERY.ACTIVE).is_file()
  backend.cleanup(root, VECTOR, BOOT, attempt)
  assert (attempt / "rtc-active.closed.json").is_file()

  root, module, attempt, backend, state = fixture(base / "return-boot-repaired")
  backend.before_arm(root, VECTOR, BOOT, attempt)
  backend.enable(root)
  backend.prearm(root, VECTOR)
  write(attempt / "rtc-return.json", json.dumps({
    "vector": VECTOR,
    "source_boot_id": BOOT,
    "module_sha256": backend.expected_sha256,
    "raw_rtc_magic": "3:928:0",
    "journal_magic": "3:928:0",
  }))
  (root / runtime.RECOVERY.ACTIVE).rename(attempt / "rtc-active.closed.json")
  state["raw_marker"] = False
  assert backend.inspect(root, VECTOR) == 3
  backend.cleanup(root, VECTOR, BOOT, attempt)
  assert not (attempt / "rtc-source.json").exists()
  assert not state["loaded"]

  root, module, attempt, backend, state = fixture(base / "conflicting-return-evidence")
  backend.before_arm(root, VECTOR, BOOT, attempt)
  write(attempt / "rtc-return.json", json.dumps({
    "vector": VECTOR,
    "source_boot_id": BOOT,
    "module_sha256": backend.expected_sha256,
    "raw_rtc_magic": "3:928:0",
    "journal_magic": "4:928:0",
  }))
  (root / runtime.RECOVERY.ACTIVE).rename(attempt / "rtc-active.closed.json")
  rejects(lambda: backend.inspect(root, VECTOR), "conflict")

  root, module, attempt, backend, state = fixture(base / "unsynchronized-cleanup")
  backend.before_arm(root, VECTOR, BOOT, attempt)
  backend.enable(root)
  backend.prearm(root, VECTOR)
  state["synchronized"] = False
  rejects(lambda: backend.cleanup(root, VECTOR, BOOT, attempt), "unsynchronized")
  assert (root / runtime.RECOVERY.ACTIVE).is_file()
  assert state["loaded"]
  assert (attempt / "rtc-source.json").is_file()

print("PASS: RTC runtime requires exact module/recovery identity, preserves active guard, verifies stage 0 and repairs or defers cleanup")
