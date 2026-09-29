#!/usr/bin/python3
"""Exercise guarded RTC return capture and clock repair without host writes."""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-rtc-stage-marker/boot_recovery.py"
spec = importlib.util.spec_from_file_location("t2_rtc_boot_recovery", script)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

SOURCE_BOOT = "11111111-2222-3333-4444-555555555555"
RETURN_BOOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
VECTOR = "a" * 64
MODULE = "b" * 64


def write(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(value)


def fixture(base):
  root = base / "root"
  write(root / recovery.BOOT_ID, RETURN_BOOT + "\n")
  state = root / recovery.STATE
  directory = state / "s4-vectors" / VECTOR
  write(directory / "s4-attempted", SOURCE_BOOT + "\n")
  write(directory / "attempts" / SOURCE_BOOT / "attempt.json", json.dumps({
    "boot_id": SOURCE_BOOT,
    "transition_vector": VECTOR,
    "state": "transition-armed",
  }))
  write(root / recovery.ACTIVE, json.dumps({
    "vector": VECTOR,
    "source_boot_id": SOURCE_BOOT,
    "module_sha256": MODULE,
  }))
  return root, directory / "attempts" / SOURCE_BOOT


def raw_for(stage):
  encoded = stage + 16 * 928
  year = encoded % 100
  encoded //= 100
  month = encoded % 12 + 1
  encoded //= 12
  day = encoded % 28 + 1
  encoded //= 28
  hour = encoded % 24
  encoded //= 24
  minute = encoded * 3
  return f"Time read from Hardware Clock: 20{year:02d}/{month:02d}/{day:02d} {hour:02d}:{minute:02d}:01\n"


with tempfile.TemporaryDirectory(prefix="t2-rtc-boot-recovery-") as temporary:
  base = Path(temporary)
  assert recovery.capture(base, "", "")["status"] == "inactive"
  root, attempt = fixture(base / "success")
  journal = "PM:  Magic number: 3:928:0\n"
  raw = raw_for(3)
  captured = recovery.capture(root, journal, raw)
  assert captured["journal_marker"]["stage"] == "image-write-returned-platform-entry-started"
  assert captured["raw_matches_journal"] is True
  assert (attempt / "rtc-return.json").is_file()
  assert recovery.capture(root, journal, "Time read from Hardware Clock: 2026/09/23 22:00:00\n") == captured

  calls = []
  now = lambda: datetime(2026, 9, 23, 22, 50, 0, tzinfo=timezone.utc)
  try:
    recovery.repair(root, captured, lambda: False, lambda: calls.append("restore"), lambda: ("2026-09-23", "22:50:00"), now)
    raise AssertionError("Unsynchronized clock was accepted for RTC repair")
  except RuntimeError as error:
    assert "synchronized system time" in str(error)
  assert calls == []
  repaired = recovery.repair(root, captured, lambda: True, lambda: calls.append("restore"), lambda: ("2026-09-23", "22:50:00"), now)
  assert repaired["status"] == "rtc-repaired-after-evidence"
  assert calls == ["restore"]
  assert recovery.repair(root, captured, lambda: True, lambda: calls.append("unexpected"), lambda: ("", ""), now) == repaired
  assert calls == ["restore"]
  archived = recovery.archive_active(root, repaired)
  assert archived.endswith("rtc-active.closed.json")
  assert Path(archived).is_file()
  assert recovery.capture(root, journal, raw)["status"] == "inactive"

  root, attempt = fixture(base / "same-boot")
  write(root / recovery.BOOT_ID, SOURCE_BOOT + "\n")
  assert recovery.capture(root, journal, raw)["status"] == "source-boot-no-return"
  assert not (attempt / "rtc-return.json").exists()

  root, attempt = fixture(base / "unknown-marker")
  unknown = recovery.capture(root, "PM: Magic number: 1:5:8\n", raw)
  assert unknown["journal_marker"]["recognized"] is False
  assert unknown["raw_matches_journal"] is False

  root, attempt = fixture(base / "wrong-guard")
  write(root / recovery.STATE / "s4-vectors" / VECTOR / "s4-attempted", RETURN_BOOT + "\n")
  try:
    recovery.capture(root, journal, raw)
    raise AssertionError("Mismatched S4 guard was accepted")
  except ValueError as error:
    assert "consumed S4 guard" in str(error)
  assert not (attempt / "rtc-return.json").exists()

  root, attempt = fixture(base / "symlink-active")
  active = root / recovery.ACTIVE
  active.unlink()
  active.symlink_to(root / "missing")
  try:
    recovery.capture(root, journal, raw)
    raise AssertionError("Symlinked active attempt was accepted")
  except ValueError as error:
    assert "not a regular file" in str(error)

print("PASS: guarded RTC return evidence precedes synchronized clock repair and is idempotent")
