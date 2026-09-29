#!/usr/bin/python3
"""Capture a guarded T2 RTC marker on a new boot, then repair the clock."""

import hashlib
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("t2_rtc_marker", HERE / "marker.py")
MARKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MARKER)

STATE = Path("var/lib/omarchy-t2-hibernation-pair")
ACTIVE = STATE / "rtc-active.json"
BOOT_ID = Path("proc/sys/kernel/random/boot_id")
HASH = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
MAGIC = re.compile(r"Magic number:\s*(\d+:\d+:\d+)")
RAW_RTC = re.compile(r"Time read from Hardware Clock:\s*(\d{4})/(\d{2})/(\d{2})\s+(\d{2}:\d{2}:\d{2})")


def rooted(root, relative):
  return root / relative


def load_active(root):
  path = rooted(root, ACTIVE)
  if not path.exists() and not path.is_symlink():
    return None
  if path.is_symlink() or not path.is_file():
    raise ValueError("RTC active attempt is not a regular file")
  if root == Path("/") and (path.stat().st_uid != 0 or path.stat().st_mode & 0o077):
    raise ValueError("RTC active attempt is not root-owned and private")
  data = json.loads(path.read_text())
  if not isinstance(data, dict):
    raise ValueError("RTC active attempt is malformed")
  vector = data.get("vector")
  source_boot_id = data.get("source_boot_id")
  module_hash = data.get("module_sha256")
  if not isinstance(vector, str) or HASH.fullmatch(vector) is None:
    raise ValueError("RTC active attempt has no exact pair vector")
  if not isinstance(source_boot_id, str) or UUID.fullmatch(source_boot_id) is None:
    raise ValueError("RTC active attempt has no source boot ID")
  if not isinstance(module_hash, str) or HASH.fullmatch(module_hash) is None:
    raise ValueError("RTC active attempt has no module hash")
  directory = rooted(root, STATE / "s4-vectors" / vector)
  guard = directory / "s4-attempted"
  attempt = directory / "attempts" / source_boot_id / "attempt.json"
  if guard.is_symlink() or not guard.is_file() or guard.read_text().strip() != source_boot_id:
    raise ValueError("RTC active attempt does not match the consumed S4 guard")
  if attempt.is_symlink() or not attempt.is_file():
    raise ValueError("RTC active attempt has no durable S4 attempt")
  record = json.loads(attempt.read_text())
  if record.get("transition_vector") != vector or record.get("boot_id") != source_boot_id:
    raise ValueError("RTC active attempt differs from the durable S4 attempt")
  return data, attempt.parent


def current_boot_id(root):
  value = rooted(root, BOOT_ID).read_text().strip()
  if UUID.fullmatch(value) is None:
    raise ValueError("Current boot ID is malformed")
  return value


def parse_journal_magic(output):
  values = MAGIC.findall(output)
  if len(values) != 1:
    return None
  return values[0]


def parse_raw_rtc(output):
  match = RAW_RTC.search(output)
  if match is None:
    return None
  year, month, day, time = match.groups()
  return f"{year}-{month}-{day}", time


def run_output(arguments):
  result = subprocess.run(arguments, check=False, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C", "TZ": "UTC"})
  if result.returncode:
    raise RuntimeError("Command failed: " + " ".join(arguments) + ": " + result.stderr.strip())
  return result.stdout + result.stderr


def atomic_new_json(path, data):
  encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(path, flags, 0o600)
  try:
    with os.fdopen(descriptor, "wb") as stream:
      stream.write(encoded)
      stream.flush()
      os.fsync(stream.fileno())
  except Exception:
    raise
  directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
  try:
    os.fsync(directory)
  finally:
    os.close(directory)
  return hashlib.sha256(encoded).hexdigest()


def capture(root, journal_output, raw_output):
  active = load_active(root)
  if active is None:
    return {"status": "inactive"}
  identity, attempt_directory = active
  boot_id = current_boot_id(root)
  if boot_id == identity["source_boot_id"]:
    return {"status": "source-boot-no-return", "boot_id": boot_id}

  magic = parse_journal_magic(journal_output)
  decoded = MARKER.decode(magic) if magic else None
  raw = parse_raw_rtc(raw_output)
  raw_magic = None
  if raw is not None:
    try:
      raw_magic = MARKER.magic_from_rtc(*raw)
    except ValueError:
      pass
  evidence = {
    "status": "captured-before-clock-repair",
    "source_boot_id": identity["source_boot_id"],
    "return_boot_id": boot_id,
    "vector": identity["vector"],
    "module_sha256": identity["module_sha256"],
    "journal_magic": magic,
    "journal_marker": decoded,
    "raw_rtc_date": raw[0] if raw else None,
    "raw_rtc_time": raw[1] if raw else None,
    "raw_rtc_magic": raw_magic,
    "raw_matches_journal": raw_magic == magic if raw_magic and magic else None,
  }
  output = attempt_directory / "rtc-return.json"
  if output.is_symlink():
    raise ValueError("RTC return evidence path is a symlink")
  if output.exists():
    saved = json.loads(output.read_text())
    if any(saved.get(name) != evidence[name] for name in ("source_boot_id", "return_boot_id", "vector", "module_sha256")):
      raise ValueError("Existing RTC return evidence belongs to a different boot or vector")
    evidence = saved
  else:
    atomic_new_json(output, evidence)
  return {**evidence, "evidence_path": str(output)}


def repair(root, captured, ntp_synchronized, restore_clock, read_normal_rtc, now_utc):
  if captured["status"] != "captured-before-clock-repair":
    return captured
  output = Path(captured["evidence_path"]).parent / "rtc-repair.json"
  if output.is_symlink():
    raise ValueError("RTC repair evidence path is a symlink")
  if output.exists():
    saved = json.loads(output.read_text())
    if saved.get("return_boot_id") != captured["return_boot_id"] or saved.get("vector") != captured["vector"]:
      raise ValueError("Existing RTC repair evidence belongs to another boot or vector")
    return {**saved, "evidence_path": str(output)}
  if not ntp_synchronized():
    raise RuntimeError("Waiting for synchronized system time before RTC repair")
  restore_clock()
  raw_date, raw_time = read_normal_rtc()
  if not raw_date or not raw_time:
    raise RuntimeError("Normal RTC reads did not recover after clock repair")
  try:
    rtc_instant = datetime.fromisoformat(raw_date + "T" + raw_time + "+00:00")
  except ValueError as error:
    raise RuntimeError("Repaired RTC date/time is malformed") from error
  if abs((rtc_instant - now_utc()).total_seconds()) > 120:
    raise RuntimeError("Repaired RTC differs from synchronized system time")
  result = {
    "status": "rtc-repaired-after-evidence",
    "return_boot_id": captured["return_boot_id"],
    "vector": captured["vector"],
    "rtc_date": raw_date,
    "rtc_time": raw_time,
  }
  atomic_new_json(output, result)
  return {**result, "evidence_path": str(output)}


def archive_active(root, repaired):
  if repaired["status"] != "rtc-repaired-after-evidence":
    raise ValueError("Cannot archive an unrepaired RTC attempt")
  active = load_active(root)
  if active is None:
    raise ValueError("RTC active attempt disappeared before archival")
  identity, attempt_directory = active
  if identity["vector"] != repaired["vector"] or current_boot_id(root) != repaired["return_boot_id"]:
    raise ValueError("RTC repair does not match the active vector and return boot")
  destination = attempt_directory / "rtc-active.closed.json"
  if destination.exists() or destination.is_symlink():
    raise ValueError("An RTC active archive already exists")
  os.rename(rooted(root, ACTIVE), destination)
  for directory in (rooted(root, STATE), attempt_directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
      os.fsync(descriptor)
    finally:
      os.close(descriptor)
  return str(destination)


def main():
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  root = Path("/")
  if load_active(root) is None:
    print(json.dumps({"status": "inactive"}))
    return
  try:
    journal = run_output(("journalctl", "-b", "-k", "-o", "cat", "--no-pager"))
  except RuntimeError as error:
    journal = "Kernel journal read failed: " + str(error)
  try:
    raw = run_output(("hwclock", "--directisa", "--show", "--utc", "--noadjfile", "--verbose"))
  except RuntimeError as error:
    raw = "Raw RTC read failed: " + str(error)
  captured = capture(root, journal, raw)
  if captured["status"] != "captured-before-clock-repair":
    print(json.dumps(captured, indent=2, sort_keys=True))
    return

  def ntp_synchronized():
    return run_output(("timedatectl", "show", "-p", "NTPSynchronized", "--value")).strip() == "yes"

  def restore_clock():
    run_output(("hwclock", "--directisa", "--systohc", "--utc", "--noadjfile"))

  def read_normal_rtc():
    return (rooted(root, Path("sys/class/rtc/rtc0/date")).read_text().strip(),
            rooted(root, Path("sys/class/rtc/rtc0/time")).read_text().strip())

  result = repair(root, captured, ntp_synchronized, restore_clock, read_normal_rtc, lambda: datetime.now(timezone.utc))
  result["active_archive"] = archive_active(root, result)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
