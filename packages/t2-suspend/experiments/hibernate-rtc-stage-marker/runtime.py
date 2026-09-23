#!/usr/bin/python3
"""Guarded stock-kernel RTC marker backend for the pair S4 runner.

This does not make S4 safe: it only records a source-side boundary and repairs
the deliberately overwritten RTC on a return that reaches userspace.
"""

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent


def import_local(name, filename):
  spec = importlib.util.spec_from_file_location(name, HERE / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


MARKER = import_local("t2_rtc_runtime_marker", "marker.py")
RECOVERY = import_local("t2_rtc_runtime_recovery", "boot_recovery.py")
MODULE = "mba_hibernate_rtc_stage_marker"
PARAMETERS = Path("sys/module") / MODULE / "parameters"
RECOVERY_UNIT = Path("etc/systemd/system/codex-mba-rtc-return.service")
RECOVERY_SCRIPT = Path("usr/local/libexec/omarchy-t2-rtc-stage-marker/boot_recovery.py")
MARKER_SCRIPT = Path("usr/local/libexec/omarchy-t2-rtc-stage-marker/marker.py")
HASH = re.compile(r"[0-9a-f]{64}\Z")


def command_output(arguments):
  result = subprocess.run(arguments, check=False, capture_output=True, text=True,
                          env={**os.environ, "LC_ALL": "C", "TZ": "UTC"})
  if result.returncode:
    raise RuntimeError("Command failed: " + " ".join(map(str, arguments)) + ": " + result.stderr.strip())
  return result.stdout + result.stderr


def digest(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def fsync_directory(path):
  descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)


class RTCBackend:
  NAME = "rtc"
  PM_TRACE_VALUE = "0"
  MIN_RETURN_STAGE = 2

  def __init__(self, module_path, expected_sha256, command=command_output, kernel_release=None):
    self.module_path = Path(module_path)
    self.expected_sha256 = expected_sha256
    self.command = command
    self.kernel_release = kernel_release or os.uname().release
    self.source_boot_id = None

  def rooted(self, root, path):
    return Path(root) / path

  def parameter(self, root, name):
    return self.rooted(root, PARAMETERS / name)

  def loaded(self, root):
    return self.rooted(root, PARAMETERS).is_dir()

  def synchronized(self):
    return self.command(("timedatectl", "show", "-p", "NTPSynchronized", "--value")).strip() == "yes"

  def raw_rtc(self):
    output = self.command(("hwclock", "--directisa", "--show", "--utc", "--noadjfile", "--verbose"))
    raw = RECOVERY.parse_raw_rtc(output)
    if raw is None:
      raise RuntimeError("Direct-ISA RTC read did not include an exact hardware time")
    return raw

  def inspect(self, root, vector):
    if HASH.fullmatch(vector) is None:
      raise ValueError("Pair vector is malformed")
    if self.source_boot_id is not None:
      directory = self.rooted(root, RECOVERY.STATE / "s4-vectors" / vector / "attempts" / self.source_boot_id)
      archive = directory / "rtc-active.closed.json"
      if archive.exists() or archive.is_symlink():
        if archive.is_symlink() or not archive.is_file() or RECOVERY.load_active(root) is not None:
          raise ValueError("RTC return archive conflicts with an active pointer")
        identity = json.loads(archive.read_text())
        evidence_path = directory / "rtc-return.json"
        if evidence_path.is_symlink() or not evidence_path.is_file():
          raise ValueError("RTC pointer was archived without return-boot evidence")
        evidence = json.loads(evidence_path.read_text())
        for record in (identity, evidence):
          if record.get("vector") != vector or record.get("source_boot_id") != self.source_boot_id or record.get("module_sha256") != self.expected_sha256:
            raise ValueError("RTC return evidence differs from the armed vector or module")
        magic = evidence.get("raw_rtc_magic")
        journal_magic = evidence.get("journal_magic")
        if journal_magic is not None and magic is not None and journal_magic != magic:
          raise ValueError("RTC return journal and raw CMOS markers conflict")
        if magic is None:
          return None
        decoded = MARKER.decode(magic)
        if not decoded["recognized"] or not magic.endswith(":" + str(0)):
          return None
        return int(magic.split(":", 1)[0])
    date, time = self.raw_rtc()
    try:
      decoded = MARKER.decode(MARKER.magic_from_rtc(date, time))
    except ValueError:
      return None
    if not decoded["recognized"] or not decoded["magic"].endswith(":" + str(0)):
      return None
    return int(decoded["magic"].split(":", 1)[0])

  def require_kernel_available(self, root):
    if HASH.fullmatch(self.expected_sha256) is None:
      raise ValueError("Exact RTC marker module SHA-256 is required")
    if not self.module_path.is_absolute() or self.module_path.is_symlink() or not self.module_path.is_file():
      raise ValueError("RTC marker module must be an exact regular absolute file")
    if root == Path("/") and (self.module_path.stat().st_uid != 0 or self.module_path.stat().st_mode & 0o077):
      raise ValueError("RTC marker module must be root-owned and private")
    if digest(self.module_path) != self.expected_sha256:
      raise ValueError("RTC marker module hash differs from the explicit expected hash")
    vermagic = self.command(("modinfo", "-F", "vermagic", str(self.module_path))).strip()
    if not vermagic or vermagic.split()[0] != self.kernel_release:
      raise ValueError("RTC marker module does not match the running kernel")
    if self.loaded(root):
      raise ValueError("RTC marker module is already loaded")
    if RECOVERY.load_active(root) is not None:
      raise ValueError("An RTC active attempt already exists")
    if self.rooted(root, Path("sys/power/pm_trace")).read_text().strip() != "0":
      raise ValueError("Kernel PM trace must be disabled before RTC marker arming")
    if not self.synchronized():
      raise ValueError("System time is not synchronized before RTC marker arming")
    for name, source in ((RECOVERY_UNIT, HERE / "codex-mba-rtc-return.service"),
                         (RECOVERY_SCRIPT, HERE / "boot_recovery.py"),
                         (MARKER_SCRIPT, HERE / "marker.py")):
      installed = self.rooted(root, name)
      if installed.is_symlink() or not installed.is_file() or digest(installed) != digest(source):
        raise ValueError("RTC recovery installation differs from the pinned source: " + str(name))
      if root == Path("/") and installed.stat().st_uid != 0:
        raise ValueError("RTC recovery installation is not root-owned: " + str(name))
    if self.command(("systemctl", "is-enabled", "codex-mba-rtc-return.service")).strip() != "enabled":
      raise ValueError("RTC return recovery service is not enabled")
    date = self.rooted(root, Path("sys/class/rtc/rtc0/date")).read_text().strip()
    time = self.rooted(root, Path("sys/class/rtc/rtc0/time")).read_text().strip()
    rtc = datetime.fromisoformat(date + "T" + time + "+00:00")
    if abs((rtc - datetime.now(timezone.utc)).total_seconds()) > 120:
      raise ValueError("Normal RTC differs from synchronized system time")

  def before_arm(self, root, vector, boot_id, attempt_directory):
    if HASH.fullmatch(vector) is None or RECOVERY.UUID.fullmatch(boot_id) is None:
      raise ValueError("RTC active identity is malformed")
    expected = self.rooted(root, RECOVERY.STATE / "s4-vectors" / vector / "attempts" / boot_id)
    if attempt_directory != expected:
      raise ValueError("RTC attempt directory does not match the pair-wide guard")
    guard = expected.parent.parent / "s4-attempted"
    record = json.loads((expected / "attempt.json").read_text())
    if guard.read_text().strip() != boot_id or record.get("transition_vector") != vector or record.get("boot_id") != boot_id:
      raise ValueError("RTC pointer has no matching consumed pair guard and attempt")
    baseline_date, baseline_time = self.raw_rtc()
    try:
      baseline_magic = MARKER.magic_from_rtc(baseline_date, baseline_time)
    except ValueError:
      baseline_magic = None
    if baseline_magic is not None and MARKER.decode(baseline_magic)["recognized"]:
      raise ValueError("RTC baseline already resembles a T2 stage marker")
    RECOVERY.atomic_new_json(expected / "rtc-baseline.json", {
      "vector": vector,
      "source_boot_id": boot_id,
      "module_sha256": self.expected_sha256,
      "raw_rtc_date": baseline_date,
      "raw_rtc_time": baseline_time,
      "raw_rtc_magic": baseline_magic,
    })
    path = self.rooted(root, RECOVERY.ACTIVE)
    RECOVERY.atomic_new_json(path, {
      "vector": vector,
      "source_boot_id": boot_id,
      "module_sha256": self.expected_sha256,
    })
    RECOVERY.load_active(root)
    self.source_boot_id = boot_id

  def enable(self, root):
    self.command(("insmod", str(self.module_path)))
    if not self.loaded(root) or self.parameter(root, "armed").read_text().strip() not in ("N", "0"):
      raise RuntimeError("RTC marker did not attach in the disarmed state")

  def prearm(self, root, vector):
    self.parameter(root, "armed").write_text("1\n")
    if self.parameter(root, "stage").read_text().strip() != "0" or self.parameter(root, "armed").read_text().strip() not in ("Y", "1"):
      raise RuntimeError("RTC marker did not report an armed stage 0")
    if self.inspect(root, vector) != 0:
      raise RuntimeError("RTC stage-0 raw CMOS readback did not match the armed marker")
    return str(self.parameter(root, "armed"))

  def cleanup(self, root, vector, boot_id, attempt_directory):
    active = RECOVERY.load_active(root)
    archive = attempt_directory / "rtc-active.closed.json"
    if active is not None and (active[0]["vector"] != vector or active[0]["source_boot_id"] != boot_id):
      raise ValueError("RTC active pointer belongs to another attempt")
    if active is None and not archive.exists():
      if self.loaded(root):
        self.parameter(root, "armed").write_text("0\n")
        self.command(("rmmod", MODULE))
      return
    if self.loaded(root):
      self.parameter(root, "armed").write_text("0\n")
    if active is not None:
      raw_date, raw_time = self.raw_rtc()
      try:
        magic = MARKER.magic_from_rtc(raw_date, raw_time)
      except ValueError:
        magic = None
      evidence = attempt_directory / "rtc-source.json"
      if not evidence.exists() and not evidence.is_symlink():
        RECOVERY.atomic_new_json(evidence, {
          "vector": vector,
          "source_boot_id": boot_id,
          "raw_rtc_date": raw_date,
          "raw_rtc_time": raw_time,
          "raw_rtc_magic": magic,
          "decoded": MARKER.decode(magic) if magic else None,
        })
      elif evidence.is_symlink():
        raise ValueError("RTC source evidence is a symlink")
    if not self.synchronized():
      raise RuntimeError("System time is unsynchronized; RTC repair deferred")
    self.command(("hwclock", "--directisa", "--systohc", "--utc", "--noadjfile"))
    repaired_date, repaired_time = self.raw_rtc()
    repaired = datetime.fromisoformat(repaired_date + "T" + repaired_time + "+00:00")
    if abs((repaired - datetime.now(timezone.utc)).total_seconds()) > 120:
      raise RuntimeError("Direct-ISA RTC repair did not match synchronized system time")
    normal = self.rooted(root, Path("sys/class/rtc/rtc0/date"))
    try:
      normal.read_text()
    except OSError:
      if not self.loaded(root):
        raise RuntimeError("RTC guard remains set but marker module is unavailable")
      self.parameter(root, "rtc_repaired").write_text("1\n")
    normal_date = normal.read_text().strip()
    normal_time = self.rooted(root, Path("sys/class/rtc/rtc0/time")).read_text().strip()
    normal_rtc = datetime.fromisoformat(normal_date + "T" + normal_time + "+00:00")
    if abs((normal_rtc - datetime.now(timezone.utc)).total_seconds()) > 120:
      raise RuntimeError("Normal RTC did not recover after guarded repair")
    if self.loaded(root):
      self.command(("rmmod", MODULE))
    if active is not None:
      if archive.exists() or archive.is_symlink():
        raise ValueError("RTC pointer archive already exists")
      os.rename(self.rooted(root, RECOVERY.ACTIVE), archive)
      fsync_directory(self.rooted(root, RECOVERY.STATE))
      fsync_directory(attempt_directory)
