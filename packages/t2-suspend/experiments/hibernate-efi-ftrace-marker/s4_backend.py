#!/usr/bin/python3
"""Offline-only external EFI ftrace marker backend for the UKI-pair S4 runner.

The EFI write at hibernate() entry passed one stock freezer test, but neither
forced-power persistence nor an S4 recovery actuator has been qualified.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
MARKER_PATH = HERE.parent / "hibernate-efi-stage-marker/marker.py"
SPEC = importlib.util.spec_from_file_location("t2_ftrace_s4_efi_layout", MARKER_PATH)
MARKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MARKER)

MODULE_NAME = "mba_hibernate_efi_ftrace_marker"
PARAMETERS = Path("sys/module") / MODULE_NAME / "parameters"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def command_output(arguments):
  result = subprocess.run(arguments, check=True, capture_output=True, text=True)
  return result.stdout


def atomic_new_json(path, data):
  value = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(path, flags, 0o600)
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(value)
    stream.flush()
    os.fsync(stream.fileno())
  directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
  try:
    os.fsync(directory)
  finally:
    os.close(directory)


class FtraceEfiBackend:
  NAME = "ftrace-efi"
  PM_TRACE_VALUE = "0"
  MIN_RETURN_STAGE = 2
  EXECUTION_QUALIFIED = False

  def __init__(self, module_path, expected_sha256, expected_srcversion,
               command=command_output, kernel_release=None, parameter_writer=None):
    self.module_path = Path(module_path)
    self.expected_sha256 = expected_sha256
    self.expected_srcversion = expected_srcversion
    self.command = command
    self.kernel_release = kernel_release or os.uname().release
    self.parameter_writer = parameter_writer
    self.vector = None
    self.source_boot_id = None

  def parameter(self, root, name):
    return Path(root) / PARAMETERS / name

  def value(self, root, name):
    path = self.parameter(root, name)
    if path.is_symlink() or not path.is_file():
      raise ValueError("Ftrace EFI marker parameter is absent: " + name)
    return path.read_text().strip()

  def loaded(self, root):
    return (Path(root) / PARAMETERS).is_dir()

  def inspect(self, root, vector):
    return MARKER.inspect(Path(root), vector)

  def require_kernel_available(self, root):
    root = Path(root)
    if SHA256.fullmatch(self.expected_sha256) is None or not self.expected_srcversion:
      raise ValueError("Exact EFI marker module hash and source version are required")
    if not self.module_path.is_absolute() or self.module_path.is_symlink() or not self.module_path.is_file():
      raise ValueError("EFI marker module must be an exact regular absolute file")
    if root == Path("/") and (self.module_path.stat().st_uid != 0 or self.module_path.stat().st_mode & 0o077):
      raise ValueError("EFI marker module must be root-owned and private")
    if hashlib.sha256(self.module_path.read_bytes()).hexdigest() != self.expected_sha256:
      raise ValueError("EFI marker module hash differs from the explicit expected hash")
    vermagic = self.command(("modinfo", "-F", "vermagic", str(self.module_path))).split()
    if not vermagic or vermagic[0] != self.kernel_release:
      raise ValueError("EFI marker module does not match the running kernel")
    if self.command(("modinfo", "-F", "srcversion", str(self.module_path))).strip() != self.expected_srcversion:
      raise ValueError("EFI marker module source version differs")
    if self.loaded(root):
      raise ValueError("EFI marker module is already loaded")
    if (root / "sys/power/pm_trace").read_text().strip() != "0":
      raise ValueError("Kernel PM trace must be disabled before EFI marker arming")

  def before_arm(self, root, vector, boot_id, attempt_directory):
    root = Path(root)
    if SHA256.fullmatch(vector) is None or UUID.fullmatch(boot_id) is None:
      raise ValueError("EFI ftrace attempt identity is malformed")
    attempt_directory = Path(attempt_directory)
    guard = attempt_directory.parent.parent / "s4-attempted"
    attempt = attempt_directory / "attempt.json"
    if guard.is_symlink() or attempt.is_symlink():
      raise ValueError("EFI ftrace guard or attempt is a symlink")
    record = json.loads(attempt.read_text())
    if (guard.read_text().strip() != boot_id or
        record.get("transition_vector") != vector or record.get("boot_id") != boot_id):
      raise ValueError("EFI ftrace prearm lacks an exact consumed pair guard")
    if self.inspect(root, vector) is not None:
      raise ValueError("EFI ftrace stage marker already exists")
    atomic_new_json(attempt_directory / "ftrace-efi-identity.json", {
      "kind": "ftrace-efi-s4-identity-v1",
      "vector": vector,
      "source_boot_id": boot_id,
      "module_sha256": self.expected_sha256,
      "module_srcversion": self.expected_srcversion,
    })
    self.vector = vector
    self.source_boot_id = boot_id

  def enable(self, root):
    if self.vector is None or self.source_boot_id is None:
      raise ValueError("EFI ftrace backend has no consumed attempt identity")
    self.command(("insmod", str(self.module_path)))
    if (not self.loaded(root) or self.value(root, "arm_vector") != "0" or
        self.value(root, "stage") != "0" or
        self.value(root, "probe_consumed") not in ("N", "0") or
        self.value(root, "entry_consumed") not in ("N", "0")):
      raise RuntimeError("EFI ftrace module did not load disarmed and unused")

  def prearm(self, root, vector):
    root = Path(root)
    if vector != self.vector or not self.loaded(root):
      raise ValueError("EFI ftrace prearm differs from its loaded attempt")
    if root == Path("/") and self.parameter_writer is not None:
      raise ValueError("Live EFI ftrace arm cannot inject a test writer")
    path = MARKER.marker_path(root)
    if path.exists() or path.is_symlink():
      raise ValueError("EFI ftrace marker already exists; preserve it")
    value = MARKER.ATTRIBUTES + MARKER.payload(vector, 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
      if os.write(descriptor, value) != len(value):
        raise OSError("Short EFI ftrace stage-0 write")
    finally:
      os.close(descriptor)
    if self.inspect(root, vector) != 0:
      raise ValueError("EFI ftrace stage-0 readback differs")
    if self.parameter_writer is None:
      self.parameter(root, "arm_vector").write_text(vector + "\n")
    else:
      self.parameter_writer(root, vector)
    if self.value(root, "arm_vector") != "1" or self.value(root, "stage") != "0" or self.inspect(root, vector) != 0:
      raise RuntimeError("EFI ftrace module did not arm at exact stage 0")
    return str(path)

  def cleanup(self, root, vector, boot_id, attempt_directory):
    if self.vector is None and not self.loaded(root):
      return
    if vector != self.vector or boot_id != self.source_boot_id:
      raise ValueError("EFI ftrace cleanup differs from its armed attempt")
    if self.loaded(root):
      self.command(("rmmod", MODULE_NAME))
      if self.loaded(root):
        raise RuntimeError("EFI ftrace module remained loaded after cleanup")
    # Preserve the EFI variable and guard even after a returned error.
