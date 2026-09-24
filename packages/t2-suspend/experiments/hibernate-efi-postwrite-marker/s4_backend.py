#!/usr/bin/python3
"""Guarded, operator-attended EFI post-write marker for a distinct pair S4 vector."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


MODULE_NAME = "mba_hibernate_efi_postwrite_marker"
PARAMETERS = Path("sys/module") / MODULE_NAME / "parameters"
VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2PostwriteStage-47a2fceb-87bc-4e58-8d83-23f62ffb3393")
V2_VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2PostwriteStageV2-47a2fceb-87bc-4e58-8d83-23f62ffb3393")
RESTORE_VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2RestoreStage-5e17d2ad-021f-4d45-a8e5-f4c191983e27")
ACCEPTANCE = Path("var/lib/omarchy-t2-postwrite-marker/recovery-acceptance.json")
V2_ACCEPTANCE = Path("var/lib/omarchy-t2-postwrite-marker/recovery-acceptance-v2.json")
ATTRIBUTES = b"\x07\x00\x00\x00"
MAGIC = b"MBPW"
RESTORE_MAGIC = b"MBRS"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


def command_output(arguments):
  return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def atomic_new_json(path, data):
  value = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
  descriptor = os.open(path, flags, 0o600)
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(value)
    stream.flush()
    os.fsync(stream.fileno())
  directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
  try:
    os.fsync(directory)
  finally:
    os.close(directory)


class PostwriteEfiBackend:
  NAME = "postwrite-efi"
  PM_TRACE_VALUE = "0"
  MIN_RETURN_STAGE = 3

  def __init__(self, module_path, expected_sha256, expected_srcversion,
               command=command_output, kernel_release=None, parameter_writer=None,
               source_variable_version="v1"):
    if source_variable_version not in ("v1", "v2"):
      raise ValueError("Unknown post-write EFI source variable version")
    self.module_path = Path(module_path)
    self.expected_sha256 = expected_sha256
    self.expected_srcversion = expected_srcversion
    self.command = command
    self.kernel_release = kernel_release or os.uname().release
    self.parameter_writer = parameter_writer
    self.source_variable_version = source_variable_version
    self.source_variable = VARIABLE if source_variable_version == "v1" else V2_VARIABLE
    self.acceptance_path = ACCEPTANCE if source_variable_version == "v1" else V2_ACCEPTANCE
    self.vector = None
    self.source_boot_id = None

  def parameter(self, root, name):
    return Path(root) / PARAMETERS / name

  def value(self, root, name):
    path = self.parameter(root, name)
    if path.is_symlink() or not path.is_file():
      raise ValueError("Post-write EFI marker parameter is absent: " + name)
    return path.read_text().strip()

  def loaded(self, root):
    return (Path(root) / PARAMETERS).is_dir()

  def inspect(self, root, vector):
    if SHA256.fullmatch(vector) is None:
      raise ValueError("Post-write EFI marker vector is malformed")
    path = Path(root) / self.source_variable
    if path.is_symlink():
      raise ValueError("Post-write EFI marker is symlinked")
    if not path.exists():
      return None
    if not path.is_file():
      raise ValueError("Post-write EFI marker is not a regular file")
    value = path.read_bytes()
    if (len(value) != 21 or value[:4] != ATTRIBUTES or
        value[4:8] != MAGIC or value[8:20] != bytes.fromhex(vector[:24]) or
        value[20] > 4):
      raise ValueError("Post-write EFI marker does not match the exact pair vector")
    return value[20]

  def require_kernel_available(self, root):
    root = Path(root)
    if SHA256.fullmatch(self.expected_sha256) is None or not self.expected_srcversion:
      raise ValueError("Exact post-write EFI module hash and source version are required")
    if not self.module_path.is_absolute() or self.module_path.is_symlink() or not self.module_path.is_file():
      raise ValueError("Post-write EFI module must be an exact regular absolute file")
    metadata = self.module_path.stat()
    if root.resolve() == Path("/") and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600):
      raise ValueError("Post-write EFI module must be root-owned and private")
    if hashlib.sha256(self.module_path.read_bytes()).hexdigest() != self.expected_sha256:
      raise ValueError("Post-write EFI module differs from the explicit hash")
    vermagic = self.command(("modinfo", "-F", "vermagic", str(self.module_path))).split()
    if not vermagic or vermagic[0] != self.kernel_release:
      raise ValueError("Post-write EFI module does not match the running kernel")
    if self.command(("modinfo", "-F", "srcversion", str(self.module_path))).strip() != self.expected_srcversion:
      raise ValueError("Post-write EFI module source version differs")
    if self.source_variable_version == "v2" and self.command(("modinfo", "-F", "mba_postwrite_variable", str(self.module_path))).strip() != "v2":
      raise ValueError("Post-write EFI module does not declare the V2 variable")
    if self.loaded(root):
      raise ValueError("Post-write EFI module is already loaded")
    if (root / "sys/power/pm_trace").read_text().strip() != "0":
      raise ValueError("PM trace must be disabled before post-write EFI marker arming")

  def require_operator_acceptance(self, root, vector, boot_id, production_uki_sha256):
    if (SHA256.fullmatch(vector) is None or UUID.fullmatch(boot_id) is None or
        SHA256.fullmatch(production_uki_sha256) is None):
      raise ValueError("Post-write EFI recovery identity is malformed")
    path = Path(root) / self.acceptance_path
    if path.is_symlink() or not path.is_file():
      raise ValueError("Boot-bound operator recovery acceptance is missing or symlinked")
    metadata = path.stat()
    expected_uid = 0 if Path(root).resolve() == Path("/") else os.geteuid()
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
      raise ValueError("Operator recovery acceptance has an unsafe owner or mode")
    raw = path.read_bytes()
    try:
      record = json.loads(raw)
    except json.JSONDecodeError as error:
      raise ValueError("Operator recovery acceptance is malformed") from error
    expected = {
      "kind": "postwrite-efi-attended-s4-" + self.source_variable_version,
      "boot_id": boot_id,
      "transition_vector": vector,
      "module_sha256": self.expected_sha256,
      "production_uki_sha256": production_uki_sha256,
      "method": "operator-attended-cold-power",
      "accepted": True,
    }
    if self.source_variable_version == "v2":
      expected["source_efi_variable"] = self.source_variable.name
    if record != expected:
      raise ValueError("Operator recovery acceptance differs from this boot and vector")
    return hashlib.sha256(raw).hexdigest()

  def before_arm(self, root, vector, boot_id, attempt_directory):
    if SHA256.fullmatch(vector) is None or UUID.fullmatch(boot_id) is None:
      raise ValueError("Post-write EFI attempt identity is malformed")
    attempt_directory = Path(attempt_directory)
    guard = attempt_directory.parent.parent / "s4-attempted"
    attempt = attempt_directory / "attempt.json"
    if guard.is_symlink() or attempt.is_symlink() or not guard.is_file() or not attempt.is_file():
      raise ValueError("Post-write EFI guard or attempt is missing or symlinked")
    record = json.loads(attempt.read_text())
    if (guard.read_text().strip() != boot_id or
        record.get("transition_vector") != vector or record.get("boot_id") != boot_id):
      raise ValueError("Post-write EFI prearm lacks an exact consumed pair guard")
    if self.inspect(root, vector) is not None:
      raise ValueError("Post-write EFI marker already exists")
    atomic_new_json(attempt_directory / "postwrite-efi-identity.json", {
      "kind": "postwrite-efi-s4-identity-v1",
      "vector": vector,
      "source_boot_id": boot_id,
      "module_sha256": self.expected_sha256,
      "module_srcversion": self.expected_srcversion,
      "recovery": "operator-attended-cold-power",
      "source_efi_variable": self.source_variable.name,
    })
    self.vector = vector
    self.source_boot_id = boot_id

  def enable(self, root):
    if self.vector is None or self.source_boot_id is None:
      raise ValueError("Post-write EFI backend has no consumed attempt identity")
    self.command(("insmod", str(self.module_path)))
    if (not self.loaded(root) or self.value(root, "arm_vector") != "0" or
        self.value(root, "stage") != "0" or self.value(root, "last_efi_status") != "0"):
      raise RuntimeError("Post-write EFI module did not load disarmed")

  def prearm(self, root, vector):
    if vector != self.vector or not self.loaded(root):
      raise ValueError("Post-write EFI prearm differs from its loaded attempt")
    if Path(root).resolve() == Path("/") and self.parameter_writer is not None:
      raise ValueError("Live post-write EFI arm cannot inject a test writer")
    path = Path(root) / self.source_variable
    if path.exists() or path.is_symlink():
      raise ValueError("Post-write EFI marker already exists; preserve it")
    value = ATTRIBUTES + MAGIC + bytes.fromhex(vector[:24]) + b"\x00"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
      if os.write(descriptor, value) != len(value):
        raise OSError("Short post-write EFI stage-0 write")
    finally:
      os.close(descriptor)
    if self.inspect(root, vector) != 0:
      raise ValueError("Post-write EFI stage-0 readback differs")
    if self.parameter_writer is None:
      self.parameter(root, "arm_vector").write_text(vector + "\n")
    else:
      self.parameter_writer(root, vector)
    if self.value(root, "arm_vector") != "1" or self.value(root, "stage") != "0" or self.inspect(root, vector) != 0:
      raise RuntimeError("Post-write EFI module did not arm at exact stage 0")
    return str(path)

  def cleanup(self, root, vector, boot_id, attempt_directory):
    if self.vector is None and not self.loaded(root):
      return
    if vector != self.vector or boot_id != self.source_boot_id:
      raise ValueError("Post-write EFI cleanup differs from its armed attempt")
    if self.loaded(root):
      self.command(("rmmod", MODULE_NAME))
      if self.loaded(root):
        raise RuntimeError("Post-write EFI module remained loaded after cleanup")
    # Keep the EFI variable and guard for returned-boot fault attribution.


class PostwriteRestoreEfiBackend(PostwriteEfiBackend):
  """Bind a second EFI stage-0 marker for the isolated cold-resume initramfs."""

  def __init__(self, module_path, expected_sha256, expected_srcversion,
               restore_module_path, restore_module_sha256, restore_module_srcversion,
               command=command_output, kernel_release=None, parameter_writer=None,
               source_variable_version="v1"):
    super().__init__(module_path, expected_sha256, expected_srcversion,
                     command=command, kernel_release=kernel_release,
                     parameter_writer=parameter_writer,
                     source_variable_version=source_variable_version)
    self.restore_module_path = Path(restore_module_path)
    self.restore_module_sha256 = restore_module_sha256
    self.restore_module_srcversion = restore_module_srcversion
    self.restore_marker_path = None

  def inspect_restore(self, root, vector):
    if SHA256.fullmatch(vector) is None:
      raise ValueError("Restore EFI marker vector is malformed")
    path = Path(root) / RESTORE_VARIABLE
    if path.is_symlink():
      raise ValueError("Restore EFI marker is symlinked")
    if not path.exists():
      return None
    if not path.is_file():
      raise ValueError("Restore EFI marker is not a regular file")
    value = path.read_bytes()
    if (len(value) != 21 or value[:4] != ATTRIBUTES or
        value[4:8] != RESTORE_MAGIC or value[8:20] != bytes.fromhex(vector[:24]) or
        value[20] > 7):
      raise ValueError("Restore EFI marker does not match the exact pair vector")
    return value[20]

  def inspect(self, root, vector):
    source_stage = super().inspect(root, vector)
    restore_stage = self.inspect_restore(root, vector)
    if source_stage is None and restore_stage is not None:
      raise ValueError("Restore EFI marker exists without its source marker")
    return source_stage

  def require_kernel_available(self, root):
    super().require_kernel_available(root)
    path = self.restore_module_path
    if (SHA256.fullmatch(self.restore_module_sha256) is None or
        not self.restore_module_srcversion or not path.is_absolute() or
        path.is_symlink() or not path.is_file()):
      raise ValueError("Exact private restore EFI module is required")
    metadata = path.stat()
    if Path(root).resolve() == Path("/") and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600):
      raise ValueError("Restore EFI module must be root-owned and private")
    if hashlib.sha256(path.read_bytes()).hexdigest() != self.restore_module_sha256:
      raise ValueError("Restore EFI module differs from the explicit hash")
    vermagic = self.command(("modinfo", "-F", "vermagic", str(path))).split()
    if not vermagic or vermagic[0] != self.kernel_release:
      raise ValueError("Restore EFI module does not match the running kernel")
    if self.command(("modinfo", "-F", "srcversion", str(path))).strip() != self.restore_module_srcversion:
      raise ValueError("Restore EFI module source version differs")
    if (Path(root) / "sys/module/mba_hibernate_efi_restore_marker").exists():
      raise ValueError("Restore EFI module is unexpectedly loaded on the source boot")

  def require_operator_acceptance(self, root, vector, boot_id, production_uki_sha256):
    if (SHA256.fullmatch(vector) is None or UUID.fullmatch(boot_id) is None or
        SHA256.fullmatch(production_uki_sha256) is None):
      raise ValueError("Restore EFI recovery identity is malformed")
    path = Path(root) / self.acceptance_path
    if path.is_symlink() or not path.is_file():
      raise ValueError("Boot-bound restore EFI recovery acceptance is missing or symlinked")
    metadata = path.stat()
    expected_uid = 0 if Path(root).resolve() == Path("/") else os.geteuid()
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
      raise ValueError("Restore EFI recovery acceptance has an unsafe owner or mode")
    raw = path.read_bytes()
    try:
      record = json.loads(raw)
    except json.JSONDecodeError as error:
      raise ValueError("Restore EFI recovery acceptance is malformed") from error
    expected = {
      "kind": "postwrite-restore-efi-attended-s4-" + self.source_variable_version,
      "boot_id": boot_id,
      "transition_vector": vector,
      "module_sha256": self.expected_sha256,
      "restore_module_sha256": self.restore_module_sha256,
      "production_uki_sha256": production_uki_sha256,
      "method": "operator-attended-cold-power",
      "accepted": True,
    }
    if self.source_variable_version == "v2":
      expected["source_efi_variable"] = self.source_variable.name
    if record != expected:
      raise ValueError("Restore EFI recovery acceptance differs from this boot and vector")
    return hashlib.sha256(raw).hexdigest()

  def before_arm(self, root, vector, boot_id, attempt_directory):
    super().before_arm(root, vector, boot_id, attempt_directory)
    if self.inspect_restore(root, vector) is not None:
      raise ValueError("Restore EFI marker already exists; preserve it")
    atomic_new_json(Path(attempt_directory) / "restore-efi-identity.json", {
      "kind": "restore-efi-s4-identity-v1",
      "vector": vector,
      "source_boot_id": boot_id,
      "module_sha256": self.restore_module_sha256,
      "module_srcversion": self.restore_module_srcversion,
      "efi_variable": RESTORE_VARIABLE.name,
      "source_efi_variable": self.source_variable.name,
    })

  def prearm(self, root, vector):
    source_path = super().prearm(root, vector)
    path = Path(root) / RESTORE_VARIABLE
    if path.exists() or path.is_symlink():
      raise ValueError("Restore EFI marker already exists; preserve it")
    value = ATTRIBUTES + RESTORE_MAGIC + bytes.fromhex(vector[:24]) + b"\x00"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
      if os.write(descriptor, value) != len(value):
        raise OSError("Short restore EFI stage-0 write")
    finally:
      os.close(descriptor)
    if self.inspect_restore(root, vector) != 0:
      raise ValueError("Restore EFI stage-0 readback differs")
    self.restore_marker_path = str(path)
    return source_path
