#!/usr/bin/python3
"""One-use, offline-tested EFI persistence probe; never runs on import.

This uses a disposable variable, not the guarded S4 stage variable. Live use
requires an explicit caller to pass allow_live=True after stock-boot checks.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess


VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2EfiPersistenceProbe-0dc7b0e2-3b57-4e62-9159-caa993087e72")
STATE = Path("var/lib/omarchy-t2-efi-persistence-probe")
BOOT_ID = Path("proc/sys/kernel/random/boot_id")
ATTRIBUTES = (7).to_bytes(4, "little")
MAGIC = b"MBAP"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
PRODUCTION_UKI_SHA256 = "18491469d046bd5805a10c7a80e47c1e9ae2af1879a3ce78b1e9c14826c789bc"
PRODUCTION_LIMINE_SHA256 = "dc775d7c13c4aadab296a81778309a0203b67e67fd7c5aa5b12349bf43dccb2b"
FAILED_VECTOR = "5b72eb22c88cf50a5938b52da02ffee9c94f5cf9468e212a961098c4bf04b230"
EFI_GLOBAL_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
STAGE_VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2HibernateStage-96234839-90c9-4cd5-97b2-7ba690f0af02")
MARKER_MODULE = Path("sys/module/mba_hibernate_efi_ftrace_marker")
HANDOFF = Path("home/jjc/.local/state/codex-mba-autonomous/handoff.json")


def sha256_file(path):
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def command_output(*arguments):
  return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def require_live_stock(root):
  if os.geteuid() != 0:
    raise ValueError("Live EFI probe requires root")
  if command_output("findmnt", "-no", "SOURCE,FSTYPE", "/").strip() != "/dev/mapper/root[/@] btrfs":
    raise ValueError("Live EFI probe requires the primary encrypted Btrfs root")
  if "Current Entry: Omarchy.linux-t2" not in command_output("bootctl", "status", "--no-pager"):
    raise ValueError("Live EFI probe requires the stock Omarchy boot entry")
  if sha256_file(root / "boot/EFI/Linux/omarchy_linux-t2.efi") != PRODUCTION_UKI_SHA256:
    raise ValueError("Production UKI differs from the qualified stock image")
  if sha256_file(root / "boot/limine.conf") != PRODUCTION_LIMINE_SHA256:
    raise ValueError("Limine configuration differs from the stock checkpoint")
  for name in ("LoaderEntryOneShot", "LoaderEntryDefault"):
    if read_regular(root / "sys/firmware/efi/efivars" / f"{name}-{EFI_GLOBAL_GUID}") is not None:
      raise ValueError("An EFI boot-entry override exists")
  if (root / MARKER_MODULE).exists() or (root / MARKER_MODULE).is_symlink():
    raise ValueError("Experimental EFI marker module is loaded")
  if read_regular(root / STAGE_VARIABLE) is not None:
    raise ValueError("A real S4 EFI stage marker exists")
  if read_regular(root / "sys/power/pm_trace") != b"0\n":
    raise ValueError("PM tracing is not disabled")


def require_live_arm_preflight(root):
  handoff_path = root / HANDOFF
  if handoff_path.is_symlink() or not handoff_path.is_file():
    raise ValueError("Reconciled handoff is absent or not a regular file")
  handoff = json.loads(handoff_path.read_text())
  repository = Path(__file__).resolve().parents[4]
  current_head = command_output("git", "-C", str(repository), "rev-parse", "HEAD").strip()
  if handoff.get("boot_id") != boot_id(root) or handoff.get("head") != current_head:
    raise ValueError("Live EFI probe does not match the reconciled handoff checkpoint")
  if command_output("git", "-C", str(repository), "status", "--porcelain"):
    raise ValueError("Live EFI probe requires a clean repository checkpoint")
  guard = root / "var/lib/omarchy-t2-hibernation-pair/s4-vectors" / FAILED_VECTOR / "s4-attempted"
  if read_regular(guard) != b"67bc517f-621a-4b49-8a7f-4177b873f389\n":
    raise ValueError("Terminal S4 guard is absent or changed")


def require_scope(root, allow_live):
  if root == Path("/") and not allow_live:
    raise ValueError("Live EFI probe requires a separately qualified stock boot and explicit allow_live=True")
  if root == Path("/"):
    require_live_stock(root)


def boot_id(root):
  value = (root / BOOT_ID).read_text().strip()
  if UUID.fullmatch(value) is None:
    raise ValueError("Current boot ID is malformed")
  return value


def read_regular(path, limit=4096):
  flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  try:
    descriptor = os.open(path, flags)
  except FileNotFoundError:
    if path.is_symlink():
      raise ValueError("Probe path is a dangling symlink") from None
    return None
  try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
      raise ValueError("Probe path is not a regular file")
    value = os.read(descriptor, limit + 1)
    if len(value) > limit:
      raise ValueError("Probe file exceeds its size limit")
    return value
  finally:
    os.close(descriptor)


def atomic_new_json(path, data):
  encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(path, flags, 0o600)
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(encoded)
    stream.flush()
    os.fsync(stream.fileno())
  directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
  try:
    os.fsync(directory)
  finally:
    os.close(directory)


def load_json(path, root):
  value = read_regular(path)
  if value is None:
    raise ValueError(f"Missing durable probe evidence: {path}")
  if root == Path("/"):
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
      raise ValueError("Probe evidence is not root-owned and private")
  data = json.loads(value)
  if not isinstance(data, dict):
    raise ValueError("Probe evidence is malformed")
  return data


def expected_value(armed):
  if armed.get("kind") != "efi-persistence-probe-v1" or UUID.fullmatch(armed.get("source_boot_id", "")) is None:
    raise ValueError("Probe arm record has an invalid identity")
  value = bytes.fromhex(armed["value_hex"])
  if len(value) != 20 or not value.startswith(ATTRIBUTES + MAGIC):
    raise ValueError("Probe arm record has an invalid value")
  if hashlib.sha256(value).hexdigest() != armed.get("value_sha256"):
    raise ValueError("Probe arm record has an invalid digest")
  return value


def arm(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    require_live_arm_preflight(root)
  source = boot_id(root)
  variable = root / VARIABLE
  directory = root / STATE
  if read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Disposable EFI probe variable already exists; preserve it")
  value = ATTRIBUTES + MAGIC + secrets.token_bytes(12)
  directory.mkdir(mode=0o700)
  atomic_new_json(directory / "armed.json", {
    "kind": "efi-persistence-probe-v1",
    "source_boot_id": source,
    "value_hex": value.hex(),
    "value_sha256": hashlib.sha256(value).hexdigest(),
  })
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(variable, flags, 0o600)
  try:
    if os.write(descriptor, value) != len(value):
      raise OSError("Short EFI persistence-probe write; preserve evidence and do not retry")
  finally:
    os.close(descriptor)
  if read_regular(variable) != value:
    raise ValueError("EFI persistence-probe readback differs; preserve evidence and do not retry")
  return {"source_boot_id": source, "value_sha256": hashlib.sha256(value).hexdigest()}


def verify(root, *, allow_live=False):
  require_scope(root, allow_live)
  directory = root / STATE
  armed = load_json(directory / "armed.json", root)
  expected = expected_value(armed)
  current = boot_id(root)
  if current == armed["source_boot_id"]:
    raise ValueError("Same-boot readback does not prove EFI persistence")
  observed = read_regular(root / VARIABLE)
  result = {
    "kind": "efi-persistence-probe-v1-result",
    "source_boot_id": armed["source_boot_id"],
    "return_boot_id": current,
    "value_sha256": armed["value_sha256"],
    "observed_sha256": hashlib.sha256(observed).hexdigest() if observed is not None else None,
    "persisted": observed == expected,
  }
  atomic_new_json(directory / "verified.json", result)
  return result


def clear(root, *, allow_live=False):
  require_scope(root, allow_live)
  directory = root / STATE
  armed = load_json(directory / "armed.json", root)
  verified = load_json(directory / "verified.json", root)
  expected = expected_value(armed)
  if (verified.get("kind") != "efi-persistence-probe-v1-result" or
      verified.get("persisted") is not True or
      verified.get("source_boot_id") != armed["source_boot_id"] or
      verified.get("return_boot_id") != boot_id(root) or
      verified.get("value_sha256") != armed["value_sha256"] or
      verified.get("observed_sha256") != armed["value_sha256"]):
    raise ValueError("Only an exact, verified return-boot probe can be cleared")
  variable = root / VARIABLE
  if read_regular(variable) != expected:
    raise ValueError("EFI probe changed after verification; preserve it")
  if read_regular(directory / "cleared.json") is not None:
    raise ValueError("EFI probe cleanup was already recorded")
  atomic_new_json(directory / "clear-intent.json", {
    "kind": "efi-persistence-probe-v1-clear-intent",
    "return_boot_id": verified["return_boot_id"],
    "value_sha256": armed["value_sha256"],
  })
  if root == Path("/"):
    subprocess.run(["chattr", "-i", str(variable)], check=True)
  variable.unlink()
  if read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Disposable EFI probe still exists after cleanup")
  atomic_new_json(directory / "cleared.json", {
    "kind": "efi-persistence-probe-v1-cleared",
    "return_boot_id": verified["return_boot_id"],
    "value_sha256": armed["value_sha256"],
  })
  return True
