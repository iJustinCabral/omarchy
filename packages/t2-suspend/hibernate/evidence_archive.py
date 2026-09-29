"""Durable, offline byte archives for one explicitly supplied product cycle.

The caller supplies an existing private directory and captured bytes, never EFI
paths. This module verifies byte-copy integrity and cycle identity, not the truth
or provenance of hardware observations. Its receipt authorizes no slot clearing,
power operation, qualification or deletion. Partial archives remain in place and
cannot be replayed. Completed archives have no update or removal API.
Private directory modes must be exact; an umask that strips owner permissions
refuses creation and preserves the partial archive for external reconciliation.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


_spec = importlib.util.spec_from_file_location("hibernate_archive_transaction", Path(__file__).with_name("transaction.py"))
TX = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TX)

PROTOCOL = "omarchy-t2-product-evidence-archive-v1"
BINDING_KEYS = ("protocol", "cycle_id", "original_boot_id", "manifest", "qualification_sha256",
                "qualification_vector", "vector", "prefix", "returned_evidence_sha256")
REQUIRED_NAMES = frozenset(("source-stage.bin", "restore-stage.bin", "restore-hook-entered.bin",
                            "restore-hook-armed.bin", "consumed-guard.bin", "consumed-attempt.bin",
                            "source-return-witness.bin", "cleanup-health.bin"))
OPTIONAL_NAMES = frozenset(("recovery-acceptance.bin",))
COMPLETION = "completion.json"
PENDING = ".completion-pending"
MAX_BYTES = 2 * 1024 * 1024


def _encoded(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(raw):
  return hashlib.sha256(raw).hexdigest()


def cycle_binding(cycle):
  """Validate the ledger record before projecting its immutable cycle identity."""
  TX.cycle_value(cycle)
  if cycle["state"] not in ("returned", "archived", "released", "reconciled"):
    raise ValueError("Archive requires a returned cycle")
  # Copy nested values as well: caller mutation must not alter the snapshot.
  return json.loads(_encoded({key: cycle[key] for key in BINDING_KEYS}))


def _private(fd, directory=False):
  info = os.fstat(fd)
  expected_mode = 0o700 if directory else 0o600
  expected_type = stat.S_ISDIR if directory else stat.S_ISREG
  if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != expected_mode or not expected_type(info.st_mode):
    raise ValueError("Archive has unsafe owner, mode or file type")
  if not directory and info.st_nlink != 1:
    raise ValueError("Archive file has unexpected hard links")


def _open_parent(directory):
  path = Path(directory)
  if not path.is_absolute() or path == Path("/") or ".." in path.parts:
    raise ValueError("Existing absolute dedicated archive directory required")
  fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try:
    # Open each ancestor without following symlinks; directory-relative access
    # stays attached to these descriptors even if a path is subsequently moved.
    for part in path.parts[1:]:
      next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
      os.close(fd)
      fd = next_fd
    _private(fd, directory=True)
    return fd
  except BaseException:
    os.close(fd)
    raise


def _open_child(parent, cycle_id):
  fd = os.open("cycle-" + cycle_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
  try:
    _private(fd, directory=True)
    return fd
  except BaseException:
    os.close(fd)
    raise


def _write_private(directory, name, raw):
  fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
               0o600, dir_fd=directory)
  try:
    # A restrictive caller umask is allowed, but archives always use exact modes.
    os.fchmod(fd, 0o600)
    _private(fd)
    remaining = memoryview(raw)
    while remaining:
      count = os.write(fd, remaining)
      if count <= 0:
        raise OSError("Short archive write")
      remaining = remaining[count:]
    os.fsync(fd)
  finally:
    os.close(fd)


def _read_private(directory, name):
  fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
  try:
    _private(fd)
    if os.fstat(fd).st_size > MAX_BYTES:
      raise ValueError("Archive file exceeds byte bound")
    chunks = []
    total = 0
    while True:
      chunk = os.read(fd, min(65536, MAX_BYTES + 1 - total))
      if not chunk:
        break
      total += len(chunk)
      if total > MAX_BYTES:
        raise ValueError("Archive file exceeds byte bound")
      chunks.append(chunk)
    return b"".join(chunks)
  finally:
    os.close(fd)


def _evidence_value(evidence):
  if type(evidence) is not dict or not REQUIRED_NAMES <= set(evidence) <= REQUIRED_NAMES | OPTIONAL_NAMES:
    raise ValueError("Archive evidence names differ from fixed allowlist")
  if any(type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES for raw in evidence.values()):
    raise ValueError("Archive evidence requires bounded nonempty bytes, never paths")
  return dict(evidence)


def _publish_manifest(directory, manifest):
  _write_private(directory, PENDING, _encoded(manifest))
  os.fsync(directory)
  # Link publishes the already durable complete bytes exclusively, unlike a
  # replacing rename. The temporary hard link is removed before verification.
  os.link(PENDING, COMPLETION, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
  os.fsync(directory)
  os.unlink(PENDING, dir_fd=directory)
  os.fsync(directory)


def _entries(directory):
  # Btrfs can retain an empty enumeration boundary on a descriptor opened
  # before these entries were created. A new open of '.' refreshes that view,
  # without trusting the mutable pathname or sharing the old directory offset.
  scan = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
  try:
    _private(scan, directory=True)
    original, current = os.fstat(directory), os.fstat(scan)
    if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
      raise ValueError("Archive enumeration inode changed")
    return set(os.listdir(scan))
  finally:
    os.close(scan)


def _verify(directory, binding, expected_receipt_sha256=None):
  manifest_raw = _read_private(directory, COMPLETION)
  manifest = json.loads(manifest_raw, object_pairs_hook=TX.no_duplicates,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite archive JSON")))
  if type(manifest) is not dict or set(manifest) != {"protocol", "binding", "files"}:
    raise ValueError("Malformed archive completion manifest")
  if manifest["protocol"] != PROTOCOL or manifest["binding"] != binding:
    raise ValueError("Archive completion is bound to another cycle")
  files = manifest["files"]
  if type(files) is not dict or not REQUIRED_NAMES <= set(files) <= REQUIRED_NAMES | OPTIONAL_NAMES:
    raise ValueError("Archive completion evidence names differ")
  if _entries(directory) != set(files) | {COMPLETION}:
    raise ValueError("Archive is partial or contains unexpected entries")
  for name, identity in files.items():
    if type(identity) is not dict or set(identity) != {"size", "sha256"}:
      raise ValueError("Malformed archived byte identity")
    if type(identity["size"]) is not int or not 0 < identity["size"] <= MAX_BYTES:
      raise ValueError("Invalid archived byte count")
    TX.hash_value(identity["sha256"])
    raw = _read_private(directory, name)
    if len(raw) != identity["size"] or _digest(raw) != identity["sha256"]:
      raise ValueError("Archived bytes differ from completion manifest")
  if files["source-return-witness.bin"]["sha256"] != binding["returned_evidence_sha256"]:
    raise ValueError("Archived witness differs from ledger return receipt")
  if manifest_raw != _encoded(manifest):
    raise ValueError("Archive completion is not canonically encoded")
  receipt_sha256 = _digest(manifest_raw)
  if expected_receipt_sha256 is not None:
    TX.hash_value(expected_receipt_sha256)
    if receipt_sha256 != expected_receipt_sha256:
      raise ValueError("Archive receipt hash differs")
  return {"protocol": PROTOCOL, "binding": binding, "manifest_sha256": receipt_sha256,
          "files": files, "slot_clear_authorized": False}


def create_archive(directory, cycle, evidence):
  """Archive captured bytes once; receipt hash can attest ledger archival only."""
  binding = cycle_binding(cycle)
  if cycle["state"] != "returned":
    raise ValueError("New archive requires exact returned ledger state")
  evidence = _evidence_value(evidence)
  if _digest(evidence["source-return-witness.bin"]) != binding["returned_evidence_sha256"]:
    raise ValueError("Supplied witness differs from ledger return receipt")
  parent = _open_parent(directory)
  archive = None
  try:
    # Existing complete, partial and symlinked cycle targets all refuse replay.
    os.mkdir("cycle-" + binding["cycle_id"], mode=0o700, dir_fd=parent)
    archive = _open_child(parent, binding["cycle_id"])
    os.fsync(parent)
    files = {}
    for name, raw in sorted(evidence.items()):
      _write_private(archive, name, raw)
      files[name] = {"size": len(raw), "sha256": _digest(raw)}
    os.fsync(archive)
    # Verify the durable byte copies before publishing the completion manifest.
    for name, raw in evidence.items():
      if _read_private(archive, name) != raw:
        raise ValueError("Archive readback differs from supplied bytes")
    manifest = {"protocol": PROTOCOL, "binding": binding, "files": files}
    _publish_manifest(archive, manifest)
    return _verify(archive, binding)
  finally:
    if archive is not None:
      os.close(archive)
    os.close(parent)


def verify_archive(directory, cycle, expected_receipt_sha256=None):
  """Re-read all bytes and exact cycle binding; never grants slot-clear authority."""
  binding = cycle_binding(cycle)
  parent = _open_parent(directory)
  archive = None
  try:
    archive = _open_child(parent, binding["cycle_id"])
    return _verify(archive, binding, expected_receipt_sha256)
  finally:
    if archive is not None:
      os.close(archive)
    os.close(parent)
