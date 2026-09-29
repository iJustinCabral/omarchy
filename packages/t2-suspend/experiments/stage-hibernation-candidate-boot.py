#!/usr/bin/env python3
"""Stage, arm, roll back or clear a one-shot T2 hibernation candidate boot.

Staging leaves the production entry as the default and does not arm a boot.
Arming is a separate action whose final mutation is LoaderEntryOneShot.
Clearing removes transaction records only after rollback verifies production.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ENTRY_PREFIX = "MBA-T2-hibernation-candidate"
IMAGE_NAME = "mba_t2_hibernation_candidate.efi"
PRODUCTION_IMAGE = "omarchy_linux-t2.efi"
STATE = Path("var/lib/omarchy-t2-hibernation-candidate")
RECEIPT = STATE / "receipt.json"
BACKUP = STATE / "limine.conf.before"
LIMINE = Path("boot/limine.conf")
IMAGE = Path("boot/EFI/Linux") / IMAGE_NAME
EFI_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
ONESHOT = Path("sys/firmware/efi/efivars/LoaderEntryOneShot-" + EFI_GUID)
DEFAULT = Path("sys/firmware/efi/efivars/LoaderEntryDefault-" + EFI_GUID)
SELECTED = Path("sys/firmware/efi/efivars/LoaderEntrySelected-" + EFI_GUID)
ENTRIES = Path("sys/firmware/efi/efivars/LoaderEntries-" + EFI_GUID)
BEGIN = "# BEGIN omarchy T2 hibernation candidate"
END = "# END omarchy T2 hibernation candidate"
EVIDENCE_FILES = {"test-resume-attempted"}
EVIDENCE_DIRECTORIES = {"test-resume-attempts", "test-resume-vectors", "s4-vectors"}


def digest(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def blake2(path):
  return hashlib.blake2b(path.read_bytes()).hexdigest()


def rooted(root, relative):
  path = root / relative
  resolved_parent = path.parent.resolve()
  root_resolved = root.resolve()
  resolved_parent.relative_to(root_resolved)
  if path.is_symlink():
    raise ValueError("Refusing symlink: " + str(path))
  return path


def atomic_write(path, data, mode):
  path.parent.mkdir(parents=True, exist_ok=True)
  temporary = None
  try:
    with tempfile.NamedTemporaryFile(prefix="." + path.name + ".", dir=path.parent, delete=False) as stream:
      temporary = Path(stream.name)
      stream.write(data)
      stream.flush()
      os.fsync(stream.fileno())
    temporary.chmod(mode)
    os.replace(temporary, path)
    temporary = None
  finally:
    if temporary is not None and temporary.exists():
      temporary.unlink()
  fsync_directory(path.parent)


def fsync_directory(path):
  descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)


def unlink_path(path):
  path.unlink()


def validate_preserved_evidence(state, transaction_names=()):
  allowed = EVIDENCE_FILES | EVIDENCE_DIRECTORIES | set(transaction_names)
  unexpected = sorted(path.name for path in state.iterdir() if path.name not in allowed)
  if unexpected:
    raise ValueError("Candidate transaction state contains unknown files: " + ", ".join(unexpected))
  for name in EVIDENCE_FILES:
    path = state / name
    if path.is_symlink() or (path.exists() and not path.is_file()):
      raise ValueError("Candidate test evidence is not a real file: " + name)
  for name in EVIDENCE_DIRECTORIES:
    path = state / name
    if path.is_symlink() or (path.exists() and not path.is_dir()):
      raise ValueError("Candidate test evidence is not a real directory: " + name)


def remove_state_if_empty(state):
  if any(state.iterdir()):
    validate_preserved_evidence(state)
    return
  state.rmdir()
  fsync_directory(state.parent)


def read_efi_string(path):
  data = path.read_bytes()
  if len(data) < 6:
    raise ValueError("Malformed EFI variable: " + str(path))
  return data[4:].decode("utf-16-le").rstrip("\x00")


def read_efi_strings(path):
  data = path.read_bytes()
  if len(data) < 6 or len(data) % 2:
    raise ValueError("Malformed EFI variable: " + str(path))
  return tuple(value for value in data[4:].decode("utf-16-le").split("\x00") if value)


def entry_id(candidate_hash):
  if not re.fullmatch(r"[0-9a-f]{64}", candidate_hash):
    raise ValueError("Candidate UKI SHA-256 is malformed")
  return ENTRY_PREFIX + "-" + candidate_hash[:16]


def entry_block(candidate_entry, image_hash):
  return (
    f"\n{BEGIN}\n"
    f"/{candidate_entry}\n"
    "comment: One-shot candidate; production remains the explicit default\n"
    "protocol: efi\n"
    f"path: boot():/EFI/Linux/{IMAGE_NAME}#{image_hash}\n"
    f"{END}\n"
  ).encode()


def load_candidate(directory):
  image = directory / "mba-t2-hibernation-candidate.efi"
  provenance_path = directory / "provenance.json"
  if image.is_symlink() or provenance_path.is_symlink():
    raise ValueError("Refusing symlinked candidate input")
  if not image.is_file() or not provenance_path.is_file():
    raise ValueError("Candidate image or provenance is missing")
  image_data = image.read_bytes()
  provenance = json.loads(provenance_path.read_text())
  if provenance.get("candidate") != "mba-t2-hibernation-module-overlay":
    raise ValueError("Unexpected candidate provenance")
  if provenance.get("candidate_uki_sha256") != hashlib.sha256(image_data).hexdigest():
    raise ValueError("Candidate UKI hash mismatch")
  for key in ("production_modified", "installed", "boot_entry_created", "hardware_qualified"):
    if provenance.get(key) is not False:
      raise ValueError("Candidate is not in offline-only state: " + key)
  return image_data, provenance


def validate_production(root, provenance):
  limine = rooted(root, LIMINE)
  production = rooted(root, Path("boot/EFI/Linux") / PRODUCTION_IMAGE)
  text = limine.read_text()
  if len(re.findall(r"^default_entry:\s*2\s*$", text, re.M)) != 1:
    raise ValueError("Production Limine default is not exactly entry 2")
  expected_path = "path: boot():/EFI/Linux/" + PRODUCTION_IMAGE + "#" + blake2(production)
  if text.count(expected_path) != 1:
    raise ValueError("Production Limine image hash is stale or ambiguous")
  if digest(production) != provenance.get("production_uki_sha256"):
    raise ValueError("Production UKI differs from the candidate build base")
  if rooted(root, DEFAULT).exists():
    raise ValueError("Persistent LoaderEntryDefault would weaken production fallback")
  if rooted(root, ONESHOT).exists():
    raise ValueError("Another one-shot boot is already armed")
  selected = rooted(root, SELECTED)
  if not selected.is_file() or read_efi_string(selected) != "Omarchy.linux-t2":
    raise ValueError("Current boot is not the healthy production entry")
  return limine, production, text


def save_receipt(root, receipt):
  atomic_write(rooted(root, RECEIPT), (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def load_receipt(root):
  return json.loads(rooted(root, RECEIPT).read_text())


def verify_staged(root, receipt):
  image = rooted(root, IMAGE)
  limine = rooted(root, LIMINE)
  if digest(image) != receipt["candidate_uki_sha256"]:
    raise ValueError("Staged candidate image changed")
  if blake2(image) != receipt["candidate_uki_blake2"]:
    raise ValueError("Staged candidate Limine hash changed")
  if digest(limine) != receipt["staged_limine_sha256"]:
    raise ValueError("Staged Limine configuration changed")
  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Limine backup changed")
  text = limine.read_text()
  if text.count(BEGIN) != 1 or text.count(END) != 1:
    raise ValueError("Managed candidate entry is missing or duplicated")
  if receipt.get("entry_id") != entry_id(receipt["candidate_uki_sha256"]):
    raise ValueError("Candidate entry identifier is not bound to the UKI hash")
  if text.count("/" + receipt["entry_id"] + "\n") != 1:
    raise ValueError("Hash-bound candidate entry is missing or duplicated")
  if len(re.findall(r"^default_entry:\s*2\s*$", text, re.M)) != 1:
    raise ValueError("Staging changed the production default")
  expected = "path: boot():/EFI/Linux/" + IMAGE_NAME + "#" + receipt["candidate_uki_blake2"]
  if text.count(expected) != 1:
    raise ValueError("Candidate Limine hash is stale or ambiguous")


def verify_recovered(root, receipt):
  limine = rooted(root, LIMINE)
  if digest(limine) != receipt["original_limine_sha256"]:
    raise ValueError("Production Limine configuration was not restored")
  if rooted(root, IMAGE).exists():
    raise ValueError("Candidate image remains after staging recovery")


def recover_failed_stage(root, receipt, failure):
  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Cannot recover staging: Limine backup changed")

  limine = rooted(root, LIMINE)
  current_limine = digest(limine)
  if current_limine == receipt["staged_limine_sha256"]:
    atomic_write(limine, backup.read_bytes(), 0o600)
  elif current_limine != receipt["original_limine_sha256"]:
    raise ValueError("Cannot recover staging: Limine configuration has an unknown hash")

  image = rooted(root, IMAGE)
  if image.exists():
    if digest(image) != receipt["candidate_uki_sha256"]:
      raise ValueError("Cannot recover staging: candidate image has an unknown hash")
    image.unlink()
    fsync_directory(image.parent)

  receipt["state"] = "stage-failed-recovered"
  receipt["failure"] = str(failure)
  save_receipt(root, receipt)
  verify_recovered(root, receipt)


def clean_unpublished_stage(root, receipt):
  if rooted(root, IMAGE).exists():
    raise ValueError("Cannot clean unpublished staging state: candidate image exists")
  if digest(rooted(root, LIMINE)) != receipt["original_limine_sha256"]:
    raise ValueError("Cannot clean unpublished staging state: Limine changed")
  backup = rooted(root, BACKUP)
  if backup.exists():
    if digest(backup) != receipt["original_limine_sha256"]:
      raise ValueError("Cannot clean unpublished staging state: backup changed")
    backup.unlink()
    fsync_directory(backup.parent)
  state = rooted(root, STATE)
  remove_state_if_empty(state)


def stage(root, candidate_directory):
  state = rooted(root, STATE)
  receipt_path = rooted(root, RECEIPT)
  backup = rooted(root, BACKUP)
  if receipt_path.exists() or backup.exists() or rooted(root, IMAGE).exists():
    raise ValueError("Candidate boot transaction already exists")
  if state.exists():
    if not state.is_dir() or state.is_symlink():
      raise ValueError("Candidate transaction state is not a real directory")
    validate_preserved_evidence(state)
  image_data, provenance = load_candidate(candidate_directory)
  limine, production, original = validate_production(root, provenance)
  if BEGIN in original or END in original or f"/{ENTRY_PREFIX}" in original:
    raise ValueError("Unowned candidate entry already exists")

  state.mkdir(parents=True, mode=0o700, exist_ok=True)
  state.chmod(0o700)
  image_sha256 = hashlib.sha256(image_data).hexdigest()
  image_blake2 = hashlib.blake2b(image_data).hexdigest()
  candidate_entry = entry_id(image_sha256)
  staged = original.encode() + entry_block(candidate_entry, image_blake2)
  receipt = {
    "state": "preparing",
    "entry_id": candidate_entry,
    "candidate_uki_sha256": image_sha256,
    "candidate_uki_blake2": image_blake2,
    "production_uki_sha256": digest(production),
    "original_limine_sha256": hashlib.sha256(original.encode()).hexdigest(),
    "staged_limine_sha256": hashlib.sha256(staged).hexdigest(),
  }
  try:
    atomic_write(rooted(root, BACKUP), original.encode(), 0o600)
    save_receipt(root, receipt)
  except Exception as failure:
    try:
      if rooted(root, RECEIPT).exists():
        recover_failed_stage(root, receipt, failure)
      else:
        clean_unpublished_stage(root, receipt)
    except Exception as recovery_failure:
      raise RuntimeError(
        f"Preparing staging failed ({failure}); automatic recovery also failed ({recovery_failure})"
      ) from failure
    raise
  try:
    atomic_write(rooted(root, IMAGE), image_data, 0o600)
    atomic_write(limine, staged, 0o600)
    verify_staged(root, receipt)
    receipt["state"] = "staged"
    save_receipt(root, receipt)
  except Exception as failure:
    try:
      recover_failed_stage(root, receipt, failure)
    except Exception as recovery_failure:
      raise RuntimeError(
        f"Staging failed ({failure}); automatic recovery also failed ({recovery_failure})"
      ) from failure
    raise
  return receipt


def arm(root, runner=subprocess.run, sync=os.sync):
  receipt = load_receipt(root)
  if receipt.get("state") != "staged":
    raise ValueError("Candidate transaction is not staged")
  validate_production(root, {
    "production_uki_sha256": receipt["production_uki_sha256"],
  })
  verify_staged(root, receipt)
  candidate_entry = receipt["entry_id"]
  entries = rooted(root, ENTRIES)
  if not entries.is_file() or candidate_entry not in read_efi_strings(entries):
    raise ValueError("Limine has not advertised the candidate entry; boot production once after staging")
  receipt["state"] = "arming"
  save_receipt(root, receipt)
  sync()
  runner(["bootctl", "set-oneshot", candidate_entry], check=True)
  one_shot = rooted(root, ONESHOT)
  if not one_shot.is_file() or read_efi_string(one_shot) != candidate_entry:
    raise ValueError("LoaderEntryOneShot verification failed")
  return receipt


def rollback(root):
  receipt = load_receipt(root)
  if rooted(root, ONESHOT).exists():
    raise ValueError("Disarm LoaderEntryOneShot before rollback")
  if receipt.get("state") == "rolled-back":
    verify_recovered(root, receipt)
    return receipt
  if receipt.get("state") == "stage-failed-recovered":
    verify_recovered(root, receipt)
    receipt["state"] = "rolled-back"
    save_receipt(root, receipt)
    return receipt
  if receipt.get("state") in ("staged", "arming"):
    verify_staged(root, receipt)
    receipt["state"] = "rolling-back"
    save_receipt(root, receipt)
  elif receipt.get("state") != "rolling-back":
    raise ValueError("Candidate transaction cannot be rolled back from this state")

  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Limine backup changed")
  limine = rooted(root, LIMINE)
  limine_hash = digest(limine)
  if limine_hash == receipt["staged_limine_sha256"]:
    atomic_write(limine, backup.read_bytes(), 0o600)
  elif limine_hash != receipt["original_limine_sha256"]:
    raise ValueError("Refusing rollback of an unknown Limine configuration")

  image = rooted(root, IMAGE)
  if image.exists():
    if digest(image) != receipt["candidate_uki_sha256"]:
      raise ValueError("Refusing rollback of an unknown candidate image")
    image.unlink()
    fsync_directory(image.parent)
  verify_recovered(root, receipt)
  receipt["state"] = "rolled-back"
  save_receipt(root, receipt)
  return receipt


def clear_rolled_back(root, unlink=unlink_path):
  if rooted(root, ONESHOT).exists():
    raise ValueError("Disarm LoaderEntryOneShot before clearing candidate state")
  state = rooted(root, STATE)
  if not state.exists():
    return {"state": "cleared"}
  if not state.is_dir() or state.is_symlink():
    raise ValueError("Candidate transaction state is not a real directory")

  receipt_path = rooted(root, RECEIPT)
  backup = rooted(root, BACKUP)
  validate_preserved_evidence(state, (receipt_path.name, backup.name))

  if not receipt_path.exists():
    if backup.exists():
      raise ValueError("Candidate transaction backup remains without a receipt")
    remove_state_if_empty(state)
    return {"state": "cleared"}

  receipt = load_receipt(root)
  if receipt.get("state") != "rolled-back":
    raise ValueError("Candidate transaction must be rolled back before clearing")
  verify_recovered(root, receipt)
  if backup.exists():
    if digest(backup) != receipt["original_limine_sha256"]:
      raise ValueError("Candidate transaction backup changed")
    unlink(backup)
    fsync_directory(state)
  unlink(receipt_path)
  fsync_directory(state)
  remove_state_if_empty(state)
  return {**receipt, "state": "cleared"}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=("stage", "verify", "arm", "rollback", "clear"))
  parser.add_argument("--candidate-source", type=Path)
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  root = Path("/")
  if args.action == "stage":
    if args.candidate_source is None:
      parser.error("stage requires --candidate-source")
    result = stage(root, args.candidate_source.resolve())
  elif args.action == "arm":
    result = arm(root)
  elif args.action == "rollback":
    result = rollback(root)
  elif args.action == "clear":
    result = clear_rolled_back(root)
  else:
    result = load_receipt(root)
    verify_staged(root, result)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
