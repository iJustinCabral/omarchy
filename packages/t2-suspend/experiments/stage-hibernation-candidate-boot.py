#!/usr/bin/env python3
"""Stage, arm or roll back a one-shot T2 hibernation candidate boot.

Staging leaves the production entry as the default and does not arm a boot.
Arming is a separate action whose final mutation is LoaderEntryOneShot.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ENTRY_NAME = "MBA-T2-hibernation-candidate"
ENTRY_ID = ENTRY_NAME
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


def entry_block(image_hash):
  return (
    f"\n{BEGIN}\n"
    f"/{ENTRY_NAME}\n"
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
  if digest(limine) != receipt["staged_limine_sha256"]:
    raise ValueError("Staged Limine configuration changed")
  text = limine.read_text()
  if text.count(BEGIN) != 1 or text.count(END) != 1:
    raise ValueError("Managed candidate entry is missing or duplicated")
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
  state.rmdir()
  fsync_directory(state.parent)


def stage(root, candidate_directory):
  state = rooted(root, STATE)
  if state.exists() or rooted(root, IMAGE).exists():
    raise ValueError("Candidate boot transaction already exists")
  image_data, provenance = load_candidate(candidate_directory)
  limine, production, original = validate_production(root, provenance)
  if BEGIN in original or END in original or f"/{ENTRY_NAME}" in original:
    raise ValueError("Unowned candidate entry already exists")

  state.mkdir(parents=True, mode=0o700)
  state.chmod(0o700)
  image_sha256 = hashlib.sha256(image_data).hexdigest()
  image_blake2 = hashlib.blake2b(image_data).hexdigest()
  staged = original.encode() + entry_block(image_blake2)
  receipt = {
    "state": "preparing",
    "entry_id": ENTRY_ID,
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
  entries = rooted(root, ENTRIES)
  if not entries.is_file() or ENTRY_ID not in read_efi_strings(entries):
    raise ValueError("Limine has not advertised the candidate entry; boot production once after staging")
  receipt["state"] = "arming"
  save_receipt(root, receipt)
  sync()
  runner(["bootctl", "set-oneshot", ENTRY_ID], check=True)
  one_shot = rooted(root, ONESHOT)
  if not one_shot.is_file() or read_efi_string(one_shot) != ENTRY_ID:
    raise ValueError("LoaderEntryOneShot verification failed")
  return receipt


def rollback(root):
  receipt = load_receipt(root)
  if rooted(root, ONESHOT).exists():
    raise ValueError("Disarm LoaderEntryOneShot before rollback")
  if receipt.get("state") == "stage-failed-recovered":
    verify_recovered(root, receipt)
    receipt["state"] = "rolled-back"
    save_receipt(root, receipt)
    return receipt
  if receipt.get("state") not in ("staged", "arming"):
    raise ValueError("Candidate transaction cannot be rolled back from this state")
  verify_staged(root, receipt)
  backup = rooted(root, BACKUP)
  if digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Limine backup changed")
  atomic_write(rooted(root, LIMINE), backup.read_bytes(), 0o600)
  image = rooted(root, IMAGE)
  image.unlink()
  fsync_directory(image.parent)
  receipt["state"] = "rolled-back"
  save_receipt(root, receipt)
  return receipt


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=("stage", "verify", "arm", "rollback"))
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
  else:
    result = load_receipt(root)
    verify_staged(root, result)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
