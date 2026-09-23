#!/usr/bin/python3
"""Transactionally stage two private T2 hibernation UKIs with stock fallback.

The ordinary source and isolated restore entries are distinct and hash-bound.
Staging does not arm or boot either one. Arming is deliberately split into a
stock-to-source step and a later source-to-restore step. This tool never enters
PM and does not qualify either private image for hardware testing.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


SINGLE = import_path("candidate_boot_stager", HERE / "stage-hibernation-candidate-boot.py")
AUDIT = import_path("hibernation_uki_pair_audit", HERE / "audit-hibernation-uki-pair.py")
STATE = Path("var/lib/omarchy-t2-hibernation-pair")
RECEIPT = STATE / "receipt.json"
BACKUP = STATE / "limine.conf.before"
IMAGES = {
  "source": Path("boot/EFI/Linux/mba_t2_hibernation_source.efi"),
  "restore": Path("boot/EFI/Linux/mba_t2_hibernation_restore.efi"),
}
BEGIN = "# BEGIN omarchy T2 hibernation pair"
END = "# END omarchy T2 hibernation pair"
EVIDENCE_DIRECTORIES = {"test-resume-vectors", "s4-vectors"}
BOOT_ID = Path("proc/sys/kernel/random/boot_id")
REJECTED_SOURCE_SHA256 = {
  # Booted to an emergency shell before /dev/mapper/root could be mounted.
  "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd",
}
atomic_write = SINGLE.atomic_write


def rooted(root, relative):
  return SINGLE.rooted(root, relative)


def digest(path):
  return SINGLE.digest(path)


def current_boot_id(root):
  value = rooted(root, BOOT_ID).read_text().strip()
  if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
    raise ValueError("Current boot ID is malformed")
  return value


def entry_id(role, image_hash):
  if role not in IMAGES or re.fullmatch(r"[0-9a-f]{64}", image_hash) is None:
    raise ValueError("Pair role or UKI SHA-256 is malformed")
  return "MBA-T2-hibernation-" + role + "-" + image_hash[:16]


def reject_failed_source(image_hash):
  if image_hash in REJECTED_SOURCE_SHA256:
    raise ValueError("Source UKI failed ordinary root mount and must not be armed again: " + image_hash)


def entry_block(role, image_hash, image_blake2):
  identifier = entry_id(role, image_hash)
  return (
    f"/{identifier}\n"
    "comment: One-shot T2 hibernation " + role + "; production remains the explicit default\n"
    "protocol: efi\n"
    f"path: boot():/EFI/Linux/{IMAGES[role].name}#{image_blake2}\n"
  )


def stage_block(images):
  return (
    "\n" + BEGIN + "\n"
    + entry_block("source", images["source"]["sha256"], images["source"]["blake2"])
    + entry_block("restore", images["restore"]["sha256"], images["restore"]["blake2"])
    + END + "\n"
  ).encode()


def load_pair(source_directory, restore_directory):
  source = AUDIT.load_candidate(source_directory, "source")
  restore = AUDIT.load_candidate(restore_directory, "restore")
  reject_failed_source(source.get("candidate_uki_sha256"))
  pair = AUDIT.audit(source, restore)
  if source.get("candidate") != "mba-t2-hibernation-early-source":
    raise ValueError("Source is not a newly built early-source UKI")
  if source.get("pre_restore_module_policy") != "early-t2-radio":
    raise ValueError("Source does not declare the early T2/radio policy")
  if restore.get("candidate") != "mba-t2-hibernation-module-overlay":
    raise ValueError("Restore is not a candidate module-overlay UKI")
  if not source.get("experiment_id") or not restore.get("experiment_id"):
    raise ValueError("Both private UKIs require embedded experiment IDs")
  images = {}
  for role, directory, provenance in (
    ("source", source_directory, source),
    ("restore", restore_directory, restore),
  ):
    image = directory / "mba-t2-hibernation-candidate.efi"
    data = image.read_bytes()
    if hashlib.sha256(data).hexdigest() != provenance["candidate_uki_sha256"]:
      raise ValueError(role + " image changed after pair audit")
    report = directory / "provenance.json"
    report_data = report.read_bytes()
    if json.loads(report_data) != provenance:
      raise ValueError(role + " provenance changed after pair audit")
    images[role] = {
      "data": data,
      "sha256": provenance["candidate_uki_sha256"],
      "blake2": hashlib.blake2b(data).hexdigest(),
      "provenance_sha256": hashlib.sha256(report_data).hexdigest(),
      "experiment_id": provenance["experiment_id"],
    }
  return pair, images, source


def save_receipt(root, receipt):
  atomic_write(rooted(root, RECEIPT), (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def load_receipt(root):
  path = rooted(root, RECEIPT)
  if not path.is_file():
    raise ValueError("Pair staging receipt is missing")
  data = json.loads(path.read_text())
  if not isinstance(data, dict):
    raise ValueError("Pair staging receipt is malformed")
  return data


def verify_staged(root, receipt):
  limine = rooted(root, SINGLE.LIMINE)
  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Pair Limine backup changed")
  if digest(limine) != receipt["staged_limine_sha256"]:
    raise ValueError("Staged pair Limine configuration changed")
  production = rooted(root, Path("boot/EFI/Linux") / SINGLE.PRODUCTION_IMAGE)
  if digest(production) != receipt["production_uki_sha256"]:
    raise ValueError("Production UKI changed during pair staging")
  text = limine.read_text()
  if text.count(BEGIN) != 1 or text.count(END) != 1:
    raise ValueError("Managed pair block is missing or duplicated")
  if len(re.findall(r"^default_entry:\s*2\s*$", text, re.M)) != 1:
    raise ValueError("Pair staging changed the stock default")
  for role, relative in IMAGES.items():
    metadata = receipt["images"][role]
    image = rooted(root, relative)
    if not image.is_file() or digest(image) != metadata["sha256"] or SINGLE.blake2(image) != metadata["blake2"]:
      raise ValueError("Staged " + role + " image changed")
    if metadata["entry_id"] != entry_id(role, metadata["sha256"]):
      raise ValueError("Staged " + role + " entry is not bound to its UKI hash")
    if text.count("/" + metadata["entry_id"] + "\n") != 1:
      raise ValueError("Staged " + role + " entry is missing or duplicated")
    expected = "path: boot():/EFI/Linux/" + relative.name + "#" + metadata["blake2"]
    if text.count(expected) != 1:
      raise ValueError("Staged " + role + " Limine hash is stale or ambiguous")
  if rooted(root, SINGLE.DEFAULT).exists():
    raise ValueError("Persistent EFI default would weaken stock fallback")


def verify_recovered(root, receipt):
  if digest(rooted(root, SINGLE.LIMINE)) != receipt["original_limine_sha256"]:
    raise ValueError("Stock Limine configuration was not restored")
  production = rooted(root, Path("boot/EFI/Linux") / SINGLE.PRODUCTION_IMAGE)
  if digest(production) != receipt["production_uki_sha256"]:
    raise ValueError("Production UKI changed")
  for role, relative in IMAGES.items():
    if rooted(root, relative).exists():
      raise ValueError("Pair " + role + " image remains after rollback")


def validate_state(state, transaction_names=()):
  if not state.is_dir() or state.is_symlink():
    raise ValueError("Pair state is not a real directory")
  allowed = EVIDENCE_DIRECTORIES | set(transaction_names)
  unexpected = sorted(path.name for path in state.iterdir() if path.name not in allowed)
  if unexpected:
    raise ValueError("Pair state contains unknown files: " + ", ".join(unexpected))
  for name in EVIDENCE_DIRECTORIES:
    path = state / name
    if path.is_symlink() or (path.exists() and not path.is_dir()):
      raise ValueError("Pair evidence is not a real directory: " + name)


def remove_state_if_empty(state):
  if any(state.iterdir()):
    validate_state(state)
  else:
    state.rmdir()
    SINGLE.fsync_directory(state.parent)


def recover_failed_stage(root, receipt, failure):
  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Cannot recover pair staging: backup changed")
  limine = rooted(root, SINGLE.LIMINE)
  current_hash = digest(limine)
  if current_hash == receipt["staged_limine_sha256"]:
    atomic_write(limine, backup.read_bytes(), 0o600)
  elif current_hash != receipt["original_limine_sha256"]:
    raise ValueError("Cannot recover pair staging: Limine has an unknown hash")
  for role, relative in IMAGES.items():
    image = rooted(root, relative)
    if image.exists():
      if digest(image) != receipt["images"][role]["sha256"]:
        raise ValueError("Cannot recover pair staging: " + role + " image has an unknown hash")
      image.unlink()
      SINGLE.fsync_directory(image.parent)
  receipt["state"] = "stage-failed-recovered"
  receipt["failure"] = str(failure)
  save_receipt(root, receipt)
  verify_recovered(root, receipt)


def clean_unpublished_stage(root, receipt):
  if any(rooted(root, relative).exists() for relative in IMAGES.values()):
    raise ValueError("Cannot clean unpublished pair images")
  if digest(rooted(root, SINGLE.LIMINE)) != receipt["original_limine_sha256"]:
    raise ValueError("Cannot clean unpublished pair Limine change")
  backup = rooted(root, BACKUP)
  if backup.exists():
    if digest(backup) != receipt["original_limine_sha256"]:
      raise ValueError("Cannot clean changed pair backup")
    backup.unlink()
    SINGLE.fsync_directory(backup.parent)
  remove_state_if_empty(rooted(root, STATE))


def stage(root, source_directory, restore_directory):
  state = rooted(root, STATE)
  if state.exists():
    validate_state(state, (RECEIPT.name, BACKUP.name))
  if rooted(root, RECEIPT).exists() or rooted(root, BACKUP).exists():
    raise ValueError("Pair boot transaction already exists")
  if any(rooted(root, relative).exists() for relative in IMAGES.values()):
    raise ValueError("A pair boot image already exists")
  if any(rooted(root, path).exists() for path in (SINGLE.RECEIPT, SINGLE.BACKUP, SINGLE.IMAGE)):
    raise ValueError("A legacy candidate boot transaction is active")

  pair, images, source = load_pair(source_directory, restore_directory)
  limine, production, original = SINGLE.validate_production(root, source)
  if BEGIN in original or END in original or SINGLE.BEGIN in original or SINGLE.END in original:
    raise ValueError("An unowned candidate or pair block already exists")
  if "/MBA-T2-hibernation-" in original:
    raise ValueError("An unowned T2 hibernation entry already exists")

  state.mkdir(parents=True, mode=0o700, exist_ok=True)
  state.chmod(0o700)
  block = stage_block(images)
  staged = original.encode() + block
  receipt = {
    "state": "preparing",
    "source_armed_from_boot_id": None,
    "restore_armed_from_boot_id": None,
    "runtime_stack_sha256": pair["runtime_stack_sha256"],
    "production_uki_sha256": digest(production),
    "original_limine_sha256": hashlib.sha256(original.encode()).hexdigest(),
    "staged_limine_sha256": hashlib.sha256(staged).hexdigest(),
    "images": {
      role: {
        "entry_id": entry_id(role, images[role]["sha256"]),
        "sha256": images[role]["sha256"],
        "blake2": images[role]["blake2"],
        "provenance_sha256": images[role]["provenance_sha256"],
        "experiment_id": images[role]["experiment_id"],
      }
      for role in IMAGES
    },
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
        f"Preparing pair staging failed ({failure}); recovery also failed ({recovery_failure})"
      ) from failure
    raise
  try:
    for role, relative in IMAGES.items():
      atomic_write(rooted(root, relative), images[role]["data"], 0o600)
    atomic_write(limine, staged, 0o600)
    verify_staged(root, receipt)
    receipt["state"] = "staged"
    save_receipt(root, receipt)
  except Exception as failure:
    try:
      recover_failed_stage(root, receipt, failure)
    except Exception as recovery_failure:
      raise RuntimeError(
        f"Pair staging failed ({failure}); recovery also failed ({recovery_failure})"
      ) from failure
    raise
  return receipt


def advertised_entries(root, receipt):
  entries = rooted(root, SINGLE.ENTRIES)
  if not entries.is_file():
    raise ValueError("Limine entry advertisement is missing")
  advertised = set(SINGLE.read_efi_strings(entries))
  required = {receipt["images"][role]["entry_id"] for role in IMAGES}
  if not required.issubset(advertised):
    raise ValueError("Limine has not advertised both pair entries; boot stock once after staging")


def selected_entry(root):
  selected = rooted(root, SINGLE.SELECTED)
  if not selected.is_file():
    raise ValueError("LoaderEntrySelected is absent")
  return SINGLE.read_efi_string(selected)


def arm_source(root, runner=subprocess.run, sync=os.sync):
  receipt = load_receipt(root)
  if receipt.get("state") != "staged":
    raise ValueError("Pair transaction is not staged for source arming")
  reject_failed_source(receipt["images"]["source"]["sha256"])
  SINGLE.validate_production(root, receipt)
  verify_staged(root, receipt)
  advertised_entries(root, receipt)
  boot_id = current_boot_id(root)
  receipt["source_armed_from_boot_id"] = boot_id
  receipt["state"] = "source-arming"
  save_receipt(root, receipt)
  sync()
  identifier = receipt["images"]["source"]["entry_id"]
  runner(["bootctl", "set-oneshot", identifier], check=True)
  one_shot = rooted(root, SINGLE.ONESHOT)
  if not one_shot.is_file() or SINGLE.read_efi_string(one_shot) != identifier:
    raise ValueError("Source LoaderEntryOneShot verification failed")
  return receipt


def arm_restore(root, runner=subprocess.run, sync=os.sync):
  receipt = load_receipt(root)
  if receipt.get("state") != "source-arming":
    raise ValueError("Pair source boot was not armed and consumed")
  verify_staged(root, receipt)
  if rooted(root, SINGLE.ONESHOT).exists() or rooted(root, SINGLE.DEFAULT).exists():
    raise ValueError("An EFI one-shot or persistent default is already present")
  if selected_entry(root) != receipt["images"]["source"]["entry_id"]:
    raise ValueError("Current boot is not the exact source UKI")
  boot_id = current_boot_id(root)
  armed_from = receipt.get("source_armed_from_boot_id")
  if not isinstance(armed_from, str) or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", armed_from) is None:
    raise ValueError("Source arming boot ID is missing or malformed")
  if boot_id == armed_from:
    raise ValueError("Source one-shot was not consumed by a new boot")
  advertised_entries(root, receipt)
  receipt["restore_armed_from_boot_id"] = boot_id
  receipt["state"] = "restore-arming"
  save_receipt(root, receipt)
  sync()
  identifier = receipt["images"]["restore"]["entry_id"]
  runner(["bootctl", "set-oneshot", identifier], check=True)
  one_shot = rooted(root, SINGLE.ONESHOT)
  if not one_shot.is_file() or SINGLE.read_efi_string(one_shot) != identifier:
    raise ValueError("Restore LoaderEntryOneShot verification failed")
  return receipt


def disarm_restore(root, runner=subprocess.run):
  receipt = load_receipt(root)
  if receipt.get("state") != "restore-arming":
    raise ValueError("Restore entry was not armed")
  verify_staged(root, receipt)
  if selected_entry(root) != receipt["images"]["source"]["entry_id"]:
    raise ValueError("Only the exact source boot may disarm restore")
  if current_boot_id(root) != receipt.get("restore_armed_from_boot_id"):
    raise ValueError("Restore one-shot was not armed from this source boot")
  one_shot = rooted(root, SINGLE.ONESHOT)
  identifier = receipt["images"]["restore"]["entry_id"]
  if not one_shot.is_file() or SINGLE.read_efi_string(one_shot) != identifier:
    raise ValueError("Refusing to clear an unknown one-shot entry")
  runner(["bootctl", "set-oneshot", ""], check=True)
  if one_shot.exists():
    raise ValueError("Restore one-shot remained after disarming")
  receipt["state"] = "restore-disarmed"
  save_receipt(root, receipt)
  return receipt


def rollback(root):
  receipt = load_receipt(root)
  if rooted(root, SINGLE.ONESHOT).exists():
    raise ValueError("Disarm LoaderEntryOneShot before pair rollback")
  if selected_entry(root) != "Omarchy.linux-t2":
    raise ValueError("Pair rollback requires the stock boot")
  if receipt.get("state") == "rolled-back":
    verify_recovered(root, receipt)
    return receipt
  if receipt.get("state") == "stage-failed-recovered":
    verify_recovered(root, receipt)
    receipt["state"] = "rolled-back"
    save_receipt(root, receipt)
    return receipt
  if receipt.get("state") in ("staged", "source-arming", "restore-arming", "restore-disarmed"):
    verify_staged(root, receipt)
    receipt["state"] = "rolling-back"
    save_receipt(root, receipt)
  elif receipt.get("state") != "rolling-back":
    raise ValueError("Pair transaction cannot be rolled back from this state")

  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Pair Limine backup changed")
  limine = rooted(root, SINGLE.LIMINE)
  current_hash = digest(limine)
  if current_hash == receipt["staged_limine_sha256"]:
    atomic_write(limine, backup.read_bytes(), 0o600)
  elif current_hash != receipt["original_limine_sha256"]:
    raise ValueError("Refusing rollback of an unknown Limine configuration")
  for role, relative in IMAGES.items():
    image = rooted(root, relative)
    if image.exists():
      if digest(image) != receipt["images"][role]["sha256"]:
        raise ValueError("Refusing rollback of an unknown " + role + " image")
      image.unlink()
      SINGLE.fsync_directory(image.parent)
  verify_recovered(root, receipt)
  receipt["state"] = "rolled-back"
  save_receipt(root, receipt)
  return receipt


def clear_rolled_back(root):
  if rooted(root, SINGLE.ONESHOT).exists():
    raise ValueError("Disarm LoaderEntryOneShot before clearing pair state")
  state = rooted(root, STATE)
  if not state.exists():
    return {"state": "cleared"}
  validate_state(state, (RECEIPT.name, BACKUP.name))
  receipt_path = rooted(root, RECEIPT)
  backup = rooted(root, BACKUP)
  if not receipt_path.exists():
    if backup.exists():
      raise ValueError("Pair backup remains without a receipt")
    remove_state_if_empty(state)
    return {"state": "cleared"}
  receipt = load_receipt(root)
  if receipt.get("state") != "rolled-back":
    raise ValueError("Pair transaction must be rolled back before clearing")
  if selected_entry(root) != "Omarchy.linux-t2":
    raise ValueError("Pair clear requires the stock boot")
  verify_recovered(root, receipt)
  if backup.exists():
    if digest(backup) != receipt["original_limine_sha256"]:
      raise ValueError("Pair backup changed")
    backup.unlink()
    SINGLE.fsync_directory(state)
  receipt_path.unlink()
  SINGLE.fsync_directory(state)
  remove_state_if_empty(state)
  return {**receipt, "state": "cleared"}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=("stage", "verify", "arm-source", "arm-restore", "disarm-restore", "rollback", "clear"))
  parser.add_argument("--source", type=Path)
  parser.add_argument("--restore", type=Path)
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  root = Path("/")
  if args.action == "stage":
    if args.source is None or args.restore is None:
      parser.error("stage requires --source and --restore")
    result = stage(root, args.source.resolve(), args.restore.resolve())
  elif args.action == "verify":
    result = load_receipt(root)
    verify_staged(root, result)
  elif args.action == "arm-source":
    result = arm_source(root)
  elif args.action == "arm-restore":
    result = arm_restore(root)
  elif args.action == "disarm-restore":
    result = disarm_restore(root)
  elif args.action == "rollback":
    result = rollback(root)
  else:
    result = clear_rolled_back(root)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
