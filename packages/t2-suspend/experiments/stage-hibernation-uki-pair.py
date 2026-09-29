#!/usr/bin/python3
"""Transactionally stage two private T2 hibernation UKIs with stock fallback.

The ordinary source and isolated restore entries are distinct and hash-bound.
Staging does not arm or boot either one. Arming is deliberately split into a
stock-to-source step and a later source-to-restore step. This tool never enters
PM and does not qualify either private image for hardware testing.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


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


def require_production_kernel(provenance, role):
  sections = provenance.get("unchanged_production_sections_sha256")
  if provenance.get("modified_sections_sha256") is not None or not isinstance(sections, dict) or ".linux" not in sections:
    raise ValueError(role + " UKI replaces the production kernel; physical root boot is unqualified")


def verify_production_boot_sections(production, private_images, expected_production_hash):
  """Compare the exact buffered UKIs to the current production boot sections."""
  production_data = production.read_bytes()
  production_hash = hashlib.sha256(production_data).hexdigest()
  if production_hash != expected_production_hash:
    raise ValueError("Production UKI changed before pair staging")
  images = {"production": production_data}
  images.update({role: private_images[role]["data"] for role in IMAGES})
  with tempfile.TemporaryDirectory(prefix="t2-pair-boot-sections-") as temporary:
    paths = {}
    for role, data in images.items():
      image = Path(temporary) / (role + ".efi")
      image.write_bytes(data)
      image.chmod(0o600)
      paths[role] = image
    for section in (".linux", ".cmdline"):
      actual = {}
      for role, image in paths.items():
        output = Path(temporary) / (role + section)
        try:
          subprocess.run(
            ("objcopy", "-O", "binary", "--only-section=" + section, str(image), str(output)),
            check=True,
            capture_output=True,
          )
        except (OSError, subprocess.CalledProcessError) as error:
          raise ValueError(role + " UKI " + section + " cannot be extracted") from error
        data = output.read_bytes()
        if not data:
          raise ValueError(role + " UKI lacks a nonempty " + section + " section")
        actual[role] = data
      for role in ("source", "restore"):
        if actual[role] != actual["production"]:
          raise ValueError(role + " UKI " + section + " differs from production; physical root boot is unqualified")
  return production_hash


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
  require_production_kernel(source, "source")
  require_production_kernel(restore, "restore")
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


def verify_staged(root, receipt, *, source_default=False):
  limine = rooted(root, SINGLE.LIMINE)
  backup = rooted(root, BACKUP)
  if not backup.is_file() or digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Pair Limine backup changed")
  # Snapshot entries written by limine-snapper-sync are not part of the qualified
  # boot policy (they never become default and boot an unrelated read-only
  # snapshot). The recorded snapshot region, retained in the pair backup, is
  # spliced into the current bytes so that everything else, including the pair
  # block, the default entry and the //linux-t2 entry, stays byte-exact against
  # staged_limine_sha256.
  policy = import_path("pair_source_default_normalizer", HERE.parent / "hibernate/boot_policy.py")
  with limine.open("rb") as stream: actual = stream.read(policy.MAX_BYTES + 1)
  donor = backup.read_bytes()
  if source_default:
    # No CLI selects this mode. The routine product verifier first verifies
    # the fixed private external policy and retained configuration backup.
    normalized = policy.normalize_source_default(actual, receipt, donor=donor)
  else:
    if len(actual) > policy.MAX_BYTES: raise ValueError("Oversized Limine configuration")
    normalized = policy.with_region(actual, donor)
    if hashlib.sha256(normalized).hexdigest() != receipt["staged_limine_sha256"]:
      raise ValueError("Staged pair Limine configuration changed")
  text = normalized.decode()
  production = rooted(root, Path("boot/EFI/Linux") / SINGLE.PRODUCTION_IMAGE)
  if digest(production) != receipt["production_uki_sha256"]:
    raise ValueError("Production UKI changed during pair staging")
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
  production_hash = verify_production_boot_sections(production, images, source["production_uki_sha256"])
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
    "kernel_policy": "production-linux-unchanged",
    "source_armed_from_boot_id": None,
    "restore_armed_from_boot_id": None,
    "runtime_stack_sha256": pair["runtime_stack_sha256"],
    "production_uki_sha256": production_hash,
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
  if receipt.get("kernel_policy") != "production-linux-unchanged":
    raise ValueError("Pair source lacks the production-kernel boot policy")
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


# ---- Retirement after a production kernel update -------------------------------------
#
# A kernel update (limine-mkinitcpio) rewrites the production UKI and the hash on the
# production Limine path line, and limine-snapper-sync rewrites the snapshot region.
# verify_staged() then fails closed forever, so rollback and clear cannot retire the
# pair. retire() is the only path out: it is allowed only during inactive package
# maintenance, never touches the production UKI, and archives everything first.
ARCHIVE_ROOT = Path("var/lib/omarchy-t2-hibernation-pair-retired")
PRODUCT_STATE = Path("var/lib/omarchy/t2-hibernate-product")
MAINTENANCE = PRODUCT_STATE / "package-maintenance.pending"
PRODUCT_ACTIVE = (
  PRODUCT_STATE / "boot-policy.json",
  PRODUCT_STATE / "source-default-activation.pending",
  PRODUCT_STATE / "source-default-deactivation.pending",
  PRODUCT_STATE / "runtime-upgrade.pending",
  PRODUCT_STATE / ".runtime-pending",
  Path("etc/omarchy/t2-hibernate-product.enabled"),
)
TRIAL_STATE = Path("var/lib/omarchy/t2-hibernate-trial")
PHYSICAL_LOCK = TRIAL_STATE / "physical-cycle.lock"
DB_LOCK = Path("var/lib/pacman/db.lck")
RETIRE_PROTOCOL = "omarchy-t2-hibernation-pair-retirement-v1"
WITH_IMAGES = ("staged", "source-arming", "restore-arming", "restore-disarmed")
WITHOUT_IMAGES = ("rolled-back", "stage-failed-recovered")
PRODUCTION_PATH = re.compile(
  rb"^([ \t]*path:[ \t]*boot\(\):/EFI/Linux/" + re.escape(SINGLE.PRODUCTION_IMAGE.encode()) + rb")#([0-9a-f]{128})[ \t]*$",
  re.M,
)


def boot_policy():
  return import_path("pair_retire_boot_policy", HERE.parent / "hibernate/boot_policy.py")


def bytes_digest(data):
  return hashlib.sha256(data).hexdigest()


def read_file(path):
  if path.is_symlink() or not path.is_file():
    raise ValueError("Missing or non-regular file: " + str(path))
  return path.read_bytes()


def tree_has_pending(path):
  if not path.is_dir():
    return False
  for _directory, names, files in os.walk(path):
    if any(name.startswith(".pending") for name in names + files):
      return True
  return False


def mask_production_hash(canonical):
  """(canonical Limine bytes with the production hash blanked, that BLAKE2b hash)."""
  matches = PRODUCTION_PATH.findall(canonical)
  if len(matches) != 1:
    raise ValueError("Limine must have exactly one production UKI path line")
  return PRODUCTION_PATH.sub(lambda match: match.group(1) + b"#<production-blake2>", canonical), matches[0][1].decode()


def receipt_block(receipt):
  for role in IMAGES:
    metadata = receipt["images"][role]
    if metadata["entry_id"] != entry_id(role, metadata["sha256"]):
      raise ValueError("Receipt " + role + " entry is not bound to its UKI hash")
  return stage_block({role: receipt["images"][role] for role in IMAGES})


def judge_limine(root, receipt, current, backup):
  """Return (current bytes without our block, new production BLAKE2b, block present).

  The only drift accepted is what a production kernel update legitimately causes:
  the hash on the production path line (which must be coherent with the current
  production UKI) and the limine-snapper-sync snapshot region (removed from both
  sides by boot_policy.limine_canonical). Everything else, including default_entry,
  /+Omarchy and //linux-t2, the EFI fallback and foreign entries, must equal the
  pre-staging backup byte for byte. Unrecognised snapshot text refuses.
  """
  policy = boot_policy()
  if bytes_digest(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Pair Limine backup changed")
  block = receipt_block(receipt)
  present = current.count(block)
  if present > 1:
    raise ValueError("Managed pair block is duplicated")
  remainder = current.replace(block, b"") if present else current
  for marker in (BEGIN, END, SINGLE.BEGIN, SINGLE.END, "/MBA-T2-hibernation-"):
    if marker.encode() in remainder:
      raise ValueError("Limine holds unowned or modified pair text: " + marker)
  expected, _old_hash = mask_production_hash(policy.limine_canonical(backup))
  actual, new_hash = mask_production_hash(policy.limine_canonical(remainder))
  if actual != expected:
    raise ValueError("Limine changed beyond the production UKI hash and snapshot region")
  production = rooted(root, Path("boot/EFI/Linux") / SINGLE.PRODUCTION_IMAGE)
  if not production.is_file() or SINGLE.blake2(production) != new_hash:
    raise ValueError("Production Limine hash is not coherent with the current production UKI; finish the kernel update first")
  return remainder, new_hash, bool(present)


def choose_archive(root, receipt_sha):
  """First archive directory for this receipt that is not a completed retirement."""
  base = rooted(root, ARCHIVE_ROOT)
  index = 0
  while True:
    directory = base / (receipt_sha[:16] + "-" + str(index))
    if not (directory / "retirement.json").exists():
      return directory
    index += 1


def retirement_records(root):
  base = rooted(root, ARCHIVE_ROOT)
  records = []
  if base.is_dir():
    for directory in sorted(base.iterdir()):
      record = directory / "retirement.json"
      if record.is_file():
        records.append(json.loads(record.read_text()))
  return sorted(records, key=lambda record: (record["retired_at_unix"], record["retired_receipt_sha256"]))


def incomplete_journals(root):
  base = rooted(root, ARCHIVE_ROOT)
  found = []
  if base.is_dir():
    for directory in sorted(base.iterdir()):
      journal = directory / "journal.json"
      if journal.is_file() and not (directory / "retirement.json").exists():
        found.append((directory, json.loads(journal.read_text())))
  return found


def check_quiescent(root):
  if not rooted(root, MAINTENANCE).is_file():
    raise ValueError("Retirement is only allowed during package maintenance (marker absent)")
  for relative in PRODUCT_ACTIVE:
    path = rooted(root, relative)
    if path.exists() or path.is_symlink():
      raise ValueError("Hibernation product is active or transitioning: " + relative.name)
  for relative in (SINGLE.ONESHOT, SINGLE.DEFAULT):
    if rooted(root, relative).exists():
      raise ValueError("A boot one-shot or persistent default is armed: " + relative.name)
  if tree_has_pending(rooted(root, TRIAL_STATE)):
    raise ValueError("A hibernation trial is pending")
  if selected_entry(root) != "Omarchy.linux-t2":
    raise ValueError("Pair retirement requires the stock boot")
  if any(rooted(root, path).exists() for path in (SINGLE.RECEIPT, SINGLE.BACKUP, SINGLE.IMAGE)):
    raise ValueError("A legacy candidate boot transaction is active")


def check_images(root, receipt, *, fresh):
  present = {}
  for role, relative in IMAGES.items():
    metadata = receipt["images"][role]
    image = rooted(root, relative)
    if not image.exists():
      present[role] = False
      continue
    if not image.is_file() or digest(image) != metadata["sha256"] or SINGLE.blake2(image) != metadata["blake2"]:
      raise ValueError("ESP " + role + " image does not match the staged receipt")
    present[role] = True
  if fresh and receipt["state"] in WITH_IMAGES and not all(present.values()):
    raise ValueError("A staged pair image is missing from the ESP")
  if fresh and receipt["state"] in WITHOUT_IMAGES and any(present.values()):
    raise ValueError("A pair image remains after rollback; use rollback")
  return present


def plan_retirement(root, receipt, receipt_raw, backup, *, fresh):
  if receipt.get("state") not in WITH_IMAGES + WITHOUT_IMAGES:
    raise ValueError("Pair transaction state cannot be retired: " + str(receipt.get("state")))
  check_quiescent(root)
  state = rooted(root, STATE)
  if state.exists():
    validate_state(state, (RECEIPT.name, BACKUP.name))
  production = rooted(root, Path("boot/EFI/Linux") / SINGLE.PRODUCTION_IMAGE)
  if not production.is_file():
    raise ValueError("Production UKI is missing")
  new_production = digest(production)
  if fresh and new_production == receipt["production_uki_sha256"]:
    raise ValueError("Production UKI is unchanged; use rollback and clear")
  present = check_images(root, receipt, fresh=fresh)
  current = read_file(rooted(root, SINGLE.LIMINE))
  remainder, new_hash, block_present = judge_limine(root, receipt, current, backup)
  if fresh and receipt["state"] in WITH_IMAGES and not block_present:
    raise ValueError("Managed pair block is missing from Limine")
  if fresh and receipt["state"] in WITHOUT_IMAGES and block_present:
    raise ValueError("Managed pair block remains after rollback; use rollback")
  return {
    "action": "retire-after-production-change",
    "receipt_sha256": bytes_digest(receipt_raw),
    "receipt_state": receipt["state"],
    "old_production_uki_sha256": receipt["production_uki_sha256"],
    "new_production_uki_sha256": new_production,
    "new_production_blake2": new_hash,
    "images_present": present,
    "limine_block_present": block_present,
    "limine_before_sha256": bytes_digest(current),
    "limine_after_sha256": bytes_digest(remainder),
    "steps": ["archive", "journal", "limine", "image-source", "image-restore", "backup", "receipt", "record"],
  }, remainder


@contextmanager
def retirement_locks(root):
  """Same exclusion the product transitions use: pacman db.lck plus the physical cycle lock."""
  lock = rooted(root, PHYSICAL_LOCK)
  if lock.is_symlink() or not lock.is_file():
    raise ValueError("Fixed physical cycle lock is missing")
  db = rooted(root, DB_LOCK)
  try:
    db_fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  except FileExistsError:
    raise ValueError("pacman db.lck is held; retry after the package transaction ends") from None
  physical = None
  try:
    physical = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      fcntl.flock(physical, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      raise ValueError("A hibernation cycle holds the physical lock") from None
    yield
  finally:
    if physical is not None:
      os.close(physical)
    held = os.fstat(db_fd)
    os.close(db_fd)
    current = db.lstat()
    if (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
      db.unlink()
      SINGLE.fsync_directory(db.parent)


def write_json(path, value):
  atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def write_archive(root, plan, receipt_raw, backup, current):
  base = rooted(root, ARCHIVE_ROOT)
  directory = choose_archive(root, plan["receipt_sha256"])
  for path in (base, directory, directory / "images"):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)
  files = {"receipt.json": receipt_raw, "limine.conf.before": backup, "limine.conf.at-retirement": current}
  for role, relative in IMAGES.items():
    if plan["images_present"][role]:
      files["images/" + role + ".efi"] = rooted(root, relative).read_bytes()
  for name, data in files.items():
    atomic_write(directory / name, data, 0o600)
  write_json(directory / "manifest.json", {
    "protocol": RETIRE_PROTOCOL,
    "receipt_sha256": plan["receipt_sha256"],
    "files": {name: bytes_digest(data) for name, data in sorted(files.items())},
  })
  for path in (directory / "images", directory, base):
    SINGLE.fsync_directory(path)
  return directory


def write_journal(directory, plan):
  seed = {key: plan[key] for key in ("receipt_sha256", "receipt_state", "old_production_uki_sha256", "new_production_uki_sha256")}
  write_json(directory / "journal.json", {**seed, "protocol": RETIRE_PROTOCOL, "phase": "archived"})
  SINGLE.fsync_directory(directory)


def verify_archive(directory, receipt_sha):
  manifest = json.loads(read_file(directory / "manifest.json"))
  if manifest.get("receipt_sha256") != receipt_sha or manifest.get("protocol") != RETIRE_PROTOCOL:
    raise ValueError("Retirement archive manifest does not bind this receipt")
  for name, expected in manifest["files"].items():
    if bytes_digest(read_file(directory / name)) != expected:
      raise ValueError("Retirement archive file changed: " + name)
  return manifest


def retire(root, *, dry_run=False, step_hook=None):
  """Retire the pair after the production UKI changed. Idempotent and resumable."""
  hook = step_hook or (lambda _name: None)
  pending = incomplete_journals(root)
  if len(pending) > 1:
    raise ValueError("More than one incomplete retirement journal")
  receipt_path = rooted(root, RECEIPT)
  if pending:
    directory, journal = pending[0]
    receipt_raw = read_file(directory / "receipt.json")
    if journal.get("receipt_sha256") != bytes_digest(receipt_raw):
      raise ValueError("Retirement journal does not bind its archived receipt")
    if receipt_path.exists() and read_file(receipt_path) != receipt_raw:
      raise ValueError("Live receipt differs from the interrupted retirement")
    fresh = False
  else:
    if not receipt_path.exists():
      records = retirement_records(root)
      if records:
        return {"state": "already-retired", "retirement": records[-1]}
      raise ValueError("Pair staging receipt is missing and no retirement record exists")
    receipt_raw = read_file(receipt_path)
    directory, fresh = None, True
  receipt = json.loads(receipt_raw)
  if not isinstance(receipt, dict):
    raise ValueError("Pair staging receipt is malformed")

  def backup_bytes():
    live = rooted(root, BACKUP)
    if live.exists():
      return read_file(live)
    if fresh:
      raise ValueError("Pair Limine backup is missing")
    return read_file(directory / "limine.conf.before")

  plan, remainder = plan_retirement(root, receipt, receipt_raw, backup_bytes(), fresh=fresh)
  plan["state"] = "dry-run" if dry_run else ("retiring" if fresh else "resume")
  if dry_run:
    return plan
  limine = rooted(root, SINGLE.LIMINE)
  with retirement_locks(root):
    plan, remainder = plan_retirement(root, receipt, receipt_raw, backup_bytes(), fresh=fresh)
    if fresh:
      directory = write_archive(root, plan, receipt_raw, backup_bytes(), limine.read_bytes())
      hook("archive")
      write_journal(directory, plan)
      hook("journal")
    manifest = verify_archive(directory, plan["receipt_sha256"])
    if plan["limine_block_present"]:
      atomic_write(limine, remainder, 0o600)
    hook("limine")
    for role, relative in IMAGES.items():
      image = rooted(root, relative)
      if image.exists():
        if digest(image) != receipt["images"][role]["sha256"]:
          raise ValueError("Refusing to remove an unknown " + role + " image")
        image.unlink()
        SINGLE.fsync_directory(image.parent)
      hook("image-" + role)
    backup_path = rooted(root, BACKUP)
    if backup_path.exists():
      backup_path.unlink()
      SINGLE.fsync_directory(backup_path.parent)
    hook("backup")
    if receipt_path.exists():
      receipt_path.unlink()
      SINGLE.fsync_directory(receipt_path.parent)
    hook("receipt")
    state = rooted(root, STATE)
    if state.exists():
      remove_state_if_empty(state)
    record = {
      "protocol": RETIRE_PROTOCOL,
      "retired_receipt_sha256": plan["receipt_sha256"],
      "receipt_state": plan["receipt_state"],
      "old_production_uki_sha256": receipt["production_uki_sha256"],
      "new_production_uki_sha256": plan["new_production_uki_sha256"],
      "new_production_blake2": plan["new_production_blake2"],
      "images": {
        role: {"sha256": receipt["images"][role]["sha256"], "archived": "images/" + role + ".efi" in manifest["files"]}
        for role in IMAGES
      },
      "limine_before_sha256": bytes_digest(read_file(directory / "limine.conf.at-retirement")),
      "limine_after_sha256": digest(limine),
      "archive": directory.name,
      "archive_manifest_sha256": digest(directory / "manifest.json"),
      "retired_at_unix": int(time.time()),
    }
    write_json(directory / "retirement.json", record)
    SINGLE.fsync_directory(directory)
    hook("record")
  return {"state": "retired", "retirement": record}


def retire_rollback(root):
  """Undo an interrupted (not completed) retirement from its archive."""
  pending = incomplete_journals(root)
  if len(pending) != 1:
    raise ValueError("Exactly one incomplete retirement journal is required")
  directory, journal = pending[0]
  receipt_raw = read_file(directory / "receipt.json")
  receipt = json.loads(receipt_raw)
  sha = bytes_digest(receipt_raw)
  if journal.get("receipt_sha256") != sha:
    raise ValueError("Retirement journal does not bind its archived receipt")
  check_quiescent(root)
  manifest = verify_archive(directory, sha)
  archived_backup = read_file(directory / "limine.conf.before")
  with retirement_locks(root):
    limine = rooted(root, SINGLE.LIMINE)
    judge_limine(root, receipt, read_file(limine), archived_backup)
    for role, relative in IMAGES.items():
      name = "images/" + role + ".efi"
      image = rooted(root, relative)
      if image.exists():
        if digest(image) != receipt["images"][role]["sha256"]:
          raise ValueError("Refusing to overwrite an unknown " + role + " image")
      elif name in manifest["files"]:
        atomic_write(image, read_file(directory / name), 0o600)
    state = rooted(root, STATE)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not rooted(root, BACKUP).exists():
      atomic_write(rooted(root, BACKUP), archived_backup, 0o600)
    _remainder, _hash, present = judge_limine(root, receipt, read_file(limine), archived_backup)
    if "images/source.efi" in manifest["files"] and not present:
      atomic_write(limine, limine.read_bytes() + receipt_block(receipt), 0o600)
    if not rooted(root, RECEIPT).exists():
      atomic_write(rooted(root, RECEIPT), receipt_raw, 0o600)
    (directory / "journal.json").replace(directory / "journal.aborted.json")
    SINGLE.fsync_directory(directory)
  return {"state": "retirement-rolled-back", "receipt_sha256": sha}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=(
    "stage", "verify", "arm-source", "arm-restore", "disarm-restore", "rollback", "clear",
    "retire-after-production-change", "retire-rollback",
  ))
  parser.add_argument("--source", type=Path)
  parser.add_argument("--restore", type=Path)
  parser.add_argument("--dry-run", action="store_true", help="retire-after-production-change: print the plan and change nothing")
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
  elif args.action == "retire-after-production-change":
    result = retire(root, dry_run=args.dry_run)
  elif args.action == "retire-rollback":
    result = retire_rollback(root)
  elif args.action == "rollback":
    result = rollback(root)
  else:
    result = clear_rolled_back(root)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
