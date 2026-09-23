#!/usr/bin/python3
"""Verify an ordinary source boot of the staged private hibernation UKI pair.

This is read-only. A passing result proves neither physical input nor any
hibernation transition, cold restore, or unattended recovery.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


PAIR = import_path("hibernation_pair_stage", HERE / "stage-hibernation-uki-pair.py")
LEGACY = import_path("hibernation_candidate_verifier", HERE / "verify-hibernation-candidate-boot.py")
MOUNTS = Path("proc/self/mounts")


def verify_primary_root(root):
  mounts = PAIR.rooted(root, MOUNTS)
  matches = [line.split() for line in mounts.read_text().splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
  if len(matches) != 1:
    raise ValueError("Exactly one primary root mount is required")
  source, _target, fstype, options = matches[0][:4]
  if source != "/dev/mapper/root" or fstype != "btrfs" or "subvol=/@" not in options.split(","):
    raise ValueError("Running root is not the primary encrypted Btrfs @ subvolume")
  return {"source": source, "fstype": fstype, "subvolume": "/@"}


def inspect(root, source_directory, restore_directory):
  receipt = PAIR.load_receipt(root)
  if receipt.get("state") != "source-arming":
    raise ValueError("Pair source one-shot was not armed")
  PAIR.verify_staged(root, receipt)
  if PAIR.rooted(root, PAIR.SINGLE.ONESHOT).exists():
    raise ValueError("Source LoaderEntryOneShot was not consumed")
  source_entry = receipt["images"]["source"]["entry_id"]
  if PAIR.selected_entry(root) != source_entry:
    raise ValueError("Running boot is not the exact source entry")
  boot_id = PAIR.current_boot_id(root)
  armed_from = receipt.get("source_armed_from_boot_id")
  if not isinstance(armed_from, str) or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", armed_from) is None:
    raise ValueError("Source arming boot ID is missing or malformed")
  if boot_id == armed_from:
    raise ValueError("Source was not selected by a new boot")

  source = PAIR.AUDIT.load_candidate(source_directory, "source")
  restore = PAIR.AUDIT.load_candidate(restore_directory, "restore")
  pair = PAIR.AUDIT.audit(source, restore)
  if source.get("candidate") != "mba-t2-hibernation-early-source" or source.get("pre_restore_module_policy") != "early-t2-radio":
    raise ValueError("Running source does not have the early T2/radio policy")
  if restore.get("candidate") != "mba-t2-hibernation-module-overlay":
    raise ValueError("Restore UKI is not the isolated module-overlay candidate")
  if pair["runtime_stack_sha256"] != receipt.get("runtime_stack_sha256"):
    raise ValueError("Staged pair has a different runtime stack")
  for role, directory, provenance in (
    ("source", source_directory, source),
    ("restore", restore_directory, restore),
  ):
    image = receipt["images"][role]
    if image.get("sha256") != provenance.get("candidate_uki_sha256"):
      raise ValueError("Staged " + role + " image differs from private provenance")
    if image.get("provenance_sha256") != PAIR.digest(directory / "provenance.json"):
      raise ValueError("Staged " + role + " provenance changed")
    if image.get("experiment_id") != provenance.get("experiment_id"):
      raise ValueError("Staged " + role + " experiment ID changed")

  if LEGACY.read(LEGACY.confined(root, LEGACY.MODEL)) != "MacBookAir9,1":
    raise ValueError("Pair qualification is restricted to MacBookAir9,1")
  if LEGACY.read(LEGACY.confined(root, LEGACY.OSRELEASE)) != source.get("kernel_release"):
    raise ValueError("Running kernel release differs from the source UKI")
  cmdline = LEGACY.read(LEGACY.confined(root, LEGACY.CMDLINE))
  if cmdline != source.get("cmdline"):
    raise ValueError("Running kernel command line differs from the source UKI")
  primary_root = verify_primary_root(root)
  return {
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "boot_id": boot_id,
    "source_armed_from_boot_id": armed_from,
    "source_entry_id": source_entry,
    "source_uki_sha256": receipt["images"]["source"]["sha256"],
    "restore_entry_id": receipt["images"]["restore"]["entry_id"],
    "restore_uki_sha256": receipt["images"]["restore"]["sha256"],
    "runtime_stack_sha256": pair["runtime_stack_sha256"],
    "kernel_release": source["kernel_release"],
    "cmdline_sha256": hashlib.sha256(cmdline.encode()).hexdigest(),
    "primary_root": primary_root,
    "modules": LEGACY.verify_modules(root, source),
    "pci": LEGACY.verify_pci(root),
    "devices": LEGACY.verify_devices(root),
    "physical_input_confirmed": False,
    "hibernate_attempted": False,
    "hardware_qualified": False,
  }


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--restore", type=Path, required=True)
  arguments = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    result = inspect(Path("/"), arguments.source.resolve(), arguments.restore.resolve())
  except (OSError, ValueError) as error:
    raise SystemExit("Pair source boot refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
