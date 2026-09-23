#!/usr/bin/python3
"""Check a proposed source-initrd/isolated-restore UKI pair without staging it.

This is a structural audit, not proof that the pair boots or restores an image.
It reads only private build artifacts and does not touch the ESP or PM controls.
Historical images with consumed hardware guards may pass; this never authorizes
repeating a PM vector.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


S4 = import_path("candidate_s4_runner", HERE / "run-hibernation-candidate-s4.py")
HASH = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_INITRD_MODULES = S4.RUNTIME_MODULES - {"t2bce_ave"}


def sha256(path):
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def load_candidate(directory, label):
  if directory.is_symlink() or not directory.is_dir():
    raise ValueError(label + " private directory is missing or symlinked")
  report = directory / "provenance.json"
  image = directory / "mba-t2-hibernation-candidate.efi"
  initrd = directory / "mba-t2-hibernation-candidate.initrd"
  for path in (report, image, initrd):
    if path.is_symlink() or not path.is_file():
      raise ValueError(label + " artifact is missing or symlinked: " + path.name)
  try:
    provenance = json.loads(report.read_text())
  except json.JSONDecodeError as error:
    raise ValueError(label + " provenance is malformed") from error
  if not isinstance(provenance, dict):
    raise ValueError(label + " provenance is not an object")
  for name, path, field in (
    ("UKI", image, "candidate_uki_sha256"),
    ("initramfs", initrd, "candidate_initrd_sha256"),
  ):
    expected = provenance.get(field)
    if not isinstance(expected, str) or HASH.fullmatch(expected) is None or sha256(path) != expected:
      raise ValueError(label + " " + name + " differs from provenance")
  for field in ("installed", "boot_entry_created", "hardware_qualified", "production_modified"):
    if provenance.get(field) is not False:
      raise ValueError(label + " is not an offline private build: " + field)
  return provenance


def audit(source, restore):
  source_stack = S4.runtime_stack_identity(source)
  restore_stack = S4.runtime_stack_identity(restore)
  if source_stack != restore_stack:
    raise ValueError("Source and restore images have different kernel/cmdline/module stack identities")
  if source.get("candidate_uki_sha256") == restore.get("candidate_uki_sha256"):
    raise ValueError("Source and restore must be distinct UKIs")

  source_modules = source.get("initrd_module_selection")
  if not isinstance(source_modules, dict) or set(source_modules) != SOURCE_INITRD_MODULES:
    raise ValueError("Source initramfs does not select the complete T2/radio module set")
  if any(not isinstance(path, str) or not path.startswith("usr/lib/modules/") for path in source_modules.values()):
    raise ValueError("Source initramfs module paths are malformed")
  if source.get("pre_restore_module_policy") not in (None, "early-t2-radio"):
    raise ValueError("Source image has an unknown or isolated pre-restore policy")

  if restore.get("pre_restore_module_policy") != "root-only-no-t2-radio":
    raise ValueError("Restore image lacks the isolated pre-restore policy")
  if restore.get("initrd_module_selection") != {}:
    raise ValueError("Restore initramfs would select a T2/radio module")
  excluded = restore.get("pre_restore_excluded_modules")
  if not isinstance(excluded, list) or set(excluded) != S4.RUNTIME_MODULES or len(excluded) != len(S4.RUNTIME_MODULES):
    raise ValueError("Restore image does not exclude the complete T2/radio module set")
  payload = restore.get("post_switch_root_payload")
  if not isinstance(payload, dict) or set(payload) != S4.RUNTIME_MODULES:
    raise ValueError("Restore image lacks the complete ordinary-boot payload")
  if any(not isinstance(path, str) or not path.startswith("usr/lib/omarchy-t2-hibernation-candidate/payload/") for path in payload.values()):
    raise ValueError("Restore payload paths are malformed")

  return {
    "classification": "structurally-matched-private-pair-not-boot-qualified",
    "source_uki_sha256": source["candidate_uki_sha256"],
    "restore_uki_sha256": restore["candidate_uki_sha256"],
    "runtime_stack_sha256": source_stack,
    "source_initrd_modules": sorted(source_modules),
    "restore_pre_restore_excluded_modules": sorted(excluded),
  }


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--restore", type=Path, required=True)
  arguments = parser.parse_args()
  try:
    result = audit(
      load_candidate(arguments.source, "source"),
      load_candidate(arguments.restore, "restore"),
    )
  except (OSError, ValueError) as error:
    parser.error(str(error))
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
