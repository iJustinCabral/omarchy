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
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


S4 = import_path("candidate_s4_runner", HERE / "run-hibernation-candidate-s4.py")
HASH = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_INITRD_MODULES = S4.RUNTIME_MODULES - {"t2bce_ave"}
RESTORE_MARKER_VARIABLE = "OmarchyT2RestoreStage-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
V2_RESTORE_MARKER_VARIABLE = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
RESTORE_MARKER_HOOK = "omarchy-t2-restore-marker"
RESTORE_MARKER_HOOK_SOURCE = HERE / "hibernate-candidate-initcpio/hooks" / RESTORE_MARKER_HOOK
LEGACY_RESTORE_MARKER_HOOK_SHA256 = {
  "6cbf3fc606eab48094e6af7d9835e538bf5e2a7e99e5695b144d7ce102ea0bc5",
  "596148e631fbf3218fdacf5c2ea83040a3ecbffab834a25204f289242b37585d",
}


def sha256(path):
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def validate_restore_marker_metadata(marker):
  legacy_fields = {"sha256", "srcversion", "efi_variable", "pre_resume_hook", "hook_sha256"}
  if not isinstance(marker, dict) or set(marker) not in (legacy_fields, legacy_fields | {"version"}):
    raise ValueError("Restore marker metadata is missing or malformed")
  version = marker.get("version", "v1")
  if version not in ("v1", "v2") or (version == "v2" and "version" not in marker):
    raise ValueError("Restore marker variable version is malformed")
  expected_variable = RESTORE_MARKER_VARIABLE if version == "v1" else V2_RESTORE_MARKER_VARIABLE
  allowed_hooks = {sha256(RESTORE_MARKER_HOOK_SOURCE)}
  if version == "v1":
    allowed_hooks.update(LEGACY_RESTORE_MARKER_HOOK_SHA256)
  if (not isinstance(marker["sha256"], str) or HASH.fullmatch(marker["sha256"]) is None or
      not isinstance(marker["srcversion"], str) or re.fullmatch(r"[0-9A-F]+", marker["srcversion"]) is None or
      marker["efi_variable"] != expected_variable or marker["pre_resume_hook"] != RESTORE_MARKER_HOOK or
      marker["hook_sha256"] not in allowed_hooks):
    raise ValueError("Restore marker identity differs from the pinned diagnostic")


def verify_restore_marker_tree(extracted, marker):
  validate_restore_marker_metadata(marker)
  directory = extracted / "usr/lib/omarchy-t2-restore-marker"
  for path in (extracted / "hooks" / RESTORE_MARKER_HOOK,
               directory / "marker.ko", directory / "marker.sha256", directory / "marker.srcversion"):
    if path.is_symlink() or not path.is_file():
      raise ValueError("Restore marker initramfs file is absent or symlinked: " + path.name)
  if sha256(directory / "marker.ko") != marker["sha256"]:
    raise ValueError("Restore marker initramfs module differs from provenance")
  if sha256(extracted / "hooks" / RESTORE_MARKER_HOOK) != marker["hook_sha256"]:
    raise ValueError("Restore marker initramfs hook differs from audited source")
  if (directory / "marker.sha256").read_text().strip() != marker["sha256"]:
    raise ValueError("Restore marker initramfs SHA identity differs")
  if (directory / "marker.srcversion").read_text().strip() != marker["srcversion"]:
    raise ValueError("Restore marker initramfs source version differs")
  version_file = directory / "marker.version"
  if "version" in marker:
    if version_file.is_symlink() or not version_file.is_file() or version_file.read_text().strip() != marker["version"]:
      raise ValueError("Restore marker initramfs variable version differs")
  elif version_file.exists() or version_file.is_symlink():
    raise ValueError("Legacy restore marker unexpectedly embeds a version file")
  config = (extracted / "config").read_text()
  hooks_line = re.search(r'^HOOKS="([^"]*)"$', config, re.M)
  if hooks_line is None:
    raise ValueError("Restore marker initramfs lacks resolved hook order")
  hooks = hooks_line.group(1).split()
  if (hooks.count(RESTORE_MARKER_HOOK) != 1 or hooks.count("resume") != 1 or
      hooks.index(RESTORE_MARKER_HOOK) + 1 != hooks.index("resume")):
    raise ValueError("Restore marker does not run immediately before resume")


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
  marker = provenance.get("restore_marker")
  if marker is not None:
    if label != "restore":
      raise ValueError("Source image must not load the cold-restore marker")
    with tempfile.TemporaryDirectory(prefix="t2-restore-marker-audit-") as temporary:
      try:
        subprocess.run(("lsinitcpio", "--cpio", "--extract", str(initrd)), cwd=temporary,
                       check=True, capture_output=True)
      except subprocess.CalledProcessError as error:
        raise ValueError("Restore marker initramfs could not be extracted") from error
      verify_restore_marker_tree(Path(temporary), marker)
  if provenance.get("modified_sections_sha256") is not None:
    modified = provenance["modified_sections_sha256"]
    if not isinstance(modified, dict) or set(modified) != {".linux"}:
      raise ValueError(label + " kernel override section list is invalid")
    override = provenance.get("kernel_override")
    if not isinstance(override, dict) or type(override.get("unpadded_size")) is not int or override["unpadded_size"] <= 0:
      raise ValueError(label + " raw kernel size is invalid")
    with tempfile.TemporaryDirectory(prefix="t2-pair-audit-") as temporary:
      for section, expected in ((".linux", modified[".linux"]), (".initrd", provenance["candidate_initrd_sha256"])):
        extracted = Path(temporary) / section.lstrip(".")
        try:
          subprocess.run(("objcopy", "-O", "binary", "--only-section=" + section, str(image), str(extracted)), check=True, capture_output=True)
        except subprocess.CalledProcessError as error:
          raise ValueError(label + " UKI " + section + " could not be extracted") from error
        if sha256(extracted) != expected:
          raise ValueError(label + " UKI " + section + " differs from provenance")
        if section == ".linux":
          contents = extracted.read_bytes()
          size = override["unpadded_size"]
          if size > len(contents) or len(contents) - size >= 4096 or any(contents[size:]):
            raise ValueError(label + " UKI .linux has unexpected padding")
          if hashlib.sha256(contents[:size]).hexdigest() != override.get("sha256"):
            raise ValueError(label + " UKI raw kernel differs from provenance")
  return provenance


def audit(source, restore):
  if source.get("restore_marker") is not None:
    raise ValueError("Source image must not contain the cold-restore marker")
  marker = restore.get("restore_marker")
  if marker is not None:
    validate_restore_marker_metadata(marker)
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
    "restore_marker": marker,
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
