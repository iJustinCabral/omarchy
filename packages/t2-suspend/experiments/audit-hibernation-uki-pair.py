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
import struct
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
MINIMAL_RESTORE_POLICY = {
  "version": "storage-no-gpu-thunderbolt-v1",
  "excluded_hooks": ["kms", "plymouth"],
  "excluded_modules": ["i915", "xe", "thunderbolt"],
}
COLD_PRE_CPU = HERE / "hibernate-cold-pre-cpu"
COLD_DIRECTORY = "usr/lib/omarchy-t2-cold-pre-cpu/"
COLD_BUNDLE_FILES = (
  "functions", "abort.ko", "abort.sha256", "abort.srcversion", "restore.variable",
  "header-reader", "header-reader.sha256", "resume.device", "resume.offset", "resume.devnum",
  "stock-resume", "stock-resume.sha256",
)
COLD_HOOKS = ("omarchy-t2-cold-pre-cpu", "omarchy-t2-cold-pre-cpu-return", "resume")
COLD = import_path("audit_cold_protocols", HERE / "cold-abort-protocols.py")
PCI = import_path("audit_cold_pci_protocols", HERE / "cold-pci-abort-protocols.py")


def validate_static_header_helper(data):
  if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
    raise ValueError("Cold pre-CPU header helper must be a static x86-64 ELF executable")
  values = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
  kind, machine, version, _, offset, _, _, size, entry_size, count, _, _, _ = values
  if kind not in (2, 3) or machine != 62 or version != 1 or size != 64 or entry_size != 56 or not count or offset < 64 or offset + entry_size * count > len(data):
    raise ValueError("Cold pre-CPU header helper has invalid ELF program headers")
  types = [struct.unpack_from("<I", data, offset + index * entry_size)[0] for index in range(count)]
  if 3 in types or 1 not in types:
    raise ValueError("Cold pre-CPU header helper must be static without PT_INTERP")


def validate_cold_pre_cpu_metadata(provenance):
  if PCI.select(provenance) == PCI.KEY:
    return PCI.validate_metadata(provenance)
  protocol = COLD.select(provenance)
  if protocol is None:
    raise ValueError("Cold abort metadata is absent")
  profile = COLD.PROFILES[protocol]
  diagnostic = provenance.get(protocol)
  if not isinstance(diagnostic, dict):
    raise ValueError("Cold abort metadata is missing or malformed")
  fields = {"version", "target", "module_sha256", "module_srcversion", "module_vermagic",
            "header_helper_sha256", "restore_variable", "resume", "source_sha256", "files_sha256"}
  if profile["observations"] is not None:
    fields.add("boundary_observations")
    observed = diagnostic.get("boundary_observations")
    if (not isinstance(observed, dict) or observed != profile["observations"] or
        any(type(observed[key]) is not type(value) for key, value in profile["observations"].items())):
      raise ValueError("Cold abort observation contract differs")
  if set(diagnostic) != fields:
    raise ValueError("Cold pre-CPU metadata is missing or malformed")
  if diagnostic["version"] != profile["version"] or diagnostic["target"] != profile["target"]:
    raise ValueError("Cold pre-CPU protocol or target differs")
  if provenance.get("experiment_id") != profile["version"]:
    raise ValueError("Cold abort experiment ID differs from its exact protocol")
  for key in ("module_sha256", "header_helper_sha256"):
    if not isinstance(diagnostic[key], str) or HASH.fullmatch(diagnostic[key]) is None:
      raise ValueError("Cold pre-CPU binary identity is malformed")
  marker = provenance.get("restore_marker")
  if not isinstance(marker, dict) or diagnostic["restore_variable"] != marker.get("efi_variable"):
    raise ValueError("Cold pre-CPU marker selector differs from the restore marker")
  srcversion, vermagic = diagnostic["module_srcversion"], diagnostic["module_vermagic"]
  if (not isinstance(srcversion, str) or re.fullmatch(r"[0-9A-F]+", srcversion) is None or
      not isinstance(vermagic, str) or not vermagic.split() or vermagic.split()[0] != provenance.get("kernel_release")):
    raise ValueError("Cold pre-CPU module source version or production ABI differs")
  if diagnostic["resume"] != {"device": "/dev/mapper/root", "offset": 1923214, "devnum": "253:0"}:
    raise ValueError("Cold pre-CPU pending-header target differs")
  sources = diagnostic["source_sha256"]
  required_sources = COLD.sources(protocol)
  if not isinstance(sources, dict) or set(sources) != set(required_sources):
    raise ValueError("Cold pre-CPU source identity is incomplete")
  for filename, expected in sources.items():
    if expected != sha256(required_sources[filename]):
      raise ValueError("Cold pre-CPU source differs from the pinned diagnostic: " + filename)
  files = diagnostic["files_sha256"]
  required = {profile["directory"] + name for name in COLD_BUNDLE_FILES} | {"hooks/" + name for name in COLD.hooks(protocol)} | {
    COLD.COMMON_DIRECTORY + "functions", COLD.COMMON_DIRECTORY + "protocol"}
  if not isinstance(files, dict) or set(files) != required or any(not isinstance(value, str) or HASH.fullmatch(value) is None for value in files.values()):
    raise ValueError("Cold pre-CPU bundle identities are incomplete")
  for filename, source in [(profile["directory"] + "functions", profile["source"] / "functions"),
                           (COLD.COMMON_DIRECTORY + "functions", COLD.COMMON / "functions"),
                           (profile["directory"] + "stock-resume", Path("/usr/lib/initcpio/hooks/resume")),
                           *[("hooks/" + hook, (COLD.COMMON if hook == "resume" else profile["source"]) / "hooks" / hook) for hook in COLD.hooks(protocol)]]:
    if files[filename] != sha256(source):
      raise ValueError("Cold pre-CPU script differs from pinned source: " + filename)
  if files[profile["directory"] + "abort.ko"] != diagnostic["module_sha256"] or files[profile["directory"] + "header-reader"] != diagnostic["header_helper_sha256"]:
    raise ValueError("Cold pre-CPU binary identity disagrees with its bundle")
  return diagnostic


def verify_cold_pre_cpu_tree(extracted, provenance):
  if PCI.select(provenance) == PCI.KEY:
    class TreeAudit:
      validate_static_header_helper = staticmethod(validate_static_header_helper)
      verify_no_unannounced_cold_tree = staticmethod(verify_no_unannounced_cold_tree)
    return PCI.verify_tree(extracted, provenance, TreeAudit)
  diagnostic = validate_cold_pre_cpu_metadata(provenance)
  protocol = COLD.select(provenance)
  profile = COLD.PROFILES[protocol]
  selected = extracted / COLD.COMMON_DIRECTORY / "protocol"
  if selected.read_text() != profile["version"] + "\n":
    raise ValueError("Cold abort shared selector differs from provenance")
  for filename, expected in diagnostic["files_sha256"].items():
    path = extracted / filename
    if path.is_symlink() or not path.is_file() or sha256(path) != expected:
      raise ValueError("Cold pre-CPU embedded file differs: " + filename)
  directory = extracted / profile["directory"]
  for filename, expected in {
    "abort.sha256": diagnostic["module_sha256"],
    "abort.srcversion": diagnostic["module_srcversion"],
    "header-reader.sha256": diagnostic["header_helper_sha256"],
    "restore.variable": diagnostic["restore_variable"],
    "resume.device": "/dev/mapper/root", "resume.offset": "1923214", "resume.devnum": "253:0",
    "stock-resume.sha256": diagnostic["files_sha256"][profile["directory"] + "stock-resume"],
  }.items():
    if (directory / filename).read_text() != expected + "\n":
      raise ValueError("Cold pre-CPU embedded identity differs: " + filename)
  module_fields = [("name", profile["module"]), ("srcversion", diagnostic["module_srcversion"]),
                   ("vermagic", diagnostic["module_vermagic"]), ("mba_cold_permanent", "v1")]
  if profile["boundary"] is not None:
    module_fields.append(("mba_cold_boundary", profile["boundary"]))
  for field, expected in module_fields:
    actual = subprocess.run(("modinfo", "-F", field, str(directory / "abort.ko")), check=True, capture_output=True, text=True).stdout.strip()
    if actual != expected:
      raise ValueError("Cold pre-CPU embedded module metadata differs: " + field)
  if not (directory / "header-reader").stat().st_mode & 0o100:
    raise ValueError("Cold pre-CPU pending-header helper is not executable")
  validate_static_header_helper((directory / "header-reader").read_bytes())
  alternative = extracted / "usr/lib/systemd/systemd-hibernate-resume"
  if alternative.exists() or alternative.is_symlink():
    raise ValueError("Cold pre-CPU would permit an alternative effective resume target")
  config = (extracted / "config").read_text()
  resolved = {}
  for field in ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    matches = re.findall(r'^' + field + r'="([^\"]*)"$', config, re.M)
    if len(matches) != 1:
      raise ValueError("Cold pre-CPU lacks resolved hook order: " + field)
    resolved[field] = matches[0].split()
  chain = [profile["hook"], "omarchy-t2-restore-marker", "resume", profile["hook"] + "-return"]
  required = ["encrypt", *chain]
  hooks = resolved["HOOKS"]
  if any(hooks.count(name) != 1 for name in required):
    raise ValueError("Cold pre-CPU hook order is missing or duplicated")
  start = hooks.index(chain[0])
  if hooks[start:start + len(chain)] != chain or hooks.index("encrypt") >= start:
    raise ValueError("Cold pre-CPU hooks must surround synchronous marker/resume after encrypt")
  for field, names in resolved.items():
    if field != "HOOKS" and set(names) & {"omarchy-t2-restore-marker", *COLD.hooks(protocol)}:
      raise ValueError("Cold pre-CPU hook is scheduled outside synchronous resume")
  for other in COLD.PROFILES:
    if other != protocol:
      verify_no_unannounced_cold_tree(extracted, protocols=(other,), common=False)
  PCI.reject_unannounced(extracted)


def verify_no_unannounced_cold_tree(extracted, protocols=None, common=True, pci=True):
  if pci:
    PCI.reject_unannounced(extracted)
  if common:
    directory = extracted / COLD.COMMON_DIRECTORY
    if directory.exists() or directory.is_symlink():
      raise ValueError("Unannounced cold abort shared bundle is forbidden")
  for protocol in (COLD.PROFILES if protocols is None else protocols):
    _verify_unannounced_protocol(extracted, protocol)


def _verify_unannounced_protocol(extracted, protocol):
  profile = COLD.PROFILES[protocol]
  directory = extracted / profile["directory"]
  if directory.exists() or directory.is_symlink():
    raise ValueError("Unannounced cold pre-CPU bundle is forbidden")
  for hook in COLD.hooks(protocol)[:2]:
    path = extracted / "hooks" / hook
    if path.exists() or path.is_symlink():
      raise ValueError("Unannounced cold pre-CPU hook is forbidden")
  for path in extracted.rglob(profile["module"] + ".ko*"):
    raise ValueError("Unannounced cold pre-CPU module is forbidden")
  for filename in ("config", "hooks/resume"):
    path = extracted / filename
    if path.is_file() and profile["hook"] in path.read_text():
      raise ValueError("Unannounced cold pre-CPU runtime policy is forbidden")


def verify_minimal_restore_tree(extracted, provenance):
  if provenance.get("minimal_restore_policy") != MINIMAL_RESTORE_POLICY:
    raise ValueError("Unknown or malformed minimal restore device policy")
  config = (extracted / "config").read_text()
  resolved = {}
  for field in ("MODULES", "HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    match = re.search(r'^' + field + r'="([^\"]*)"$', config, re.M)
    if match is None:
      raise ValueError("Minimal restore audit lacks resolved " + field)
    resolved[field] = match.group(1).split()
    excluded = MINIMAL_RESTORE_POLICY["excluded_modules"] if field == "MODULES" else MINIMAL_RESTORE_POLICY["excluded_hooks"]
    if set(resolved[field]) & set(excluded):
      raise ValueError("Minimal restore audit found an excluded device or hook")
  if not {"udev", "encrypt", "resume"}.issubset(resolved["HOOKS"]):
    raise ValueError("Minimal restore audit lacks encrypted-root resume hooks")
  if "omarchy-t2-candidate-modules" not in resolved["LATEHOOKS"]:
    raise ValueError("Minimal restore audit lacks ordinary-boot payload hook")
  module_tree = extracted / "usr/lib/modules" / provenance["kernel_release"]
  modules = []
  for path in module_tree.rglob("*"):
    if not re.search(r"\.ko(?:\.|$)", path.name):
      continue
    name = path.name.split(".ko", 1)[0]
    if (name in MINIMAL_RESTORE_POLICY["excluded_modules"] or
        "drivers/gpu/drm/" in path.as_posix() or "drivers/thunderbolt/" in path.as_posix()):
      raise ValueError("Minimal restore audit found an excluded driver or DRM dependency: " + path.name)
    modules.append(name)
  for name in ("nvme", "nvme-core", "dm-crypt", "dm-mod"):
    if modules.count(name) != 1:
      raise ValueError("Minimal restore audit lacks one exact root-critical module: " + name)
  for name in ("usr/bin/cryptsetup", "usr/bin/btrfs", "etc/cryptsetup-keys.d/root.key"):
    path = extracted / name
    if path.is_symlink() or not path.is_file():
      raise ValueError("Minimal restore audit lacks a regular root-critical file: " + name)


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


def extract_restore_initramfs(initrd, extracted):
  # mkinitcpio can place root-critical modules alongside early microcode;
  # audit the same combined tree the kernel unpacks, including both archives.
  try:
    subprocess.run(("lsinitcpio", "--early", "--extract", str(initrd)), cwd=extracted,
                   check=True, capture_output=True)
    subprocess.run(("lsinitcpio", "--cpio", "--extract", str(initrd)), cwd=extracted,
                   check=True, capture_output=True)
  except subprocess.CalledProcessError as error:
    detail = error.stderr.decode(errors="replace").strip() if isinstance(error.stderr, bytes) else str(error.stderr or "").strip()
    raise ValueError("Restore marker initramfs could not be extracted: " + detail) from error


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
  minimal = "minimal_restore_policy" in provenance
  cold = PCI.select(provenance)
  if minimal and marker is None:
    raise ValueError("Minimal cold-restore policy requires the restore marker")
  if cold:
    if label != "restore" or provenance.get("minimal_restore_policy") != MINIMAL_RESTORE_POLICY:
      raise ValueError("Cold pre-CPU is restricted to a minimal private restore image")
    validate_cold_pre_cpu_metadata(provenance)
  if (marker is not None or minimal) and label != "restore":
    raise ValueError("Source image must not load the cold-restore marker")
  with tempfile.TemporaryDirectory(prefix="t2-initramfs-audit-") as temporary:
    extracted = Path(temporary)
    extract_restore_initramfs(initrd, extracted)
    if marker is not None:
      verify_restore_marker_tree(extracted, marker)
    if minimal:
      verify_minimal_restore_tree(extracted, provenance)
    if cold:
      verify_cold_pre_cpu_tree(extracted, provenance)
    else:
      verify_no_unannounced_cold_tree(extracted)
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
  if PCI.select(source) is not None:
    raise ValueError("Source image must not contain cold pre-CPU diagnostics")
  protocol = PCI.select(restore)
  if protocol is not None:
    if restore.get("minimal_restore_policy") != MINIMAL_RESTORE_POLICY:
      raise ValueError("Cold pre-CPU requires the minimal private restore policy")
    validate_cold_pre_cpu_metadata(restore)
  if "minimal_restore_policy" in source:
    raise ValueError("Source image must not use the minimal cold-restore policy")
  if "minimal_restore_policy" in restore and restore["minimal_restore_policy"] != MINIMAL_RESTORE_POLICY:
    raise ValueError("Unknown or malformed minimal restore device policy")
  if source.get("restore_marker") is not None:
    raise ValueError("Source image must not contain the cold-restore marker")
  marker = restore.get("restore_marker")
  if "minimal_restore_policy" in restore and marker is None:
    raise ValueError("Minimal cold-restore policy requires the restore marker")
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

  result = {
    "classification": "structurally-matched-private-pair-not-boot-qualified",
    "source_uki_sha256": source["candidate_uki_sha256"],
    "restore_uki_sha256": restore["candidate_uki_sha256"],
    "runtime_stack_sha256": source_stack,
    "source_initrd_modules": sorted(source_modules),
    "restore_pre_restore_excluded_modules": sorted(excluded),
    "restore_marker": marker,
  }
  if "minimal_restore_policy" in restore:
    result["minimal_restore_policy"] = restore["minimal_restore_policy"]
  if protocol is not None:
    result[protocol] = restore[protocol]
    if protocol == PCI.KEY:
      result["kernel_release"] = restore["kernel_release"]
      result["experiment_id"] = restore["experiment_id"]
  return result


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
