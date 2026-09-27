"""Offline product pins derived from explicitly supplied private UKI artifacts.

This adapter reuses the existing pair auditor and section extractor. Scratch
extraction uses disposable private temporary directories; no build, staging,
live-host sampling, EFI or PM operation exists. Structural audit never creates
product qualification or authorizes repeating a consumed experimental vector.
Audited details have a separate digest: the strict ledger manifest is unchanged.
UKI .cmdline bytes and a future /proc/cmdline sample have different framing and
must not be treated as the same hash. The external source marker still requires
its own audited pin; it is not embedded in the early-source UKI.
"""

import copy
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import re
import stat
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent


def _module(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


TX = _module("artifact_product_transaction", HERE / "transaction.py")
AUDIT = _module("artifact_pair_audit", HERE.parent / "experiments/audit-hibernation-uki-pair.py")
SOURCE = _module("artifact_source_layout", HERE.parent / "experiments/build-hibernation-source-uki.py")
DETAILS_PROTOCOL = "omarchy-t2-product-artifact-details-v1"
FULLRESTORE = "cold-pci-guard-fullrestore-v1"
CHUNK_BYTES = 1024 * 1024
MAX_SMALL_BYTES = 2 * 1024 * 1024


def _regular_path(path):
  path = Path(path)
  if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents):
    raise ValueError("Artifact path is missing, nonregular or symlinked")
  return path


def _chunks(value):
  if type(value) is bytes:
    for offset in range(0, len(value), CHUNK_BYTES):
      yield value[offset:offset + CHUNK_BYTES]
  else:
    path = _regular_path(value)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
      if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        raise ValueError("Artifact changed to nonregular file")
      while chunk := stream.read(CHUNK_BYTES):
        yield chunk


def _file_digest(value):
  digest = hashlib.sha256()
  for chunk in _chunks(value):
    digest.update(chunk)
  return digest.hexdigest()


def _same_bytes(left, right):
  with contextlib.ExitStack() as stack:
    left_chunks = stack.enter_context(contextlib.closing(_chunks(left)))
    right_chunks = stack.enter_context(contextlib.closing(_chunks(right)))
    for left_chunk in left_chunks:
      if left_chunk != next(right_chunks, None):
        return False
    return next(right_chunks, None) is None


def _raw(path):
  """Bounded reads are reserved for JSON, tiny helpers and command-line text."""
  path = _regular_path(path)
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  with os.fdopen(fd, "rb") as stream:
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_size > MAX_SMALL_BYTES:
      raise ValueError("Small artifact exceeds bounded read contract")
    raw = stream.read(MAX_SMALL_BYTES + 1)
    if len(raw) > MAX_SMALL_BYTES:
      raise ValueError("Small artifact exceeds bounded read contract")
    return raw


def _digest(raw):
  return hashlib.sha256(raw).hexdigest()


@contextlib.contextmanager
def extract_section(image, section):
  """Use the existing objcopy extractor; scratch output never touches inputs."""
  with tempfile.TemporaryDirectory(prefix="t2-product-section-audit-") as directory:
    output = Path(directory) / "section"
    SOURCE.BASE.extract_section(Path(image), section, output)
    if output.stat().st_size == 0:
      raise ValueError("UKI section is empty: " + section)
    yield output


def _section_value(stack, extractor, image, section):
  value = extractor(image, section)
  if hasattr(value, "__enter__") and hasattr(value, "__exit__"):
    value = stack.enter_context(value)
  if type(value) is bytes:
    if not value:
      raise ValueError("Extractor returned empty section bytes")
  elif isinstance(value, Path):
    _regular_path(value)
    if value.stat().st_size == 0:
      raise ValueError("Extractor returned empty section file")
  else:
    raise ValueError("Extractor must return scoped section file or synthetic bytes")
  return value


def verify_source_layout(directory, provenance):
  """Recheck the early-source builder's layout against the actual initramfs."""
  with tempfile.TemporaryDirectory(prefix="t2-product-source-audit-") as temporary:
    tree = Path(temporary)
    AUDIT.extract_restore_initramfs(Path(directory) / "mba-t2-hibernation-candidate.initrd", tree)
    for name in ("init", "usr/bin/cryptsetup", "usr/bin/btrfs", "etc/cryptsetup-keys.d/root.key",
                 *SOURCE.REQUIRED_INITRD_FILES, "config", "etc/modprobe.d/t2-bluetooth-order.conf"):
      _regular_path(tree / name)
    if _raw(tree / SOURCE.REQUIRED_INITRD_FILES[2]).decode().strip() != provenance["experiment_id"]:
      raise ValueError("Early-source experiment marker differs")
    config = _raw(tree / "config").decode()
    if "omarchy-t2-source-bluetooth" not in config or "omarchy-t2-candidate-modules" in config:
      raise ValueError("Early-source initramfs hook policy differs")
    if not _same_bytes(tree / SOURCE.REQUIRED_INITRD_FILES[0], SOURCE.SOURCE_HOOKS / SOURCE.REQUIRED_INITRD_FILES[0]):
      raise ValueError("Early-source Bluetooth hook differs")
    if not _same_bytes(tree / SOURCE.REQUIRED_INITRD_FILES[1], SOURCE.BASE.CANDIDATE_BLUETOOTH_HELPER):
      raise ValueError("Early-source Bluetooth helper differs")
    blacklist = _raw(tree / "etc/modprobe.d/t2-bluetooth-order.conf").decode()
    if re.search(r"^\s*blacklist\s+hci_bcm4377(?:\s|$)", blacklist, re.M) is None:
      raise ValueError("Early-source Bluetooth blacklist is inactive")
    module_tree = tree / "usr/lib/modules" / provenance["kernel_release"]
    for name in SOURCE.INITRD_MODULES:
      paths = list(module_tree.rglob(name + ".ko"))
      if len(paths) != 1 or _file_digest(paths[0]) != provenance["modules"][name]["sha256"]:
        raise ValueError("Early-source module differs: " + name)
      if paths[0].relative_to(tree).as_posix() != provenance["initrd_module_selection"][name]:
        raise ValueError("Early-source module location differs: " + name)
      for field in ("srcversion", "vermagic"):
        actual = subprocess.run(("modinfo", "-F", field, str(paths[0])), check=True,
                                capture_output=True, text=True).stdout.strip()
        if actual != provenance["modules"][name][field]:
          raise ValueError("Early-source module metadata differs: " + name)
    if list(module_tree.rglob("t2bce_ave.ko*")):
      raise ValueError("Early-source unexpectedly embeds AVE")
    for path in tree.rglob("*"):
      if re.search(r"\.ko(?:\.|$)", path.name):
        name = subprocess.run(("modinfo", "-F", "name", str(path)), check=True,
                              capture_output=True, text=True).stdout.strip()
        if name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name == "mba_hibernate_efi_restore_marker":
          raise ValueError("Early-source embeds restore-only or abort module")
    AUDIT.verify_no_unannounced_cold_tree(tree)
    resolution = SOURCE.BASE.run(("modprobe", "--config", tree / "etc/modprobe.d", "--dirname", tree,
                                  "--set-version", provenance["kernel_release"], "--show-depends",
                                  "--use-blacklist", "hci_bcm4377"), capture=True)
    if resolution.stderr.strip() or any(Path(line.split()[1]).name == "hci_bcm4377.ko"
                                       for line in resolution.stdout.splitlines() if line.startswith("insmod ")):
      raise ValueError("Early-source would load Bluetooth before Wi-Fi readiness")


def derive_artifacts(source_directory, restore_directory, production_uki, *,
                     section_extractor=extract_section, candidate_loader=AUDIT.load_candidate,
                     pair_auditor=AUDIT.audit, source_layout_verifier=verify_source_layout):
  """Return structural manifest/details; injected auditors are synthetic test seams.

  The default loader checks the actual initramfs modules, isolated fullrestore
  hooks, exact corrected guard, restore marker and permanent no-abort profile.
  This function supplies no qualification receipt and performs no live sampling.
  """
  directories = {"source": Path(source_directory), "restore": Path(restore_directory)}
  production = Path(production_uki)
  image_hashes = {"production": _file_digest(production)}
  reports = {}
  initrd_hashes = {}
  provenance = {}
  for role, directory in directories.items():
    reports[role] = _raw(directory / "provenance.json")
    # Reject ambiguous provenance even though the historical loader allows
    # duplicate JSON fields; then cross-check its parsed/audited result.
    decoded = json.loads(reports[role], object_pairs_hook=TX.no_duplicates,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite provenance JSON")))
    if type(decoded) is not dict or decoded.get("modified_sections_sha256") is not None or decoded.get("kernel_override") is not None:
      raise ValueError("Malformed or replacement kernel provenance is forbidden")
    provenance[role] = candidate_loader(directory, role)
    if decoded != provenance[role]:
      raise ValueError("Candidate loader differs from actual provenance bytes")
    image_hashes[role] = _file_digest(directory / "mba-t2-hibernation-candidate.efi")
    initrd_hashes[role] = _file_digest(directory / "mba-t2-hibernation-candidate.initrd")
    for actual, key in ((image_hashes[role], "candidate_uki_sha256"), (initrd_hashes[role], "candidate_initrd_sha256")):
      if actual != provenance[role].get(key):
        raise ValueError("Actual " + role + " artifact hash differs from provenance")
    preserved = provenance[role].get("unchanged_production_sections_sha256")
    if provenance[role].get("modified_sections_sha256") is not None or provenance[role].get("kernel_override") is not None:
      raise ValueError("Replacement kernel artifacts are forbidden")
    if type(preserved) is not dict or not {".linux", ".cmdline"} <= set(preserved):
      raise ValueError("Production section preservation metadata is incomplete")
    if provenance[role].get("production_uki_sha256") != image_hashes["production"]:
      raise ValueError("Actual production UKI differs from provenance")
  source, restore = provenance["source"], provenance["restore"]
  if source.get("candidate") != "mba-t2-hibernation-early-source" or source.get("pre_restore_module_policy") != "early-t2-radio":
    raise ValueError("Source lacks exact early T2/radio layout")
  if restore.get("experiment_id") != FULLRESTORE or restore.get("cold_pci_restore", {}).get("version") != FULLRESTORE:
    raise ValueError("Restore is not the exact fullrestore profile")
  audited = pair_auditor(source, restore)
  source_layout_verifier(directories["source"], source)
  sections = {}
  paths = {"production": production, **{role: directory / "mba-t2-hibernation-candidate.efi" for role, directory in directories.items()}}
  actual_cmdline = None
  for section in sorted(AUDIT.S4.RUNTIME_SECTIONS | {".initrd"}):
    with contextlib.ExitStack() as stack:
      values = {role: _section_value(stack, section_extractor, path, section) for role, path in paths.items()}
      identities = {role: _file_digest(value) for role, value in values.items()}
      if section != ".initrd":
        if any(not _same_bytes(values[role], values["production"]) for role in directories):
          raise ValueError("Private " + section + " bytes differ from production")
        for role in directories:
          if identities[role] != provenance[role]["unchanged_production_sections_sha256"][section]:
            raise ValueError("Actual preserved section differs from provenance")
        if section == ".cmdline":
          raw = values["production"] if type(values["production"]) is bytes else _raw(values["production"])
          if len(raw) > MAX_SMALL_BYTES:
            raise ValueError("Command line section exceeds bounded text contract")
          actual_cmdline = raw.replace(b"\0", b" ").decode().strip()
      else:
        for role, directory in directories.items():
          if identities[role] != initrd_hashes[role] or not _same_bytes(values[role], directory / "mba-t2-hibernation-candidate.initrd"):
            raise ValueError("Embedded initramfs differs from audited external archive")
      sections[section] = identities
  if any(item["cmdline"] != actual_cmdline for item in provenance.values()):
    raise ValueError("Provenance command line text differs from actual UKI section")
  resume = restore["cold_pci_restore"]["resume"]
  for key, expected in (("resume", resume["device"]), ("resume_offset", str(resume["offset"]))):
    values = [token.split("=", 1)[1] for token in actual_cmdline.split() if token.startswith(key + "=")]
    if values != [expected]:
      raise ValueError("Production command line differs from audited resume location")
  if any(token in ("noresume", "hibernate=noresume", "hibernate=no") or token.startswith(("noresume=", "disablehooks="))
         for token in actual_cmdline.split()):
    raise ValueError("Production command line disables audited resume policy")
  # Recheck all input identities after extraction; no successful audit of files
  # changed during sampling is returned.
  for role, path in paths.items():
    if _file_digest(path) != image_hashes[role]:
      raise ValueError("UKI changed during offline audit")
  for role, directory in directories.items():
    if _raw(directory / "provenance.json") != reports[role]:
      raise ValueError("Provenance changed during offline audit")
    if _file_digest(directory / "mba-t2-hibernation-candidate.initrd") != initrd_hashes[role]:
      raise ValueError("Initramfs changed during offline audit")
  manifest = TX.manifest_value({"protocol": TX.PROTOCOL, "model": "MacBookAir9,1",
                                "source_sha256": image_hashes["source"], "restore_sha256": image_hashes["restore"],
                                "runtime_sha256": AUDIT.S4.runtime_stack_identity(source),
                                "linux_sha256": sections[".linux"]["production"],
                                "cmdline_sha256": sections[".cmdline"]["production"]})
  if audited.get("source_uki_sha256") != manifest["source_sha256"] or audited.get("restore_uki_sha256") != manifest["restore_sha256"] or audited.get("runtime_stack_sha256") != manifest["runtime_sha256"]:
    raise ValueError("Audited pair result differs from actual artifact identities")
  details = {"protocol": DETAILS_PROTOCOL, "manifest_sha256": TX.digest(manifest),
             "production_uki_sha256": image_hashes["production"], "sections": sections,
             "provenance_sha256": {role: _digest(raw) for role, raw in reports.items()},
             "kernel_release": source["kernel_release"], "cmdline_text": source["cmdline"],
             "runtime_modules": copy.deepcopy(source["modules"]),
             "source_initrd_module_selection": copy.deepcopy(source["initrd_module_selection"]),
             "restore_marker": copy.deepcopy(restore["restore_marker"]),
             "restore_protocol": copy.deepcopy(restore["cold_pci_restore"]),
             "external_source_marker_pin_required": True}
  return {"manifest": manifest, "audited_details": details, "audited_details_sha256": TX.digest(details),
          "classification": "structurally-audited-artifacts-not-product-qualified",
          "hardware_qualified": False, "usable_hibernation_qualified": False}
