#!/usr/bin/env python3
"""Build a private candidate UKI from the exact production kernel and cmdline.

The output stays outside the ESP.  This program never installs modules, edits
the production UKI, changes a boot entry, or initiates a power transition.
Run it as root so mkinitcpio can preserve the embedded root-unlock key.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CONFIG = HERE / "hibernate-candidate-mkinitcpio.conf"
CANDIDATE_HOOKS = HERE / "hibernate-candidate-initcpio"
CANDIDATE_MODULE_HELPER = HERE / "hibernate-candidate-modules.py"
CANDIDATE_BLUETOOTH_HELPER = HERE / "hibernate-candidate-bluetooth.py"
COLD_PRE_CPU = HERE / "hibernate-cold-pre-cpu"
COLD_STOCK_RESUME = Path("/usr/lib/initcpio/hooks/resume")
_protocol_spec = importlib.util.spec_from_file_location("builder_cold_protocols", HERE / "cold-abort-protocols.py")
COLD = importlib.util.module_from_spec(_protocol_spec)
_protocol_spec.loader.exec_module(COLD)
_pci_spec = importlib.util.spec_from_file_location("builder_cold_pci_protocols", HERE / "cold-pci-abort-protocols.py")
PCI = importlib.util.module_from_spec(_pci_spec)
_pci_spec.loader.exec_module(PCI)
RESTORE_MARKER_FILES = (
  "hooks/omarchy-t2-restore-marker",
  "usr/lib/omarchy-t2-restore-marker/marker.ko",
  "usr/lib/omarchy-t2-restore-marker/marker.sha256",
  "usr/lib/omarchy-t2-restore-marker/marker.srcversion",
  "usr/lib/omarchy-t2-restore-marker/marker.version",
)
MODULES = {
  "brcmfmac": "drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko",
  "brcmfmac-bca": "drivers/net/wireless/broadcom/brcm80211/brcmfmac/bca/brcmfmac-bca.ko",
  "brcmfmac-cyw": "drivers/net/wireless/broadcom/brcm80211/brcmfmac/cyw/brcmfmac-cyw.ko",
  "brcmfmac-wcc": "drivers/net/wireless/broadcom/brcm80211/brcmfmac/wcc/brcmfmac-wcc.ko",
  "hci_bcm4377": "drivers/bluetooth/hci_bcm4377.ko",
  "t2bce_dma": "drivers/staging/t2bce/t2bce_dma/t2bce_dma.ko",
  "t2bce_core": "drivers/staging/t2bce/t2bce_core/t2bce_core.ko",
  "t2bce_vhci": "drivers/staging/t2bce/t2bce_vhci/t2bce_vhci.ko",
  "t2bce_audio": "drivers/staging/t2bce/t2bce_audio/t2bce_audio.ko",
  "t2bce_ave": "drivers/staging/t2bce/t2bce_ave/t2bce_ave.ko",
}
PRE_RESTORE_EXCLUDED_MODULES = tuple(MODULES)
MINIMAL_RESTORE_POLICY = {
  "version": "storage-no-gpu-thunderbolt-v1",
  "excluded_hooks": ["kms", "plymouth"],
  "excluded_modules": ["i915", "xe", "thunderbolt"],
}
REQUIRED_INITRD_FILES = (
  "hooks/omarchy-t2-candidate-modules",
  "usr/lib/omarchy-t2-hibernation-candidate/load-modules.py",
  "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py",
  "usr/lib/omarchy-t2-hibernation-candidate/payload/manifest.json",
)
CRITICAL_CMDLINE_KEYS = {
  "cryptdevice",
  "cryptkey",
  "root",
  "rootflags",
  "rootfstype",
  "resume",
  "resume_offset",
}


def digest(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_experiment_id(value):
  if value is not None and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is None:
    raise ValueError("Experiment ID must be a short lowercase ASCII label")
  return value


def run(arguments, cwd=None, capture=False):
  command = [str(argument) for argument in arguments]
  print("+ " + " ".join(command), flush=True)
  return subprocess.run(
    command,
    cwd=cwd,
    check=True,
    text=True,
    capture_output=capture,
  )


def under(path, parent):
  try:
    path.resolve().relative_to(parent.resolve())
    return True
  except ValueError:
    return False


def cmdline_values(data):
  values = {}
  for item in data.replace("\x00", " ").split():
    key = item.split("=", 1)[0]
    if key in CRITICAL_CMDLINE_KEYS or item in ("ro", "rw"):
      values[key] = item.split("=", 1)[1] if "=" in item else True
  return values


def module_metadata(path):
  return {
    "sha256": digest(path),
    "srcversion": run(("modinfo", "-F", "srcversion", path), capture=True).stdout.strip(),
    "vermagic": run(("modinfo", "-F", "vermagic", path), capture=True).stdout.strip(),
  }


def validate_cold_private_file(path, expected_sha256, executable=False):
  if (path is None or not path.is_absolute() or path.is_symlink() or not path.is_file() or
      under(path, Path("/boot")) or under(path, Path("/efi"))):
    raise ValueError("Cold pre-CPU input must be a private regular file outside boot storage")
  metadata = path.stat()
  required_mode = 0o700 if executable else 0o600
  if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != required_mode:
    raise ValueError("Cold pre-CPU input must be root-owned with exact protected mode")
  if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or digest(path) != expected_sha256:
    raise ValueError("Cold pre-CPU input differs from its explicit SHA-256")
  if executable:
    validate_static_header_helper(path.read_bytes())


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


def prepare_restore_marker(work, path, expected_sha256, expected_srcversion, release, version="v1"):
  if version not in ("v1", "v2"):
    raise ValueError("Unknown restore marker variable version")
  if path is None and expected_sha256 is None and expected_srcversion is None:
    if version != "v1":
      raise ValueError("Restore marker version requires an exact module")
    return None
  if path is None or expected_sha256 is None or expected_srcversion is None:
    raise ValueError("Restore marker requires exact path, SHA-256 and source version together")
  if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
      under(path, Path("/boot")) or under(path, Path("/efi"))):
    raise ValueError("Restore marker must be a private regular file outside boot storage")
  metadata = path.stat()
  if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise ValueError("Restore marker must be root-owned mode 0600")
  if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or digest(path) != expected_sha256:
    raise ValueError("Restore marker differs from its explicit SHA-256")
  identity = module_metadata(path)
  if (not expected_srcversion or identity["srcversion"] != expected_srcversion or
      identity["vermagic"].split()[0] != release):
    raise ValueError("Restore marker source version or kernel ABI differs")
  declared_version = run(("modinfo", "-F", "mba_restore_variable", path), capture=True).stdout.strip()
  if declared_version != ("v2" if version == "v2" else ""):
    raise ValueError("Restore marker module variable version differs")
  sha_file = work / "restore-marker.sha256"
  srcversion_file = work / "restore-marker.srcversion"
  version_file = work / "restore-marker.version"
  sha_file.write_text(expected_sha256 + "\n")
  srcversion_file.write_text(expected_srcversion + "\n")
  version_file.write_text(version + "\n")
  sha_file.chmod(0o600)
  srcversion_file.chmod(0o600)
  version_file.chmod(0o600)
  return {
    "module": path,
    "sha256": expected_sha256,
    "srcversion": expected_srcversion,
    "sha_file": sha_file,
    "srcversion_file": srcversion_file,
    "version_file": version_file,
    "version": version,
  }


def prepare_cold_pre_cpu(work, module, module_sha256, srcversion, helper, helper_sha256, release, restore_marker, protocol="cold_pre_cpu"):
  profile = COLD.PROFILES[protocol]
  inputs = (module, module_sha256, srcversion, helper, helper_sha256)
  if all(value is None for value in inputs):
    return None
  if any(value is None for value in inputs) or restore_marker is None:
    raise ValueError("Cold pre-CPU requires exact module/helper pins and an exact restore marker together")
  validate_cold_private_file(module, module_sha256)
  validate_cold_private_file(helper, helper_sha256, executable=True)
  identity = module_metadata(module)
  if (not isinstance(srcversion, str) or re.fullmatch(r"[0-9A-F]+", srcversion) is None or
      identity["srcversion"] != srcversion or not identity["vermagic"] or
      identity["vermagic"].split()[0] != release):
    raise ValueError("Cold pre-CPU module source version or production ABI differs")
  if run(("modinfo", "-F", "name", module), capture=True).stdout.strip() != profile["module"]:
    raise ValueError("Cold pre-CPU module name differs from the diagnostic")
  if run(("modinfo", "-F", "mba_cold_permanent", module), capture=True).stdout.strip() != "v1":
    raise ValueError("Cold abort compiled module lacks exact permanent-ftrace attestation")
  if profile["boundary"] is not None and run(("modinfo", "-F", "mba_cold_boundary", module), capture=True).stdout.strip() != profile["boundary"]:
    raise ValueError("Cold abort module boundary metadata differs")
  bundle = work / (profile["version"] + "-bundle")
  bundle.mkdir(mode=0o700)
  variable = "OmarchyT2RestoreStage" + ("V2" if restore_marker["version"] == "v2" else "") + "-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
  for filename, source in (("abort.ko", module), ("header-reader", helper),
                           ("functions", profile["source"] / "functions"),
                           ("common.functions", COLD.COMMON / "functions"), ("stock-resume", COLD_STOCK_RESUME)):
    if source.is_symlink() or not source.is_file():
      raise ValueError("Cold pre-CPU bundle source is missing or symlinked: " + filename)
    shutil.copyfile(source, bundle / filename)
    (bundle / filename).chmod(0o700 if filename == "header-reader" else 0o600)
  for filename, value in {
    "abort.sha256": module_sha256,
    "abort.srcversion": srcversion,
    "header-reader.sha256": helper_sha256,
    "restore.variable": variable,
    "resume.device": "/dev/mapper/root",
    "resume.offset": "1923214",
    "resume.devnum": "253:0",
    "stock-resume.sha256": digest(COLD_STOCK_RESUME),
    "common.protocol": profile["version"],
  }.items():
    (bundle / filename).write_text(value + "\n")
    (bundle / filename).chmod(0o600)
  files = {profile["directory"] + path.name: digest(path) for path in bundle.iterdir() if not path.name.startswith("common.")}
  files[COLD.COMMON_DIRECTORY + "functions"] = digest(bundle / "common.functions")
  files[COLD.COMMON_DIRECTORY + "protocol"] = digest(bundle / "common.protocol")
  for hook in COLD.hooks(protocol):
    source = COLD.COMMON if hook == "resume" else profile["source"]
    files["hooks/" + hook] = digest(source / "hooks" / hook)
  result = {
    "bundle": bundle,
    "protocol": protocol,
    "provenance": {
      "version": profile["version"],
      "target": profile["target"],
      "module_sha256": module_sha256,
      "module_srcversion": srcversion,
      "module_vermagic": identity["vermagic"],
      "header_helper_sha256": helper_sha256,
      "restore_variable": variable,
      "resume": {"device": "/dev/mapper/root", "offset": 1923214, "devnum": "253:0"},
      "source_sha256": {name: digest(path) for name, path in COLD.sources(protocol).items()},
      "files_sha256": files,
    },
  }
  if profile["observations"] is not None:
    result["provenance"]["boundary_observations"] = profile["observations"].copy()
  return result


def verify_cold_pre_cpu_tree(extracted, provenance, release, restore_marker, protocol="cold_pre_cpu"):
  spec = importlib.util.spec_from_file_location("cold_pre_cpu_tree_auditor", HERE / "audit-hibernation-uki-pair.py")
  auditor = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(auditor)
  marker = {"efi_variable": "OmarchyT2RestoreStage" + ("V2" if restore_marker["version"] == "v2" else "") + "-5e17d2ad-021f-4d45-a8e5-f4c191983e27"}
  auditor.verify_cold_pre_cpu_tree(extracted, {protocol: provenance, "restore_marker": marker, "kernel_release": release,
                                            "experiment_id": PCI.PROFILES[protocol]["version"]})


def prepare_cold_pci_pre_arch(work, module, module_sha256, srcversion, helper, helper_sha256,
                             guard, guard_sha256, guard_srcversion, release, restore_marker):
  inputs = (module, module_sha256, srcversion, helper, helper_sha256, guard, guard_sha256, guard_srcversion)
  if all(value is None for value in inputs):
    return None
  if any(value is None for value in inputs) or restore_marker is None or restore_marker.get("version") != "v2":
    raise ValueError("Combined PCI guard requires both exact modules, helper and V2 restore marker together")
  validate_cold_private_file(module, module_sha256)
  validate_cold_private_file(guard, guard_sha256)
  validate_cold_private_file(helper, helper_sha256, executable=True)
  identities = []
  for path, pin, name in ((module, srcversion, PCI.PROFILE["module"]),
                          (guard, guard_srcversion, PCI.PROFILE["guard_module"])):
    identity = module_metadata(path)
    if (not isinstance(pin, str) or re.fullmatch(r"[0-9A-F]+", pin) is None or
        identity["srcversion"] != pin or not identity["vermagic"].split() or
        identity["vermagic"].split()[0] != release):
      raise ValueError("Combined PCI guard module source version or production ABI differs")
    if run(("modinfo", "-F", "name", path), capture=True).stdout.strip() != name:
      raise ValueError("Combined PCI guard module name differs")
    identities.append(identity)
  if identities[0]["vermagic"] != identities[1]["vermagic"] or module_sha256 == guard_sha256:
    raise ValueError("Combined PCI guard modules must be distinct with identical production ABI")
  for field, expected in (("mba_cold_permanent", "v1"), ("mba_cold_boundary", "pre-arch-v1")):
    if run(("modinfo", "-F", field, module), capture=True).stdout.strip() != expected:
      raise ValueError("Combined PCI guard abort module attestation differs: " + field)
  profile = PCI.PROFILE
  bundle = work / (profile["version"] + "-bundle")
  bundle.mkdir(mode=0o700)
  for name, path in (("abort.ko", module), ("guard.ko", guard), ("header-reader", helper),
                     ("functions", profile["source"] / "functions"), ("stock-resume", COLD_STOCK_RESUME)):
    if path.is_symlink() or not path.is_file():
      raise ValueError("Combined PCI guard bundle source missing or symlinked: " + name)
    shutil.copyfile(path, bundle / name)
    (bundle / name).chmod(0o700 if name == "header-reader" else 0o600)
  variable = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
  for name, value in {
    "abort.sha256": module_sha256, "abort.srcversion": srcversion,
    "guard.sha256": guard_sha256, "guard.srcversion": guard_srcversion,
    "header-reader.sha256": helper_sha256, "restore.variable": variable,
    "resume.device": "/dev/mapper/root", "resume.offset": "1923214", "resume.devnum": "253:0",
    "stock-resume.sha256": digest(COLD_STOCK_RESUME),
  }.items():
    (bundle / name).write_text(value + "\n")
    (bundle / name).chmod(0o600)
  files = {profile["directory"] + path.name: digest(path) for path in bundle.iterdir()}
  files.update({"hooks/" + hook: digest(profile["source"] / "hooks" / hook) for hook in PCI.hooks(PCI.KEY)})
  return {"bundle": bundle, "protocol": PCI.KEY, "provenance": {
    "version": profile["version"], "target": profile["target"],
    "module_sha256": module_sha256, "module_srcversion": srcversion, "module_vermagic": identities[0]["vermagic"],
    "guard_module_sha256": guard_sha256, "guard_module_srcversion": guard_srcversion,
    "guard_module_vermagic": identities[1]["vermagic"], "header_helper_sha256": helper_sha256,
    "restore_variable": variable, "resume": {"device": "/dev/mapper/root", "offset": 1923214, "devnum": "253:0"},
    "boundary_observations": profile["observations"].copy(), "guard_observations": profile["guard_observations"].copy(),
    "source_sha256": {name: digest(path) for name, path in PCI.sources(PCI.KEY).items()}, "files_sha256": files,
  }}


def validate_candidate(candidate, release):
  provenance_path = candidate / "provenance.json"
  provenance = json.loads(provenance_path.read_text())
  if provenance.get("candidate_tests") != "passed":
    raise ValueError("Candidate tests are not recorded as passed")
  if provenance.get("candidate_kernel_release") != release:
    raise ValueError("Candidate was not built for " + release)
  if provenance.get("installed") is not False or provenance.get("hardware_qualified") is not False:
    raise ValueError("Unexpected candidate lifecycle state")

  recorded = provenance.get("candidate_module_sha256", {})
  result = {}
  for name, relative in MODULES.items():
    path = candidate / relative
    if not path.is_file():
      raise ValueError("Missing candidate module: " + name)
    if recorded.get(relative) != digest(path):
      raise ValueError("Candidate module hash mismatch: " + name)
    metadata = module_metadata(path)
    if metadata["vermagic"].split()[0] != release:
      raise ValueError("Candidate module ABI mismatch: " + name)
    result[name] = {"source": relative, **metadata}
  return provenance_path, result


def selected_module_path(module_root, release, name):
  selected = Path(run(("modinfo", "-b", module_root, "-k", release, "-n", name), capture=True).stdout.strip())
  if not selected.is_absolute():
    raise ValueError("Unexpected modinfo path for " + name)
  if under(selected, module_root):
    return selected
  return module_root / selected.relative_to("/")


def prepare_module_root(work, candidate, release, expected):
  installed = Path("/usr/lib/modules") / release
  if not (installed / "modules.dep").is_file():
    raise ValueError("Missing installed module metadata for " + release)
  module_root = work / "module-root"
  target = module_root / "usr/lib/modules" / release
  target.parent.mkdir(parents=True)
  (module_root / "lib").symlink_to("usr/lib")
  run(("cp", "--archive", "--reflink=auto", installed, target))

  for name, relative in MODULES.items():
    current = selected_module_path(module_root, release, name)
    directory = current.parent
    for suffix in (".ko", ".ko.zst", ".ko.xz", ".ko.gz"):
      existing = directory / (name + suffix)
      if existing.exists() or existing.is_symlink():
        existing.unlink()
    destination = directory / (name + ".ko")
    shutil.copyfile(candidate / relative, destination)
    destination.chmod(0o644)

  run(("depmod", "-b", module_root, release))
  selected = {}
  for name in MODULES:
    path = selected_module_path(module_root, release, name)
    if digest(path) != expected[name]["sha256"]:
      raise ValueError("Private module root selected the wrong module: " + name)
    selected[name] = str(path.relative_to(module_root))
  return module_root, selected


def prepare_payload(work, candidate, release, expected, experiment_id=None):
  payload = work / "candidate-payload"
  payload.mkdir()
  modules = {}
  for name, relative in MODULES.items():
    source = candidate / relative
    destination = payload / (name + ".ko")
    shutil.copyfile(source, destination)
    destination.chmod(0o600)
    modules[name] = {
      "file": destination.name,
      "sha256": expected[name]["sha256"],
      "srcversion": expected[name]["srcversion"],
    }
  manifest = {
    "kernel_release": release,
    "modules": modules,
    "policy": "post-switch-root-only",
  }
  if experiment_id is not None:
    manifest["experiment_id"] = experiment_id
  (payload / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
  (payload / "manifest.json").chmod(0o600)
  (payload / "hci_bcm4377.sha256").write_text(expected["hci_bcm4377"]["sha256"] + "\n")
  (payload / "hci_bcm4377.sha256").chmod(0o600)
  return payload, modules


def minimal_restore_config(base):
  # Filter inherited settings after all host drop-ins have been sourced. Only
  # the private build configuration changes; dependency resolution stays with
  # mkinitcpio and no files are pruned from its completed module tree.
  return "source " + shlex.quote(str(base)) + "\n" + '''
minimal_hooks=()
for minimal_hook in "${HOOKS[@]}"; do
  case $minimal_hook in
    kms|plymouth) ;;
    *) minimal_hooks+=("$minimal_hook") ;;
  esac
done
HOOKS=("${minimal_hooks[@]}")
minimal_modules=()
for minimal_module in "${MODULES[@]}"; do
  case $minimal_module in
    i915|xe|thunderbolt) ;;
    *) minimal_modules+=("$minimal_module") ;;
  esac
done
MODULES=("${minimal_modules[@]}")
unset minimal_hooks minimal_hook minimal_modules minimal_module
'''


def cold_pre_cpu_config(base, protocol="cold_pre_cpu"):
  hook = PCI.PROFILES[protocol]["hook"]
  script = "source " + shlex.quote(str(base)) + "\n" + '''
cold_hooks=()
cold_marker_count=0
cold_resume_count=0
for cold_hook in "${HOOKS[@]}"; do
  case $cold_hook in
    omarchy-t2-cold-pre-cpu|omarchy-t2-cold-pre-cpu-return|omarchy-t2-cold-pre-syscore|omarchy-t2-cold-pre-syscore-return|omarchy-t2-cold-pre-arch|omarchy-t2-cold-pre-arch-return|omarchy-t2-cold-pci-pre-arch|omarchy-t2-cold-pci-pre-arch-return)
      echo "Cold pre-CPU hook already configured" >&2
      exit 1
      ;;
    omarchy-t2-restore-marker)
      cold_hooks+=(omarchy-t2-cold-pre-cpu)
      (( cold_marker_count += 1 ))
      ;;
    resume) (( cold_resume_count += 1 )) ;;
  esac
  cold_hooks+=("$cold_hook")
  if [[ $cold_hook == "resume" ]]; then
    cold_hooks+=(omarchy-t2-cold-pre-cpu-return)
  fi
done
if (( cold_marker_count != 1 || cold_resume_count != 1 )); then
  echo "Cold pre-CPU requires one restore marker and one resume" >&2
  exit 1
fi
HOOKS=("${cold_hooks[@]}")
unset cold_hooks cold_hook cold_marker_count cold_resume_count
'''
  return script.replace("cold_hooks+=(omarchy-t2-cold-pre-cpu)", "cold_hooks+=(" + hook + ")").replace(
    "cold_hooks+=(omarchy-t2-cold-pre-cpu-return)", "cold_hooks+=(" + hook + "-return)")


def verify_minimal_restore_tree(extracted, release):
  config = (extracted / "config").read_text()
  for field in ("MODULES", "HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    match = re.search(r'^' + field + r'="([^\"]*)"$', config, re.M)
    if match is None:
      raise ValueError("Minimal restore initramfs lacks resolved " + field)
    banned = MINIMAL_RESTORE_POLICY["excluded_modules"] if field == "MODULES" else MINIMAL_RESTORE_POLICY["excluded_hooks"]
    if set(match.group(1).split()) & set(banned):
      raise ValueError("Minimal restore initramfs schedules an excluded device or hook")
  module_tree = extracted / "usr/lib/modules" / release
  for path in module_tree.rglob("*"):
    if not re.search(r"\.ko(?:\.|$)", path.name):
      continue
    if (path.name.split(".ko", 1)[0] in MINIMAL_RESTORE_POLICY["excluded_modules"] or
        "drivers/gpu/drm/" in path.as_posix() or "drivers/thunderbolt/" in path.as_posix()):
      raise ValueError("Minimal restore initramfs contains an excluded driver or DRM dependency: " + path.name)
  hooks = re.search(r'^HOOKS="([^\"]*)"$', config, re.M).group(1).split()
  if not {"udev", "encrypt", "resume"}.issubset(hooks):
    raise ValueError("Minimal restore initramfs lacks encrypted-root resume hooks")
  late = re.search(r'^LATEHOOKS="([^\"]*)"$', config, re.M).group(1).split()
  if "omarchy-t2-candidate-modules" not in late:
    raise ValueError("Minimal restore initramfs lacks ordinary-boot payload hook")


def build_initrd(work, module_root, payload, release, expected, experiment_id=None, restore_marker=None, minimal_restore_devices=False, cold_pre_cpu=None):
  initrd = work / "candidate.initrd"
  config_path = CONFIG
  if minimal_restore_devices:
    config_path = work / "minimal-restore-mkinitcpio.conf"
    config_path.write_text(minimal_restore_config(CONFIG))
  if cold_pre_cpu is not None:
    wrapped = work / "cold-pre-cpu-mkinitcpio.conf"
    wrapped.write_text(cold_pre_cpu_config(config_path, cold_pre_cpu["protocol"]))
    config_path = wrapped
  if cold_pre_cpu is None:
    cold_sources = ()
  elif cold_pre_cpu["protocol"] == PCI.KEY:
    cold_sources = (PCI.PROFILE["source"],)
  else:
    cold_sources = (COLD.COMMON, COLD.PROFILES[cold_pre_cpu["protocol"]]["source"])
  cold_hooks = "".join(str(path / "hooks") + ":" for path in cold_sources)
  cold_install = "".join(str(path / "install") + ":" for path in cold_sources)
  environment = [
    "env",
    "MKINITCPIO_HOOKS=" + cold_hooks + str(CANDIDATE_HOOKS / "hooks") + ":/etc/initcpio/hooks:/usr/lib/initcpio/hooks",
    "MKINITCPIO_INSTALL=" + cold_install + str(CANDIDATE_HOOKS / "install") + ":/etc/initcpio/install:/usr/lib/initcpio/install",
    "OMARCHY_T2_CANDIDATE_PAYLOAD=" + str(payload),
    "OMARCHY_T2_CANDIDATE_MODULE_HELPER=" + str(CANDIDATE_MODULE_HELPER),
    "OMARCHY_T2_CANDIDATE_BLUETOOTH_HELPER=" + str(CANDIDATE_BLUETOOTH_HELPER),
    "OMARCHY_T2_RESTORE_MARKER_MODULE=" + (str(restore_marker["module"]) if restore_marker is not None else ""),
  ]
  if cold_pre_cpu is not None:
    variable = "OMARCHY_T2_COLD_PCI_ABORT_BUNDLE" if cold_pre_cpu["protocol"] == PCI.KEY else "OMARCHY_T2_COLD_ABORT_BUNDLE"
    environment.append(variable + "=" + str(cold_pre_cpu["bundle"]))
  if restore_marker is not None:
    environment.extend((
      "OMARCHY_T2_RESTORE_MARKER_SHA256_FILE=" + str(restore_marker["sha_file"]),
      "OMARCHY_T2_RESTORE_MARKER_SRCVERSION_FILE=" + str(restore_marker["srcversion_file"]),
      "OMARCHY_T2_RESTORE_MARKER_VERSION_FILE=" + str(restore_marker["version_file"]),
    ))
  run((
    *environment,
    "mkinitcpio",
    "--config",
    config_path,
    "--generate",
    initrd,
    "--kernel",
    release,
    "--moduleroot",
    module_root,
  ))

  extracted = work / "initrd-root"
  extracted.mkdir()
  run(("lsinitcpio", "--early", "--extract", initrd), cwd=extracted)
  run(("lsinitcpio", "--cpio", "--extract", initrd), cwd=extracted)
  required = (
    "init",
    "usr/bin/cryptsetup",
    "usr/bin/btrfs",
    "etc/cryptsetup-keys.d/root.key",
  )
  for name in required:
    if not (extracted / name).exists():
      raise ValueError("Candidate initramfs omitted boot-critical file: " + name)
  for name in REQUIRED_INITRD_FILES:
    if not (extracted / name).is_file():
      raise ValueError("Candidate initramfs omitted candidate boot policy: " + name)
  build_config = (extracted / "config").read_text()
  if minimal_restore_devices:
    verify_minimal_restore_tree(extracted, release)
  if cold_pre_cpu is not None:
    verify_cold_pre_cpu_tree(extracted, cold_pre_cpu["provenance"], release, restore_marker, cold_pre_cpu["protocol"])
  if "omarchy-t2-candidate-modules" not in build_config:
    raise ValueError("Candidate initramfs late hook is not scheduled")
  if restore_marker is not None:
    for name in RESTORE_MARKER_FILES:
      if not (extracted / name).is_file():
        raise ValueError("Candidate initramfs omitted restore marker file: " + name)
    embedded = extracted / "usr/lib/omarchy-t2-restore-marker"
    if digest(extracted / "hooks/omarchy-t2-restore-marker") != digest(CANDIDATE_HOOKS / "hooks/omarchy-t2-restore-marker"):
      raise ValueError("Candidate initramfs restore marker hook differs from source")
    if digest(embedded / "marker.ko") != restore_marker["sha256"]:
      raise ValueError("Candidate initramfs restore marker module differs")
    if (embedded / "marker.sha256").read_text().strip() != restore_marker["sha256"]:
      raise ValueError("Candidate initramfs restore marker SHA identity differs")
    if (embedded / "marker.srcversion").read_text().strip() != restore_marker["srcversion"]:
      raise ValueError("Candidate initramfs restore marker source version differs")
    if (embedded / "marker.version").read_text().strip() != restore_marker["version"]:
      raise ValueError("Candidate initramfs restore marker variable version differs")
    hooks_line = re.search(r'^HOOKS="([^"]*)"$', build_config, re.M)
    if hooks_line is None:
      raise ValueError("Candidate initramfs lacks resolved runtime hooks")
    hooks = hooks_line.group(1).split()
    if hooks.count("omarchy-t2-restore-marker") != 1 or hooks.count("resume") != 1 or hooks.index("omarchy-t2-restore-marker") + 1 != hooks.index("resume"):
      raise ValueError("Restore marker must run immediately before resume")

  module_tree = extracted / "usr/lib/modules" / release
  for name in PRE_RESTORE_EXCLUDED_MODULES:
    if list(module_tree.rglob(name + ".ko")) or list(module_tree.rglob(name + ".ko.*")):
      raise ValueError("Candidate initramfs would load a pre-restore module: " + name)

  for name in ("nvme", "nvme-core", "dm-crypt"):
    matches = list(module_tree.rglob(name + ".ko")) + list(module_tree.rglob(name + ".ko.*"))
    if len(matches) != 1:
      raise ValueError(f"Candidate initramfs contains {len(matches)} copies of root-critical module {name}")

  payload_root = extracted / "usr/lib/omarchy-t2-hibernation-candidate/payload"
  payload_manifest = json.loads((payload_root / "manifest.json").read_text())
  if payload_manifest.get("policy") != "post-switch-root-only":
    raise ValueError("Candidate initramfs payload policy mismatch")
  if payload_manifest.get("experiment_id") != experiment_id:
    raise ValueError("Candidate initramfs experiment ID mismatch")
  bluetooth_digest = payload_root / "hci_bcm4377.sha256"
  if bluetooth_digest.read_text().strip() != expected["hci_bcm4377"]["sha256"]:
    raise ValueError("Candidate initramfs Bluetooth digest mismatch")
  staged_payload = {}
  for name in MODULES:
    expected_path = payload_root / (name + ".ko")
    if not expected_path.is_file() or expected_path.is_symlink():
      raise ValueError("Candidate initramfs omitted post-switch-root payload: " + name)
    if digest(expected_path) != expected[name]["sha256"]:
      raise ValueError("Candidate initramfs payload hash mismatch: " + name)
    metadata = payload_manifest.get("modules", {}).get(name, {})
    if metadata.get("file") != name + ".ko" or metadata.get("sha256") != expected[name]["sha256"]:
      raise ValueError("Candidate initramfs payload manifest mismatch: " + name)
    staged_payload[name] = str(expected_path.relative_to(extracted))

  for name in PRE_RESTORE_EXCLUDED_MODULES:
    matches = list((extracted / "usr/lib/modules" / release).rglob(name + ".ko"))
    if matches:
      raise ValueError("Candidate initramfs duplicated payload in module tree: " + name)
  return initrd, staged_payload


def pe_sections(path):
  output = run(("objdump", "-h", path), capture=True).stdout
  result = {}
  for match in re.finditer(r"^\s*\d+\s+(\.\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)", output, re.M):
    result[match.group(1)] = int(match.group(2), 16)
  return result


def extract_section(image, section, output):
  run(("objcopy", "-O", "binary", "--only-section=" + section, image, output))


def build_uki(work, production, initrd):
  live_hash_before = digest(production)
  stock = work / "production.efi"
  shutil.copyfile(production, stock)
  sections = pe_sections(stock)
  if ".initrd" not in sections:
    raise ValueError("Production image has no .initrd section")

  original = {}
  for section in sections:
    output = work / ("stock" + section)
    extract_section(stock, section, output)
    original[section] = digest(output)

  stock_cmdline = (work / "stock.cmdline").read_bytes().replace(b"\x00", b" ").decode().strip()
  running_cmdline = Path("/proc/cmdline").read_text().strip()
  if cmdline_values(stock_cmdline) != cmdline_values(running_cmdline):
    raise ValueError("Production UKI root-critical cmdline differs from the healthy running boot")
  expected_root = {
    "root": "/dev/mapper/root",
    "rootflags": "subvol=@",
    "rootfstype": "btrfs",
    "resume": "/dev/mapper/root",
  }
  values = cmdline_values(stock_cmdline)
  for key, value in expected_root.items():
    if values.get(key) != value:
      raise ValueError("Unsafe production UKI cmdline: " + key)
  if "cryptdevice" not in values or "cryptkey" not in values or "resume_offset" not in values:
    raise ValueError("Production UKI is missing encrypted-root or resume parameters")

  no_initrd = work / "without-initrd.efi"
  candidate = work / "candidate.efi"
  run(("objcopy", "--remove-section=.initrd", stock, no_initrd))
  run((
    "objcopy",
    "--add-section",
    ".initrd=" + str(initrd),
    "--change-section-vma",
    ".initrd=" + hex(sections[".initrd"]),
    "--set-section-flags",
    ".initrd=alloc,load,readonly,data",
    no_initrd,
    candidate,
  ))

  candidate_sections = pe_sections(candidate)
  if set(candidate_sections) != set(sections):
    raise ValueError("Candidate UKI section set changed")
  for section in sections:
    output = work / ("candidate" + section)
    extract_section(candidate, section, output)
    if section == ".initrd":
      if digest(output) != digest(initrd):
        raise ValueError("Candidate UKI does not contain the verified initramfs")
    elif digest(output) != original[section]:
      raise ValueError("Candidate UKI changed production section " + section)

  identity = run(("bootctl", "kernel-identify", candidate), capture=True).stdout.strip()
  if identity != "uki":
    raise ValueError("bootctl did not identify the candidate as a UKI")
  if digest(production) != live_hash_before:
    raise ValueError("Production UKI changed during private construction")
  return candidate, stock_cmdline, original, live_hash_before


def secure_output(path):
  uid = int(os.environ.get("SUDO_UID", "0"))
  gid = int(os.environ.get("SUDO_GID", "0"))
  for item in (path, *path.rglob("*")):
    item.chmod(0o700 if item.is_dir() else 0o600)
    if os.geteuid() == 0:
      os.chown(item, uid, gid)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  parser.add_argument("--production-uki", type=Path, default=Path("/boot/EFI/Linux/omarchy_linux-t2.efi"))
  parser.add_argument("--output", type=Path, required=True, help="new private output directory outside the ESP")
  parser.add_argument("--kernel-release", default=os.uname().release)
  parser.add_argument("--experiment-id", help="embed a bounded diagnostic ID in the private initramfs")
  parser.add_argument("--restore-marker-module", type=Path, help="private disarmed cold-restore marker module")
  parser.add_argument("--expected-restore-marker-sha256")
  parser.add_argument("--expected-restore-marker-srcversion")
  parser.add_argument("--restore-marker-version", choices=("v1", "v2"), default="v1")
  parser.add_argument("--minimal-restore-devices", action="store_true", help="omit private initramfs KMS/Plymouth and GPU/Thunderbolt drivers; retain normal root userspace loading")
  parser.add_argument("--cold-pre-cpu-module", type=Path, help="private controlled-abort cold-restore module")
  parser.add_argument("--expected-cold-pre-cpu-sha256")
  parser.add_argument("--expected-cold-pre-cpu-srcversion")
  parser.add_argument("--cold-pre-cpu-header-helper", type=Path, help="private read-only pending-swap header helper")
  parser.add_argument("--expected-cold-pre-cpu-header-helper-sha256")
  parser.add_argument("--cold-pre-syscore-module", type=Path)
  parser.add_argument("--expected-cold-pre-syscore-sha256")
  parser.add_argument("--expected-cold-pre-syscore-srcversion")
  parser.add_argument("--cold-pre-syscore-header-helper", type=Path)
  parser.add_argument("--expected-cold-pre-syscore-header-helper-sha256")
  parser.add_argument("--cold-pre-arch-module", type=Path)
  parser.add_argument("--expected-cold-pre-arch-sha256")
  parser.add_argument("--expected-cold-pre-arch-srcversion")
  parser.add_argument("--cold-pre-arch-header-helper", type=Path)
  parser.add_argument("--expected-cold-pre-arch-header-helper-sha256")
  parser.add_argument("--cold-pci-pre-arch-module", type=Path)
  parser.add_argument("--expected-cold-pci-pre-arch-sha256")
  parser.add_argument("--expected-cold-pci-pre-arch-srcversion")
  parser.add_argument("--cold-pci-pre-arch-header-helper", type=Path)
  parser.add_argument("--expected-cold-pci-pre-arch-header-helper-sha256")
  parser.add_argument("--cold-pci-pre-arch-guard-module", type=Path)
  parser.add_argument("--expected-cold-pci-pre-arch-guard-sha256")
  parser.add_argument("--expected-cold-pci-pre-arch-guard-srcversion")
  args = parser.parse_args()
  if args.minimal_restore_devices and args.restore_marker_module is None:
    parser.error("--minimal-restore-devices requires an explicit --restore-marker-module")
  profiles = {
    protocol: (getattr(args, protocol + "_module"), getattr(args, "expected_" + protocol + "_sha256"),
               getattr(args, "expected_" + protocol + "_srcversion"), getattr(args, protocol + "_header_helper"),
               getattr(args, "expected_" + protocol + "_header_helper_sha256"))
    for protocol in COLD.PROFILES
  }
  profiles[PCI.KEY] = (args.cold_pci_pre_arch_module, args.expected_cold_pci_pre_arch_sha256,
                       args.expected_cold_pci_pre_arch_srcversion, args.cold_pci_pre_arch_header_helper,
                       args.expected_cold_pci_pre_arch_header_helper_sha256, args.cold_pci_pre_arch_guard_module,
                       args.expected_cold_pci_pre_arch_guard_sha256, args.expected_cold_pci_pre_arch_guard_srcversion)
  selected = [protocol for protocol, inputs in profiles.items() if any(value is not None for value in inputs)]
  if len(selected) > 1:
    parser.error("Cold abort protocols are mutually exclusive")
  cold_protocol = selected[0] if selected else "cold_pre_cpu"
  cold_inputs = profiles[cold_protocol]
  if any(value is not None for value in cold_inputs):
    if any(value is None for value in cold_inputs) or args.restore_marker_module is None or not args.minimal_restore_devices:
      parser.error("Cold abort requires complete module/helper pins, restore marker and --minimal-restore-devices")
    if cold_protocol == PCI.KEY and args.restore_marker_version != "v2":
      parser.error("Combined PCI guard requires the V2 restore marker")

  if os.geteuid() != 0:
    raise SystemExit("Run as root so the root-unlock key retains protected handling")
  experiment_id = validate_experiment_id(args.experiment_id)
  if any(value is not None for value in cold_inputs) and experiment_id != PCI.PROFILES[cold_protocol]["version"]:
    parser.error("Cold diagnostic experiment ID must exactly match its selected protocol")
  output = args.output.absolute()
  if output.exists():
    raise ValueError("Output already exists; choose a new directory")
  if any(under(output, path) for path in (Path("/boot"), Path("/efi"))):
    raise ValueError("Offline builder refuses to publish onto an EFI or boot filesystem")
  output.parent.mkdir(parents=True, exist_ok=True)
  os.umask(0o077)

  candidate_source = args.candidate_source.resolve()
  production = args.production_uki.resolve()
  with tempfile.TemporaryDirectory(prefix=".t2-candidate-uki-", dir=output.parent) as directory:
    work = Path(directory)
    provenance_path, expected = validate_candidate(candidate_source, args.kernel_release)
    module_root, selected = prepare_module_root(work, candidate_source, args.kernel_release, expected)
    payload, payload_modules = prepare_payload(work, candidate_source, args.kernel_release, expected, experiment_id)
    restore_marker = prepare_restore_marker(work, args.restore_marker_module, args.expected_restore_marker_sha256,
                                            args.expected_restore_marker_srcversion, args.kernel_release,
                                            args.restore_marker_version)
    if cold_protocol == PCI.KEY:
      cold_pre_cpu = prepare_cold_pci_pre_arch(work, *cold_inputs, args.kernel_release, restore_marker)
    else:
      cold_pre_cpu = prepare_cold_pre_cpu(work, *cold_inputs, args.kernel_release, restore_marker, protocol=cold_protocol)
    initrd, staged_payload = build_initrd(work, module_root, payload, args.kernel_release, expected, experiment_id, restore_marker, args.minimal_restore_devices, cold_pre_cpu)
    uki, cmdline, sections, production_hash = build_uki(work, production, initrd)

    publish = work / "publish"
    publish.mkdir(mode=0o700)
    shutil.copyfile(uki, publish / "mba-t2-hibernation-candidate.efi")
    shutil.copyfile(initrd, publish / "mba-t2-hibernation-candidate.initrd")
    report = {
      "candidate": "mba-t2-hibernation-module-overlay",
      "kernel_release": args.kernel_release,
      "production_uki": str(production),
      "production_uki_sha256": production_hash,
      "candidate_uki_sha256": digest(publish / "mba-t2-hibernation-candidate.efi"),
      "candidate_initrd_sha256": digest(publish / "mba-t2-hibernation-candidate.initrd"),
      "experiment_id": experiment_id,
      "cmdline": cmdline,
      "unchanged_production_sections_sha256": {name: value for name, value in sections.items() if name != ".initrd"},
      "source_provenance_sha256": digest(provenance_path),
      "modules": expected,
      "private_module_selection": selected,
      "initrd_module_selection": {},
      "pre_restore_module_policy": "root-only-no-t2-radio",
      "pre_restore_excluded_modules": list(PRE_RESTORE_EXCLUDED_MODULES),
      "post_switch_root_payload": staged_payload,
      "payload_modules": payload_modules,
      "restore_marker": None if restore_marker is None else {
        "sha256": restore_marker["sha256"],
        "srcversion": restore_marker["srcversion"],
        "version": restore_marker["version"],
        "efi_variable": "OmarchyT2RestoreStage" + ("V2" if restore_marker["version"] == "v2" else "") + "-5e17d2ad-021f-4d45-a8e5-f4c191983e27",
        "pre_resume_hook": "omarchy-t2-restore-marker",
        "hook_sha256": digest(CANDIDATE_HOOKS / "hooks/omarchy-t2-restore-marker"),
      },
      "production_modified": False,
      "installed": False,
      "boot_entry_created": False,
      "hardware_qualified": False,
    }
    if args.minimal_restore_devices:
      report["minimal_restore_policy"] = MINIMAL_RESTORE_POLICY
    if cold_pre_cpu is not None:
      report[cold_protocol] = cold_pre_cpu["provenance"]
    (publish / "provenance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    publish.rename(output)
  secure_output(output)
  print("PASS: private candidate UKI preserves production kernel/cmdline and verified root-capable initramfs: " + str(output))


if __name__ == "__main__":
  main()
