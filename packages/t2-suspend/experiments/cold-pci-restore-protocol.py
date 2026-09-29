"""Closed guard-only restore profile; historical abort registries stay intact."""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("restore_historical_pci", HERE / "cold-pci-abort-protocols.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
KEY = "cold_pci_restore"
GUARD_SHA256 = "f04c0d369b2538fd51676d584b6fd60566b3c966e7c43ee5d770de360ded9198"
GUARD_SRCVERSION = "9D7B498FA4B5693DA3769B7"
RESTORE_VARIABLE = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
RESUME = {"device": "/dev/mapper/root", "offset": 1923214, "devnum": "253:0"}
PROFILE = {
  "version": "cold-pci-guard-fullrestore-v1", "target": "swsusp_arch_resume",
  "guard_module": "mba_hibernate_cold_pci_guard",
  "directory": "usr/lib/omarchy-t2-cold-pci-restore/",
  "hook": "omarchy-t2-cold-pci-restore", "source": HERE / "hibernate-cold-pci-restore",
}
PROFILES = {**BASE.PROFILES, KEY: PROFILE}
BUNDLE_FILES = (
  "functions", "guard.ko", "guard.sha256", "guard.srcversion", "restore.variable",
  "header-reader", "header-reader.sha256", "resume.device", "resume.offset", "resume.devnum",
  "stock-resume", "stock-resume.sha256",
)
HASH = re.compile(r"[0-9a-f]{64}\Z")


def select(provenance):
  if provenance.get("experiment_id") == PROFILE["version"] and KEY not in provenance:
    raise ValueError("Full restore experiment ID lacks its protocol metadata")
  if any(name.startswith("cold_") and name not in PROFILES for name in provenance):
    raise ValueError("Unknown cold restore protocol")
  keys = [key for key in PROFILES if key in provenance]
  if len(keys) > 1:
    raise ValueError("Cold protocols are mutually exclusive")
  return keys[0] if keys else None


def hooks(key):
  if key != KEY:
    return BASE.hooks(key)
  return (PROFILE["hook"], PROFILE["hook"] + "-stop", "resume")


def sources(key):
  if key != KEY:
    return BASE.sources(key)
  result = {
    "cold-pci-restore-protocol.py": Path(__file__),
    "guard.c": HERE / "hibernate-cold-pci-guard/mba_hibernate_cold_pci_guard.c",
    "read-swap-header.c": HERE / "hibernate-cold-pre-cpu/read-swap-header.c",
    "functions": PROFILE["source"] / "functions",
    "install/bundle": PROFILE["source"] / "install/bundle",
  }
  for hook in hooks(key):
    result["hooks/" + hook] = PROFILE["source"] / "hooks" / hook
    result["install/" + hook] = PROFILE["source"] / "install" / hook
  return result


def sha256(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_metadata(provenance):
  if select(provenance) != KEY:
    raise ValueError("Full restore metadata is absent")
  data = provenance[KEY]
  fields = {"version", "target", "guard_module_sha256", "guard_module_srcversion", "guard_module_vermagic",
            "header_helper_sha256", "restore_variable", "resume", "source_sha256", "files_sha256"}
  if not isinstance(data, dict) or set(data) != fields:
    raise ValueError("Full restore metadata is missing or malformed")
  if (data["version"] != PROFILE["version"] or data["target"] != PROFILE["target"] or
      provenance.get("experiment_id") != PROFILE["version"]):
    raise ValueError("Full restore protocol or experiment ID differs")
  if (data["guard_module_sha256"] != GUARD_SHA256 or data["guard_module_srcversion"] != GUARD_SRCVERSION):
    raise ValueError("Full restore requires the exact corrected guard")
  abi = data["guard_module_vermagic"]
  if not isinstance(abi, str) or not abi.split() or abi.split()[0] != provenance.get("kernel_release"):
    raise ValueError("Full restore guard production ABI differs")
  if not isinstance(data["header_helper_sha256"], str) or HASH.fullmatch(data["header_helper_sha256"]) is None:
    raise ValueError("Full restore helper identity is malformed")
  marker = provenance.get("restore_marker")
  if (not isinstance(marker, dict) or marker.get("version") != "v2" or
      marker.get("efi_variable") != RESTORE_VARIABLE or data["restore_variable"] != RESTORE_VARIABLE):
    raise ValueError("Full restore requires the exact V2 restore marker")
  if data["resume"] != RESUME or type(data["resume"].get("offset")) is not int:
    raise ValueError("Full restore pending-header target differs")
  identities, required_sources = data["source_sha256"], sources(KEY)
  if not isinstance(identities, dict) or set(identities) != set(required_sources):
    raise ValueError("Full restore source identity is incomplete")
  for name, path in required_sources.items():
    if identities[name] != sha256(path):
      raise ValueError("Full restore source differs: " + name)
  files = data["files_sha256"]
  required = {PROFILE["directory"] + name for name in BUNDLE_FILES} | {"hooks/" + hook for hook in hooks(KEY)}
  if (not isinstance(files, dict) or set(files) != required or
      any(not isinstance(value, str) or HASH.fullmatch(value) is None for value in files.values())):
    raise ValueError("Full restore bundle identities are incomplete")
  for filename, source in [(PROFILE["directory"] + "functions", PROFILE["source"] / "functions"),
                           (PROFILE["directory"] + "stock-resume", Path("/usr/lib/initcpio/hooks/resume")),
                           *[("hooks/" + hook, PROFILE["source"] / "hooks" / hook) for hook in hooks(KEY)]]:
    if files[filename] != sha256(source):
      raise ValueError("Full restore script differs: " + filename)
  for filename, identity in (("guard.ko", "guard_module_sha256"), ("header-reader", "header_helper_sha256")):
    if files[PROFILE["directory"] + filename] != data[identity]:
      raise ValueError("Full restore binary identity disagrees with bundle")
  return data


def reject_unannounced(extracted):
  directory = extracted / PROFILE["directory"]
  if directory.exists() or directory.is_symlink():
    raise ValueError("Unannounced full restore bundle is forbidden")
  for hook in hooks(KEY)[:2]:
    path = extracted / "hooks" / hook
    if path.exists() or path.is_symlink():
      raise ValueError("Unannounced full restore hook is forbidden")
  for filename in ("config", "hooks/resume"):
    path = extracted / filename
    if path.is_file() and PROFILE["hook"] in path.read_text():
      raise ValueError("Unannounced full restore runtime policy is forbidden")


def verify_tree(extracted, provenance, auditor):
  data = validate_metadata(provenance)
  directory = extracted / PROFILE["directory"]
  if directory.is_symlink() or not directory.is_dir():
    raise ValueError("Full restore bundle directory is missing or symlinked")
  if {path.name for path in directory.iterdir()} != set(BUNDLE_FILES):
    raise ValueError("Full restore bundle has orphan payloads")
  for name, identity in data["files_sha256"].items():
    path = extracted / name
    if path.is_symlink() or not path.is_file() or sha256(path) != identity:
      raise ValueError("Full restore embedded file differs: " + name)
  for name, value in {
    "guard.sha256": data["guard_module_sha256"], "guard.srcversion": data["guard_module_srcversion"],
    "header-reader.sha256": data["header_helper_sha256"], "restore.variable": RESTORE_VARIABLE,
    "resume.device": RESUME["device"], "resume.offset": str(RESUME["offset"]), "resume.devnum": RESUME["devnum"],
    "stock-resume.sha256": data["files_sha256"][PROFILE["directory"] + "stock-resume"],
  }.items():
    if (directory / name).read_text() != value + "\n":
      raise ValueError("Full restore embedded identity differs: " + name)
  for field, expected in (("name", PROFILE["guard_module"]), ("srcversion", GUARD_SRCVERSION),
                          ("vermagic", data["guard_module_vermagic"])):
    actual = subprocess.run(("modinfo", "-F", field, str(directory / "guard.ko")),
                            check=True, capture_output=True, text=True).stdout.strip()
    if actual != expected:
      raise ValueError("Full restore embedded guard metadata differs: " + field)
  if not (directory / "header-reader").stat().st_mode & 0o100:
    raise ValueError("Full restore header reader is not executable")
  auditor.validate_static_header_helper((directory / "header-reader").read_bytes())
  alternate = extracted / "usr/lib/systemd/systemd-hibernate-resume"
  if alternate.exists() or alternate.is_symlink():
    raise ValueError("Full restore permits alternative effective resume")
  resolved = {}
  config = (extracted / "config").read_text()
  for field in ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    matches = re.findall(r'^' + field + r'="([^\"]*)"$', config, re.M)
    if len(matches) != 1:
      raise ValueError("Full restore lacks exact resolved hook order")
    resolved[field] = matches[0].split()
  chain = [PROFILE["hook"], "omarchy-t2-restore-marker", "resume", PROFILE["hook"] + "-stop"]
  ordered = resolved["HOOKS"]
  if any(ordered.count(name) != 1 for name in ("encrypt", *chain)):
    raise ValueError("Full restore hook missing or duplicated")
  start = ordered.index(chain[0])
  if ordered[start:start + len(chain)] != chain or ordered.index("encrypt") >= start:
    raise ValueError("Full restore hooks must surround synchronous resume after encrypt")
  for field, values in resolved.items():
    if field != "HOOKS" and set(values) & set(chain):
      raise ValueError("Full restore hook scheduled outside synchronous resume")
  for path in extracted.rglob("*"):
    if re.search(r"\.ko(?:\.|$)", path.name):
      if (path.name.startswith(("abort.ko", "mba_hibernate_cold_")) or path.name.startswith("guard.ko")) and path != directory / "guard.ko":
        raise ValueError("Full restore contains abort or orphan guard module")
      # Module identity, not its filename, excludes a renamed abort/guard.
      name = subprocess.run(("modinfo", "-F", "name", str(path)),
                            check=True, capture_output=True, text=True).stdout.strip()
      if name.startswith("mba_hibernate_cold_") and (path != directory / "guard.ko" or name != PROFILE["guard_module"]):
        raise ValueError("Full restore contains renamed abort or orphan guard module")
  auditor.verify_no_unannounced_cold_tree(extracted, restore=False)
