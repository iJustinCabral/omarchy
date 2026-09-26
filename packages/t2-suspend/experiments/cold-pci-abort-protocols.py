"""Separate combined PCI-guard registry; historical source manifests are intact."""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pci_historical_cold_protocols", HERE / "cold-abort-protocols.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
KEY = "cold_pci_pre_arch"
PROFILE = {
  "version": "cold-pci-guard-pre-arch-abort-v1", "target": "swsusp_arch_resume",
  "module": "mba_hibernate_cold_pre_arch", "boundary": "pre-arch-v1",
  "guard_module": "mba_hibernate_cold_pci_guard",
  "observations": {"observed_irqs_disabled": "Y", "observed_online_cpus": 1, "observed_boundary_valid": "Y"},
  "guard_observations": {"arm_prefix": 0, "arm_consumed": "Y", "gates": 1,
                         "gate_active": "N", "gate_failed": "N"},
  "directory": "usr/lib/omarchy-t2-cold-pci-pre-arch/",
  "hook": "omarchy-t2-cold-pci-pre-arch", "source": HERE / "hibernate-cold-pci-pre-arch",
  "magic": b"MBPG", "returned": "OmarchyT2ColdPciPreArchReturned",
}
PROFILES = {**BASE.PROFILES, KEY: PROFILE}
BUNDLE_FILES = (
  "functions", "abort.ko", "abort.sha256", "abort.srcversion", "guard.ko", "guard.sha256",
  "guard.srcversion", "restore.variable", "header-reader", "header-reader.sha256",
  "resume.device", "resume.offset", "resume.devnum", "stock-resume", "stock-resume.sha256",
)
HASH = re.compile(r"[0-9a-f]{64}\Z")


def select(provenance):
  unknown = [name for name in provenance if name.startswith("cold_") and name not in PROFILES]
  if unknown:
    raise ValueError("Unknown cold abort protocol")
  keys = [key for key in PROFILES if key in provenance]
  if len(keys) > 1:
    raise ValueError("Cold abort protocols are mutually exclusive")
  return keys[0] if keys else None


def hooks(key):
  if key != KEY:
    return BASE.hooks(key)
  return (PROFILE["hook"], PROFILE["hook"] + "-return", "resume")


def sources(key):
  if key != KEY:
    return BASE.sources(key)
  result = {
    "cold-pci-abort-protocols.py": Path(__file__),
    "abort.c": HERE / "hibernate-cold-pre-arch/mba_hibernate_cold_pre_arch.c",
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


def exact_observations(actual, expected, description):
  if (not isinstance(actual, dict) or actual != expected or
      any(type(actual.get(key)) is not type(value) for key, value in expected.items())):
    raise ValueError(description + " observation contract differs")


def validate_metadata(provenance):
  if select(provenance) != KEY:
    raise ValueError("Combined PCI guard metadata is absent")
  diagnostic = provenance[KEY]
  fields = {"version", "target", "module_sha256", "module_srcversion", "module_vermagic",
            "guard_module_sha256", "guard_module_srcversion", "guard_module_vermagic",
            "header_helper_sha256", "restore_variable", "resume", "source_sha256", "files_sha256",
            "boundary_observations", "guard_observations"}
  if not isinstance(diagnostic, dict) or set(diagnostic) != fields:
    raise ValueError("Combined PCI guard metadata is missing or malformed")
  if (diagnostic["version"] != PROFILE["version"] or diagnostic["target"] != PROFILE["target"] or
      provenance.get("experiment_id") != PROFILE["version"]):
    raise ValueError("Combined PCI guard protocol, target or experiment ID differs")
  exact_observations(diagnostic["boundary_observations"], PROFILE["observations"], "Abort")
  exact_observations(diagnostic["guard_observations"], PROFILE["guard_observations"], "Guard")
  for field in ("module_sha256", "guard_module_sha256", "header_helper_sha256"):
    if not isinstance(diagnostic[field], str) or HASH.fullmatch(diagnostic[field]) is None:
      raise ValueError("Combined PCI guard binary identity is malformed")
  if diagnostic["guard_module_sha256"] == diagnostic["module_sha256"]:
    raise ValueError("Abort and PCI guard modules must be distinct")
  for prefix in ("module", "guard_module"):
    src, abi = diagnostic[prefix + "_srcversion"], diagnostic[prefix + "_vermagic"]
    if (not isinstance(src, str) or re.fullmatch(r"[0-9A-F]+", src) is None or
        not isinstance(abi, str) or not abi.split() or abi.split()[0] != provenance.get("kernel_release")):
      raise ValueError("Combined PCI guard source version or production ABI differs")
  if diagnostic["module_vermagic"] != diagnostic["guard_module_vermagic"]:
    raise ValueError("Combined PCI guard module ABIs differ")
  marker = provenance.get("restore_marker")
  variable = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
  if (not isinstance(marker, dict) or marker.get("efi_variable") != variable or
      diagnostic["restore_variable"] != variable):
    raise ValueError("Combined PCI guard requires the exact V2 restore marker")
  if diagnostic["resume"] != {"device": "/dev/mapper/root", "offset": 1923214, "devnum": "253:0"}:
    raise ValueError("Combined PCI guard pending-header target differs")
  identities, required_sources = diagnostic["source_sha256"], sources(KEY)
  if not isinstance(identities, dict) or set(identities) != set(required_sources):
    raise ValueError("Combined PCI guard source identity is incomplete")
  for name, path in required_sources.items():
    if identities[name] != sha256(path):
      raise ValueError("Combined PCI guard source differs: " + name)
  files = diagnostic["files_sha256"]
  required = {PROFILE["directory"] + name for name in BUNDLE_FILES} | {"hooks/" + hook for hook in hooks(KEY)}
  if (not isinstance(files, dict) or set(files) != required or
      any(not isinstance(value, str) or HASH.fullmatch(value) is None for value in files.values())):
    raise ValueError("Combined PCI guard bundle identities are incomplete")
  for filename, source in [(PROFILE["directory"] + "functions", PROFILE["source"] / "functions"),
                           (PROFILE["directory"] + "stock-resume", Path("/usr/lib/initcpio/hooks/resume")),
                           *[("hooks/" + hook, PROFILE["source"] / "hooks" / hook) for hook in hooks(KEY)]]:
    if files[filename] != sha256(source):
      raise ValueError("Combined PCI guard script differs: " + filename)
  for filename, identity in (("abort.ko", "module_sha256"), ("guard.ko", "guard_module_sha256"),
                              ("header-reader", "header_helper_sha256")):
    if files[PROFILE["directory"] + filename] != diagnostic[identity]:
      raise ValueError("Combined PCI guard binary identity disagrees with bundle")
  return diagnostic


def reject_unannounced(extracted):
  directory = extracted / PROFILE["directory"]
  if directory.exists() or directory.is_symlink():
    raise ValueError("Unannounced combined PCI guard bundle is forbidden")
  for hook in hooks(KEY)[:2]:
    path = extracted / "hooks" / hook
    if path.exists() or path.is_symlink():
      raise ValueError("Unannounced combined PCI guard hook is forbidden")
  for path in extracted.rglob(PROFILE["guard_module"] + ".ko*"):
    raise ValueError("Unannounced combined PCI guard module is forbidden")
  for filename in ("config", "hooks/resume"):
    path = extracted / filename
    if path.is_file() and PROFILE["hook"] in path.read_text():
      raise ValueError("Unannounced combined PCI guard runtime policy is forbidden")


def verify_tree(extracted, provenance, auditor):
  diagnostic = validate_metadata(provenance)
  directory = extracted / PROFILE["directory"]
  if directory.is_symlink() or not directory.is_dir():
    raise ValueError("Combined PCI guard bundle directory is missing or symlinked")
  for name, identity in diagnostic["files_sha256"].items():
    path = extracted / name
    if path.is_symlink() or not path.is_file() or sha256(path) != identity:
      raise ValueError("Combined PCI guard embedded file differs: " + name)
  for name, value in {
    "abort.sha256": diagnostic["module_sha256"], "abort.srcversion": diagnostic["module_srcversion"],
    "guard.sha256": diagnostic["guard_module_sha256"], "guard.srcversion": diagnostic["guard_module_srcversion"],
    "header-reader.sha256": diagnostic["header_helper_sha256"], "restore.variable": diagnostic["restore_variable"],
    "resume.device": "/dev/mapper/root", "resume.offset": "1923214", "resume.devnum": "253:0",
    "stock-resume.sha256": diagnostic["files_sha256"][PROFILE["directory"] + "stock-resume"],
  }.items():
    if (directory / name).read_text() != value + "\n":
      raise ValueError("Combined PCI guard embedded identity differs: " + name)
  for filename, prefix, name in (("abort.ko", "module", PROFILE["module"]),
                                  ("guard.ko", "guard_module", PROFILE["guard_module"])):
    fields = [("name", name), ("srcversion", diagnostic[prefix + "_srcversion"]),
              ("vermagic", diagnostic[prefix + "_vermagic"])]
    if filename == "abort.ko":
      fields += [("mba_cold_permanent", "v1"), ("mba_cold_boundary", "pre-arch-v1")]
    for field, expected in fields:
      actual = subprocess.run(("modinfo", "-F", field, str(directory / filename)),
                              check=True, capture_output=True, text=True).stdout.strip()
      if actual != expected:
        raise ValueError("Combined PCI guard embedded module metadata differs: " + filename + ":" + field)
  if not (directory / "header-reader").stat().st_mode & 0o100:
    raise ValueError("Combined PCI guard header reader is not executable")
  auditor.validate_static_header_helper((directory / "header-reader").read_bytes())
  alternate = extracted / "usr/lib/systemd/systemd-hibernate-resume"
  if alternate.exists() or alternate.is_symlink():
    raise ValueError("Combined PCI guard permits alternative effective resume")
  config = (extracted / "config").read_text()
  resolved = {}
  for field in ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    matches = re.findall(r'^' + field + r'="([^\"]*)"$', config, re.M)
    if len(matches) != 1:
      raise ValueError("Combined PCI guard lacks exact resolved hook order")
    resolved[field] = matches[0].split()
  chain = [PROFILE["hook"], "omarchy-t2-restore-marker", "resume", PROFILE["hook"] + "-return"]
  ordered = resolved["HOOKS"]
  if any(ordered.count(name) != 1 for name in ("encrypt", *chain)):
    raise ValueError("Combined PCI guard hook missing or duplicated")
  start = ordered.index(chain[0])
  if ordered[start:start + len(chain)] != chain or ordered.index("encrypt") >= start:
    raise ValueError("Combined PCI guard hooks must surround synchronous resume after encrypt")
  for field, values in resolved.items():
    if field != "HOOKS" and set(values) & set(chain):
      raise ValueError("Combined PCI guard hook scheduled outside synchronous resume")
  # Both modules must exist only as pending-image bundle inputs, never as
  # ordinary module-tree entries or payloads that auto-load during normal boot.
  for pattern in ("abort.ko*", "guard.ko*", PROFILE["module"] + ".ko*", PROFILE["guard_module"] + ".ko*"):
    for path in extracted.rglob(pattern):
      if path not in (directory / "abort.ko", directory / "guard.ko"):
        raise ValueError("Combined PCI guard module placed outside pending-only bundle")
  auditor.verify_no_unannounced_cold_tree(extracted, pci=False)
