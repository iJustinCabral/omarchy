#!/usr/bin/python3
"""Build the private upstream-model UKI: stock boot image, patched t2bce family only.

The image keeps the production .linux and .cmdline byte-for-byte and every other
non-.initrd section. Its initramfs is built from the stock /etc/mkinitcpio.conf and
/etc/mkinitcpio.conf.d/*.conf with exactly two deltas: the patched t2bce_audio is added to
MODULES (D1, so the whole t2bce family is the candidate) and an initramfs-only modprobe
blacklist keeps brcmfmac, brcmfmac-bca, brcmfmac-cyw and brcmfmac-wcc out of the restore
kernel (D2, variant U1b). No marker hook, cold PCI guard or minimal-restore initramfs is
present. The builder changes no installed boot image, module or power setting and creates
no boot entry. Run it as root from a root-owned export of the reviewed commit (the builder itself,
common.py and the install hook must be root-owned and not group/world writable, like every other
input); the output directory must not exist.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import importlib.util

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("upstream_model_common", HERE / "common.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)
BASE = C.import_path("candidate_uki_builder", C.EXPERIMENTS / "build-hibernation-candidate-uki.py")

INSTALL_HOOKS = HERE / "initcpio" / "install"
SCHEMA = "omarchy-t2-upstream-model-build-v1"
HOST_CONF = Path("/etc/mkinitcpio.conf")
HOST_CONF_DIRECTORY = Path("/etc/mkinitcpio.conf.d")
RADIO_PACKAGE = "omarchy-t2-radio/1.6"
# Files of the installed stock kernel tree the omarchy-t2-suspend build hook reads relative to
# the private module root; they are copied, never edited.
HOOK_SUPPORT = ("usr/src/omarchy-t2-radio-1.6", "var/lib/dkms/omarchy-t2-radio/1.6/{release}")
FIRMWARE_GLOB = "usr/lib/firmware/brcm/brcmfmac4377b3-*"
RUNTIME_CONFIG_KEYS = ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS")
# BCM4377 Wi-Fi PCI alias as udev would request it.
ALIAS_PROBE = "pci:v000014E4d00004488sv0000106Bsd00000001bc02sc80i00"


def private_config():
  """Private mkinitcpio config text: stock sources plus the D1 module and the D2 hook."""
  return (
    "source " + str(HOST_CONF) + "\n"
    "for upstream_model_conf in " + str(HOST_CONF_DIRECTORY) + "/*.conf; do\n"
    "  [[ -e $upstream_model_conf ]] && source \"$upstream_model_conf\"\n"
    "done\n"
    "unset upstream_model_conf\n"
    "\n"
    "# D1: the whole t2bce family in the image is the patched candidate.\n"
    "MODULES+=(t2bce_audio)\n"
    "# D2: initramfs-only brcmfmac blacklist, installed by a build-time-only hook.\n"
    "HOOKS+=(" + C.HOOK + ")\n"
  )


def require_root_tree(path, *, directory=None, owner=0):
  """Refuse anything a non-root user could influence: symlinks, foreign owners, group/world write."""
  path = Path(path)
  if path.is_symlink():
    raise ValueError("Refusing symlinked build input: " + str(path))
  if directory is None:
    directory = path.is_dir()
  items = [path]
  if directory:
    if not path.is_dir():
      raise ValueError("Build input is not a directory: " + str(path))
    items += sorted(path.rglob("*"))
  for item in items:
    if item.is_symlink():
      raise ValueError("Refusing symlinked build input: " + str(item))
    metadata = item.lstat()
    if metadata.st_uid != owner or metadata.st_mode & 0o022:
      raise ValueError("Build input must be root-owned and not group/world writable: " + str(item))


def shell_arrays(config):
  """HOOKS, FILES, BINARIES and MODULES as bash sees them after sourcing a config in a subshell."""
  script = ('source "$1"; for name in HOOKS FILES BINARIES MODULES; do declare -n array=$name; '
            'printf "%s\\0" "@$name" "${array[@]}"; done')
  output = subprocess.run(("bash", "-c", script, "bash", str(config)), check=True, capture_output=True).stdout
  result, current = {}, None
  for token in output.split(b"\0")[:-1]:
    text = token.decode()
    if text.startswith("@") and text[1:] in ("HOOKS", "FILES", "BINARIES", "MODULES"):
      current = text[1:]
      result[current] = []
    else:
      result[current].append(text)
  return result


def audit_config(private, stock):
  """Build-time arrays equal stock plus exactly the declared deltas."""
  before, after = shell_arrays(stock), shell_arrays(private)
  if after["HOOKS"] != before["HOOKS"] + [C.HOOK]:
    raise ValueError("Build HOOKS differ from stock plus the blacklist hook")
  for name in ("FILES", "BINARIES"):
    if after[name] != before[name]:
      raise ValueError("Build " + name + " differ from stock")
  expected = before["MODULES"] + ([] if "t2bce_audio" in before["MODULES"] else ["t2bce_audio"])
  if after["MODULES"] != expected:
    raise ValueError("Build MODULES differ from stock plus t2bce_audio")
  return {"hooks": after["HOOKS"], "modules": after["MODULES"], "files": after["FILES"], "binaries": after["BINARIES"]}


def stock_config_text():
  return private_config().split("\n# D1:")[0] + "\n"


def require_stock_config(conf=HOST_CONF, directory=HOST_CONF_DIRECTORY):
  """The stock configuration is sourced as root, so it must be root-owned like the pair builders require."""
  require_root_tree(conf, directory=False)
  if directory.exists():
    require_root_tree(directory, directory=True)


def validate_candidate(candidate, release):
  """Provenance and pins for the four t2bce modules only."""
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
  for name in C.T2BCE_MODULES:
    relative = BASE.MODULES[name]
    path = candidate / relative
    if path.is_symlink() or not path.is_file():
      raise ValueError("Missing candidate module: " + name)
    if recorded.get(relative) != BASE.digest(path):
      raise ValueError("Candidate module hash mismatch: " + name)
    metadata = BASE.module_metadata(path)
    if not metadata["vermagic"].split() or metadata["vermagic"].split()[0] != release:
      raise ValueError("Candidate module ABI mismatch: " + name)
    if not metadata["srcversion"]:
      raise ValueError("Candidate module has no srcversion: " + name)
    result[name] = {"source": relative, **metadata}
  return provenance_path, result


def prepare_module_root(work, candidate, release, expected):
  """Copy the installed module tree and substitute the four t2bce modules in place.

  The omarchy-t2-suspend build hook requires every t2bce_* to resolve under
  kernel/drivers/staging/t2bce/, which an in-place substitution preserves. The radio DKMS
  tree, its source package and the Apple Wi-Fi firmware the hook reads are copied alongside.
  """
  installed = Path("/usr/lib/modules") / release
  if not (installed / "modules.dep").is_file():
    raise ValueError("Missing installed module metadata for " + release)
  module_root = work / "module-root"
  target = module_root / "usr/lib/modules" / release
  target.parent.mkdir(parents=True)
  (module_root / "lib").symlink_to("usr/lib")
  BASE.run(("cp", "--archive", "--reflink=auto", installed, target))
  for template in HOOK_SUPPORT:
    source = Path("/") / template.format(release=release)
    if source.exists():
      destination = module_root / source.relative_to("/")
      destination.parent.mkdir(parents=True, exist_ok=True)
      BASE.run(("cp", "--archive", "--reflink=auto", source, destination))
  firmware = sorted(Path("/").glob(FIRMWARE_GLOB))
  for source in firmware:
    destination = module_root / source.relative_to("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    BASE.run(("cp", "--archive", "--reflink=auto", source, destination))

  for name in C.T2BCE_MODULES:
    current = BASE.selected_module_path(module_root, release, name)
    if "/kernel/drivers/staging/t2bce/" not in str(current):
      raise ValueError("Installed t2bce module is outside the stock kernel tree: " + name)
    for suffix in (".ko", ".ko.zst", ".ko.xz", ".ko.gz"):
      existing = current.parent / (name + suffix)
      if existing.exists() or existing.is_symlink():
        existing.unlink()
    destination = current.parent / (name + ".ko")
    shutil.copyfile(candidate / expected[name]["source"], destination)
    destination.chmod(0o644)
  BASE.run(("depmod", "-b", module_root, release))
  selected = {}
  for name in C.T2BCE_MODULES:
    path = BASE.selected_module_path(module_root, release, name)
    if BASE.digest(path) != expected[name]["sha256"]:
      raise ValueError("Private module root selected the wrong module: " + name)
    selected[name] = str(path.relative_to(module_root))
  return module_root, selected


def manifest(tree):
  """Relative path -> 'file:<sha256>:<mode>' | 'link:<target>' for everything but directories."""
  result = {}
  root = Path(tree)
  for path in sorted(root.rglob("*")):
    relative = str(path.relative_to(root))
    if path.is_symlink():
      result[relative] = "link:" + os.readlink(path)
    elif path.is_file():
      result[relative] = "file:" + BASE.digest(path) + ":" + format(stat.S_IMODE(path.lstat().st_mode), "o")
  return result


def config_values(text):
  values = {}
  for match in re.finditer(r'^([A-Z]+)="([^"\n]*)"\s*$', text, re.M):
    values[match.group(1)] = match.group(2).split()
  return values


def manifest_diff(production, candidate, release, *, dependencies=(), production_config="", candidate_config=""):
  """Compare two extracted-initramfs manifests; raise unless every difference is expected.

  Expected: the four t2bce modules (changed) and their module-tree indexes, the .ko
  dependencies of t2bce_audio (added), the blacklist file (added), and a `config` whose runtime
  hook lists are identical and whose MODULES gains at most t2bce_audio. Anything else is refused.
  """
  tree = "usr/lib/modules/" + release + "/"
  audio_paths = {str(Path(item).relative_to("/")) if item.startswith("/") else item for item in dependencies}
  added = sorted(set(candidate) - set(production))
  removed = sorted(set(production) - set(candidate))
  changed = sorted(path for path in set(production) & set(candidate) if production[path] != candidate[path])
  allowed_changed, allowed_added, disallowed = [], [], []
  # Removals and additions are judged by the validator the stager shares (common.delta_problems).
  disallowed.extend(C.delta_problems(removed, added, release, audio_paths))
  allowed_added = [path for path in added if "added: " + path not in disallowed]
  indexes = {path for path in changed if path.startswith(tree) and "/" not in path[len(tree):] and path[len(tree):].startswith("modules.")}
  t2bce = {path for path in candidate if path.startswith(tree) and Path(path).name in tuple(name + ".ko" for name in C.T2BCE_MODULES)}
  for path in changed:
    if path in indexes or path in t2bce:
      allowed_changed.append(path)
    elif path == "config":
      before, after = config_values(production_config), config_values(candidate_config)
      for key in RUNTIME_CONFIG_KEYS:
        if before.get(key) != after.get(key):
          disallowed.append("config " + key + " differs from production")
      extra = [name for name in after.get("MODULES", []) if name not in before.get("MODULES", [])]
      missing = [name for name in before.get("MODULES", []) if name not in after.get("MODULES", [])]
      if missing or any(name != "t2bce_audio" for name in extra):
        disallowed.append("config MODULES differs beyond t2bce_audio")
      rest = {key: value for key, value in before.items() if key not in RUNTIME_CONFIG_KEYS + ("MODULES",)}
      if rest != {key: value for key, value in after.items() if key not in RUNTIME_CONFIG_KEYS + ("MODULES",)}:
        disallowed.append("config has other differing settings")
      allowed_changed.append(path)
    elif path == "buildconfig":
      allowed_changed.append(path)  # private source-wrapper text; the runtime `config` is what counts
    else:
      disallowed.append("changed: " + path)
  markers = [path for path in candidate if re.search(r"marker|cold|ftrace|kretprobe|source-bluetooth|hibernation-candidate", path)]
  for path in markers:
    if path not in production:
      disallowed.append("marker/guard-like path: " + path)
  if disallowed:
    raise ValueError("Initramfs differs from production beyond the upstream-model deltas: " + "; ".join(disallowed[:12]))
  return {"added": added, "removed": removed, "changed": changed, "audio_dependencies": sorted(audio_paths),
          "allowed_changed_count": len(allowed_changed), "allowed_added_count": len(allowed_added)}


def extract_initrd(initrd, destination):
  destination.mkdir()
  BASE.run(("lsinitcpio", "--early", "--extract", initrd), cwd=destination)
  BASE.run(("lsinitcpio", "--cpio", "--extract", initrd), cwd=destination)


def verify_blacklist(extracted, release):
  """The blacklist file is present and keeps brcmfmac from loading by its PCI alias."""
  path = extracted / C.BLACKLIST_DESTINATION
  if not path.is_file() or C.blacklist_names(path.read_text()) != set(C.BLACKLISTED_MODULES):
    raise ValueError("Initramfs blacklist is missing or incomplete")
  common = ("modprobe", "--config", extracted / "etc/modprobe.d", "--dirname", extracted,
            "--set-version", release, "--show-depends", ALIAS_PROBE)
  plain = BASE.run(common, capture=True).stdout
  if not re.search(r"brcmfmac\.ko", plain):
    raise ValueError("Wi-Fi alias does not resolve to brcmfmac in the initramfs; blacklist check would be vacuous")
  result = subprocess.run([str(item) for item in common[:-1] + ("--use-blacklist", ALIAS_PROBE)],
                          text=True, capture_output=True, check=False)
  if re.search(r"brcmfmac[^\s]*\.ko", result.stdout):
    raise ValueError("Initramfs would still load brcmfmac from the Wi-Fi PCI alias")
  return {"alias_probe": ALIAS_PROBE, "without_blacklist_loads_brcmfmac": True, "with_blacklist_loads_brcmfmac": False}


def audio_dependencies(extracted, release):
  output = BASE.run(("modprobe", "--config", extracted / "etc/modprobe.d", "--dirname", extracted,
                     "--set-version", release, "--show-depends", "t2bce_audio"), capture=True).stdout
  paths = [line.split()[1] for line in output.splitlines() if line.startswith("insmod ")]
  return normalize_dependencies(paths, extracted)


def normalize_dependencies(paths, extracted):
  """modprobe --dirname prints <extracted>/lib/modules/... (lib is a symlink to usr/lib); return usr/lib paths."""
  result = []
  for path in paths:
    for prefix in (str(extracted), str(Path(extracted).resolve())):
      if path.startswith(prefix + "/"):
        path = path[len(prefix):]
        break
    path = "/" + path.lstrip("/")
    if path.startswith("/lib/"):
      path = "/usr" + path
    result.append(path)
  return result


def build_initrd(work, module_root, release, expected, production_initrd):
  blacklist = work / "initramfs-blacklist.conf"
  blacklist.write_text(C.blacklist_text())
  blacklist.chmod(0o600)
  config = work / "upstream-model-mkinitcpio.conf"
  config.write_text(private_config())
  config.chmod(0o600)
  stock = work / "stock-mkinitcpio.conf"
  stock.write_text(stock_config_text())
  stock.chmod(0o600)
  config_audit = audit_config(config, stock)
  initrd = work / "upstream-model.initrd"
  BASE.run((
    "env",
    "MKINITCPIO_INSTALL=" + str(INSTALL_HOOKS) + ":/etc/initcpio/install:/usr/lib/initcpio/install",
    "OMARCHY_T2_UPSTREAM_MODEL_BLACKLIST=" + str(blacklist),
    "mkinitcpio", "--config", config, "--generate", initrd, "--kernel", release, "--moduleroot", module_root,
  ))
  extracted = work / "initrd-root"
  extract_initrd(initrd, extracted)
  for name in ("init", "usr/bin/cryptsetup", "usr/bin/btrfs", "etc/cryptsetup-keys.d/root.key"):
    if not (extracted / name).exists():
      raise ValueError("Initramfs omitted boot-critical file: " + name)
  tree = extracted / "usr/lib/modules" / release
  selected = {}
  for name in C.T2BCE_MODULES:
    matches = list(tree.rglob(name + ".ko"))
    if len(matches) != 1 or BASE.digest(matches[0]) != expected[name]["sha256"]:
      raise ValueError("Initramfs t2bce module missing or mismatched: " + name)
    selected[name] = str(matches[0].relative_to(extracted))
  if list(tree.rglob("t2bce_ave.ko")):
    raise ValueError("Initramfs unexpectedly includes optional AVE")
  blacklist_report = verify_blacklist(extracted, release)
  production_tree = work / "production-initrd-root"
  extract_initrd(production_initrd, production_tree)
  production_manifest = manifest(production_tree)
  candidate_manifest = manifest(extracted)
  diff = manifest_diff(
    production_manifest, candidate_manifest, release,
    dependencies=audio_dependencies(extracted, release),
    production_config=(production_tree / "config").read_text(),
    candidate_config=(extracted / "config").read_text(),
  )
  blacklist_report["config_arrays"] = config_audit
  return initrd, selected, blacklist_report, diff, production_manifest, candidate_manifest


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True, help="root-owned candidate-7.2.7-h1 directory")
  parser.add_argument("--production-uki", type=Path, default=Path("/boot/EFI/Linux/omarchy_linux-t2.efi"))
  parser.add_argument("--output", type=Path, required=True, help="new private directory outside the ESP")
  parser.add_argument("--kernel-release", default=os.uname().release)
  parser.add_argument("--experiment-id", required=True)
  args = parser.parse_args()

  if os.geteuid() != 0:
    raise SystemExit("Run as root so the root-unlock key retains protected handling")
  experiment_id = BASE.validate_experiment_id(args.experiment_id)
  output = args.output.absolute()
  if output.exists() or output.is_symlink():
    raise ValueError("Output already exists; choose a new directory")
  if any(BASE.under(output, path) for path in (Path("/boot"), Path("/efi"))):
    raise ValueError("Offline builder refuses to publish onto an EFI or boot filesystem")
  candidate_source = args.candidate_source.resolve()
  production = args.production_uki.resolve()
  require_root_tree(candidate_source, directory=True)
  require_root_tree(production, directory=False)
  require_stock_config()
  require_root_tree(INSTALL_HOOKS, directory=True)
  require_root_tree(HERE / "common.py", directory=False)
  require_root_tree(Path(__file__).resolve(), directory=False)
  output.parent.mkdir(parents=True, exist_ok=True)
  os.umask(0o077)

  with tempfile.TemporaryDirectory(prefix=".t2-upstream-model-", dir=output.parent) as directory:
    work = Path(directory)
    source_provenance, expected = validate_candidate(candidate_source, args.kernel_release)
    module_root, selected = prepare_module_root(work, candidate_source, args.kernel_release, expected)
    production_initrd = work / "production.initrd"
    BASE.extract_section(production, ".initrd", production_initrd)
    initrd, initrd_modules, blacklist, diff, production_manifest, candidate_manifest = build_initrd(
      work, module_root, args.kernel_release, expected, production_initrd)
    uki, cmdline, sections, production_hash = BASE.build_uki(work, production, initrd)
    uki_hash = BASE.digest(uki)
    if uki_hash in C.REJECTED_IMAGE_SHA256 or uki_hash == production_hash:
      raise ValueError("Built image hash is rejected or equals production")
    if sections[".initrd"] == BASE.digest(initrd):
      raise ValueError("Initramfs section did not change")

    publish = work / "publish"
    publish.mkdir(mode=0o700)
    shutil.copyfile(uki, publish / C.BUILD_IMAGE)
    shutil.copyfile(initrd, publish / C.BUILD_INITRD)
    for name, data in (("initrd-manifest-production.json", production_manifest),
                       ("initrd-manifest-candidate.json", candidate_manifest)):
      (publish / name).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    (publish / "initrd-manifest-diff.json").write_text(json.dumps(diff, indent=1, sort_keys=True) + "\n")
    report = {
      "candidate": C.CANDIDATE,
      "schema": SCHEMA,
      "protocol": C.PROTOCOL,
      "kernel_release": args.kernel_release,
      "production_uki": str(production),
      "production_uki_sha256": production_hash,
      "candidate_uki_sha256": BASE.digest(publish / C.BUILD_IMAGE),
      "candidate_initrd_sha256": BASE.digest(publish / C.BUILD_INITRD),
      "experiment_id": experiment_id,
      "cmdline": cmdline,
      "unchanged_production_sections_sha256": {name: value for name, value in sections.items() if name != ".initrd"},
      "modified_sections_sha256": None,
      "source_provenance_sha256": BASE.digest(source_provenance),
      "modules": expected,
      "private_module_selection": selected,
      "initrd_module_selection": initrd_modules,
      "deltas": {
        "D1_modules_added": ["t2bce_audio"],
        "D2_initramfs_blacklist": list(C.BLACKLISTED_MODULES),
        "D2_blacklist_destination": C.BLACKLIST_DESTINATION,
        "build_hook": C.HOOK,
        "private_config_sha256": C.sha256(private_config().encode()),
        "blacklist_sha256": C.sha256(C.blacklist_text().encode()),
      },
      "blacklist_check": blacklist,
      "initrd_manifest_diff": diff,
      "initrd_manifest_sha256": {
        "production": C.sha256((publish / "initrd-manifest-production.json").read_bytes()),
        "candidate": C.sha256((publish / "initrd-manifest-candidate.json").read_bytes()),
        "diff": C.sha256((publish / "initrd-manifest-diff.json").read_bytes()),
      },
      "production_modified": False,
      "installed": False,
      "boot_entry_created": False,
      "hardware_qualified": False,
    }
    (publish / C.BUILD_PROVENANCE).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    publish.rename(output)
  for item in (output, *output.rglob("*")):
    item.chmod(0o700 if item.is_dir() else 0o600)
  print("PASS: private upstream-model UKI preserves production kernel/cmdline and stock initramfs deltas: " + str(output))


if __name__ == "__main__":
  main()
