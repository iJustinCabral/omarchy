#!/usr/bin/env python3
"""Build a private candidate UKI from the exact production kernel and cmdline.

The output stays outside the ESP.  This program never installs modules, edits
the production UKI, changes a boot entry, or initiates a power transition.
Run it as root so mkinitcpio can preserve the embedded root-unlock key.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CONFIG = HERE / "hibernate-candidate-mkinitcpio.conf"
CANDIDATE_HOOKS = HERE / "hibernate-candidate-initcpio"
CANDIDATE_BLUETOOTH_HELPER = HERE / "hibernate-candidate-bluetooth.py"
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
EARLY_MODULES = tuple(name for name in MODULES if name != "t2bce_ave")
REQUIRED_INITRD_FILES = (
  "etc/modprobe.d/t2-bluetooth-order.conf",
  "hooks/omarchy-t2-candidate-bluetooth",
  "usr/bin/find",
  "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py",
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


def build_initrd(work, module_root, release, expected):
  initrd = work / "candidate.initrd"
  run((
    "env",
    "MKINITCPIO_HOOKS=" + str(CANDIDATE_HOOKS / "hooks") + ":/etc/initcpio/hooks:/usr/lib/initcpio/hooks",
    "MKINITCPIO_INSTALL=" + str(CANDIDATE_HOOKS / "install") + ":/etc/initcpio/install:/usr/lib/initcpio/install",
    "OMARCHY_T2_CANDIDATE_BLUETOOTH_HELPER=" + str(CANDIDATE_BLUETOOTH_HELPER),
    "mkinitcpio",
    "--config",
    CONFIG,
    "--generate",
    initrd,
    "--kernel",
    release,
    "--moduleroot",
    module_root,
  ))

  extracted = work / "initrd-root"
  extracted.mkdir()
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
  blacklist = (extracted / "etc/modprobe.d/t2-bluetooth-order.conf").read_text()
  if not re.search(r"^\s*blacklist\s+hci_bcm4377(?:\s|$)", blacklist, re.M):
    raise ValueError("Candidate initramfs Bluetooth blacklist is inactive")
  build_config = (extracted / "config").read_text()
  if "omarchy-t2-candidate-bluetooth" not in build_config:
    raise ValueError("Candidate initramfs late hook is not scheduled")

  initrd_modules = {}
  for name in EARLY_MODULES:
    matches = list((extracted / "usr/lib/modules" / release).rglob(name + ".ko"))
    if len(matches) != 1:
      raise ValueError(f"Candidate initramfs contains {len(matches)} uncompressed copies of {name}")
    if digest(matches[0]) != expected[name]["sha256"]:
      raise ValueError("Candidate initramfs module hash mismatch: " + name)
    initrd_modules[name] = str(matches[0].relative_to(extracted))

  runtime = work / "initrd-runtime-root"
  runtime.mkdir()
  run(("lsinitcpio", "--early", "--extract", initrd), cwd=runtime)
  run(("lsinitcpio", "--cpio", "--extract", initrd), cwd=runtime)
  resolution = run((
    "modprobe",
    "--config",
    runtime / "etc/modprobe.d",
    "--dirname",
    runtime,
    "--set-version",
    release,
    "--show-depends",
    "--use-blacklist",
    "hci_bcm4377",
  ), capture=True)
  if resolution.stderr.strip():
    raise ValueError("Candidate initramfs cannot resolve hci_bcm4377 dependencies: " + resolution.stderr.strip())
  loaded = [Path(line.split()[1]) for line in resolution.stdout.splitlines() if line.startswith("insmod ")]
  if any(path.name == "hci_bcm4377.ko" for path in loaded):
    raise ValueError("Candidate initramfs would load hci_bcm4377 before Wi-Fi readiness")
  return initrd, initrd_modules


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
  args = parser.parse_args()

  if os.geteuid() != 0:
    raise SystemExit("Run as root so the root-unlock key retains protected handling")
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
    initrd, initrd_modules = build_initrd(work, module_root, args.kernel_release, expected)
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
      "cmdline": cmdline,
      "unchanged_production_sections_sha256": {name: value for name, value in sections.items() if name != ".initrd"},
      "source_provenance_sha256": digest(provenance_path),
      "modules": expected,
      "private_module_selection": selected,
      "initrd_module_selection": initrd_modules,
      "production_modified": False,
      "installed": False,
      "boot_entry_created": False,
      "hardware_qualified": False,
    }
    (publish / "provenance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    publish.rename(output)
  secure_output(output)
  print("PASS: private candidate UKI preserves production kernel/cmdline and verified root-capable initramfs: " + str(output))


if __name__ == "__main__":
  main()
