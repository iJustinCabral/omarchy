#!/usr/bin/env python3
"""Verify that a boot-only T2 hibernation candidate loaded as intended.

This is a read-only verifier. It does not qualify physical input, arm another
boot, install anything, or initiate a power transition.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
STAGER_PATH = HERE / "stage-hibernation-candidate-boot.py"
SPEC = importlib.util.spec_from_file_location("candidate_boot_stager", STAGER_PATH)
STAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGER)

MODEL = Path("sys/class/dmi/id/product_name")
BOOT_ID = Path("proc/sys/kernel/random/boot_id")
OSRELEASE = Path("proc/sys/kernel/osrelease")
CMDLINE = Path("proc/cmdline")
INPUT_DEVICES = Path("proc/bus/input/devices")
ASOUND_CARDS = Path("proc/asound/cards")
ORDINARY_BOOT_MARKER = Path("run/omarchy-t2-hibernation-candidate/ordinary-boot-loaded.json")
REQUIRED_MODULES = (
  "brcmfmac",
  "brcmfmac-wcc",
  "hci_bcm4377",
  "t2bce_dma",
  "t2bce_core",
  "t2bce_vhci",
  "t2bce_audio",
)
PCI_DEVICES = {
  "0000:73:00.0": ("0x14e4", "0x4488", "brcmfmac"),
  "0000:73:00.1": ("0x14e4", "0x5fa0", "hci_bcm4377"),
  "0000:74:00.0": ("0x106b", "0x2005", "nvme"),
  "0000:74:00.1": ("0x106b", "0x1801", "t2bce_core"),
  "0000:74:00.2": ("0x106b", "0x1802", None),
  "0000:74:00.3": ("0x106b", "0x1803", "t2bce_audio"),
}


def rooted(root, relative):
  return STAGER.rooted(root, relative)


def confined(root, relative):
  path = root / relative
  path.resolve().relative_to(root.resolve())
  return path


def read(path):
  return path.read_text().strip()


def sha256_text(value):
  return hashlib.sha256(value.encode()).hexdigest()


def driver_name(device):
  driver = device / "driver"
  if not driver.is_symlink():
    return None
  return Path(os.readlink(driver)).name


def load_provenance(directory):
  path = directory / "provenance.json"
  image = directory / "mba-t2-hibernation-candidate.efi"
  if path.is_symlink() or image.is_symlink() or not path.is_file() or not image.is_file():
    raise ValueError("Private candidate image or provenance is missing or symlinked")
  provenance = json.loads(path.read_text())
  if STAGER.digest(image) != provenance.get("candidate_uki_sha256"):
    raise ValueError("Private candidate UKI hash mismatch")
  return provenance


def verify_modules(root, provenance):
  recorded = provenance.get("modules", {})
  result = {}
  for name in REQUIRED_MODULES:
    expected = recorded.get(name, {}).get("srcversion")
    if not expected:
      raise ValueError("Candidate provenance omits module: " + name)
    module = confined(root, Path("sys/module") / name.replace("-", "_"))
    actual = read(module / "srcversion")
    if actual != expected:
      raise ValueError(f"Loaded {name} srcversion {actual} does not match candidate {expected}")
    result[name] = actual
  if confined(root, Path("sys/module/t2bce_ave")).exists():
    raise ValueError("Optional AVE module unexpectedly loaded during boot-only qualification")
  return result


def verify_pci(root):
  result = {}
  for address, expected in PCI_DEVICES.items():
    device = confined(root, Path("sys/bus/pci/devices") / address)
    actual = (read(device / "vendor"), read(device / "device"), driver_name(device))
    if actual != expected:
      raise ValueError(f"PCI identity or binding mismatch for {address}: {actual}")
    result[address] = {
      "vendor": actual[0],
      "device": actual[1],
      "driver": actual[2],
    }
  return result


def verify_devices(root):
  wifi = confined(root, Path("sys/bus/pci/devices/0000:73:00.0/net"))
  interfaces = sorted(path.name for path in wifi.iterdir() if path.is_dir())
  if len(interfaces) != 1:
    raise ValueError("Candidate Wi-Fi function does not expose exactly one interface")
  if not confined(root, Path("sys/class/bluetooth/hci0")).exists():
    raise ValueError("Candidate Bluetooth controller hci0 is absent")

  inputs = read(confined(root, INPUT_DEVICES))
  internal_input_count = inputs.count('N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"')
  if internal_input_count < 2 or inputs.count("Phys=usb-t2bce_vhci-") < 2:
    raise ValueError("Candidate BCE keyboard/trackpad interfaces are incomplete")
  if "Apple T2 Audio" not in read(confined(root, ASOUND_CARDS)):
    raise ValueError("Candidate T2 audio card is absent")
  return {
    "wifi_interfaces": interfaces,
    "bluetooth_controller": "hci0",
    "internal_input_interfaces": internal_input_count,
    "t2_audio_present": True,
  }


def verify_post_switch_root_policy(root, provenance, boot_id, entry_id):
  policy = provenance.get("pre_restore_module_policy")
  if policy is None:
    return None
  if policy != "root-only-no-t2-radio":
    raise ValueError("Candidate provenance has an unknown pre-restore module policy")
  excluded = provenance.get("pre_restore_excluded_modules")
  if not isinstance(excluded, list) or not set(REQUIRED_MODULES).issubset(excluded):
    raise ValueError("Candidate provenance does not exclude every required module before restore")
  marker_path = confined(root, ORDINARY_BOOT_MARKER)
  if marker_path.is_symlink() or not marker_path.is_file():
    raise ValueError("Candidate post-switch-root module marker is missing or symlinked")
  try:
    marker = json.loads(marker_path.read_text())
  except json.JSONDecodeError as error:
    raise ValueError("Candidate post-switch-root module marker is malformed") from error
  expected = {
    "boot_id": boot_id,
    "entry_id": entry_id,
    "kernel_release": provenance["kernel_release"],
    "policy": "post-switch-root-only",
  }
  for key, value in expected.items():
    if marker.get(key) != value:
      raise ValueError("Candidate post-switch-root module marker mismatch: " + key)
  loaded = marker.get("loaded_srcversions")
  if not isinstance(loaded, dict):
    raise ValueError("Candidate post-switch-root module marker omits source versions")
  for name in REQUIRED_MODULES:
    if name == "hci_bcm4377":
      continue
    if loaded.get(name) != provenance.get("modules", {}).get(name, {}).get("srcversion"):
      raise ValueError("Candidate post-switch-root module marker mismatch: " + name)
  return policy


def inspect(root, candidate_directory):
  receipt = STAGER.load_receipt(root)
  if receipt.get("state") != "arming":
    raise ValueError("Candidate transaction does not record an armed boot")
  STAGER.verify_staged(root, receipt)
  if rooted(root, STAGER.ONESHOT).exists():
    raise ValueError("LoaderEntryOneShot was not consumed")
  selected = rooted(root, STAGER.SELECTED)
  if not selected.is_file() or STAGER.read_efi_string(selected) != receipt["entry_id"]:
    raise ValueError("Running boot is not the hash-bound candidate entry")

  provenance = load_provenance(candidate_directory)
  if provenance.get("candidate_uki_sha256") != receipt["candidate_uki_sha256"]:
    raise ValueError("Staged candidate differs from private provenance")
  if read(confined(root, MODEL)) != "MacBookAir9,1":
    raise ValueError("Boot-only qualification is restricted to MacBookAir9,1")
  if read(confined(root, OSRELEASE)) != provenance.get("kernel_release"):
    raise ValueError("Running kernel release differs from candidate provenance")
  cmdline = read(confined(root, CMDLINE))
  if cmdline != provenance.get("cmdline"):
    raise ValueError("Running kernel command line differs from the private candidate")
  boot_id = read(confined(root, BOOT_ID))
  if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
    raise ValueError("Running boot ID is malformed")
  pre_restore_module_policy = verify_post_switch_root_policy(
    root,
    provenance,
    boot_id,
    receipt["entry_id"],
  )

  return {
    "qualification": "candidate-boot-preflight-passed",
    "boot_id": boot_id,
    "entry_id": receipt["entry_id"],
    "kernel_release": provenance["kernel_release"],
    "cmdline_sha256": sha256_text(cmdline),
    "candidate_uki_sha256": receipt["candidate_uki_sha256"],
    "pre_restore_module_policy": pre_restore_module_policy,
    "modules": verify_modules(root, provenance),
    "pci": verify_pci(root),
    "devices": verify_devices(root),
    "physical_input_confirmed": False,
    "hibernate_attempted": False,
    "hardware_qualified": False,
  }


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  result = inspect(Path("/"), args.candidate_source.resolve())
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
