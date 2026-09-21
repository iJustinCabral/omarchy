#!/usr/bin/env python3
"""Exercise read-only candidate boot qualification against synthetic sysfs."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/verify-hibernation-candidate-boot.py"
spec = importlib.util.spec_from_file_location("candidate_boot_verifier", script)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
stager = verifier.STAGER


def write(path, data):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(data)


def efi_string(value):
  return b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le")


def efi_strings(values):
  return b"\x06\x00\x00\x00" + "".join(value + "\x00" for value in values).encode("utf-16-le")


with tempfile.TemporaryDirectory(prefix="t2-candidate-boot-verifier-") as directory:
  base = Path(directory)
  root = base / "root"
  candidate = base / "candidate"
  candidate.mkdir()
  production = root / "boot/EFI/Linux/omarchy_linux-t2.efi"
  production.parent.mkdir(parents=True)
  production.write_bytes(b"healthy production uki")
  production_blake2 = hashlib.blake2b(production.read_bytes()).hexdigest()
  write(root / stager.LIMINE, (
    "timeout: 3\n"
    "default_entry: 2\n"
    "/+Omarchy\n"
    "  //linux-t2\n"
    "  protocol: efi\n"
    f"  path: boot():/EFI/Linux/omarchy_linux-t2.efi#{production_blake2}\n"
  ))
  selected = root / stager.SELECTED
  selected.parent.mkdir(parents=True)
  selected.write_bytes(efi_string("Omarchy.linux-t2"))

  image = candidate / "mba-t2-hibernation-candidate.efi"
  image.write_bytes(b"private candidate uki")
  release = "7.2.6-arch2-Watanare-T2-2-t2"
  cmdline = "cryptdevice=PARTUUID=test:root root=/dev/mapper/root rootflags=subvol=@ rw rootfstype=btrfs resume=/dev/mapper/root resume_offset=42 cryptkey=rootfs:/key"
  modules = {name: {"srcversion": "SRC_" + name.replace("-", "_")} for name in verifier.REQUIRED_MODULES}
  provenance = {
    "candidate": "mba-t2-hibernation-module-overlay",
    "candidate_uki_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
    "production_uki_sha256": hashlib.sha256(production.read_bytes()).hexdigest(),
    "production_modified": False,
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
    "kernel_release": release,
    "cmdline": cmdline,
    "modules": modules,
  }
  (candidate / "provenance.json").write_text(json.dumps(provenance))

  receipt = stager.stage(root, candidate)
  entries = root / stager.ENTRIES
  entries.write_bytes(efi_strings(("Omarchy.linux-t2", receipt["entry_id"])))

  def fake_bootctl(_arguments, check):
    assert check
    (root / stager.ONESHOT).write_bytes(efi_string(receipt["entry_id"]))

  stager.arm(root, runner=fake_bootctl, sync=lambda: None)
  (root / stager.ONESHOT).unlink()
  selected.write_bytes(efi_string(receipt["entry_id"]))

  write(root / verifier.MODEL, "MacBookAir9,1\n")
  write(root / verifier.BOOT_ID, "11111111-2222-3333-4444-555555555555\n")
  write(root / verifier.OSRELEASE, release + "\n")
  write(root / verifier.CMDLINE, cmdline + "\n")
  write(root / verifier.INPUT_DEVICES, (
    'N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"\n'
    "P: Phys=usb-t2bce_vhci-5/input1\n\n"
    'N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"\n'
    "P: Phys=usb-t2bce_vhci-5/input2\n"
  ))
  write(root / verifier.ASOUND_CARDS, " 0 [AppleT2        ]: Apple T2 Audio\n")

  for name in verifier.REQUIRED_MODULES:
    write(root / "sys/module" / name.replace("-", "_") / "srcversion", modules[name]["srcversion"] + "\n")
  for address, (vendor, device, driver) in verifier.PCI_DEVICES.items():
    path = root / "sys/bus/pci/devices" / address
    write(path / "vendor", vendor + "\n")
    write(path / "device", device + "\n")
    if driver is not None:
      (path / "driver").symlink_to("../../../drivers/" + driver)
  (root / "sys/bus/pci/devices/0000:73:00.0/net/wlp115s0f0").mkdir(parents=True)
  (root / "sys/class/bluetooth/hci0").mkdir(parents=True)

  result = verifier.inspect(root, candidate)
  assert result["qualification"] == "candidate-boot-preflight-passed"
  assert result["entry_id"] == receipt["entry_id"]
  assert result["physical_input_confirmed"] is False
  assert result["hibernate_attempted"] is False
  assert result["hardware_qualified"] is False

  selected.write_bytes(efi_string("Omarchy.linux-t2"))
  try:
    verifier.inspect(root, candidate)
    raise AssertionError("production selection passed candidate verification")
  except ValueError as error:
    assert "not the hash-bound candidate" in str(error)
  selected.write_bytes(efi_string(receipt["entry_id"]))

  module_version = root / "sys/module/t2bce_core/srcversion"
  module_version.write_text("WRONG\n")
  try:
    verifier.inspect(root, candidate)
    raise AssertionError("wrong loaded candidate module passed verification")
  except ValueError as error:
    assert "does not match candidate" in str(error)

print("PASS: candidate boot verifier proves selected entry, loaded modules and T2 devices without claiming physical input")
