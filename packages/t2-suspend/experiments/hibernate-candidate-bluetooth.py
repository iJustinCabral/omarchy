#!/usr/bin/python3
"""Load the private BCM4377 candidate only after firmware-backed Wi-Fi is ready."""

import hashlib
import os
from pathlib import Path
import subprocess
import time


WIFI_PCI = "0000:73:00.0"
BLUETOOTH_PCI = "0000:73:00.1"
PAYLOAD = Path("/run/omarchy-t2-hibernation-candidate")


def wifi_ready(sys):
  device = sys / "bus/pci/devices" / WIFI_PCI
  try:
    if (device / "vendor").read_text().strip() != "0x14e4":
      return None
    if (device / "device").read_text().strip() != "0x4488":
      return None
    if (device / "driver").resolve().name != "brcmfmac":
      return None
    for interface in (device / "net").iterdir():
      if int((interface / "ifindex").read_text()) > 0 and (interface / "phy80211").is_dir():
        return interface.name
  except (OSError, ValueError):
    return None
  return None


def output(run, arguments):
  result = run(arguments, check=True, capture_output=True, text=True, timeout=8)
  return result.stdout.strip()


def gate(
  sys=Path("/sys"),
  payload=PAYLOAD,
  run=subprocess.run,
  monotonic=time.monotonic,
  sleep=time.sleep,
  release=None,
):
  if (sys / "class/dmi/id/product_name").read_text().strip() != "MacBookAir9,1":
    raise RuntimeError("unsupported model")
  if (sys / "module/hci_bcm4377").exists():
    raise RuntimeError("Bluetooth already loaded before candidate gate")

  module = payload / "hci_bcm4377.ko"
  digest_file = payload / "hci_bcm4377.sha256"
  if module.is_symlink() or not module.is_file() or not digest_file.is_file():
    raise RuntimeError("candidate Bluetooth payload is incomplete")
  expected_digest = digest_file.read_text().strip()
  if hashlib.sha256(module.read_bytes()).hexdigest() != expected_digest:
    raise RuntimeError("candidate Bluetooth payload hash mismatch")
  expected_srcversion = output(run, ["/usr/bin/modinfo", "-F", "srcversion", str(module)])
  vermagic = output(run, ["/usr/bin/modinfo", "-F", "vermagic", str(module)])
  running_release = release or os.uname().release
  if not expected_srcversion or vermagic.split()[0] != running_release:
    raise RuntimeError("candidate Bluetooth module ABI mismatch")

  print("t2-hibernate-candidate-bt: BEGIN waiting for firmware-backed BCM netdev", flush=True)
  deadline = monotonic() + 25
  while monotonic() < deadline:
    interface = wifi_ready(sys)
    if interface:
      if (sys / "module/hci_bcm4377").exists():
        raise RuntimeError("Bluetooth bypassed candidate gate")
      print(f"t2-hibernate-candidate-bt: WIFI_READY interface={interface}; loading candidate", flush=True)
      run(["/usr/bin/modprobe", "bluetooth"], check=True, timeout=8)
      run(["/usr/bin/insmod", str(module)], check=True, timeout=8)
      break
    sleep(0.2)
  else:
    raise RuntimeError("Wi-Fi netdev not ready; candidate Bluetooth left unloaded")

  deadline = monotonic() + 8
  while monotonic() < deadline:
    try:
      actual_srcversion = (sys / "module/hci_bcm4377/srcversion").read_text().strip()
      driver = (sys / "bus/pci/devices" / BLUETOOTH_PCI / "driver").resolve().name
      controller = (sys / "class/bluetooth/hci0").is_dir()
      if actual_srcversion == expected_srcversion and driver == "hci_bcm4377" and controller:
        print("t2-hibernate-candidate-bt: candidate loaded and controller registered", flush=True)
        return
    except OSError:
      pass
    sleep(0.2)
  raise RuntimeError("candidate Bluetooth module loaded without healthy controller registration")


if __name__ == "__main__":
  gate()
