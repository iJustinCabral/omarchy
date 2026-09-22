#!/usr/bin/python3
"""Load the private T2 candidate only after an ordinary switch_root."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


PAYLOAD = Path("/run/omarchy-t2-hibernation-candidate")
LOAD_ORDER = (
  "t2bce_dma",
  "t2bce_core",
  "t2bce_vhci",
  "t2bce_audio",
  "brcmfmac",
  "brcmfmac-wcc",
)
PAYLOAD_MODULES = frozenset((
  *LOAD_ORDER,
  "brcmfmac-bca",
  "brcmfmac-cyw",
  "hci_bcm4377",
  "t2bce_ave",
))
GENERIC_DEPENDENCIES = ("snd", "snd_pcm", "mmc_core", "brcmutil", "cfg80211")
PCI_BINDINGS = {
  "0000:73:00.0": "brcmfmac",
  "0000:74:00.1": "t2bce_core",
  "0000:74:00.3": "t2bce_audio",
}
EFI_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
SELECTED = Path("/sys/firmware/efi/efivars/LoaderEntrySelected-" + EFI_GUID)


def output(run, arguments):
  result = run(arguments, check=True, capture_output=True, text=True, timeout=10)
  return result.stdout.strip()


def selected_entry(path=SELECTED):
  data = path.read_bytes()
  if len(data) < 6:
    raise RuntimeError("LoaderEntrySelected is malformed")
  return data[4:].decode("utf-16-le").rstrip("\x00")


def load_manifest(payload):
  path = payload / "manifest.json"
  if path.is_symlink() or not path.is_file():
    raise RuntimeError("candidate module manifest is missing or symlinked")
  try:
    manifest = json.loads(path.read_text())
  except json.JSONDecodeError as error:
    raise RuntimeError("candidate module manifest is malformed") from error
  if manifest.get("policy") != "post-switch-root-only":
    raise RuntimeError("candidate module manifest has an unknown policy")
  return manifest


def verify_payload(payload, release, run):
  manifest = load_manifest(payload)
  if manifest.get("kernel_release") != release:
    raise RuntimeError("candidate module manifest kernel release mismatch")
  recorded = manifest.get("modules")
  if not isinstance(recorded, dict):
    raise RuntimeError("candidate module manifest omits modules")
  if set(recorded) != PAYLOAD_MODULES:
    raise RuntimeError("candidate module manifest has an unexpected module set")

  result = {}
  for name, metadata in recorded.items():
    if not isinstance(metadata, dict) or metadata.get("file") != name + ".ko":
      raise RuntimeError("candidate module manifest entry is malformed: " + name)
    module = payload / metadata["file"]
    if module.is_symlink() or not module.is_file():
      raise RuntimeError("candidate module payload is missing or symlinked: " + name)
    if hashlib.sha256(module.read_bytes()).hexdigest() != metadata.get("sha256"):
      raise RuntimeError("candidate module payload hash mismatch: " + name)
    srcversion = output(run, ["/usr/bin/modinfo", "-F", "srcversion", str(module)])
    vermagic = output(run, ["/usr/bin/modinfo", "-F", "vermagic", str(module)])
    if srcversion != metadata.get("srcversion") or vermagic.split()[0] != release:
      raise RuntimeError("candidate module payload metadata mismatch: " + name)
    result[name] = {
      "module": module,
      "srcversion": srcversion,
    }
  return result


def driver_name(device):
  driver = device / "driver"
  if not driver.is_symlink():
    return None
  return Path(os.readlink(driver)).name


def load_candidate(
  sys=Path("/sys"),
  proc=Path("/proc"),
  payload=PAYLOAD,
  run=subprocess.run,
  monotonic=time.monotonic,
  sleep=time.sleep,
  release=None,
  entry_reader=selected_entry,
):
  if (sys / "class/dmi/id/product_name").read_text().strip() != "MacBookAir9,1":
    raise RuntimeError("unsupported model")
  running_release = release or os.uname().release
  modules = verify_payload(payload, running_release, run)
  for name in LOAD_ORDER:
    if (sys / "module" / name.replace("-", "_")).exists():
      raise RuntimeError("candidate module loaded before post-switch-root gate: " + name)

  run(["/usr/bin/modprobe", "-a", *GENERIC_DEPENDENCIES], check=True, timeout=20)
  for name in LOAD_ORDER:
    run(["/usr/bin/insmod", str(modules[name]["module"])], check=True, timeout=10)

  deadline = monotonic() + 20
  while monotonic() < deadline:
    healthy = True
    for name in LOAD_ORDER:
      source = sys / "module" / name.replace("-", "_") / "srcversion"
      try:
        healthy = healthy and source.read_text().strip() == modules[name]["srcversion"]
      except OSError:
        healthy = False
    for address, driver in PCI_BINDINGS.items():
      healthy = healthy and driver_name(sys / "bus/pci/devices" / address) == driver
    wifi = sys / "bus/pci/devices/0000:73:00.0/net"
    try:
      healthy = healthy and any(path.is_dir() for path in wifi.iterdir())
    except OSError:
      healthy = False
    if healthy:
      break
    sleep(0.2)
  else:
    raise RuntimeError("candidate modules loaded without healthy device registration")

  marker = {
    "boot_id": (proc / "sys/kernel/random/boot_id").read_text().strip(),
    "entry_id": entry_reader(),
    "kernel_release": running_release,
    "loaded_srcversions": {name: modules[name]["srcversion"] for name in LOAD_ORDER},
    "policy": "post-switch-root-only",
  }
  marker_path = payload / "ordinary-boot-loaded.json"
  if marker_path.exists() or marker_path.is_symlink():
    raise RuntimeError("candidate ordinary-boot marker already exists")
  temporary = payload / ".ordinary-boot-loaded.json.tmp"
  descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  try:
    with os.fdopen(descriptor, "w") as stream:
      stream.write(json.dumps(marker, indent=2, sort_keys=True) + "\n")
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(temporary, marker_path)
  finally:
    if temporary.exists():
      temporary.unlink()
  print("omarchy-t2-hibernation-candidate: post-switch-root modules loaded", flush=True)
  return marker


if __name__ == "__main__":
  load_candidate()
