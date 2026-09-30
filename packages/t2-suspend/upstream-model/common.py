"""Shared names and pure helpers for the attended upstream-model hibernation test.

The upstream model is one private UKI that keeps the production .linux and .cmdline,
uses the stock mkinitcpio configuration (plus the patched t2bce_* family and an
initramfs-only Wi-Fi blacklist), has no marker hooks and restores through the stock
resume hook. Nothing here touches hardware; the stager and runner import this module.
"""

from importlib.machinery import SourceFileLoader
import hashlib
import importlib.util
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
EXPERIMENTS = PACKAGE / "experiments"
HIBERNATE = PACKAGE / "hibernate"


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


PROTOCOL = "omarchy-t2-upstream-model-v1"
CANDIDATE = "mba-t2-upstream-model"
BUILD_IMAGE = "mba-t2-upstream-model.efi"
BUILD_INITRD = "mba-t2-upstream-model.initrd"
BUILD_PROVENANCE = "provenance.json"
ENTRY_PREFIX = "MBA-T2-upstream-model-"
ESP_IMAGE = "mba_t2_upstream_model.efi"
PRODUCTION_IMAGE = "omarchy_linux-t2.efi"
STOCK_ENTRY = "Omarchy.linux-t2"
BEGIN = "# BEGIN omarchy T2 upstream model"
END = "# END omarchy T2 upstream model"

STATE = Path("var/lib/omarchy-t2-upstream-model")
RECEIPT = STATE / "receipt.json"
BACKUP = STATE / "limine.conf.before"
GUARDS = STATE / "guards"
ATTEMPTS = STATE / "attempts"
TERMINAL = STATE / "terminal"
STATE_NAMES = ("guards", "attempts", "terminal")

RUNTIME_DIR = Path("run/omarchy-t2-upstream-model")
DROPIN = Path("run/systemd/system/systemd-hibernate.service.d/zz-upstream-model.conf")

# The one image that failed to mount /dev/mapper/root; replacement-kernel images are never
# staged. The stager adds every hash it can find in the pair receipt, archive and vectors.
REJECTED_IMAGE_SHA256 = frozenset({
  "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd",
})

T2BCE_MODULES = ("t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio")
BLACKLISTED_MODULES = ("brcmfmac", "brcmfmac-bca", "brcmfmac-cyw", "brcmfmac-wcc")
HOOK = "omarchy-t2-upstream-model-blacklist"
BLACKLIST_DESTINATION = "etc/modprobe.d/zz-omarchy-t2-upstream-model.conf"
WIFI_FUNCTION = "0000:73:00.0"
T2_FUNCTIONS = ("0000:74:00.0", "0000:74:00.1", "0000:74:00.2", "0000:74:00.3")

SHA256 = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def sha256(data):
  return hashlib.sha256(data).hexdigest()


def blake2(data):
  return hashlib.blake2b(data).hexdigest()


def entry_id(image_sha256):
  if SHA256.fullmatch(image_sha256) is None:
    raise ValueError("Image SHA-256 is malformed")
  return ENTRY_PREFIX + image_sha256[:16]


def blacklist_text():
  lines = [
    "# Upstream-model test image: initramfs only. The rootfs radio DKMS stack loads Wi-Fi and",
    "# Bluetooth normally after switch_root; the restore kernel must not bind brcmfmac while",
    "# the saved image is copied, because the function keeps bus-master after its freeze.",
  ]
  lines += ["blacklist " + name for name in BLACKLISTED_MODULES]
  return "\n".join(lines) + "\n"


def blacklist_names(text):
  return {match.group(1) for match in re.finditer(r"^\s*blacklist\s+(\S+)\s*$", text, re.M)}


def attendance_phrase(image_sha256, boot_id, cycle, power):
  """Typed attendance phrase; bound to the image, the boot, the cycle number and the power source."""
  if SHA256.fullmatch(image_sha256) is None or UUID.fullmatch(boot_id) is None:
    raise ValueError("Attendance identity is malformed")
  if type(cycle) is not int or not 1 <= cycle <= 3 or power not in ("AC", "battery"):
    raise ValueError("Attendance cycle or power source is invalid")
  return ("I am at the MacBook with the power button reachable; image " + image_sha256[:12] + " boot " + boot_id[:8]
          + " cycle " + str(cycle) + " on " + power + "; stock is the recovery choice")


def confirmation_phrase(kind, image_sha256, boot_id):
  """Typed physical-input confirmation for the ordinary-boot (G1), S3 and post-return (G4) checks."""
  if kind not in ("boot", "s3", "s4"):
    raise ValueError("Unknown confirmation kind")
  return ("keyboard, trackpad, Wi-Fi and audio work after " + kind + " without replugging anything; image "
          + image_sha256[:12] + " boot " + boot_id[:8])


def dropin_text(runtime_dir, prepare_sha256):
  """Text of the /run drop-in. ExecStart is reset to stock systemd-sleep; the product dispatcher is bypassed."""
  script = "/" + str(runtime_dir) + "/prepare.py"
  return (
    "# Transient upstream-model test drop-in (prepare.py sha256 " + prepare_sha256 + ").\n"
    "# Sorts after omarchy-t2.conf; /run is gone after any reboot.\n"
    "[Service]\n"
    "ExecStart=\n"
    "ExecStart=/usr/lib/systemd/systemd-sleep hibernate\n"
    "ExecStartPre=\n"
    "ExecStartPre=/usr/bin/python3 -I -B " + script + " pre\n"
    "ExecStopPost=\n"
    "ExecStopPost=/usr/bin/python3 -I -B " + script + " post\n"
  )
