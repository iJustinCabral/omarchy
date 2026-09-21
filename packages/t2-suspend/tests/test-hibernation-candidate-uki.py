#!/usr/bin/env python3
"""Check the pure safety invariants of the private candidate UKI builder."""

import importlib.util
from pathlib import Path


package = Path(__file__).resolve().parents[1]
builder_path = package / "experiments/build-hibernation-candidate-uki.py"
spec = importlib.util.spec_from_file_location("candidate_uki", builder_path)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

assert set(builder.MODULES) == {
  "brcmfmac",
  "brcmfmac-bca",
  "brcmfmac-cyw",
  "brcmfmac-wcc",
  "hci_bcm4377",
  "t2bce_dma",
  "t2bce_core",
  "t2bce_vhci",
  "t2bce_audio",
  "t2bce_ave",
}
assert set(builder.EARLY_MODULES) == set(builder.MODULES) - {"t2bce_ave"}
assert builder.FORBIDDEN_INITRD_FILES == (
  "etc/modprobe.d/t2-bluetooth-order.conf",
)

cmdline = "cryptdevice=PARTUUID=test:root root=/dev/mapper/root rootflags=subvol=@ rw rootfstype=btrfs resume=/dev/mapper/root resume_offset=42 cryptkey=rootfs:/key quiet"
assert builder.cmdline_values(cmdline) == {
  "cryptdevice": "PARTUUID=test:root",
  "root": "/dev/mapper/root",
  "rootflags": "subvol=@",
  "rw": True,
  "rootfstype": "btrfs",
  "resume": "/dev/mapper/root",
  "resume_offset": "42",
  "cryptkey": "rootfs:/key",
}
assert builder.under(Path("/boot/EFI/Linux/candidate.efi"), Path("/boot"))
assert not builder.under(Path("/tmp/candidate.efi"), Path("/boot"))

config = (package / "experiments/hibernate-candidate-mkinitcpio.conf").read_text()
assert '$candidate_hook != "omarchy-t2-suspend"' in config
assert '$candidate_hook != "modconf"' in config
assert 'candidate_bluetooth_blacklist=/etc/modprobe.d/t2-bluetooth-order.conf' in config
assert "candidate_modprobe_conf != $candidate_bluetooth_blacklist" in config
for name in builder.EARLY_MODULES:
  assert name in config

print("PASS: candidate UKI builder keeps complete module and encrypted-root safety gates")
