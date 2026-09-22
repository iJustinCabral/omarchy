#!/usr/bin/env python3
"""Check the pure safety invariants of the private candidate UKI builder."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile


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
assert builder.REQUIRED_INITRD_FILES == (
  "etc/modprobe.d/t2-bluetooth-order.conf",
  "hooks/omarchy-t2-candidate-bluetooth",
  "usr/bin/find",
  "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py",
)
assert builder.CANDIDATE_HOOKS.is_dir()
assert builder.CANDIDATE_BLUETOOTH_HELPER.is_file()
assert builder.CANDIDATE_BLUETOOTH_HELPER.stat().st_mode & 0o111
install_hook = builder.CANDIDATE_HOOKS / "install/omarchy-t2-candidate-bluetooth"
assert "add_binary find || exit 1" in install_hook.read_text()

runtime_hook = builder.CANDIDATE_HOOKS / "hooks/omarchy-t2-candidate-bluetooth"
with tempfile.TemporaryDirectory(prefix="t2-candidate-hook-") as directory:
  root = Path(directory)
  release = "7.2.6-test-t2"
  osrelease = root / "proc/sys/kernel/osrelease"
  osrelease.parent.mkdir(parents=True)
  osrelease.write_text(release + "\n")
  module = root / "usr/lib/modules" / release / "updates/dkms/hci_bcm4377.ko"
  module.parent.mkdir(parents=True)
  module.write_bytes(b"candidate hci module")
  helper = root / "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py"
  helper.parent.mkdir(parents=True)
  helper.write_bytes(builder.CANDIDATE_BLUETOOTH_HELPER.read_bytes())
  subprocess.run(
    [
      "bash",
      "-c",
      'before=$(umask); source "$1"; run_latehook; [[ $(umask) == "$before" ]]',
      "bash",
      str(runtime_hook),
    ],
    check=True,
    env={"PATH": "/usr/bin", "OMARCHY_T2_CANDIDATE_ROOT": str(root)},
    capture_output=True,
    text=True,
  )
  state = root / "run/omarchy-t2-hibernation-candidate"
  assert (state / "hci_bcm4377.ko").read_bytes() == module.read_bytes()
  assert (state / "bluetooth-after-wifi.py").read_bytes() == helper.read_bytes()
  assert (state / "hci_bcm4377.sha256").read_text().strip() == builder.digest(module)
  dropin = root / "run/systemd/system/bluetooth-after-wifi.service.d/50-hibernation-candidate.conf"
  assert dropin.read_text() == (
    "[Service]\n"
    "ExecStart=\n"
    "ExecStart=/usr/bin/python3 /run/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py\n"
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
assert '$candidate_hook != "modconf"' not in config
assert "HOOKS+=(omarchy-t2-candidate-bluetooth)" in config
for name in builder.EARLY_MODULES:
  assert name in config

print("PASS: candidate UKI builder keeps complete module and encrypted-root safety gates")
