#!/usr/bin/env python3
"""Check the pure safety invariants of the private candidate UKI builder."""

import importlib.util
import json
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
assert set(builder.PRE_RESTORE_EXCLUDED_MODULES) == set(builder.MODULES)
assert builder.validate_experiment_id("shutdown-cold-v11") == "shutdown-cold-v11"
assert builder.validate_experiment_id(None) is None
for invalid in ("", "Shutdown-v11", "../shutdown", "a" * 65):
  try:
    builder.validate_experiment_id(invalid)
    raise AssertionError("builder accepted an invalid experiment ID")
  except ValueError:
    pass

with tempfile.TemporaryDirectory(prefix="t2-candidate-experiment-id-") as directory:
  root = Path(directory)
  source = root / "source"
  source.mkdir()
  expected = {}
  for name, relative in builder.MODULES.items():
    module = source / relative
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_bytes(name.encode())
    expected[name] = {"sha256": builder.digest(module), "srcversion": "test-" + name}
  payload, _modules = builder.prepare_payload(root, source, "7.2.6-test-t2", expected, "shutdown-cold-v11")
  manifest = json.loads((payload / "manifest.json").read_text())
  assert manifest["experiment_id"] == "shutdown-cold-v11"
  assert manifest["policy"] == "post-switch-root-only"
assert builder.REQUIRED_INITRD_FILES == (
  "hooks/omarchy-t2-candidate-modules",
  "usr/lib/omarchy-t2-hibernation-candidate/load-modules.py",
  "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py",
  "usr/lib/omarchy-t2-hibernation-candidate/payload/manifest.json",
)
assert builder.CANDIDATE_HOOKS.is_dir()
assert builder.CANDIDATE_MODULE_HELPER.is_file()
assert builder.CANDIDATE_MODULE_HELPER.stat().st_mode & 0o111
assert builder.CANDIDATE_BLUETOOTH_HELPER.is_file()
assert builder.CANDIDATE_BLUETOOTH_HELPER.stat().st_mode & 0o111
builder_source = builder_path.read_text()
assert 'run(("lsinitcpio", "--early", "--extract", initrd), cwd=extracted)' in builder_source
install_hook = builder.CANDIDATE_HOOKS / "install/omarchy-t2-candidate-modules"
assert "OMARCHY_T2_CANDIDATE_PAYLOAD" in install_hook.read_text()

runtime_hook = builder.CANDIDATE_HOOKS / "hooks/omarchy-t2-candidate-modules"
with tempfile.TemporaryDirectory(prefix="t2-candidate-hook-") as directory:
  root = Path(directory)
  release = "7.2.6-test-t2"
  osrelease = root / "proc/sys/kernel/osrelease"
  osrelease.parent.mkdir(parents=True)
  osrelease.write_text(release + "\n")
  source = root / "usr/lib/omarchy-t2-hibernation-candidate"
  payload = source / "payload"
  payload.mkdir(parents=True)
  for name in builder.MODULES:
    (payload / (name + ".ko")).write_bytes(("candidate " + name).encode())
  (payload / "manifest.json").write_text('{"policy":"post-switch-root-only"}\n')
  (payload / "hci_bcm4377.sha256").write_text("candidate digest\n")
  (source / "load-modules.py").write_bytes(builder.CANDIDATE_MODULE_HELPER.read_bytes())
  (source / "bluetooth-after-wifi.py").write_bytes(builder.CANDIDATE_BLUETOOTH_HELPER.read_bytes())
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
  for name in builder.MODULES:
    assert (state / (name + ".ko")).read_bytes() == (payload / (name + ".ko")).read_bytes()
    assert (state / (name + ".ko")).stat().st_mode & 0o777 == 0o600
  assert (state / "manifest.json").read_bytes() == (payload / "manifest.json").read_bytes()
  assert (state / "hci_bcm4377.sha256").read_bytes() == (payload / "hci_bcm4377.sha256").read_bytes()
  assert (state / "load-modules.py").read_bytes() == builder.CANDIDATE_MODULE_HELPER.read_bytes()
  assert (state / "bluetooth-after-wifi.py").read_bytes() == builder.CANDIDATE_BLUETOOTH_HELPER.read_bytes()
  dropin = root / "run/systemd/system/bluetooth-after-wifi.service.d/50-hibernation-candidate.conf"
  unit = root / "run/systemd/system/omarchy-t2-hibernation-candidate-modules.service"
  wanted = root / "run/systemd/system/sysinit.target.wants/omarchy-t2-hibernation-candidate-modules.service"
  assert state.stat().st_mode & 0o777 == 0o700
  assert (root / "run/systemd").stat().st_mode & 0o777 == 0o755
  assert (root / "run/systemd/system").stat().st_mode & 0o777 == 0o755
  assert dropin.parent.stat().st_mode & 0o777 == 0o755
  assert unit.is_file()
  assert "Before=systemd-modules-load.service systemd-udev-trigger.service" in unit.read_text()
  assert wanted.is_symlink()
  assert wanted.readlink() == Path("../omarchy-t2-hibernation-candidate-modules.service")
  assert dropin.read_text() == (
    "[Unit]\n"
    "Requires=omarchy-t2-hibernation-candidate-modules.service\n"
    "After=omarchy-t2-hibernation-candidate-modules.service\n"
    "\n"
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
assert "HOOKS+=(omarchy-t2-candidate-modules)" in config
assert "MODULES+=(" not in config
for name in ("brcmfmac", "hci_bcm4377", "t2bce_core", "t2bce_vhci"):
  assert name in config

print("PASS: candidate UKI keeps T2 modules out of pre-restore initramfs and stages exact ordinary-boot payload")
