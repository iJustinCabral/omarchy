#!/usr/bin/python3
"""Check source-UKI separation and the retained Bluetooth readiness gate."""

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/build-hibernation-source-uki.py"
spec = importlib.util.spec_from_file_location("hibernation_source_uki", script)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

assert set(source.INITRD_MODULES) == set(source.BASE.MODULES) - {"t2bce_ave"}
assert source.CONFIG.is_file()
assert source.SOURCE_HOOKS.is_dir()
assert source.BASE.CANDIDATE_BLUETOOTH_HELPER.is_file()

config = source.CONFIG.read_text()
assert 'candidate_hook != "omarchy-t2-suspend"' in config
assert "HOOKS+=(omarchy-t2-source-bluetooth)" in config
assert "omarchy-t2-candidate-modules" not in config
for name in source.INITRD_MODULES:
  assert name in config

runtime_hook = source.SOURCE_HOOKS / "hooks/omarchy-t2-source-bluetooth"
install_hook = source.SOURCE_HOOKS / "install/omarchy-t2-source-bluetooth"
for hook in (runtime_hook, install_hook):
  subprocess.run(("bash", "-n", hook), check=True)
assert "OMARCHY_T2_SOURCE_EXPERIMENT_MARKER" in install_hook.read_text()
assert "add_runscript" in install_hook.read_text()

with tempfile.TemporaryDirectory(prefix="t2-source-hook-") as directory:
  root = Path(directory)
  release = "7.2.6-test-t2"
  module = root / "usr/lib/modules" / release / "updates/dkms/hci_bcm4377.ko"
  module.parent.mkdir(parents=True)
  module.write_bytes(b"private source Bluetooth module")
  osrelease = root / "proc/sys/kernel/osrelease"
  osrelease.parent.mkdir(parents=True)
  osrelease.write_text(release + "\n")
  runtime = root / "usr/lib/omarchy-t2-hibernation-candidate"
  runtime.mkdir(parents=True)
  (runtime / "bluetooth-after-wifi.py").write_bytes(source.BASE.CANDIDATE_BLUETOOTH_HELPER.read_bytes())
  (runtime / "source-experiment-id").write_text("dual-source-v1\n")

  subprocess.run(
    (
      "bash", "-c",
      'before=$(umask); source "$1"; run_latehook; [[ $(umask) == "$before" ]]',
      "bash", str(runtime_hook),
    ),
    check=True,
    env={"PATH": "/usr/bin", "OMARCHY_T2_CANDIDATE_ROOT": str(root)},
    capture_output=True,
    text=True,
  )
  state = root / "run/omarchy-t2-hibernation-candidate"
  assert (state / "hci_bcm4377.ko").read_bytes() == module.read_bytes()
  assert (state / "hci_bcm4377.sha256").read_text().strip() == hashlib.sha256(module.read_bytes()).hexdigest()
  assert (state / "source-experiment-id").read_text().strip() == "dual-source-v1"
  assert state.stat().st_mode & 0o777 == 0o700
  for name in ("hci_bcm4377.ko", "hci_bcm4377.sha256", "source-experiment-id"):
    assert (state / name).stat().st_mode & 0o777 == 0o600
  dropin = root / "run/systemd/system/bluetooth-after-wifi.service.d/50-hibernation-candidate.conf"
  assert "bluetooth-after-wifi.py" in dropin.read_text()

print("PASS: source UKI keeps candidate modules in initramfs and gates private Bluetooth")
