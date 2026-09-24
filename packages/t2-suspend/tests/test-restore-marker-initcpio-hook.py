#!/usr/bin/python3
"""Exercise the restore marker hook under mkinitcpio's ash without a PM transition."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


hook = Path(__file__).resolve().parents[1] / "experiments/hibernate-candidate-initcpio/hooks/omarchy-t2-restore-marker"
ash = Path("/usr/lib/initcpio/busybox")
variable = "OmarchyT2RestoreStage-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
prefix = "0123456789abcdef01234567"
srcversion = "3119365A09AED2D4CD65DD6"

script = r'''
. "$1"
msg() { :; }
err() { printf 'ERROR: %s\n' "$*"; }
launch_interactive_shell() {
  [[ $1 == "--exec" ]] || exit 90
  printf 'called\n' > "$OMARCHY_T2_RESTORE_MARKER_ROOT/recovery-shell"
  return 0
}
insmod() {
  [[ ${MOCK_FAIL_INSMOD:-0} == "0" ]] || return 1
  module=$OMARCHY_T2_RESTORE_MARKER_ROOT/sys/module/mba_hibernate_efi_restore_marker
  mkdir -p "$module/parameters"
  printf '%s\n' "$MOCK_SRCVERSION" > "$module/srcversion"
  printf '0\n' > "$module/parameters/stage"
  printf '0\n' > "$module/parameters/arm_prefix"
}
write_restore_arm_prefix() {
  [[ $1 == "0123456789abcdef01234567" ]] || exit 91
  printf '1\n' > "$2"
}
run_hook
printf 'hook_status=%s\n' "$?"
'''


def run(root, *, fail_insmod=False, version=srcversion):
  result = subprocess.run(
    (str(ash), "ash", "-c", script, "ash", str(hook)),
    check=True, capture_output=True, text=True,
    env={
      "PATH": os.environ["PATH"],
      "OMARCHY_T2_RESTORE_MARKER_ROOT": str(root),
      "MOCK_FAIL_INSMOD": "1" if fail_insmod else "0",
      "MOCK_SRCVERSION": version,
    },
  )
  return result.stdout, (root / "recovery-shell").exists()


with tempfile.TemporaryDirectory(prefix="t2-restore-hook-") as temporary:
  root = Path(temporary)
  marker = root / "sys/firmware/efi/efivars" / variable
  marker.parent.mkdir(parents=True)
  directory = root / "usr/lib/omarchy-t2-restore-marker"
  directory.mkdir(parents=True)
  module = directory / "marker.ko"
  module.write_bytes(b"exact synthetic restore marker")
  (directory / "marker.sha256").write_text(hashlib.sha256(module.read_bytes()).hexdigest() + "\n")
  (directory / "marker.srcversion").write_text(srcversion + "\n")

  output, recovery = run(root)
  assert "hook_status=0" in output and not recovery
  assert not (root / "sys/module/mba_hibernate_efi_restore_marker").exists()

  marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\x00")
  output, recovery = run(root)
  assert "hook_status=0" in output and not recovery
  assert (root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix").read_text().strip() == "1"

  marker.write_bytes(marker.read_bytes()[:-1] + b"\x03")
  output, recovery = run(root)
  assert "hook_status=1" in output and recovery
  assert "refusing uninstrumented image resume" in output

  (root / "recovery-shell").unlink()
  marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\x00")
  (directory / "marker.sha256").write_text("0" * 64 + "\n")
  output, recovery = run(root)
  assert "hook_status=1" in output and recovery
  assert "embedded module identity differs" in output

  (root / "recovery-shell").unlink()
  (directory / "marker.sha256").write_text(hashlib.sha256(module.read_bytes()).hexdigest() + "\n")
  output, recovery = run(root, fail_insmod=True)
  assert "hook_status=1" in output and recovery

  (root / "recovery-shell").unlink()
  output, recovery = run(root, version="WRONG")
  assert "hook_status=1" in output and recovery
  assert "loaded module source version differs" in output

print("PASS: mkinitcpio ash hook arms only an exact restore marker and fails closed before resume")
