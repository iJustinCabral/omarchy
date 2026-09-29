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
witness_guid = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"


def witness(root, stage):
  return root / "sys/firmware/efi/efivars" / f"OmarchyT2RestoreHook{stage}{prefix}-{witness_guid}"


def clear_witnesses(root):
  for stage in ("Entered", "Armed"):
    witness(root, stage).unlink(missing_ok=True)

script = r'''
. "$2"
. "$1"
getarg() {
  if [[ $1 == "quiet" && $MOCK_QUIET == "1" ]]; then
    printf 'y\n'
  fi
}
err() { printf 'ERROR: %s\n' "$*"; }
launch_interactive_shell() {
  [[ $1 == "--exec" ]] || exit 90
  printf 'shell\n' >> "$OMARCHY_T2_RESTORE_MARKER_ROOT/recovery-order"
  printf 'called\n' > "$OMARCHY_T2_RESTORE_MARKER_ROOT/recovery-shell"
  return 0
}
plymouth() {
  [[ $1 == "quit" ]] || exit 92
  printf 'plymouth\n' >> "$OMARCHY_T2_RESTORE_MARKER_ROOT/recovery-order"
}
insmod() {
  [[ ${MOCK_FAIL_INSMOD:-0} == "0" ]] || return 1
  printf 'called\n' >> "$OMARCHY_T2_RESTORE_MARKER_ROOT/module-insertions"
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


def run(root, *, fail_insmod=False, version=srcversion, quiet=False):
  result = subprocess.run(
    (str(ash), "ash", "-c", script, "ash", str(hook), "/usr/lib/initcpio/init_functions"),
    check=True, capture_output=True, text=True,
    env={
      "PATH": os.environ["PATH"],
      "OMARCHY_T2_RESTORE_MARKER_ROOT": str(root),
      "MOCK_FAIL_INSMOD": "1" if fail_insmod else "0",
      "MOCK_SRCVERSION": version,
      "MOCK_QUIET": "1" if quiet else "0",
    },
  )
  if quiet:
    assert result.stderr == "", "Quiet BusyBox hook emitted a shell error: " + result.stderr
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
  assert witness(root, "Entered").read_bytes() == b"\x07\x00\x00\x00MBRH" + prefix.encode() + b"\x01"
  assert witness(root, "Armed").read_bytes() == b"\x07\x00\x00\x00MBRH" + prefix.encode() + b"\x02"

  # Real mkinitcpio msg() returns 1 when quiet suppresses its output.
  # That must not turn a successfully armed marker into a recovery shell.
  clear_witnesses(root)
  output, recovery = run(root, quiet=True)
  assert "hook_status=0" in output and not recovery
  assert "exact cold-restore marker armed" not in output
  assert witness(root, "Entered").exists() and witness(root, "Armed").exists()

  output, recovery = run(root)
  assert "hook_status=1" in output and recovery
  assert "stale Entered witness" in output
  assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
  (root / "recovery-shell").unlink()
  (root / "recovery-order").unlink()
  clear_witnesses(root)
  marker.write_bytes(marker.read_bytes()[:-1] + b"\x03")
  output, recovery = run(root)
  assert "hook_status=1" in output and recovery
  assert "refusing uninstrumented image resume" in output
  assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
  assert not witness(root, "Entered").exists() and not witness(root, "Armed").exists()

  (root / "recovery-shell").unlink()
  (root / "recovery-order").unlink()
  marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\x00")
  (directory / "marker.sha256").write_text("0" * 64 + "\n")
  output, recovery = run(root)
  assert "hook_status=1" in output and recovery
  assert "embedded module identity differs" in output
  assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
  assert witness(root, "Entered").exists() and not witness(root, "Armed").exists()

  (root / "recovery-shell").unlink()
  (root / "recovery-order").unlink()
  clear_witnesses(root)
  (directory / "marker.sha256").write_text(hashlib.sha256(module.read_bytes()).hexdigest() + "\n")
  output, recovery = run(root, fail_insmod=True)
  assert "hook_status=1" in output and recovery
  assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
  assert witness(root, "Entered").exists() and not witness(root, "Armed").exists()

  (root / "recovery-shell").unlink()
  (root / "recovery-order").unlink()
  clear_witnesses(root)
  output, recovery = run(root, version="WRONG")
  assert "hook_status=1" in output and recovery
  assert "loaded module source version differs" in output
  assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
  assert witness(root, "Entered").exists() and not witness(root, "Armed").exists()

  (root / "recovery-shell").unlink()
  (root / "recovery-order").unlink()
  clear_witnesses(root)
  version_file = directory / "marker.version"
  version_file.write_text("v2\n")
  v2_marker = marker.parent / ("OmarchyT2RestoreStageV2-" + witness_guid)
  v2_marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\x00")
  output, recovery = run(root, quiet=True)
  assert "hook_status=0" in output and not recovery
  assert witness(root, "Entered").exists() and witness(root, "Armed").exists()
  assert marker.read_bytes()[-1] == 0

  # BusyBox ash must reject nonexact payload lengths before inserting the
  # marker module or creating witnesses. Bash's (( ... )) command is not
  # supported by ash: it emits `42: not found` even for the valid payload,
  # and can accept trailing bytes when the independent prefix/stage matches.
  valid = v2_marker.read_bytes()
  for malformed in (valid[:-1], valid + b"\xff", valid + b"\0" * 100):
    clear_witnesses(root)
    insertions = (root / "module-insertions").read_bytes()
    v2_marker.write_bytes(malformed)
    output, recovery = run(root, quiet=True)
    assert "hook_status=1" in output and recovery
    assert "EFI stage 0 is malformed; preserving it" in output
    assert v2_marker.read_bytes() == malformed
    assert (root / "module-insertions").read_bytes() == insertions
    assert not witness(root, "Entered").exists() and not witness(root, "Armed").exists()
    assert (root / "recovery-order").read_text().splitlines() == ["plymouth", "shell"]
    (root / "recovery-shell").unlink()
    (root / "recovery-order").unlink()

print("PASS: mkinitcpio ash hook arms only an exact restore marker and fails closed before resume")
