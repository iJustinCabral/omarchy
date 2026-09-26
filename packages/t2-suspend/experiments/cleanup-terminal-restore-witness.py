#!/usr/bin/python3
"""Clear only hash-pinned, archived c285fe83 terminal marker slots on stock.

Consumed PM guards, attempts, archived bytes and vector-bound hook witnesses
are never removed. This does not authorize replaying the terminal vector.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess


HERE = Path(__file__).resolve().parent


def import_file(name, filename):
  spec = importlib.util.spec_from_file_location(name, HERE / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


PAIR = import_file("terminal_pair", "stage-hibernation-uki-pair.py")
SOURCE = import_file("terminal_source", "verify-hibernation-uki-pair-source.py")
HEADER = import_file("terminal_header", "audit-hibernation-swap-header.py")
BACKEND = import_file("terminal_backend", "hibernate-efi-postwrite-marker/s4_backend.py")
VECTOR = "c285fe8373277ec968f1026e7557807b05bdb78484a3982d0c261df76d32f677"
SOURCE_BOOT = "272af8a5-11a9-4ac5-87b7-77de037cc668"
ARCHIVE = Path("var/lib/omarchy-t2-postwrite-marker/archive-v3-c285fe8373277ec9")
GUARD = PAIR.STATE / "s4-vectors" / VECTOR / "s4-attempted"
ATTEMPT = GUARD.parent / "attempts" / SOURCE_BOOT / "attempt.json"
SOURCE_VAR = BACKEND.V3_VARIABLE.name
RESTORE_VAR = BACKEND.V2_RESTORE_VARIABLE.name
ENTERED = "OmarchyT2RestoreHookEntered" + VECTOR[:24] + "-" + BACKEND.RESTORE_HOOK_GUID
ARMED = "OmarchyT2RestoreHookArmed" + VECTOR[:24] + "-" + BACKEND.RESTORE_HOOK_GUID
PINS = {
  SOURCE_VAR: "745bf014058379caa3e28a3a05701417e5947c81dda8bb19ed6afdade3c5678a",
  RESTORE_VAR: "31d25d453ac7112451ddf0bc0a2fa7f598dd35d4d87fa0ed7c9b1ceb1376d3ab",
  ENTERED: "60a0e3c86c564d57b213289b541ab5951c147e15b7f1ee84d80af97d87edd60e",
  ARMED: "46c8d46f850a3130c84d6a504fd03ed94f464a9d862b9667d214bb369c70dae7",
  "receipt.json": "f00a65b9df63d5554153417254dd9623a278711c6dd943ae78a414055c5b203c",
  "recovery-acceptance-v3.json": "4ac77cbce8dd0e198461848f351948c93f0635af463a86900d3d2f782b676736",
}
GUARD_SHA = "0750dd47817f3f753fe0756c5783174b9fefe9795924170684f93710e841c3bf"
ATTEMPT_SHA = "cfe5b2f4da5bd5292fa199881fbe302edad273da0f82ab40591fa8332cf34a81"
PRODUCTION_SHA = "18491469d046bd5805a10c7a80e47c1e9ae2af1879a3ce78b1e9c14826c789bc"
TARGETS = {
  SOURCE_VAR: BACKEND.V3_VARIABLE,
  RESTORE_VAR: BACKEND.V2_RESTORE_VARIABLE,
  "recovery-acceptance-v3.json": BACKEND.V3_ACCEPTANCE,
}


def path(root, relative):
  result = Path(root)
  for part in relative.parts:
    result /= part
    if result.is_symlink():
      raise ValueError("Symlink in terminal evidence path: " + str(result))
  return result


def read(root, relative, private=False):
  result = path(root, relative)
  metadata = result.stat()
  owner = 0 if Path(root) == Path("/") else os.geteuid()
  if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner or
      (private and stat.S_IMODE(metadata.st_mode) != 0o600)):
    raise ValueError("Unsafe terminal evidence: " + str(result))
  return result.read_bytes()


def exact(root, relative, expected, private=False):
  value = read(root, relative, private)
  if hashlib.sha256(value).hexdigest() != expected:
    raise ValueError("Terminal evidence hash changed: " + str(relative))
  return value


def current_stock(root):
  if PAIR.selected_entry(root) != "Omarchy.linux-t2":
    raise ValueError("Cleanup requires selected stock")
  SOURCE.verify_primary_root(root)
  if (read(root, Path("proc/sys/kernel/osrelease")).strip() != b"7.2.6-arch2-Watanare-T2-2-t2" or
      read(root, Path("sys/devices/virtual/dmi/id/product_name")).strip() != b"MacBookAir9,1"):
    raise ValueError("Running kernel or hardware changed")
  current = PAIR.current_boot_id(root)
  if current == SOURCE_BOOT:
    raise ValueError("Cleanup requires a distinct return boot")
  for relative in (PAIR.SINGLE.ONESHOT, PAIR.SINGLE.DEFAULT):
    if path(root, relative).exists():
      raise ValueError("EFI boot override remains")
  exact(root, Path("boot/EFI/Linux/omarchy_linux-t2.efi"), PRODUCTION_SHA)
  for name, selected in (("pm_test", "none"), ("disk", "platform")):
    if "[" + selected + "]" not in read(root, Path("sys/power") / name).decode():
      raise ValueError("PM baseline differs")
  if read(root, Path("sys/power/pm_trace")).strip() != b"0":
    raise ValueError("PM tracing enabled")
  if (read(root, Path("sys/power/resume")).strip() != b"253:0" or
      read(root, Path("sys/power/resume_offset")).strip() != b"1923214"):
    raise ValueError("Resume target changed")
  for name in ("mba_hibernate_efi_postwrite_marker", "mba_hibernate_efi_restore_marker"):
    if path(root, Path("sys/module") / name).exists():
      raise ValueError("Marker module is still loaded")
  if Path(root) == Path("/"):
    if HEADER.read_header(Path("/dev/mapper/root"), 1923214)["marker"] != "normal-swap-signature":
      raise ValueError("Pending or unknown swap signature; preserve markers")
    if subprocess.check_output(["systemctl", "--failed", "--no-legend", "--plain"], text=True).strip():
      raise ValueError("Failed systemd units")
  return current


def validate(root, stock_validator=current_stock):
  current = stock_validator(root)
  archive = path(root, ARCHIVE)
  owner = 0 if Path(root) == Path("/") else os.geteuid()
  if archive.stat().st_uid != owner or stat.S_IMODE(archive.stat().st_mode) != 0o700:
    raise ValueError("Unsafe terminal archive")
  for name, expected in PINS.items():
    exact(root, ARCHIVE / name, expected, True)
  if exact(root, GUARD, GUARD_SHA, True).strip().decode() != SOURCE_BOOT:
    raise ValueError("Terminal guard names another source boot")
  attempt = json.loads(exact(root, ATTEMPT, ATTEMPT_SHA, True))
  if (attempt.get("transition_vector") != VECTOR or attempt.get("boot_id") != SOURCE_BOOT or
      attempt.get("state") != "transition-armed" or attempt.get("real_s4_attempted") is not True):
    raise ValueError("Not the pinned terminal S4 attempt")
  for name in (ENTERED, ARMED):
    exact(root, Path("sys/firmware/efi/efivars") / name, PINS[name])
  record = {"kind": "archived-terminal-marker-slot-clear-v1", "vector": VECTOR,
            "return_boot_id": current, "archive_sha256": PINS,
            "guard_sha256": GUARD_SHA, "attempt_sha256": ATTEMPT_SHA}
  intent = path(root, ARCHIVE / "slot-clear-intent.json")
  if intent.exists() and json.loads(read(root, ARCHIVE / intent.name, True)) != record:
    raise ValueError("Cleanup intent differs from current boot/evidence")
  completion = path(root, ARCHIVE / "slot-clear-complete.json")
  if completion.exists():
    expected = {**record, "slots_cleared": True, "guards_and_witnesses_preserved": True}
    if not intent.exists() or json.loads(read(root, ARCHIVE / completion.name, True)) != expected:
      raise ValueError("Cleanup completion differs or has no intent")
    if any(path(root, relative).exists() for relative in TARGETS.values()):
      raise ValueError("Marker slot reappeared after completed cleanup")
  for name, relative in TARGETS.items():
    target = path(root, relative)
    if target.exists():
      exact(root, relative, PINS[name], name.endswith(".json"))
    elif not intent.exists():
      raise ValueError("Marker slot missing before durable clear intent")
  return record


def execute(root, stock_validator=current_stock, remover=None):
  record = validate(root, stock_validator)
  intent = path(root, ARCHIVE / "slot-clear-intent.json")
  if not intent.exists():
    BACKEND.atomic_new_json(intent, record)
  for name, relative in TARGETS.items():
    target = path(root, relative)
    if target.exists():
      exact(root, relative, PINS[name], name.endswith(".json"))
      if remover:
        remover(target)
      else:
        if relative == BACKEND.V3_VARIABLE or relative == BACKEND.V2_RESTORE_VARIABLE:
          subprocess.run(["chattr", "-i", str(target)], check=True, timeout=20)
        target.unlink()
      if target.exists():
        raise ValueError("Terminal slot remained after removal")
  validate(root, stock_validator)
  result = {**record, "slots_cleared": True, "guards_and_witnesses_preserved": True}
  completion = path(root, ARCHIVE / "slot-clear-complete.json")
  if completion.exists():
    if json.loads(read(root, ARCHIVE / completion.name, True)) != result:
      raise ValueError("Cleanup completion differs")
  else:
    BACKEND.atomic_new_json(completion, result)
  os.sync()
  return result


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  modes = parser.add_mutually_exclusive_group(required=True)
  modes.add_argument("--validate-only", action="store_true")
  modes.add_argument("--execute", action="store_true")
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    result = execute(Path("/")) if args.execute else validate(Path("/"))
  except (OSError, ValueError) as error:
    raise SystemExit("Terminal marker cleanup refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
