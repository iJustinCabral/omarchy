#!/usr/bin/python3
"""Clear only explicitly selected, hash-pinned archived terminal slots on stock.

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
RESTORE_STAGE = 0
PRESERVED_LIVE_PREFIXES = (
  "OmarchyT2RestoreHookEntered", "OmarchyT2RestoreHookArmed", "OmarchyT2ColdPreCpuReturned",
  "OmarchyT2ColdPreSyscoreReturned",
)
RETURN_BOOTS = {
  "529d919f498f44aee33c92f63604a85fd6e5c447e8e84740df6c340feb074f32": "aec7b794-2684-4277-b6ff-2050493f3932",
  "538d486ba4a44f7e41227526e28e9d545b0b705a226d4d0c0fe8f2eae65ff66a": "911e153f-ce56-4baa-97b2-2d5e7d93f6bf",
}
NO_CURRENT_MODULES = (
  "mba_hibernate_efi_postwrite_marker", "mba_hibernate_efi_restore_marker",
  "mba_hibernate_cold_pre_cpu", "mba_hibernate_cold_pre_syscore", "mba_hibernate_cold_pre_arch",
)
TERMINALS = {
  VECTOR: (SOURCE_BOOT, ARCHIVE, dict(PINS), GUARD_SHA, ATTEMPT_SHA, 0),
  "cf01e856dcab2e454332b80c96f9dd04c0698e3e8b214fe02b0b549a31623418": (
    "32072873-3fc3-499d-843d-c1e115e3bef3",
    Path("var/lib/omarchy-t2-postwrite-marker/archive-v3-cf01e856dcab2e45"),
    {
      SOURCE_VAR: "c0ad385464abca5088229e8a097e43bd3294c705f7e03932a7a69582ddd36c02",
      RESTORE_VAR: "b434034f45daf745710a8a4de44d11c9641856de2754b088d33cbd170cea643a",
      "OmarchyT2RestoreHookEnteredcf01e856dcab2e454332b80c-" + BACKEND.RESTORE_HOOK_GUID: "cc8a9f216630bd4fb7152e0dfc030db341424f701e6c81bf839143fb92f33caa",
      "OmarchyT2RestoreHookArmedcf01e856dcab2e454332b80c-" + BACKEND.RESTORE_HOOK_GUID: "848f09a42a7616fab904ff14d9278852b93baa21a4ac8d546df56457e66594ef",
      "receipt.json": "ec085ee988a39b7af28ef3e32dcca1c9510b549132ac11735185bf4b8a528bb4",
      "recovery-acceptance-v3.json": "7cd869e34224d9c0ae7863b73b723a1b98e6a1cd6e0162978580afd4e40d9ee9",
    },
    "ed6a4ae4b2c9bda29f8de46b7011878a8e2c706ac775456a794b4de6fe3ec329",
    "ff7d51d0d70e9a7a4752b6241bdb0d71603e77b6257e7c8514a06e1fb7fbf12e",
    7,
  ),
  "8309257dfe8c39719e890bebc8e52587b8407d08c47b97952185c6d7ebd009d6": (
    "cdf79ca2-cd83-49fb-b679-6d1b8e8d8af5",
    Path("var/lib/omarchy-t2-postwrite-marker/archive-v3-8309257dfe8c3971"),
    {
      SOURCE_VAR: "647405b735e1d081479db5dda820a383bfdcdc58504766b91d4c102d8b70b0f3",
      RESTORE_VAR: "6b89dfa08d1e4e583d81caf561e1776bc162e0830f712642694fb03b0ccf2b58",
      "OmarchyT2RestoreHookEntered8309257dfe8c39719e890beb-" + BACKEND.RESTORE_HOOK_GUID: "096648b84f76a8f6bdb6a9195d82f71a1175fd8f540659d95b18a283e0921bda",
      "OmarchyT2RestoreHookArmed8309257dfe8c39719e890beb-" + BACKEND.RESTORE_HOOK_GUID: "46bbf4e5c12c5a7827dad6b0d34e215f6f336461678f32253b5ca04984ad22d3",
      "receipt.json": "c41f2f8c4f74016b23675aa6f29a6a6cb52812b776ff795d10ca39d1c85dfc5e",
      "recovery-acceptance-v3.json": "d97c34c9bacd25909c3c84a655729b4a9e11bb09434f4b946a30157d388ea500",
    },
    "9dbc1b06708097b5ac3575f6952c0716808080eb7b9863bda9ec0f412db5c460",
    "69578178f3821d513e6e639209649ded15d48e992a7f5cc7e04427d845a3a92e",
    7,
  ),
  "529d919f498f44aee33c92f63604a85fd6e5c447e8e84740df6c340feb074f32": (
    "ef4c6f48-9b79-4560-978f-b523e5545f0e",
    Path("var/lib/omarchy-t2-postwrite-marker/archive-v3-529d919f498f44ae"),
    {
      SOURCE_VAR: "de7593194d4007e9fd04bfb32ec3a58917346765488a3773fadd1a22cd86fc4a",
      RESTORE_VAR: "8ddf71ff4f8aa05f82e74ff69de4dcea1b216ab5f32fdafbe9c251b5656a232b",
      "OmarchyT2RestoreHookEntered529d919f498f44aee33c92f6-" + BACKEND.RESTORE_HOOK_GUID: "6261d5c5181a5ba5ea9bccfa730b84a46bff4c58bc0a68be510520fea3fdd19b",
      "OmarchyT2RestoreHookArmed529d919f498f44aee33c92f6-" + BACKEND.RESTORE_HOOK_GUID: "756ea4a1698d30b366923d19f74c9d4c43edaa6356881167587ba9905013fefa",
      "OmarchyT2ColdPreCpuReturned529d919f498f44aee33c92f6-" + BACKEND.RESTORE_HOOK_GUID: "f210dcbb855fd837e92bc64e0af11c6d26902a4ff3c7b7167ec9306196c152e0",
      "receipt.json": "fb7a8f217cfdc12bd029392f42b47acaa7ead0c8d8d5c158a96e01ca005741e9",
      "recovery-acceptance-v3.json": "b63cd291c36c15d15f077ed966ca28517d64b9a60cc5a39627e3085f02327e8b",
      "s4-attempted": "cf50fbdb69e2a0ed26adda22e2c65695953d5b9609ecd57137d5aee38de3aee5",
      "attempt.json": "25505b8e548c79af9081d8908e3d215714c64d78fa07b21ec9e2adf4872d94fa",
      "postwrite-efi-identity.json": "6680c86a560ed609ab390736da123e9604370bbdaf2baf08e2f9064aa3eca7c3",
      "restore-efi-identity.json": "0e99e8140ef8ccd75d8d860b2fed12c3d400bc046a71e3d9fb872bb7d626ac6e",
    },
    "cf50fbdb69e2a0ed26adda22e2c65695953d5b9609ecd57137d5aee38de3aee5",
    "25505b8e548c79af9081d8908e3d215714c64d78fa07b21ec9e2adf4872d94fa",
    7,
  ),
  "538d486ba4a44f7e41227526e28e9d545b0b705a226d4d0c0fe8f2eae65ff66a": (
    "520e5b24-0ca7-4663-ad50-c151404ef229",
    Path("var/lib/omarchy-t2-postwrite-marker/archive-v3-538d486ba4a44f7e"),
    {
      SOURCE_VAR: "4efa1b5a748593affc4fa7d937249f714b74da6dfefd881f1b185948a40f479c",
      RESTORE_VAR: "4f1374f64e6e25671a6aca076c91b78ed678770503d97d57f4ed4ded2fa28fb2",
      "OmarchyT2RestoreHookEntered538d486ba4a44f7e41227526-" + BACKEND.RESTORE_HOOK_GUID: "d36be73fbdc96431604d9784017835eddc6d05a4f89b553f0808cadaf72ef10e",
      "OmarchyT2RestoreHookArmed538d486ba4a44f7e41227526-" + BACKEND.RESTORE_HOOK_GUID: "2304f465258b359d9b748160bb43c283ee174e10d5a8406b3ea70386038db8a9",
      "OmarchyT2ColdPreSyscoreReturned538d486ba4a44f7e41227526-" + BACKEND.RESTORE_HOOK_GUID: "3dbc954c07ac66843d6bca5a854b84fab6a875ffa219b19dabd2dda2fdba340b",
      "receipt.json": "dcd0f4a9e1373d7bf749ece51ed98b2249da609f1f2768a29f92873e0bc12b0d",
      "recovery-acceptance-v3.json": "2476397389e41a1a1be2e58ed361f73856ce223495468cb33469c326a91153bb",
      "s4-attempted": "2211c808d99f2c75716e1652d031f15439030b48816061d29cfa54fc00bbb535",
      "attempt.json": "906c97dbe3b52908fb5a7cfe4f272ea80e96cfa3295c8538d7c0fe9731cf8e96",
      "postwrite-efi-identity.json": "aa934444da64a816d800664f20dd1b2d0ba773cd88bb7727cfc316561eb52170",
      "restore-efi-identity.json": "db0e0ec7c2d306689ad29ff5334dac843449db89ae2dfd96fde8b6867403dca5",
    },
    "2211c808d99f2c75716e1652d031f15439030b48816061d29cfa54fc00bbb535",
    "906c97dbe3b52908fb5a7cfe4f272ea80e96cfa3295c8538d7c0fe9731cf8e96",
    7,
  ),
}


def select_terminal(vector):
  global VECTOR, SOURCE_BOOT, ARCHIVE, PINS, GUARD_SHA, ATTEMPT_SHA, RESTORE_STAGE
  global GUARD, ATTEMPT, ENTERED, ARMED
  if vector not in TERMINALS:
    raise ValueError("Unknown terminal vector; no caller-supplied evidence pins allowed")
  VECTOR = vector
  SOURCE_BOOT, ARCHIVE, pins, GUARD_SHA, ATTEMPT_SHA, RESTORE_STAGE = TERMINALS[vector]
  PINS = dict(pins)
  GUARD = PAIR.STATE / "s4-vectors" / VECTOR / "s4-attempted"
  ATTEMPT = GUARD.parent / "attempts" / SOURCE_BOOT / "attempt.json"
  ENTERED = "OmarchyT2RestoreHookEntered" + VECTOR[:24] + "-" + BACKEND.RESTORE_HOOK_GUID
  ARMED = "OmarchyT2RestoreHookArmed" + VECTOR[:24] + "-" + BACKEND.RESTORE_HOOK_GUID


def preserved_live_pins():
  # Only internally pinned, vector-bound witness names qualify. No caller can
  # extend the preservation set or provide alternative live evidence hashes.
  prefixes = tuple(prefix + VECTOR[:24] + "-" for prefix in PRESERVED_LIVE_PREFIXES)
  return {name: expected for name, expected in PINS.items() if name.startswith(prefixes)}


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
  for name in NO_CURRENT_MODULES:
    if path(root, Path("sys/module") / name).exists():
      raise ValueError("Marker or cold diagnostic module is still loaded")
  if Path(root) == Path("/"):
    if HEADER.read_header(Path("/dev/mapper/root"), 1923214)["marker"] != "normal-swap-signature":
      raise ValueError("Pending or unknown swap signature; preserve markers")
    if subprocess.check_output(["systemctl", "--failed", "--no-legend", "--plain"], text=True).strip():
      raise ValueError("Failed systemd units")
  return current


def validate(root, stock_validator=current_stock):
  current = stock_validator(root)
  if VECTOR in RETURN_BOOTS and current != RETURN_BOOTS[VECTOR]:
    raise ValueError("Cleanup requires the pinned physical stock return boot")
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
  for name, expected in preserved_live_pins().items():
    exact(root, Path("sys/firmware/efi/efivars") / name, expected)
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
  parser.add_argument("--terminal-vector", choices=tuple(TERMINALS), default=VECTOR)
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    select_terminal(args.terminal_vector)
    result = execute(Path("/")) if args.execute else validate(Path("/"))
  except (OSError, ValueError) as error:
    raise SystemExit("Terminal marker cleanup refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
