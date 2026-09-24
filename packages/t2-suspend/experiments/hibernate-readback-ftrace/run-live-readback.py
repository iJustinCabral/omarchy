#!/usr/bin/python3
"""One-use stock-kernel image-I/O diagnostic; not S4 or a hibernation fix."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess


HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent


def import_file(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


COMMON = import_file("t2_live_readback_common", EXPERIMENTS / "hibernate-efi-ftrace-marker/persistence_probe.py")
MARKER = import_file("t2_live_readback_marker", EXPERIMENTS / "hibernate-efi-stage-marker/marker.py")
HEADER = import_file("t2_live_readback_header", EXPERIMENTS / "audit-hibernation-swap-header.py")

KIND = "stock-separate-swap-readback-abort-v1"
STATE = Path("/var/lib/omarchy-t2-readback-boundary")
SWAP_FILE = Path("/swap/mba-readback-one-shot.swap")
STOCK_SWAP_FILE = Path("/swap/swapfile")
DEVICE = Path("/dev/mapper/root")
STOCK_OFFSET = 1923214
MARKER_MODULE = Path("/var/lib/omarchy-t2-efi-ftrace-stage-marker/mba_hibernate_efi_ftrace_marker.ko")
ABORT_MODULE = Path("/var/lib/omarchy-t2-readback-abort/mba_hibernate_readback_abort.ko")
MARKER_SHA256 = "28e13ee2a660c590d0d66988c0af9d768aa5a37e2e2ed52624215f624b149f32"
ABORT_SHA256 = "1d524ff4ca53980be38654f3f872fe3d82b725baac5fd6c9dbc86306db9aba39"
MARKER_SRCVERSION = "693755E32EFAB59747D2ED1"
ABORT_SRCVERSION = "7DCE0D2BAF567A1426BAD50"
EARLY_PREPARED_HEAD = "6a465d16fc574e96bde67a7df34c64d80ba889b0"
EARLY_PREPARE_INTENT_SHA256 = "fb86cf4ad8664cb6258df33160d41bda2dd35c96336bb0b94cee11fcc889b1bf"
MARKER_PARAMETERS = Path("/sys/module/mba_hibernate_efi_ftrace_marker/parameters")
ABORT_PARAMETERS = Path("/sys/module/mba_hibernate_readback_abort/parameters")
HELPER = Path(__file__).resolve().parents[4] / "bin/omarchy-debug-t2-hibernate"


def command(*arguments):
  return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def selected(name):
  import re
  value = (Path("/sys/power") / name).read_text()
  match = re.search(r"\[([^]]+)\]", value)
  if match is None:
    raise ValueError("No selected PM value for " + name)
  return match.group(1)


def parameter(base, name):
  value = COMMON.read_regular(base / name, 128)
  if value is None:
    raise ValueError("Missing probe parameter: " + name)
  return value.strip().decode()


def swap_offset(path):
  value = command("btrfs", "inspect-internal", "map-swapfile", "-r", str(path))
  if not value.isdecimal() or int(value) <= 0:
    raise ValueError("Swap mapping is not a positive page offset")
  return int(value)


def header(offset):
  value = HEADER.read_header(DEVICE, offset)
  if value["marker"] != "normal-swap-signature":
    raise ValueError("Swap header is not a normal swap signature")
  return value


def active_swap_paths():
  lines = Path("/proc/swaps").read_text().splitlines()
  return {line.split()[0] for line in lines[1:] if line.split()}


def require_module(path, digest, srcversion):
  if path.is_symlink() or not path.is_file() or path.parent.is_symlink():
    raise ValueError("Private module is absent or symlinked: " + str(path))
  mode = path.stat()
  parent = path.parent.stat()
  if (mode.st_uid != 0 or not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o077 or
      parent.st_uid != 0 or parent.st_mode & 0o077):
    raise ValueError("Module and directory must be root-owned and private")
  if COMMON.sha256_file(path) != digest:
    raise ValueError("Private module hash differs: " + str(path))
  if command("modinfo", "-F", "srcversion", str(path)) != srcversion:
    raise ValueError("Private module source version differs")
  if command("modinfo", "-F", "vermagic", str(path)).split()[0] != os.uname().release:
    raise ValueError("Private module kernel differs")


def validate_stock(*, prepared=False):
  root = Path("/")
  COMMON.require_live_stock(root)
  COMMON.require_live_arm_preflight(root)
  if os.uname().release != "7.2.6-arch2-Watanare-T2-2-t2":
    raise ValueError("Unqualified production kernel")
  if (Path("/sys/class/dmi/id/product_name").read_text().strip() != "MacBookAir9,1" or
      Path("/sys/class/power_supply/ADP1/online").read_text().strip() != "1"):
    raise ValueError("MacBookAir9,1 on AC power required")
  if selected("pm_test") != "none" or selected("disk") != "platform":
    raise ValueError("PM controls differ from the stock baseline")
  if "test_resume" not in Path("/sys/power/disk").read_text().split():
    raise ValueError("Kernel does not offer test_resume")
  cmdline = Path("/proc/cmdline").read_text().split()
  if (f"resume={DEVICE}" not in cmdline or f"resume_offset={STOCK_OFFSET}" not in cmdline):
    raise ValueError("Stock command line does not pin the original resume target")
  device = DEVICE.stat()
  if not stat.S_ISBLK(device.st_mode):
    raise ValueError("Encrypted root resume device is not a block device")
  if Path("/sys/power/resume").read_text().strip() != f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}":
    raise ValueError("Runtime resume device is not the encrypted root")
  if Path("/sys/power/resume_offset").read_text().strip() != str(STOCK_OFFSET):
    raise ValueError("Runtime resume offset is not the stock target")
  if swap_offset(STOCK_SWAP_FILE) != STOCK_OFFSET or str(STOCK_SWAP_FILE) not in active_swap_paths():
    raise ValueError("Original active swapfile differs from its pinned mapping")
  if command("systemctl", "--failed", "--no-legend", "--plain"):
    raise ValueError("Failed systemd units exist")
  require_module(MARKER_MODULE, MARKER_SHA256, MARKER_SRCVERSION)
  require_module(ABORT_MODULE, ABORT_SHA256, ABORT_SRCVERSION)
  for module in (MARKER_PARAMETERS, ABORT_PARAMETERS):
    if module.exists() or module.is_symlink():
      raise ValueError("An experiment module is already loaded")
  if MARKER.marker_path(root).exists() or MARKER.marker_path(root).is_symlink():
    raise ValueError("EFI stage marker already exists")
  if not prepared and (STATE.exists() or STATE.is_symlink() or SWAP_FILE.exists() or SWAP_FILE.is_symlink()):
    raise ValueError("A one-use readback state or swapfile already exists")
  if prepared:
    if (STATE.is_symlink() or SWAP_FILE.is_symlink() or not STATE.is_dir() or
        not SWAP_FILE.is_file() or STATE.stat().st_uid != 0 or
        STATE.stat().st_mode & 0o077 or SWAP_FILE.stat().st_uid != 0 or
        SWAP_FILE.stat().st_mode & 0o077 or SWAP_FILE.stat().st_size != 10 * 1024**3):
      raise ValueError("Prepared state or 10 GiB swapfile is not root-owned and private")
  return {
    "boot_id": COMMON.boot_id(root),
    "head": command("git", "-C", str(HELPER.parents[1]), "rev-parse", "HEAD"),
    "stock_header": header(STOCK_OFFSET),
  }


def expected_marker(arm, stage):
  if (arm.get("kind") != KIND or arm.get("marker_module_sha256") != MARKER_SHA256 or
      arm.get("abort_module_sha256") != ABORT_SHA256 or arm.get("stock_offset") != STOCK_OFFSET or
      arm.get("alternate_offset") in (None, STOCK_OFFSET) or
      COMMON.UUID.fullmatch(arm.get("boot_id", "")) is None):
    raise ValueError("Readback arm identity differs")
  value = MARKER.ATTRIBUTES + MARKER.payload(arm["vector"], stage)
  if hashlib.sha256(value).hexdigest() != arm.get(f"stage{stage}_sha256"):
    raise ValueError("Readback EFI stage digest differs")
  return value


def finish_preparation(evidence):
  if (STATE / "armed.json").exists() or (STATE / "pm-attempted.json").exists():
    raise ValueError("Preparation or PM guard already exists")
  descriptor = os.open(SWAP_FILE, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)
  alternate = swap_offset(SWAP_FILE)
  if alternate == STOCK_OFFSET:
    raise ValueError("Alternate swapfile maps to the stock resume page")
  alternate_header = header(alternate)
  vector = hashlib.sha256(KIND.encode() + secrets.token_bytes(32) +
                          evidence["boot_id"].encode() + bytes.fromhex(ABORT_SHA256)).hexdigest()
  arm = {
    **evidence, "kind": KIND, "vector": vector,
    "stock_offset": STOCK_OFFSET, "alternate_offset": alternate,
    "alternate_header": alternate_header, "marker_module_sha256": MARKER_SHA256,
    "abort_module_sha256": ABORT_SHA256, "swap_file": str(SWAP_FILE),
  }
  for stage in range(3):
    arm[f"stage{stage}_sha256"] = hashlib.sha256(
      MARKER.ATTRIBUTES + MARKER.payload(vector, stage)).hexdigest()
  COMMON.atomic_new_json(STATE / "armed.json", arm)
  return {"boot_id": arm["boot_id"], "vector": vector, "alternate_offset": alternate}


def matching_intent_head(intent, evidence):
  if intent.get("head") == evidence["head"]:
    return True
  return (intent.get("head") == EARLY_PREPARED_HEAD and
          COMMON.sha256_file(STATE / "prepare-intent.json") == EARLY_PREPARE_INTENT_SHA256)


def prepare():
  evidence = validate_stock()
  if int(command("df", "--output=avail", "-B1", str(SWAP_FILE.parent)).splitlines()[-1]) < 16 * 1024**3:
    raise ValueError("Less than 16 GiB free for the 10 GiB diagnostic swapfile")
  STATE.mkdir(mode=0o700)
  COMMON.atomic_new_json(STATE / "prepare-intent.json", {
    "kind": KIND + "-prepare-intent", "boot_id": evidence["boot_id"],
    "head": evidence["head"], "swap_file": str(SWAP_FILE),
    "stock_offset": STOCK_OFFSET, "stock_header": evidence["stock_header"],
  })
  command("btrfs", "filesystem", "mkswapfile", "--size", "10G", str(SWAP_FILE))
  if SWAP_FILE.is_symlink() or SWAP_FILE.stat().st_uid != 0 or SWAP_FILE.stat().st_mode & 0o077:
    raise ValueError("New swapfile is not root-owned and private")
  return finish_preparation(evidence)


def recover_preparation():
  evidence = validate_stock(prepared=True)
  intent = COMMON.load_json(STATE / "prepare-intent.json", Path("/"))
  if (intent.get("kind") != KIND + "-prepare-intent" or
      intent.get("boot_id") != evidence["boot_id"] or
      not matching_intent_head(intent, evidence) or
      intent.get("swap_file") != str(SWAP_FILE) or
      intent.get("stock_offset") != STOCK_OFFSET or
      intent.get("stock_header", {}).get("page_sha256") != evidence["stock_header"]["page_sha256"]):
    raise ValueError("Incomplete preparation does not match this stock boot")
  return finish_preparation(evidence)


def validate_armed():
  evidence = validate_stock(prepared=True)
  arm = COMMON.load_json(STATE / "armed.json", Path("/"))
  intent = COMMON.load_json(STATE / "prepare-intent.json", Path("/"))
  if (arm["boot_id"] != evidence["boot_id"] or arm["head"] != evidence["head"] or
      intent.get("kind") != KIND + "-prepare-intent" or
      intent["boot_id"] != evidence["boot_id"] or not matching_intent_head(intent, evidence) or
      intent.get("swap_file") != str(SWAP_FILE) or arm.get("swap_file") != str(SWAP_FILE) or
      intent.get("stock_offset") != STOCK_OFFSET or
      intent.get("stock_header", {}).get("page_sha256") != evidence["stock_header"]["page_sha256"] or
      arm.get("stock_header", {}).get("page_sha256") != evidence["stock_header"]["page_sha256"] or
      arm.get("alternate_offset") != swap_offset(SWAP_FILE) or
      str(SWAP_FILE) in active_swap_paths() or
      (STATE / "pm-attempted.json").exists()):
    raise ValueError("Prepared one-use readback evidence changed or was consumed")
  for stage in range(3):
    expected_marker(arm, stage)
  if header(arm["alternate_offset"])["page_sha256"] != arm["alternate_header"]["page_sha256"]:
    raise ValueError("Alternate swap header changed since preparation")
  return arm


def require_hooks():
  lines = Path("/sys/kernel/tracing/enabled_functions").read_text().splitlines()
  hibernate = [line for line in lines if line.split()[:1] == ["hibernate"]]
  swsusp = [line for line in lines if line.split()[:1] == ["swsusp_write"]]
  restore = [line for line in lines if line.split()[:1] == ["hibernation_restore"]]
  if (len(hibernate) != 1 or "(1)" not in hibernate[0] or
      len(swsusp) != 1 or "(1)" not in swsusp[0] or
      len(restore) != 1 or "(1)" not in restore[0] or " R I " not in restore[0]):
    raise ValueError("Expected marker and IPMODIFY hooks are not registered once")


def write_resume_offset(offset):
  Path("/sys/power/resume_offset").write_text(str(offset) + "\n")
  if Path("/sys/power/resume_offset").read_text().strip() != str(offset):
    raise ValueError("Runtime resume offset write did not persist")


def execute(*, operator_attended=False):
  if not operator_attended:
    raise ValueError("The one-use image-I/O test requires an operator at the power button")
  arm = validate_armed()
  COMMON.atomic_new_json(STATE / "pm-attempted.json", {
    "kind": KIND + "-pm-attempted", "boot_id": arm["boot_id"],
    "head": arm["head"], "vector": arm["vector"],
    "stock_offset": STOCK_OFFSET, "alternate_offset": arm["alternate_offset"],
    "recovery_method": "operator-attended-physical-cold-power",
    "stock_boot_cmdline_offset": STOCK_OFFSET,
  })
  marker_loaded = False
  abort_loaded = False
  swap_active = False
  result = None
  errors = []
  try:
    command("swapon", "--priority", "-2", str(SWAP_FILE))
    swap_active = True
    if str(SWAP_FILE) not in active_swap_paths():
      raise ValueError("Alternate swapfile did not become active")
    if header(arm["alternate_offset"])["page_sha256"] != arm["alternate_header"]["page_sha256"]:
      raise ValueError("Alternate swap header changed upon activation")
    variable = MARKER.marker_path(Path("/"))
    value = expected_marker(arm, 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(variable, flags, 0o600)
    try:
      if os.write(descriptor, value) != len(value):
        raise OSError("Short EFI stage-0 write; preserve evidence")
    finally:
      os.close(descriptor)
    if COMMON.read_regular(variable) != value:
      raise ValueError("EFI stage-0 readback differs")
    command("insmod", str(MARKER_MODULE))
    marker_loaded = True
    command("insmod", str(ABORT_MODULE))
    abort_loaded = True
    if (parameter(MARKER_PARAMETERS, "arm_vector") != "0" or
        parameter(MARKER_PARAMETERS, "stage") != "0" or
        parameter(ABORT_PARAMETERS, "armed") != "0" or
        parameter(ABORT_PARAMETERS, "interceptions") != "0"):
      raise ValueError("Readback modules were not loaded disarmed")
    require_hooks()
    (MARKER_PARAMETERS / "arm_vector").write_text(arm["vector"] + "\n")
    if parameter(MARKER_PARAMETERS, "arm_vector") != "1":
      raise ValueError("EFI module did not arm")
    (ABORT_PARAMETERS / "armed").write_text("Y\n")
    if parameter(ABORT_PARAMETERS, "armed") != "1":
      raise ValueError("Readback module did not arm")
    write_resume_offset(arm["alternate_offset"])
    if (swap_offset(SWAP_FILE) != arm["alternate_offset"] or
        HEADER.read_header(DEVICE, arm["alternate_offset"])["marker"] != "normal-swap-signature"):
      raise ValueError("Alternate swap target changed immediately before PM")
    os.sync()
    command_line = [str(HELPER), "test", "test-resume", "--bluetooth-off",
                    "--wifi-unbind", "--no-sudo-prompt", "--yes"]
    COMMON.atomic_new_json(STATE / "pm-enter-intent.json", {
      "kind": KIND + "-pm-enter-intent", "boot_id": arm["boot_id"],
      "vector": arm["vector"], "command": command_line,
      "alternate_offset": arm["alternate_offset"],
    })
    completed = subprocess.run(command_line, check=False, capture_output=True, text=True,
                               env={**os.environ, "PATH": str(HELPER.parent) + ":/usr/local/sbin:/usr/local/bin:/usr/bin"})
    alternate_after = HEADER.read_header(DEVICE, arm["alternate_offset"])
    stock_after = HEADER.read_header(DEVICE, STOCK_OFFSET)
    result = {
      "kind": KIND + "-result", "boot_id": arm["boot_id"], "vector": arm["vector"],
      "helper_returncode": completed.returncode,
      "helper_output_tail": (completed.stdout + completed.stderr)[-4096:],
      "observed_stage": MARKER.inspect(Path("/"), arm["vector"]),
      "efi_status": parameter(MARKER_PARAMETERS, "last_efi_status"),
      "interceptions": int(parameter(ABORT_PARAMETERS, "interceptions")),
      "alternate_header_after": alternate_after, "stock_header_after": stock_after,
      "pm_test_after": selected("pm_test"), "disk_after": selected("disk"),
    }
    result["success"] = (
      result["helper_returncode"] != 0 and result["observed_stage"] == 2 and
      result["efi_status"] == "0" and result["interceptions"] == 1 and
      alternate_after["marker"] == "normal-swap-signature" and
      stock_after["page_sha256"] == arm["stock_header"]["page_sha256"] and
      result["pm_test_after"] == "none" and result["disk_after"] == "platform"
    )
    COMMON.atomic_new_json(STATE / "result.json", result)
  finally:
    try:
      write_resume_offset(STOCK_OFFSET)
    except (OSError, ValueError) as error:
      errors.append("resume offset: " + str(error))
    if abort_loaded:
      try:
        (ABORT_PARAMETERS / "armed").write_text("N\n")
        command("rmmod", "mba_hibernate_readback_abort")
      except (OSError, ValueError, subprocess.SubprocessError) as error:
        errors.append("abort module: " + str(error))
    if marker_loaded:
      try:
        command("rmmod", "mba_hibernate_efi_ftrace_marker")
      except (OSError, ValueError, subprocess.SubprocessError) as error:
        errors.append("marker module: " + str(error))
    alternate_signature = None
    if swap_active:
      try:
        alternate_signature = HEADER.read_header(DEVICE, arm["alternate_offset"])["marker"]
        if alternate_signature == "normal-swap-signature":
          command("swapoff", str(SWAP_FILE))
        else:
          errors.append("alternate swap header is not normal; preserving active swap")
      except (OSError, ValueError, subprocess.SubprocessError) as error:
        errors.append("alternate swap: " + str(error))
    COMMON.atomic_new_json(STATE / "cleanup.json", {
      "kind": KIND + "-cleanup", "boot_id": arm["boot_id"],
      "vector": arm["vector"], "resume_offset": Path("/sys/power/resume_offset").read_text().strip(),
      "alternate_signature": alternate_signature,
      "alternate_swap_active": str(SWAP_FILE) in active_swap_paths(),
      "abort_module_loaded": ABORT_PARAMETERS.exists(),
      "marker_module_loaded": MARKER_PARAMETERS.exists(),
      "errors": errors,
    })
  if errors:
    raise RuntimeError("Image-I/O cleanup needs inspection: " + "; ".join(errors))
  if result is None:
    raise RuntimeError("Image-I/O test never returned a result; guard and EFI marker are retained")
  if not result["success"]:
    raise RuntimeError("Image-I/O test did not return the expected controlled abort; preserve evidence")
  return result


def main():
  os.umask(0o077)
  parser = argparse.ArgumentParser(description=__doc__)
  modes = parser.add_mutually_exclusive_group(required=True)
  modes.add_argument("--validate-only", action="store_true")
  modes.add_argument("--prepare", action="store_true")
  modes.add_argument("--recover-preparation", action="store_true")
  modes.add_argument("--validate-armed", action="store_true")
  modes.add_argument("--execute", action="store_true")
  parser.add_argument("--operator-attended", action="store_true")
  arguments = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  if arguments.validate_only:
    result = validate_stock()
  elif arguments.prepare:
    result = prepare()
  elif arguments.recover_preparation:
    result = recover_preparation()
  elif arguments.validate_armed:
    result = validate_armed()
  else:
    result = execute(operator_attended=arguments.operator_attended)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
