#!/usr/bin/python3
"""One-use stock-kernel image-write boundary probe; never run on import.

The existing EFI ftrace module records hibernate() and swsusp_write() entry.
The existing IPMODIFY module then returns -ECANCELED before writing an image.
This is a test_resume diagnostic, not S4 or a hibernation fix.
"""

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


COMMON = import_file("t2_efi_boundary_common", EXPERIMENTS / "hibernate-efi-ftrace-marker/persistence_probe.py")
MARKER = import_file("t2_efi_boundary_layout", EXPERIMENTS / "hibernate-efi-stage-marker/marker.py")
HEADER = import_file("t2_efi_boundary_header", EXPERIMENTS / "audit-hibernation-swap-header.py")

STATE = Path("var/lib/omarchy-t2-efi-pre-write-boundary")
MARKER_MODULE = Path("/var/lib/omarchy-t2-efi-ftrace-stage-marker/mba_hibernate_efi_ftrace_marker.ko")
ABORT_MODULE = Path("/var/lib/codex-mba-pre-write-ftrace/mba_hibernate_pre_write_ftrace.ko")
MARKER_SHA256 = "28e13ee2a660c590d0d66988c0af9d768aa5a37e2e2ed52624215f624b149f32"
ABORT_SHA256 = "ca1afffe28b16a41421ad6f0feb36fe5a7ad35dfb7bfb93ac95beb8882b551b6"
MARKER_SRCVERSION = "693755E32EFAB59747D2ED1"
ABORT_SRCVERSION = "440D2D921CE195B50E52595"
MARKER_PARAMETERS = Path("sys/module/mba_hibernate_efi_ftrace_marker/parameters")
ABORT_PARAMETERS = Path("sys/module/mba_hibernate_pre_write_ftrace/parameters")
HELPER = Path(__file__).resolve().parents[4] / "bin/omarchy-debug-t2-hibernate"
RESUME_DEVICE = Path("/dev/mapper/root")
SWAP_FILE = Path("/swap/swapfile")
RESUME_OFFSET = 1923214
KIND = "stock-efi-pre-write-boundary-v1"


def run(*arguments):
  return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout.strip()


def regular_private_module(path, expected_hash, expected_srcversion):
  if path.is_symlink() or not path.is_file():
    raise ValueError("Private probe module is absent or symlinked: " + str(path))
  metadata = path.stat()
  parent = path.parent.stat()
  if (metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or
      parent.st_uid != 0 or parent.st_mode & 0o077 or path.parent.is_symlink()):
    raise ValueError("Probe module and directory must be root-owned and private")
  if COMMON.sha256_file(path) != expected_hash:
    raise ValueError("Private probe module hash differs: " + str(path))
  if run("modinfo", "-F", "srcversion", str(path)) != expected_srcversion:
    raise ValueError("Private probe module source version differs")
  if run("modinfo", "-F", "vermagic", str(path)).split()[0] != os.uname().release:
    raise ValueError("Private probe module does not match the running kernel")


def selected(root, name):
  value = COMMON.read_regular(root / "sys/power" / name, 1024)
  if value is None:
    raise ValueError("Missing PM control: " + name)
  import re
  match = re.search(rb"\[([^]]+)\]", value)
  if match is None:
    raise ValueError("Missing selected PM value: " + name)
  return match.group(1).decode()


def swap_header():
  mapped = run("btrfs", "inspect-internal", "map-swapfile", "-r", str(SWAP_FILE))
  if mapped != str(RESUME_OFFSET):
    raise ValueError("Swap file physical page differs from the pinned resume offset")
  if Path("/sys/power/resume_offset").read_text().strip() != mapped:
    raise ValueError("Kernel resume offset differs from the active swap file")
  device = RESUME_DEVICE.stat()
  if not stat.S_ISBLK(device.st_mode):
    raise ValueError("Resume device is not a block device")
  if Path("/sys/power/resume").read_text().strip() != f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}":
    raise ValueError("Kernel resume device differs from the physical encrypted root")
  result = HEADER.read_header(RESUME_DEVICE, RESUME_OFFSET)
  if result["marker"] != "normal-swap-signature":
    raise ValueError("Swap header is not in the normal state")
  return result


def validate_live():
  root = Path("/")
  COMMON.require_live_stock(root)
  COMMON.require_live_arm_preflight(root)
  if (root / ABORT_PARAMETERS).exists() or (root / ABORT_PARAMETERS).is_symlink():
    raise ValueError("Pre-write abort module is already loaded")
  if (root / STATE).exists() or (root / STATE).is_symlink():
    raise ValueError("One-use EFI pre-write boundary state already exists")
  if MARKER.inspect(root, "0" * 64) is not None:
    raise ValueError("EFI stage marker already exists")
  if (root / "sys/class/power_supply/ADP1/online").read_text().strip() != "1":
    raise ValueError("AC power is not connected")
  if selected(root, "pm_test") != "none" or selected(root, "disk") != "platform":
    raise ValueError("PM controls differ from the qualified stock baseline")
  if "test_resume" not in (root / "sys/power/disk").read_text().split():
    raise ValueError("Kernel does not advertise test_resume")
  regular_private_module(MARKER_MODULE, MARKER_SHA256, MARKER_SRCVERSION)
  regular_private_module(ABORT_MODULE, ABORT_SHA256, ABORT_SRCVERSION)
  if run("systemctl", "--failed", "--no-legend", "--plain"):
    raise ValueError("Failed systemd units exist")
  return {
    "boot_id": COMMON.boot_id(root),
    "head": run("git", "-C", str(HELPER.parents[1]), "rev-parse", "HEAD"),
    "marker_module_sha256": MARKER_SHA256,
    "abort_module_sha256": ABORT_SHA256,
    "swap_header_before": swap_header(),
  }


def require_hook_registration():
  lines = Path("/sys/kernel/tracing/enabled_functions").read_text().splitlines()
  hibernate = [line for line in lines if line.split()[:1] == ["hibernate"]]
  swsusp = [line for line in lines if line.split()[:1] == ["swsusp_write"]]
  if len(hibernate) != 1 or "(1)" not in hibernate[0]:
    raise ValueError("Hibernate-entry marker hook is not registered exactly once")
  if len(swsusp) != 1 or "(2)" not in swsusp[0] or " R I " not in swsusp[0]:
    raise ValueError("Image-write marker and IPMODIFY abort hooks are not both registered")


def expected(arm, stage):
  if (arm.get("kind") != KIND or arm.get("marker_module_sha256") != MARKER_SHA256 or
      arm.get("abort_module_sha256") != ABORT_SHA256 or
      COMMON.UUID.fullmatch(arm.get("boot_id", "")) is None or
      len(arm.get("vector", "")) != 64):
    raise ValueError("One-use boundary arm identity differs")
  value = MARKER.ATTRIBUTES + MARKER.payload(arm["vector"], stage)
  if hashlib.sha256(value).hexdigest() != arm.get(f"stage{stage}_sha256"):
    raise ValueError("One-use boundary stage digest differs")
  return value


def prepare_live():
  evidence = validate_live()
  nonce = secrets.token_bytes(32)
  vector = hashlib.sha256(KIND.encode() + nonce + evidence["boot_id"].encode() +
                          bytes.fromhex(MARKER_SHA256) + bytes.fromhex(ABORT_SHA256)).hexdigest()
  arm = {**evidence, "kind": KIND, "vector": vector}
  for stage in range(3):
    value = MARKER.ATTRIBUTES + MARKER.payload(vector, stage)
    arm[f"stage{stage}_sha256"] = hashlib.sha256(value).hexdigest()
  directory = Path("/") / STATE
  directory.mkdir(mode=0o700)
  COMMON.atomic_new_json(directory / "armed.json", arm)
  variable = MARKER.marker_path(Path("/"))
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(variable, flags, 0o600)
  try:
    value = expected(arm, 0)
    if os.write(descriptor, value) != len(value):
      raise OSError("Short EFI stage-0 write; preserve evidence")
  finally:
    os.close(descriptor)
  if COMMON.read_regular(variable) != expected(arm, 0):
    raise ValueError("EFI stage-0 readback differs; preserve evidence")
  return {"boot_id": arm["boot_id"], "vector": vector, "stage0_sha256": arm["stage0_sha256"]}


def parameter(base, name):
  value = COMMON.read_regular(Path("/") / base / name, 128)
  if value is None:
    raise ValueError("Missing probe module parameter: " + name)
  return value.strip().decode()


def validate_armed_live():
  root = Path("/")
  COMMON.require_live_stock(root, allow_marker_module=True, allow_stage_marker=True)
  COMMON.require_live_arm_preflight(root)
  arm = COMMON.load_json(root / STATE / "armed.json", root)
  if arm["boot_id"] != COMMON.boot_id(root) or arm["head"] != run("git", "-C", str(HELPER.parents[1]), "rev-parse", "HEAD"):
    raise ValueError("Boundary arm differs from current stock boot or checkpoint")
  if COMMON.read_regular(MARKER.marker_path(root)) != expected(arm, 0):
    raise ValueError("EFI stage-0 marker differs; preserve it")
  expected(arm, 1)
  expected(arm, 2)
  if (root / "sys/class/power_supply/ADP1/online").read_text().strip() != "1":
    raise ValueError("AC power is not connected")
  regular_private_module(MARKER_MODULE, MARKER_SHA256, MARKER_SRCVERSION)
  regular_private_module(ABORT_MODULE, ABORT_SHA256, ABORT_SRCVERSION)
  if (root / STATE / "pm-attempted.json").exists():
    raise ValueError("One-use boundary PM guard already exists")
  if swap_header()["page_sha256"] != arm["swap_header_before"]["page_sha256"]:
    raise ValueError("Swap header changed since the boundary arm")
  if selected(root, "pm_test") != "none" or selected(root, "disk") != "platform":
    raise ValueError("PM controls changed since the boundary arm")
  return arm


def execute_live(*, operator_attended=False):
  if not operator_attended:
    raise ValueError("The one-use PM boundary requires an operator at the power button")
  root = Path("/")
  arm = validate_armed_live()
  command = [str(HELPER), "test", "test-resume", "--bluetooth-off", "--wifi-unbind",
             "--no-sudo-prompt", "--yes"]
  COMMON.atomic_new_json(root / STATE / "pm-attempted.json", {
    "kind": KIND + "-pm-attempted",
    "boot_id": arm["boot_id"],
    "vector": arm["vector"],
    "marker_module_sha256": MARKER_SHA256,
    "abort_module_sha256": ABORT_SHA256,
    "recovery_method": "operator-attended-physical-cold-power",
    "command": command,
  })
  marker_loaded = False
  abort_loaded = False
  result = None
  cleanup_errors = []
  try:
    subprocess.run(["insmod", str(MARKER_MODULE)], check=True, timeout=20)
    marker_loaded = True
    subprocess.run(["insmod", str(ABORT_MODULE)], check=True, timeout=20)
    abort_loaded = True
    if (parameter(MARKER_PARAMETERS, "arm_vector") != "0" or
        parameter(MARKER_PARAMETERS, "stage") != "0" or
        parameter(ABORT_PARAMETERS, "armed") not in ("N", "0") or
        parameter(ABORT_PARAMETERS, "interceptions") != "0"):
      raise ValueError("Co-loaded ftrace modules are not disarmed")
    require_hook_registration()
    (root / MARKER_PARAMETERS / "arm_vector").write_text(arm["vector"] + "\n")
    if parameter(MARKER_PARAMETERS, "arm_vector") != "1":
      raise ValueError("EFI stage module did not arm")
    (root / ABORT_PARAMETERS / "armed").write_text("Y\n")
    if parameter(ABORT_PARAMETERS, "armed") not in ("Y", "1"):
      raise ValueError("Image-write abort module did not arm")
    os.sync()
    completed = subprocess.run(command, check=False, capture_output=True, text=True,
                               env={**os.environ, "PATH": str(HELPER.parent) + ":/usr/local/sbin:/usr/local/bin:/usr/bin"})
    stage = MARKER.inspect(root, arm["vector"])
    count = int(parameter(ABORT_PARAMETERS, "interceptions"))
    status = parameter(MARKER_PARAMETERS, "last_efi_status")
    after = swap_header()
    result = {
      "kind": KIND + "-result",
      "boot_id": arm["boot_id"],
      "vector": arm["vector"],
      "helper_returncode": completed.returncode,
      "helper_output_tail": (completed.stdout + completed.stderr)[-4096:],
      "observed_stage": stage,
      "efi_status": status,
      "interceptions": count,
      "swap_header_after": after,
      "pm_test_after": selected(root, "pm_test"),
      "disk_after": selected(root, "disk"),
    }
    result["success"] = (completed.returncode != 0 and stage == 2 and status == "0" and
                         count == 1 and after["page_sha256"] == arm["swap_header_before"]["page_sha256"] and
                         result["pm_test_after"] == "none" and result["disk_after"] == "platform")
    COMMON.atomic_new_json(root / STATE / "result.json", result)
  finally:
    if abort_loaded:
      try:
        (root / ABORT_PARAMETERS / "armed").write_text("N\n")
        subprocess.run(["rmmod", "mba_hibernate_pre_write_ftrace"], check=True, timeout=20)
      except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        cleanup_errors.append("abort module: " + str(error))
    if marker_loaded:
      try:
        subprocess.run(["rmmod", "mba_hibernate_efi_ftrace_marker"], check=True, timeout=20)
      except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        cleanup_errors.append("marker module: " + str(error))
    COMMON.atomic_new_json(root / STATE / "cleanup.json", {
      "kind": KIND + "-cleanup",
      "boot_id": arm["boot_id"],
      "abort_module_unloaded": not (root / ABORT_PARAMETERS).exists(),
      "marker_module_unloaded": not (root / MARKER_PARAMETERS).exists(),
      "errors": cleanup_errors,
    })
  if cleanup_errors:
    raise RuntimeError("Boundary probe module cleanup failed: " + "; ".join(cleanup_errors))
  if result is None:
    raise RuntimeError("Boundary probe did not return a result; preserve marker and guard")
  if not result["success"]:
    raise RuntimeError("Boundary probe returned without the expected controlled abort; preserve marker and guard")
  return result


def main():
  os.umask(0o077)
  parser = argparse.ArgumentParser(description=__doc__)
  mode = parser.add_mutually_exclusive_group(required=True)
  mode.add_argument("--validate-only", action="store_true")
  mode.add_argument("--prepare", action="store_true")
  mode.add_argument("--validate-armed", action="store_true")
  mode.add_argument("--execute", action="store_true")
  parser.add_argument("--operator-attended", action="store_true")
  arguments = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  if arguments.validate_only:
    result = validate_live()
  elif arguments.prepare:
    result = prepare_live()
  elif arguments.validate_armed:
    result = validate_armed_live()
  else:
    result = execute_live(operator_attended=arguments.operator_attended)
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
