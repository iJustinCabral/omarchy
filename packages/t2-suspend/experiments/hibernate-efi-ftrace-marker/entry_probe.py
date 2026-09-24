#!/usr/bin/python3
"""One-use freezer-depth qualification of the hibernate-entry ftrace hook.

This is not S4: the pinned kernel returns at TEST_FREEZER before device
suspend, image creation, swsusp_write, or platform power-down.
"""

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("t2_efi_persistence_common", HERE / "persistence_probe.py")
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2FtraceEntryProbe-9f946df0-1b9c-4af5-97e8-bc322a728241")
STATE = Path("var/lib/omarchy-t2-ftrace-entry-probe")
RECOVERY_ACCEPTANCE = Path("var/lib/omarchy-t2-ftrace-entry-recovery/recovery-acceptance.json")
MODULE = Path("sys/module/mba_hibernate_efi_ftrace_marker")
MODULE_FILE = Path("/home/jjc/.local/state/codex-mba-autonomous/efi-ftrace-entry-build.GpkgJK/mba_hibernate_efi_ftrace_marker.ko")
MODULE_SHA256 = "28e13ee2a660c590d0d66988c0af9d768aa5a37e2e2ed52624215f624b149f32"
MODULE_SRCVERSION = "693755E32EFAB59747D2ED1"
SOURCE_SHA256 = "811eba590b0dce745b085ea95ca55a80d8cc5da8dbff43454f22422cd542cdee"
HELPER = Path(__file__).resolve().parents[4] / "bin/omarchy-debug-t2-hibernate"
HELPER_SHA256 = "e47e500103e36537a8c899eaa45eed215ea4a136a8c479b766704c12739634e6"
MAGIC = b"MBFE"
HEX24 = re.compile(r"[0-9a-f]{24}\Z")


def require_scope(root, allow_live):
  if root == Path("/") and not allow_live:
    raise ValueError("Live ftrace entry probe requires explicit allow_live=True")
  if root == Path("/") and os.geteuid() != 0:
    raise ValueError("Live ftrace entry probe requires root")


def module_parameter(root, name):
  return root / MODULE / "parameters" / name


def parameter_value(root, name):
  value = COMMON.read_regular(module_parameter(root, name), 128)
  if value is None:
    raise ValueError("Missing ftrace entry module parameter: " + name)
  return value.strip().decode()


def module_srcversion(root):
  value = COMMON.read_regular(root / MODULE / "srcversion", 128)
  if value is None:
    raise ValueError("Loaded ftrace entry module has no source version")
  return value.strip().decode()


def selected_value(root, name):
  value = COMMON.read_regular(root / "sys/power" / name, 1024)
  if value is None:
    raise ValueError("Missing PM control: " + name)
  match = re.search(rb"\[([^]]+)\]", value)
  if match is None:
    raise ValueError("PM control has no selected value: " + name)
  return match.group(1).decode()


def load_arm(root):
  arm = COMMON.load_json(root / STATE / "armed.json", root)
  nonce = arm.get("nonce_hex")
  if (arm.get("kind") != "ftrace-entry-freezer-probe-v1" or
      not isinstance(arm.get("source_boot_id"), str) or
      COMMON.UUID.fullmatch(arm["source_boot_id"]) is None or
      arm.get("module_sha256") != MODULE_SHA256 or
      arm.get("module_srcversion") != MODULE_SRCVERSION or
      arm.get("helper_sha256") != HELPER_SHA256 or
      not isinstance(nonce, str) or HEX24.fullmatch(nonce) is None):
    raise ValueError("Ftrace entry probe arm identity is malformed")
  stage0 = COMMON.ATTRIBUTES + MAGIC + bytes.fromhex(nonce) + b"\x00"
  stage1 = stage0[:-1] + b"\x01"
  if (arm.get("stage0_sha256") != hashlib.sha256(stage0).hexdigest() or
      arm.get("stage1_sha256") != hashlib.sha256(stage1).hexdigest()):
    raise ValueError("Ftrace entry probe arm digests are malformed")
  return arm, stage0, stage1


def stage(root, stage0, stage1):
  observed = COMMON.read_regular(root / VARIABLE)
  if observed is None:
    return None
  if observed == stage0:
    return 0
  if observed == stage1:
    return 1
  raise ValueError("Ftrace entry probe variable has unexpected bytes; preserve it")


def require_recovery_acceptance(root):
  directory = (root / RECOVERY_ACCEPTANCE).parent
  if root == Path("/"):
    if (directory.is_symlink() or not directory.is_dir() or
        directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077):
      raise ValueError("Ftrace entry recovery acceptance directory is not root-owned and private")
  try:
    accepted = COMMON.load_json(root / RECOVERY_ACCEPTANCE, root)
  except ValueError as error:
    raise ValueError("Ftrace entry probe needs an explicit operator-attended cold-power recovery acceptance") from error
  if (accepted.get("kind") != "ftrace-entry-freezer-recovery-acceptance-v1" or
      accepted.get("source_boot_id") != COMMON.boot_id(root) or
      accepted.get("module_sha256") != MODULE_SHA256 or
      accepted.get("helper_sha256") != HELPER_SHA256 or
      accepted.get("production_uki_sha256") != COMMON.PRODUCTION_UKI_SHA256 or
      accepted.get("production_limine_sha256") != COMMON.PRODUCTION_LIMINE_SHA256 or
      accepted.get("method") != "operator-attended-cold-power" or
      accepted.get("accepted") is not True):
    raise ValueError("Ftrace entry recovery acceptance does not bind this stock boot and probe")
  return accepted


def require_live_preflight(root, *, allow_module=False):
  COMMON.require_live_stock(root, allow_marker_module=allow_module)
  COMMON.require_live_arm_preflight(root)
  require_recovery_acceptance(root)
  if COMMON.sha256_file(MODULE_FILE) != MODULE_SHA256:
    raise ValueError("Private ftrace entry module hash differs")
  if COMMON.sha256_file(HELPER) != HELPER_SHA256:
    raise ValueError("Freezer diagnostic helper hash differs")
  if COMMON.command_output("modinfo", "-F", "srcversion", str(MODULE_FILE)).strip() != MODULE_SRCVERSION:
    raise ValueError("Private ftrace entry module source version differs")
  if COMMON.command_output("modinfo", "-F", "vermagic", str(MODULE_FILE)).split()[0] != os.uname().release:
    raise ValueError("Private ftrace entry module vermagic differs")


def prepare(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    require_live_preflight(root)
    if COMMON.sha256_file(HERE / "mba_hibernate_efi_ftrace_marker.c") != SOURCE_SHA256:
      raise ValueError("Ftrace entry source differs from pinned module")
  if (root / MODULE).exists() or (root / MODULE).is_symlink():
    raise ValueError("Ftrace entry probe module is already loaded")
  variable = root / VARIABLE
  if COMMON.read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Ftrace entry probe variable already exists; preserve it")
  nonce = os.urandom(12)
  stage0 = COMMON.ATTRIBUTES + MAGIC + nonce + b"\x00"
  stage1 = stage0[:-1] + b"\x01"
  directory = root / STATE
  directory.mkdir(mode=0o700)
  COMMON.atomic_new_json(directory / "armed.json", {
    "kind": "ftrace-entry-freezer-probe-v1",
    "source_boot_id": COMMON.boot_id(root),
    "module_sha256": MODULE_SHA256,
    "module_srcversion": MODULE_SRCVERSION,
    "helper_sha256": HELPER_SHA256,
    "nonce_hex": nonce.hex(),
    "stage0_sha256": hashlib.sha256(stage0).hexdigest(),
    "stage1_sha256": hashlib.sha256(stage1).hexdigest(),
  })
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(variable, flags, 0o600)
  try:
    if os.write(descriptor, stage0) != len(stage0):
      raise OSError("Short ftrace entry EFI pre-arm write; preserve evidence")
  finally:
    os.close(descriptor)
  if COMMON.read_regular(variable) != stage0:
    raise ValueError("Ftrace entry EFI stage-0 readback differs; preserve evidence")
  return {"source_boot_id": COMMON.boot_id(root), "stage0_sha256": hashlib.sha256(stage0).hexdigest()}


def arm_module(root, *, allow_live=False, write_parameter=None):
  require_scope(root, allow_live)
  if root == Path("/") and write_parameter is not None:
    raise ValueError("Live ftrace entry module arm cannot inject a test writer")
  if root == Path("/"):
    require_live_preflight(root)
  arm, stage0, stage1 = load_arm(root)
  if COMMON.boot_id(root) != arm["source_boot_id"] or stage(root, stage0, stage1) != 0:
    raise ValueError("Ftrace entry probe source boot or stage 0 differs")
  if COMMON.read_regular(root / STATE / "module-armed.json") is not None:
    raise ValueError("Ftrace entry module arm already recorded")
  if root == Path("/"):
    subprocess.run(["insmod", str(MODULE_FILE)], check=True, timeout=20)
  if module_srcversion(root) != MODULE_SRCVERSION:
    raise ValueError("Loaded ftrace entry module source version differs")
  if (parameter_value(root, "arm_vector") != "0" or
      parameter_value(root, "probe_consumed") not in ("N", "0") or
      parameter_value(root, "entry_consumed") not in ("N", "0") or
      parameter_value(root, "entry_armed") not in ("N", "0") or
      parameter_value(root, "entry_stage") != "0"):
    raise ValueError("Loaded ftrace entry module is not disarmed and unused")
  value = (arm["nonce_hex"] + "\n").encode()
  if write_parameter is None:
    flags = os.O_WRONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(module_parameter(root, "entry_nonce"), flags)
    try:
      if os.write(descriptor, value) != len(value):
        raise OSError("Short ftrace entry module arm write")
    finally:
      os.close(descriptor)
  else:
    write_parameter(root, value)
  if (parameter_value(root, "entry_consumed") not in ("Y", "1") or
      parameter_value(root, "entry_armed") not in ("Y", "1") or
      parameter_value(root, "arm_vector") != "0" or
      stage(root, stage0, stage1) != 0):
    raise ValueError("Ftrace entry module arm did not read back exactly")
  result = {
    "kind": "ftrace-entry-freezer-probe-v1-module-armed",
    "source_boot_id": arm["source_boot_id"],
    "module_sha256": MODULE_SHA256,
    "stage0_sha256": arm["stage0_sha256"],
  }
  COMMON.atomic_new_json(root / STATE / "module-armed.json", result)
  return result


def execute_freezer(root, *, allow_live=False, transition=None):
  require_scope(root, allow_live)
  if root == Path("/") and transition is not None:
    raise ValueError("Live freezer execution cannot inject a test transition")
  if root == Path("/"):
    require_live_preflight(root, allow_module=True)
  arm, stage0, stage1 = load_arm(root)
  module_arm = COMMON.load_json(root / STATE / "module-armed.json", root)
  if (module_arm.get("kind") != "ftrace-entry-freezer-probe-v1-module-armed" or
      module_arm.get("source_boot_id") != arm["source_boot_id"] or
      module_arm.get("stage0_sha256") != arm["stage0_sha256"] or
      COMMON.boot_id(root) != arm["source_boot_id"] or
      stage(root, stage0, stage1) != 0):
    raise ValueError("Ftrace entry probe execution does not match its one-use arm")
  if (module_srcversion(root) != MODULE_SRCVERSION or
      parameter_value(root, "entry_consumed") not in ("Y", "1") or
      parameter_value(root, "entry_armed") not in ("Y", "1") or
      parameter_value(root, "entry_stage") != "0" or
      parameter_value(root, "arm_vector") != "0" or
      parameter_value(root, "probe_consumed") not in ("N", "0")):
    raise ValueError("Ftrace entry module is not exclusively armed")
  previous_pm_test = selected_value(root, "pm_test")
  previous_disk = selected_value(root, "disk")
  if previous_pm_test != "none" or previous_disk not in ("platform", "shutdown"):
    raise ValueError("PM controls are not at the qualified baseline")
  command = [str(HELPER), "test", "freezer", "--disk-mode", "shutdown", "--no-sudo-prompt", "--yes"]
  COMMON.atomic_new_json(root / STATE / "pm-attempted.json", {
    "kind": "ftrace-entry-freezer-probe-v1-pm-attempted",
    "source_boot_id": arm["source_boot_id"],
    "module_sha256": MODULE_SHA256,
    "stage0_sha256": arm["stage0_sha256"],
    "previous_pm_test": previous_pm_test,
    "previous_disk": previous_disk,
    "command": command,
  })
  if root == Path("/"):
    environment = {**os.environ, "PATH": str(HELPER.parent) + ":/usr/local/sbin:/usr/local/bin:/usr/bin"}
    completed = subprocess.run(command, check=False, capture_output=True, text=True,
                               env=environment)
    returncode, output = completed.returncode, (completed.stdout + completed.stderr)[-4096:]
  else:
    if transition is None:
      raise ValueError("Synthetic freezer execution requires a test transition")
    returncode, output = transition(root)
  status = parameter_value(root, "entry_efi_status")
  observed_stage = stage(root, stage0, stage1)
  result = {
    "kind": "ftrace-entry-freezer-probe-v1-result",
    "source_boot_id": arm["source_boot_id"],
    "module_sha256": MODULE_SHA256,
    "helper_returncode": returncode,
    "helper_output_tail": output,
    "entry_efi_status": status,
    "entry_stage": parameter_value(root, "entry_stage"),
    "observed_stage": observed_stage,
    "pm_test_after": selected_value(root, "pm_test"),
    "disk_after": selected_value(root, "disk"),
    "success": (returncode == 0 and status == "0" and observed_stage == 1 and
                parameter_value(root, "entry_stage") == "1" and
                parameter_value(root, "entry_armed") in ("N", "0") and
                parameter_value(root, "arm_vector") == "0" and
                selected_value(root, "pm_test") == previous_pm_test and
                selected_value(root, "disk") == previous_disk),
  }
  COMMON.atomic_new_json(root / STATE / "result.json", result)
  if root == Path("/"):
    subprocess.run(["rmmod", "mba_hibernate_efi_ftrace_marker"], check=True, timeout=20)
    if (root / MODULE).exists():
      raise ValueError("Ftrace entry module remained loaded after cleanup")
    COMMON.atomic_new_json(root / STATE / "unloaded.json", {
      "kind": "ftrace-entry-freezer-probe-v1-unloaded",
      "source_boot_id": arm["source_boot_id"],
      "result_success": result["success"],
    })
  return result


def capture_return(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root)
  arm, stage0, stage1 = load_arm(root)
  attempt = COMMON.load_json(root / STATE / "pm-attempted.json", root)
  current = COMMON.boot_id(root)
  if current == arm["source_boot_id"]:
    raise ValueError("Same-boot readback does not prove ftrace EFI persistence")
  if (attempt.get("kind") != "ftrace-entry-freezer-probe-v1-pm-attempted" or
      attempt.get("source_boot_id") != arm["source_boot_id"] or
      attempt.get("module_sha256") != MODULE_SHA256 or
      attempt.get("stage0_sha256") != arm["stage0_sha256"]):
    raise ValueError("Ftrace entry PM guard differs from its exact arm")
  source_result = None
  if COMMON.read_regular(root / STATE / "result.json") is not None:
    source_result = COMMON.load_json(root / STATE / "result.json", root)
    if (source_result.get("kind") != "ftrace-entry-freezer-probe-v1-result" or
        source_result.get("source_boot_id") != arm["source_boot_id"] or
        source_result.get("module_sha256") != MODULE_SHA256):
      raise ValueError("Ftrace entry source result differs from its exact arm")
  observed_stage = stage(root, stage0, stage1)
  result = {
    "kind": "ftrace-entry-freezer-probe-v1-return",
    "source_boot_id": arm["source_boot_id"],
    "return_boot_id": current,
    "stage1_sha256": arm["stage1_sha256"],
    "observed_stage": observed_stage,
    "marker_persisted": observed_stage == 1,
    "source_returned_successfully": source_result is not None and source_result.get("success") is True,
  }
  COMMON.atomic_new_json(root / STATE / "return-result.json", result)
  return result


def clear(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root)
  arm, stage0, stage1 = load_arm(root)
  returned = COMMON.load_json(root / STATE / "return-result.json", root)
  if (returned.get("kind") != "ftrace-entry-freezer-probe-v1-return" or
      returned.get("marker_persisted") is not True or
      returned.get("source_returned_successfully") is not True or
      returned.get("source_boot_id") != arm["source_boot_id"] or
      returned.get("return_boot_id") != COMMON.boot_id(root) or
      returned.get("stage1_sha256") != arm["stage1_sha256"] or
      stage(root, stage0, stage1) != 1):
    raise ValueError("Only an exact successful ftrace entry return may be cleared")
  variable = root / VARIABLE
  COMMON.atomic_new_json(root / STATE / "clear-intent.json", {
    "kind": "ftrace-entry-freezer-probe-v1-clear-intent",
    "return_boot_id": returned["return_boot_id"],
    "stage1_sha256": arm["stage1_sha256"],
  })
  if root == Path("/"):
    subprocess.run(["chattr", "-i", str(variable)], check=True)
  variable.unlink()
  if COMMON.read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Ftrace entry probe variable still exists after cleanup")
  COMMON.atomic_new_json(root / STATE / "cleared.json", {
    "kind": "ftrace-entry-freezer-probe-v1-cleared",
    "return_boot_id": returned["return_boot_id"],
    "stage1_sha256": arm["stage1_sha256"],
  })
  return True
