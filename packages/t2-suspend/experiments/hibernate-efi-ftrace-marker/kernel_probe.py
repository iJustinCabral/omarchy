#!/usr/bin/python3
"""One-use stock-boot protocol for the module's nonblocking EFI write path.

This is a distinct variable and state directory from the earlier efivarfs
persistence test. Importing this file never loads a module or writes EFI.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("t2_efi_persistence_common", HERE / "persistence_probe.py")
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2KernelEfiProbe-d963eecc-8654-47d4-bc1c-456d7b776a86")
STATE = Path("var/lib/omarchy-t2-kernel-efi-probe")
MODULE = Path("sys/module/mba_hibernate_efi_ftrace_marker")
MODULE_FILE = Path("/home/jjc/.local/state/codex-mba-autonomous/efi-kernel-probe-build.Dil1La/mba_hibernate_efi_ftrace_marker.ko")
MODULE_SHA256 = "496745c0c57fb10b16a2508ffc5071a738ec81e5fce1340ee38df519d373697b"
MODULE_SRCVERSION = "CA1877C53A97AD3DA935CE2"
MAGIC = b"MBKP"
HEX24 = re.compile(r"[0-9a-f]{24}\Z")


def require_scope(root, allow_live):
  if root == Path("/") and not allow_live:
    raise ValueError("Live kernel EFI probe requires explicit allow_live=True")
  if root == Path("/") and os.geteuid() != 0:
    raise ValueError("Live kernel EFI probe requires root")


def load_arm(root):
  arm = COMMON.load_json(root / STATE / "armed.json", root)
  nonce = arm.get("nonce_hex")
  if (arm.get("kind") != "kernel-efi-nonblocking-probe-v1" or
      arm.get("source_boot_id") is None or
      COMMON.UUID.fullmatch(arm["source_boot_id"]) is None or
      arm.get("module_sha256") != MODULE_SHA256 or
      arm.get("module_srcversion") != MODULE_SRCVERSION or
      not isinstance(nonce, str) or HEX24.fullmatch(nonce) is None):
    raise ValueError("Kernel EFI probe arm identity is malformed")
  stage0 = COMMON.ATTRIBUTES + MAGIC + bytes.fromhex(nonce) + b"\x00"
  stage1 = stage0[:-1] + b"\x01"
  if (arm.get("stage0_sha256") != hashlib.sha256(stage0).hexdigest() or
      arm.get("stage1_sha256") != hashlib.sha256(stage1).hexdigest()):
    raise ValueError("Kernel EFI probe arm digests are malformed")
  return arm, stage0, stage1


def stage(root, stage0, stage1):
  observed = COMMON.read_regular(root / VARIABLE)
  if observed is None:
    return None
  if observed == stage0:
    return 0
  if observed == stage1:
    return 1
  raise ValueError("Kernel EFI probe variable has unexpected bytes; preserve it")


def prepare(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root)
    COMMON.require_live_arm_preflight(root)
    if COMMON.sha256_file(MODULE_FILE) != MODULE_SHA256:
      raise ValueError("Private kernel EFI probe module hash differs")
    if COMMON.command_output("modinfo", "-F", "srcversion", str(MODULE_FILE)).strip() != MODULE_SRCVERSION:
      raise ValueError("Private kernel EFI probe module source version differs")
    if COMMON.command_output("modinfo", "-F", "vermagic", str(MODULE_FILE)).split()[0] != os.uname().release:
      raise ValueError("Private kernel EFI probe module vermagic differs")
  if (root / MODULE).exists() or (root / MODULE).is_symlink():
    raise ValueError("Kernel EFI probe module is already loaded")
  variable = root / VARIABLE
  if COMMON.read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Kernel EFI probe variable already exists; preserve it")
  nonce = os.urandom(12)
  stage0 = COMMON.ATTRIBUTES + MAGIC + nonce + b"\x00"
  stage1 = stage0[:-1] + b"\x01"
  directory = root / STATE
  directory.mkdir(mode=0o700)
  COMMON.atomic_new_json(directory / "armed.json", {
    "kind": "kernel-efi-nonblocking-probe-v1",
    "source_boot_id": COMMON.boot_id(root),
    "module_sha256": MODULE_SHA256,
    "module_srcversion": MODULE_SRCVERSION,
    "nonce_hex": nonce.hex(),
    "stage0_sha256": hashlib.sha256(stage0).hexdigest(),
    "stage1_sha256": hashlib.sha256(stage1).hexdigest(),
  })
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(variable, flags, 0o600)
  try:
    if os.write(descriptor, stage0) != len(stage0):
      raise OSError("Short EFI kernel-probe pre-arm write; preserve evidence")
  finally:
    os.close(descriptor)
  if COMMON.read_regular(variable) != stage0:
    raise ValueError("EFI kernel-probe stage-0 readback differs; preserve evidence")
  return {"source_boot_id": COMMON.boot_id(root), "stage0_sha256": hashlib.sha256(stage0).hexdigest()}


def parameter(root, name):
  return root / MODULE / "parameters" / name


def read_parameter(root, name):
  value = COMMON.read_regular(parameter(root, name), 128)
  if value is None:
    raise ValueError("Kernel EFI probe parameter is absent: " + name)
  return value.strip().decode()


def read_module_srcversion(root):
  value = COMMON.read_regular(root / MODULE / "srcversion", 128)
  if value is None:
    raise ValueError("Loaded kernel EFI probe has no source version")
  return value.strip().decode()


def record_write(root, *, allow_live=False, parameter_write_error=None):
  require_scope(root, allow_live)
  arm, stage0, stage1 = load_arm(root)
  if COMMON.boot_id(root) != arm["source_boot_id"]:
    raise ValueError("Kernel EFI write result belongs to another boot")
  if read_module_srcversion(root) != MODULE_SRCVERSION:
    raise ValueError("Loaded kernel EFI probe source version differs")
  consumed = read_parameter(root, "probe_consumed")
  status = read_parameter(root, "probe_efi_status")
  if consumed not in ("Y", "1"):
    raise ValueError("Kernel EFI write probe was not consumed")
  if read_parameter(root, "arm_vector") != "0" or read_parameter(root, "stage") != "0":
    raise ValueError("Kernel EFI probe module has S4 arming state")
  observed_stage = stage(root, stage0, stage1)
  result = {
    "kind": "kernel-efi-nonblocking-probe-v1-write",
    "source_boot_id": arm["source_boot_id"],
    "stage0_sha256": arm["stage0_sha256"],
    "stage1_sha256": arm["stage1_sha256"],
    "probe_efi_status": status,
    "parameter_write_error": parameter_write_error,
    "observed_stage": observed_stage,
    "success": parameter_write_error is None and status == "0" and observed_stage == 1,
  }
  COMMON.atomic_new_json(root / STATE / "write-result.json", result)
  return result


def execute(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root, allow_marker_module=True)
    COMMON.require_live_arm_preflight(root)
  arm, stage0, stage1 = load_arm(root)
  if COMMON.boot_id(root) != arm["source_boot_id"]:
    raise ValueError("Kernel EFI probe can write only on its source boot")
  if stage(root, stage0, stage1) != 0:
    raise ValueError("Kernel EFI probe stage 0 is absent or changed")
  if COMMON.read_regular(root / STATE / "write-result.json") is not None:
    raise ValueError("Kernel EFI probe write already recorded")
  if (read_module_srcversion(root) != MODULE_SRCVERSION or
      read_parameter(root, "probe_consumed") not in ("N", "0") or
      read_parameter(root, "arm_vector") != "0" or
      read_parameter(root, "stage") != "0"):
    raise ValueError("Kernel EFI probe module is not disarmed and unused")
  value = (arm["nonce_hex"] + "\n").encode()
  flags = os.O_WRONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(parameter(root, "probe_nonce"), flags)
  write_error = None
  try:
    if os.write(descriptor, value) != len(value):
      write_error = OSError("Short kernel EFI probe parameter write")
  except OSError as error:
    write_error = error
  finally:
    os.close(descriptor)
  if read_parameter(root, "probe_consumed") not in ("Y", "1"):
    if write_error is not None:
      raise write_error
    raise ValueError("Kernel EFI probe parameter write did not consume the one-shot gate")
  return record_write(root, allow_live=allow_live,
                      parameter_write_error=str(write_error) if write_error is not None else None)


def verify_return(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root)
  arm, stage0, stage1 = load_arm(root)
  write = COMMON.load_json(root / STATE / "write-result.json", root)
  current = COMMON.boot_id(root)
  if current == arm["source_boot_id"]:
    raise ValueError("Same-boot readback does not prove kernel EFI persistence")
  if (write.get("kind") != "kernel-efi-nonblocking-probe-v1-write" or
      write.get("source_boot_id") != arm["source_boot_id"] or
      write.get("stage1_sha256") != arm["stage1_sha256"]):
    raise ValueError("Kernel EFI write evidence differs from arm record")
  observed_stage = stage(root, stage0, stage1)
  result = {
    "kind": "kernel-efi-nonblocking-probe-v1-return",
    "source_boot_id": arm["source_boot_id"],
    "return_boot_id": current,
    "stage1_sha256": arm["stage1_sha256"],
    "observed_stage": observed_stage,
    "persisted": write.get("success") is True and observed_stage == 1,
  }
  COMMON.atomic_new_json(root / STATE / "return-result.json", result)
  return result


def clear(root, *, allow_live=False):
  require_scope(root, allow_live)
  if root == Path("/"):
    COMMON.require_live_stock(root)
  arm, stage0, stage1 = load_arm(root)
  returned = COMMON.load_json(root / STATE / "return-result.json", root)
  if (returned.get("kind") != "kernel-efi-nonblocking-probe-v1-return" or
      returned.get("persisted") is not True or
      returned.get("source_boot_id") != arm["source_boot_id"] or
      returned.get("return_boot_id") != COMMON.boot_id(root) or
      returned.get("stage1_sha256") != arm["stage1_sha256"] or
      stage(root, stage0, stage1) != 1):
    raise ValueError("Only an exact verified kernel EFI probe may be cleared")
  variable = root / VARIABLE
  COMMON.atomic_new_json(root / STATE / "clear-intent.json", {
    "kind": "kernel-efi-nonblocking-probe-v1-clear-intent",
    "return_boot_id": returned["return_boot_id"],
    "stage1_sha256": arm["stage1_sha256"],
  })
  if root == Path("/"):
    subprocess.run(["chattr", "-i", str(variable)], check=True)
  variable.unlink()
  if COMMON.read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("Kernel EFI probe variable still exists after cleanup")
  COMMON.atomic_new_json(root / STATE / "cleared.json", {
    "kind": "kernel-efi-nonblocking-probe-v1-cleared",
    "return_boot_id": returned["return_boot_id"],
    "stage1_sha256": arm["stage1_sha256"],
  })
  return True
