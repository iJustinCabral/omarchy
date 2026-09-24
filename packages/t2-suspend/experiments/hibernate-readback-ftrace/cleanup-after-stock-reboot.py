#!/usr/bin/python3
"""Reconcile and clean the exact consumed readback vector after a stock reboot."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent


def import_file(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


RUNNER = import_file("t2_readback_live_cleanup", HERE / "run-live-readback.py")
COMMON = RUNNER.COMMON
MARKER = RUNNER.MARKER
HEADER = RUNNER.HEADER
STATE = RUNNER.STATE
VECTOR = "6701f3dfc5473a618c7b0411e650f1ea223b8d84c0eb3e0f4f351144763b90c8"
SOURCE_BOOT = "7e684644-8756-423b-b509-5504c220dee7"
SOURCE_HEAD = "433176008e38fb34ac5f2622c82c5aa7a3c65413"
ALT_OFFSET = 10761168
STOCK_HEADER_SHA256 = "3a00c538e52aa2323a4efbf970fff729b857dbe6b2ef4ba7bec7803b9998ef3f"
ALT_HEADER_SHA256 = "ecd30051cfc6ee8fb3ab0353575da6136081aa96df0db489b78e97dd7d751d65"
RETURN_ALT_HEADER_SHA256 = "ab8bb2b214dafed4d1f3862f02d1fcd09e19d3421cf19721147bb8f1203674ba"
RETURN_ALT_HEADER_CRC32 = 3652613935
RETURN_ALT_FIRST_MAP_PAGE = 10761169
EVIDENCE = {
  "prepare-intent.json": "fb86cf4ad8664cb6258df33160d41bda2dd35c96336bb0b94cee11fcc889b1bf",
  "armed.json": "a3d337b1f195884db081f115f79fc8124f71997cf4fc9d7cc8fd314508a75653",
  "pm-attempted.json": "ca3cd478ad3b32ee408e50bd8dccb6b20d1926b36773d825cf10771fc1c4ec99",
  "pm-enter-intent.json": "e063560f08f2606d54ccfaaeee1f11e8b69af1908ae353c181bd1a17b8f5771a",
  "result.json": "55adfd5105a44d511185b897ec0653b359c017239d7f1f8dc876d871b78ccc66",
  "cleanup.json": "ab287daac171795ba3ae86f95a1d1004b9947fd34de0a493f6508be7a5637e61",
}


def exact_state():
  arm = COMMON.load_json(STATE / "armed.json", Path("/"))
  guard = COMMON.load_json(STATE / "pm-attempted.json", Path("/"))
  result = COMMON.load_json(STATE / "result.json", Path("/"))
  cleanup = COMMON.load_json(STATE / "cleanup.json", Path("/"))
  for name, expected in EVIDENCE.items():
    if COMMON.sha256_file(STATE / name) != expected:
      raise ValueError("Consumed readback evidence changed: " + name)
  if (arm.get("kind") != RUNNER.KIND or arm.get("boot_id") != SOURCE_BOOT or
      arm.get("head") != SOURCE_HEAD or arm.get("vector") != VECTOR or
      arm.get("stock_offset") != RUNNER.STOCK_OFFSET or
      arm.get("alternate_offset") != ALT_OFFSET or
      arm.get("stock_header", {}).get("page_sha256") != STOCK_HEADER_SHA256 or
      arm.get("alternate_header", {}).get("page_sha256") != ALT_HEADER_SHA256 or
      guard.get("kind") != RUNNER.KIND + "-pm-attempted" or
      guard.get("vector") != VECTOR or
      result.get("kind") != RUNNER.KIND + "-result" or
      result.get("vector") != VECTOR or result.get("success") is not True or
      result.get("observed_stage") != 2 or result.get("efi_status") != "0" or
      result.get("interceptions") != 1 or
      result.get("alternate_header_after", {}).get("page_sha256") != ALT_HEADER_SHA256 or
      result.get("stock_header_after", {}).get("page_sha256") != STOCK_HEADER_SHA256 or
      cleanup.get("kind") != RUNNER.KIND + "-cleanup" or
      cleanup.get("vector") != VECTOR or
      cleanup.get("resume_offset") != str(RUNNER.STOCK_OFFSET) or
      cleanup.get("alternate_swap_active") is not True or
      cleanup.get("abort_module_loaded") is not False or
      cleanup.get("marker_module_loaded") is not False or
      len(cleanup.get("errors", [])) != 1 or "timed out after 60 seconds" not in cleanup["errors"][0]):
    raise ValueError("Consumed readback result or cleanup differs")
  RUNNER.expected_marker(arm, 2)
  return arm


def current_stock():
  root = Path("/")
  COMMON.require_live_stock(root, allow_stage_marker=True)
  COMMON.require_live_arm_preflight(root)
  if os.uname().release != "7.2.6-arch2-Watanare-T2-2-t2":
    raise ValueError("Running kernel changed")
  if Path("/sys/class/dmi/id/product_name").read_text().strip() != "MacBookAir9,1":
    raise ValueError("Wrong hardware")
  if RUNNER.selected("pm_test") != "none" or RUNNER.selected("disk") != "platform":
    raise ValueError("PM controls differ from stock")
  if (Path("/sys/power/resume_offset").read_text().strip() != str(RUNNER.STOCK_OFFSET) or
      RUNNER.swap_offset(RUNNER.STOCK_SWAP_FILE) != RUNNER.STOCK_OFFSET or
      str(RUNNER.STOCK_SWAP_FILE) not in RUNNER.active_swap_paths()):
    raise ValueError("Original resume target or active swap differs")
  if HEADER.read_header(RUNNER.DEVICE, RUNNER.STOCK_OFFSET)["page_sha256"] != STOCK_HEADER_SHA256:
    raise ValueError("Stock swap header changed")
  current = COMMON.boot_id(root)
  alternate = HEADER.read_header(RUNNER.DEVICE, ALT_OFFSET)
  if current == SOURCE_BOOT:
    if alternate["page_sha256"] != ALT_HEADER_SHA256:
      raise ValueError("Source-boot alternate swap header changed")
  elif (alternate["page_sha256"] != RETURN_ALT_HEADER_SHA256 or
        alternate["marker"] != "normal-swap-signature" or
        alternate["flags"] != 4 or alternate["crc32"] != RETURN_ALT_HEADER_CRC32 or
        alternate["first_map_page"] != RETURN_ALT_FIRST_MAP_PAGE):
    raise ValueError("Returned alternate swap header differs from the finalized image evidence")
  if (RUNNER.SWAP_FILE.is_symlink() or not RUNNER.SWAP_FILE.is_file() or
      RUNNER.SWAP_FILE.stat().st_uid != 0 or RUNNER.SWAP_FILE.stat().st_mode & 0o077 or
      RUNNER.SWAP_FILE.stat().st_size != 10 * 1024**3 or
      RUNNER.swap_offset(RUNNER.SWAP_FILE) != ALT_OFFSET):
    raise ValueError("Exact temporary swapfile changed")
  if RUNNER.MARKER_PARAMETERS.exists() or RUNNER.ABORT_PARAMETERS.exists():
    raise ValueError("Experiment module is loaded")
  if RUNNER.command("systemctl", "--failed", "--no-legend", "--plain"):
    raise ValueError("Failed systemd units exist")
  return current


def require_marker(arm):
  value = RUNNER.expected_marker(arm, 2)
  if COMMON.read_regular(MARKER.marker_path(Path("/"))) != value:
    raise ValueError("Exact EFI stage-2 marker differs")
  return value


def mark_reboot_intent():
  current = current_stock()
  if current != SOURCE_BOOT:
    raise ValueError("Reboot intent requires the original source boot")
  arm = exact_state()
  require_marker(arm)
  if str(RUNNER.SWAP_FILE) not in RUNNER.active_swap_paths():
    raise ValueError("Alternate swap unexpectedly inactive before reboot")
  if (STATE / "reboot-intent.json").exists():
    raise ValueError("Exact stock-reboot intent already recorded")
  record = {
    "kind": RUNNER.KIND + "-stock-reboot-intent",
    "source_boot_id": SOURCE_BOOT, "vector": VECTOR,
    "stock_offset": RUNNER.STOCK_OFFSET, "alternate_offset": ALT_OFFSET,
    "marker_stage2_sha256": arm["stage2_sha256"],
    "stock_uki_sha256": COMMON.PRODUCTION_UKI_SHA256,
    "stock_limine_sha256": COMMON.PRODUCTION_LIMINE_SHA256,
  }
  COMMON.atomic_new_json(STATE / "reboot-intent.json", record)
  return record


def validate_return():
  current = current_stock()
  if current == SOURCE_BOOT:
    raise ValueError("An ordinary stock reboot has not occurred")
  arm = exact_state()
  intent = COMMON.load_json(STATE / "reboot-intent.json", Path("/"))
  if (intent.get("kind") != RUNNER.KIND + "-stock-reboot-intent" or
      intent.get("source_boot_id") != SOURCE_BOOT or intent.get("vector") != VECTOR or
      intent.get("stock_offset") != RUNNER.STOCK_OFFSET or
      intent.get("alternate_offset") != ALT_OFFSET or
      intent.get("marker_stage2_sha256") != arm["stage2_sha256"] or
      intent.get("stock_uki_sha256") != COMMON.PRODUCTION_UKI_SHA256 or
      intent.get("stock_limine_sha256") != COMMON.PRODUCTION_LIMINE_SHA256):
    raise ValueError("Stock-reboot intent differs")
  if str(RUNNER.SWAP_FILE) in RUNNER.active_swap_paths():
    raise ValueError("Temporary swapfile reactivated; do not delete it")
  if str(RUNNER.SWAP_FILE) in Path("/etc/fstab").read_text():
    raise ValueError("Temporary swapfile is referenced by fstab")
  value = require_marker(arm)
  return {"kind": RUNNER.KIND + "-stock-return", "source_boot_id": SOURCE_BOOT,
          "return_boot_id": current, "vector": VECTOR,
          "stage2_value_hex": value.hex(), "stage2_sha256": hashlib.sha256(value).hexdigest(),
          "alternate_swap_active": False,
          "alternate_header_sha256": RETURN_ALT_HEADER_SHA256,
          "alternate_header_flags": 4,
          "alternate_header_crc32": RETURN_ALT_HEADER_CRC32,
          "alternate_first_map_page": RETURN_ALT_FIRST_MAP_PAGE}


def record_return():
  record = validate_return()
  COMMON.atomic_new_json(STATE / "return.json", record)
  return record


def cleanup_return():
  observed = validate_return()
  retained = COMMON.load_json(STATE / "return.json", Path("/"))
  if retained != observed:
    raise ValueError("Recorded stock return differs from live evidence")
  clear_intent = STATE / "clear-intent.json"
  if clear_intent.exists() or clear_intent.is_symlink():
    raise ValueError("Cleanup already attempted; inspect exact evidence")
  COMMON.atomic_new_json(clear_intent, {
    "kind": RUNNER.KIND + "-clear-intent", **observed,
    "swap_file": str(RUNNER.SWAP_FILE), "swap_file_size": 10 * 1024**3,
  })
  variable = MARKER.marker_path(Path("/"))
  subprocess.run(["chattr", "-i", str(variable)], check=True, timeout=20)
  variable.unlink()
  if COMMON.read_regular(variable) is not None or variable.is_symlink():
    raise ValueError("EFI stage marker remains after exact clear")
  COMMON.atomic_new_json(STATE / "marker-cleared.json", {
    "kind": RUNNER.KIND + "-marker-cleared", "return_boot_id": observed["return_boot_id"],
    "vector": VECTOR, "stage2_sha256": observed["stage2_sha256"],
  })
  if str(RUNNER.SWAP_FILE) in RUNNER.active_swap_paths():
    raise ValueError("Temporary swapfile became active during cleanup")
  RUNNER.SWAP_FILE.unlink()
  if RUNNER.SWAP_FILE.exists() or RUNNER.SWAP_FILE.is_symlink():
    raise ValueError("Temporary swapfile remains after exact cleanup")
  COMMON.atomic_new_json(STATE / "swapfile-removed.json", {
    "kind": RUNNER.KIND + "-swapfile-removed", "return_boot_id": observed["return_boot_id"],
    "vector": VECTOR, "alternate_offset": ALT_OFFSET,
  })
  return {"marker_cleared": True, "swapfile_removed": True,
          "return_boot_id": observed["return_boot_id"]}


def main():
  os.umask(0o077)
  parser = argparse.ArgumentParser(description=__doc__)
  modes = parser.add_mutually_exclusive_group(required=True)
  modes.add_argument("--mark-reboot-intent", action="store_true")
  modes.add_argument("--validate-return", action="store_true")
  modes.add_argument("--record-return", action="store_true")
  modes.add_argument("--cleanup-return", action="store_true")
  arguments = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  if arguments.mark_reboot_intent:
    result = mark_reboot_intent()
  elif arguments.validate_return:
    result = validate_return()
  elif arguments.record_return:
    result = record_return()
  else:
    result = cleanup_return()
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
