#!/usr/bin/python3
"""Run one guarded in-place image restore on an exact paired source boot.

This does not select the restore UKI or enter ACPI S4. A successful return
does not qualify a cold image restore or lift the independent-reset S4 gate.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import stat


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


SOURCE = import_path("hibernation_pair_source_verifier", HERE / "verify-hibernation-uki-pair-source.py")
TEST = import_path("hibernation_candidate_test_runner", HERE / "run-hibernation-candidate-test.py")
PAIR = SOURCE.PAIR
TEST.VECTORS = PAIR.STATE / "test-resume-vectors"


def supplied_path(root, path):
  relative = path.relative_to("/") if path.is_absolute() else path
  return TEST.confined(root, relative)


def verify_input(root, evidence, input_path):
  path = supplied_path(root, input_path)
  if path.is_symlink() or not path.is_file():
    raise ValueError("Exact-entry physical-input evidence is missing or symlinked")
  metadata = path.stat()
  expected_uid = 0 if root.resolve() == Path("/") else os.geteuid()
  if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise ValueError("Physical-input evidence has an unsafe owner or mode")
  try:
    recorded = json.loads(path.read_text())
  except json.JSONDecodeError as error:
    raise ValueError("Physical-input evidence is malformed") from error
  if recorded.get("boot_id") != evidence["boot_id"] or recorded.get("entry_id") != evidence["entry_id"]:
    raise ValueError("Physical-input evidence names another boot or entry")
  if recorded.get("keyboard_seen") is not True or recorded.get("trackpad_seen") is not True:
    raise ValueError("Physical-input evidence is incomplete")
  return {"physical_input_confirmed": True, "pre_test_input": str(path), "pre_test_input_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def pair_inspector(source_directory, restore_directory, input_path):
  def inspect(root, _candidate_directory):
    evidence = SOURCE.inspect(root, source_directory, restore_directory)
    if PAIR.rooted(root, PAIR.SINGLE.DEFAULT).exists():
      raise ValueError("Persistent EFI default would weaken stock fallback")
    result = {
      **evidence,
      "entry_id": evidence["source_entry_id"],
      "candidate_uki_sha256": evidence["source_uki_sha256"],
    }
    return {**result, **verify_input(root, result, input_path)}

  return inspect


def preflight(root, source_directory, restore_directory, input_path):
  inspector = pair_inspector(source_directory, restore_directory, input_path)
  evidence = TEST.preflight(root, source_directory, inspector=inspector)
  cmdline = TEST.confined(root, Path("proc/cmdline")).read_text().split()
  expected_offset = next((item.split("=", 1)[1] for item in cmdline if item.startswith("resume_offset=")), None)
  if expected_offset != str(evidence["resume_offset"]) or "resume=/dev/mapper/root" not in cmdline:
    raise ValueError("Runtime resume target differs from the production command line")
  if evidence["swap_file"] != "/swap/swapfile":
    raise ValueError("Primary production swap file is not the sole active file swap")
  if evidence["pm_test_before"] != "none" or evidence["disk_before"] != "platform":
    raise ValueError("PM controls are not at the source boot baseline")
  if evidence["pm_trace_before"] != "0":
    raise ValueError("PM tracing must be off for the pair test")
  attempts, guard = TEST.vector_paths(root, evidence)
  if attempts.exists() or guard.exists():
    raise ValueError("The pair source test-resume vector has already been prepared or consumed")
  return evidence


def execute(root, source_directory, restore_directory, input_path, expected_source_sha256, operator_attended, candidate_execute=TEST.execute):
  if not operator_attended:
    raise ValueError("An operator must be present for physical cold-power recovery")
  evidence = preflight(root, source_directory, restore_directory, input_path)
  if TEST.candidate_hash(expected_source_sha256) != evidence["source_uki_sha256"]:
    raise ValueError("Explicit source SHA-256 differs from the selected UKI")
  inspector = pair_inspector(source_directory, restore_directory, input_path)
  return candidate_execute(root, source_directory, True, inspector=inspector, pm_trace_value="0", label="omarchy-t2-hibernation-pair")


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--restore", type=Path, required=True)
  parser.add_argument("--physical-input-evidence", type=Path, required=True)
  parser.add_argument("--validate-only", action="store_true")
  parser.add_argument("--execute", action="store_true")
  parser.add_argument("--expected-source-sha256")
  parser.add_argument("--operator-attended", action="store_true")
  arguments = parser.parse_args()
  if arguments.validate_only == arguments.execute:
    parser.error("select exactly one of --validate-only or --execute")
  if arguments.execute and arguments.expected_source_sha256 is None:
    parser.error("--execute requires --expected-source-sha256")
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  root = Path("/")
  source = arguments.source.resolve()
  restore = arguments.restore.resolve()
  try:
    if arguments.validate_only:
      result = preflight(root, source, restore, arguments.physical_input_evidence)
    else:
      result = execute(root, source, restore, arguments.physical_input_evidence, arguments.expected_source_sha256, arguments.operator_attended)
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Pair test-resume refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
