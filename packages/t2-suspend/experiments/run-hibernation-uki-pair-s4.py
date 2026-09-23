#!/usr/bin/python3
"""Validate or run one guarded source-to-restore UKI hibernation transition.

The source and restore entries must be distinct private UKIs with the same
runtime stack. Validation is read-only. Execution consumes a pair-wide durable
guard and pre-arms an opt-in EFI stage marker before arming the restore
one-shot; a failed attempt cannot be retried by switching hibernation mode.
A returned runner is not proof of usable input or unattended cold-start recovery.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


SOURCE = import_path("hibernation_pair_source_verifier", HERE / "verify-hibernation-uki-pair-source.py")
PAIR = SOURCE.PAIR
S4 = import_path("hibernation_candidate_s4_runner", HERE / "run-hibernation-candidate-s4.py")
MARKER = import_path("hibernation_efi_stage_marker", HERE / "hibernate-efi-stage-marker/marker.py")
TEST = S4.TEST
WIFI = S4.WIFI
VECTORS = PAIR.STATE / "s4-vectors"


def pair_vector(receipt):
  source = TEST.candidate_hash(receipt["images"]["source"]["sha256"])
  restore = TEST.candidate_hash(receipt["images"]["restore"]["sha256"])
  runtime = TEST.candidate_hash(receipt["runtime_stack_sha256"])
  return hashlib.sha256((source + ":" + restore + ":" + runtime).encode()).hexdigest()


def vector_paths(root, vector):
  identity = TEST.candidate_hash(vector)
  directory = S4.confined(root, VECTORS / identity)
  return directory / "attempts", directory / "s4-attempted"


def source_platform_preflight(root, source_directory, restore_directory):
  def inspect_pair(host, _candidate):
    source = SOURCE.inspect(host, source_directory, restore_directory)
    return {
      **source,
      "entry_id": source["source_entry_id"],
      "candidate_uki_sha256": source["source_uki_sha256"],
    }

  return TEST.platform_preflight(root, source_directory, inspector=inspect_pair)


def preflight(
  root,
  source_directory,
  restore_directory,
  proof_directory,
  post_input_path,
  pre_s4_input_path,
  disk_mode,
  platform_preflight=source_platform_preflight,
  proof_verifier=S4.verify_test_resume_proof,
  current_input_verifier=S4.verify_current_input,
  require_efi_marker=False,
):
  if disk_mode not in ("platform", "shutdown"):
    raise ValueError("Unsupported cold-boot hibernation mode")
  evidence = platform_preflight(root, source_directory, restore_directory)
  receipt = PAIR.load_receipt(root)
  PAIR.verify_staged(root, receipt)
  if receipt.get("state") != "source-arming":
    raise ValueError("Pair is not in the consumed source-arm state")
  if receipt["images"]["source"]["sha256"] != evidence.get("source_uki_sha256"):
    raise ValueError("Running source differs from staged pair")
  if receipt["images"]["restore"]["sha256"] != evidence.get("restore_uki_sha256"):
    raise ValueError("Restore differs from staged pair")

  power = S4.confined(root, TEST.POWER)
  if not TEST.available(power / "disk", disk_mode):
    raise ValueError("Kernel does not advertise requested hibernation mode")
  selected_mode = TEST.selected_value(power / "disk")
  if selected_mode not in ("platform", "shutdown"):
    raise ValueError("Unexpected initial hibernation mode")
  if disk_mode == "platform" and selected_mode != "platform":
    raise ValueError("Platform hibernation is not selected")

  proof = proof_verifier(
    root, evidence, post_input_path, source_directory, proof_directory,
    allow_matching_early_source=True,
  )
  current_input = current_input_verifier(root, evidence, pre_s4_input_path)
  vector = pair_vector(receipt)
  attempts, guard = vector_paths(root, vector)
  if guard.exists() or attempts.exists():
    raise ValueError("The pair-wide S4 vector already has an attempt or guard")
  if require_efi_marker:
    MARKER.require_kernel_available(root)
    if MARKER.inspect(root, vector) is not None:
      raise ValueError("An EFI stage marker already exists; preserve it and do not retry")
  return {
    **evidence,
    **proof,
    **current_input,
    "physical_input_confirmed": True,
    "transition_vector": vector,
    "requested_disk_mode": disk_mode,
    "s4_attempts": str(attempts),
    "real_s4_attempted": False,
  }


def execute(
  root,
  source_directory,
  restore_directory,
  proof_directory,
  post_input_path,
  pre_s4_input_path,
  disk_mode,
  expected_pair_vector,
  platform_preflight=source_platform_preflight,
  proof_verifier=S4.verify_test_resume_proof,
  current_input_verifier=S4.verify_current_input,
  wifi_prepare=WIFI.prepare,
  wifi_restore=WIFI.restore,
  power_writer=TEST.write_power,
  runner=S4.run,
  sync=os.sync,
  sleeper=TEST.time.sleep,
  services_verifier=S4.verify_services,
  restore_armer=PAIR.arm_restore,
  restore_disarmer=PAIR.disarm_restore,
):
  evidence = preflight(
    root, source_directory, restore_directory, proof_directory,
    post_input_path, pre_s4_input_path, disk_mode,
    platform_preflight, proof_verifier, current_input_verifier,
    require_efi_marker=True,
  )
  if TEST.candidate_hash(expected_pair_vector) != evidence["transition_vector"]:
    raise ValueError("Explicit pair-wide vector does not match the staged images")
  services_verifier(runner)
  boot_id = evidence["boot_id"]
  attempts, guard = vector_paths(root, evidence["transition_vector"])
  attempt_directory = attempts / boot_id
  attempt_directory.mkdir(parents=True, mode=0o700)
  attempt = attempt_directory / "attempt.json"
  record = {
    **evidence,
    "state": "preparing",
    "hibernate_attempted": False,
    "real_s4_attempted": False,
    "hardware_qualified": False,
  }
  TEST.save_attempt(attempt, record)

  power = S4.confined(root, TEST.POWER)
  bluetooth_was_powered = None
  bolt_was_active = False
  wifi_prepare_started = False
  guard_consumed = False
  restore_arm_started = False
  transition_started = False
  try:
    bolt_was_active = S4.service_active("bolt.service", runner)
    if bolt_was_active:
      runner(("systemctl", "stop", "bolt.service"))
    bluetooth_was_powered = TEST.bluetooth_powered(runner)
    if bluetooth_was_powered:
      TEST.set_bluetooth(False, runner, sleeper)
    wifi_prepare_started = True
    wifi_prepare(root)
    power_writer(power / "pm_test", "none")
    power_writer(power / "disk", disk_mode)
    if TEST.selected_value(power / "disk") != disk_mode:
      raise RuntimeError("Requested hibernation mode did not select")
    power_writer(power / "pm_trace", "1")
    record["state"] = "isolated"
    TEST.save_attempt(attempt, record)

    TEST.create_guard(guard, boot_id)
    guard_consumed = True
    record["state"] = "guard-consumed"
    TEST.save_attempt(attempt, record)
    MARKER.enable(root)
    record["efi_stage_marker"] = MARKER.prearm(root, evidence["transition_vector"])
    record["state"] = "efi-marker-armed"
    TEST.save_attempt(attempt, record)
    restore_arm_started = True
    restore_armer(root, runner=runner, sync=sync)
    record["state"] = "restore-entry-armed"
    TEST.save_attempt(attempt, record)
    print(
      "omarchy-t2-hibernation-pair: starting guarded cold-boot hibernation "
      f"boot={boot_id} source={evidence['source_entry_id']} restore={evidence['restore_entry_id']} mode={disk_mode}",
      flush=True,
    )
    sync()
    transition_started = True
    record["hibernate_attempted"] = True
    record["real_s4_attempted"] = True
    record["state"] = "transition-armed"
    TEST.save_attempt(attempt, record)
    sync()
    power_writer(power / "state", "disk")
    record["state"] = "returned"
    record["efi_stage"] = MARKER.inspect(root, evidence["transition_vector"])
    TEST.save_attempt(attempt, record)
    if record["efi_stage"] != 2:
      raise RuntimeError("Returned S4 without the source snapshot EFI stage marker")
    if PAIR.rooted(root, PAIR.SINGLE.ONESHOT).exists():
      raise RuntimeError("Restore LoaderEntryOneShot was not consumed")
    if PAIR.selected_entry(root) != evidence["restore_entry_id"]:
      raise RuntimeError("Resume boot did not select the exact restore entry")
  except Exception as error:
    if transition_started:
      record["state"] = "transition-failed"
    elif guard_consumed:
      record["state"] = "guard-consumed-pretransition-failure"
    else:
      record["state"] = "preflight-cleanup"
    record["hibernate_attempted"] = transition_started
    record["real_s4_attempted"] = transition_started
    record["error"] = str(error)
    TEST.save_attempt(attempt, record)
    raise
  finally:
    cleanup_errors = []
    one_shot = PAIR.rooted(root, PAIR.SINGLE.ONESHOT)
    if restore_arm_started and one_shot.exists():
      try:
        restore_disarmer(root, runner=runner)
      except Exception as error:
        cleanup_errors.append("restore-entry: " + str(error))
    for name, value in (
      ("pm_test", evidence["pm_test_before"]),
      ("disk", evidence["disk_before"]),
      ("pm_trace", evidence["pm_trace_before"]),
    ):
      try:
        power_writer(power / name, value)
      except Exception as error:
        cleanup_errors.append(f"{name}: {error}")
    if wifi_prepare_started:
      try:
        wifi_restore(root)
      except Exception as error:
        cleanup_errors.append("wifi: " + str(error))
    if bluetooth_was_powered:
      try:
        TEST.set_bluetooth(True, runner, sleeper)
      except Exception as error:
        cleanup_errors.append("bluetooth: " + str(error))
    if bolt_was_active:
      try:
        runner(("systemctl", "start", "bolt.service"))
      except Exception as error:
        cleanup_errors.append("bolt: " + str(error))
    if cleanup_errors:
      record["cleanup_errors"] = cleanup_errors
      record["state"] = "cleanup-failed"
      TEST.save_attempt(attempt, record)

  if record.get("cleanup_errors"):
    raise RuntimeError("Pair S4 returned but cleanup failed: " + "; ".join(record["cleanup_errors"]))
  record["state"] = "returned-and-cleaned"
  TEST.save_attempt(attempt, record)
  print("omarchy-t2-hibernation-pair: S4 cleanup complete; physical input still unverified", flush=True)
  return record


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--restore", type=Path, required=True)
  parser.add_argument("--test-resume-proof-source", type=Path, required=True)
  parser.add_argument("--post-resume-input-evidence", type=Path, required=True)
  parser.add_argument("--pre-s4-input-evidence", type=Path, required=True)
  parser.add_argument("--disk-mode", choices=("platform", "shutdown"), required=True)
  parser.add_argument("--validate-only", action="store_true")
  parser.add_argument("--execute", action="store_true")
  parser.add_argument("--expected-pair-vector")
  arguments = parser.parse_args()
  if arguments.validate_only == arguments.execute:
    parser.error("select exactly one of --validate-only or --execute")
  if arguments.execute and arguments.expected_pair_vector is None:
    parser.error("--execute requires --expected-pair-vector")
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    paths = (
      Path("/"), arguments.source.resolve(), arguments.restore.resolve(),
      arguments.test_resume_proof_source.resolve(),
      arguments.post_resume_input_evidence, arguments.pre_s4_input_evidence,
      arguments.disk_mode,
    )
    if arguments.validate_only:
      S4.verify_services()
      result = preflight(*paths)
    else:
      result = execute(*paths, arguments.expected_pair_vector)
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Pair cold-boot hibernation refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
