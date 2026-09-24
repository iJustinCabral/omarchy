#!/usr/bin/python3
"""Validate or run one guarded source-to-restore UKI hibernation transition.

The source and restore entries must be distinct private UKIs with the same
runtime stack, and the test_resume proof must name this exact pair source.
Validation is read-only. Execution consumes a pair-wide durable guard and
pre-arms an opt-in stage marker before arming the restore one-shot; a failed
attempt cannot be retried by switching hibernation mode.
A returned runner is not proof of usable input or unattended cold-start recovery.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


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
RTC = import_path("hibernation_rtc_stage_runtime", HERE / "hibernate-rtc-stage-marker/runtime.py")
FTRACE = import_path("hibernation_ftrace_efi_stage_runtime", HERE / "hibernate-efi-ftrace-marker/s4_backend.py")
POSTWRITE = import_path("hibernation_postwrite_efi_stage_runtime", HERE / "hibernate-efi-postwrite-marker/s4_backend.py")
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


def private_evidence(path, root, description):
  if path.is_symlink() or not path.is_file():
    raise ValueError(description + " is missing or symlinked")
  metadata = path.stat()
  expected_uid = 0 if Path(root).resolve() == Path("/") else os.geteuid()
  if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise ValueError(description + " has an unsafe owner or mode")
  return S4.load_json_file(path, description)


INPUT_EVENT_WAIVER = "operator-declined-manual-events-v1"


def has_both_internal_inputs(evidence):
  devices = evidence.get("devices")
  return isinstance(devices, dict) and devices.get("internal_input_interfaces") == 2


def verify_pair_test_resume_proof(root, evidence, post_input_path, source_directory, proof_source_directory, allow_matching_early_source=False, input_event_waiver=False, allow_restore_only_revision=False):
  if Path(source_directory).resolve() != Path(proof_source_directory).resolve():
    raise ValueError("Pair test_resume proof must name this exact source image")
  source_hash = TEST.candidate_hash(evidence.get("source_uki_sha256"))
  if evidence.get("candidate_uki_sha256") != source_hash:
    raise ValueError("Running source differs from pair test_resume proof identity")
  directory = S4.confined(root, PAIR.STATE / "test-resume-vectors" / source_hash)
  guard = directory / "test-resume-attempted"
  if guard.is_symlink() or not guard.is_file():
    raise ValueError("Pair test_resume guard is missing or symlinked")
  guard_metadata = guard.stat()
  expected_uid = 0 if Path(root).resolve() == Path("/") else os.geteuid()
  if guard_metadata.st_uid != expected_uid or stat.S_IMODE(guard_metadata.st_mode) != 0o600:
    raise ValueError("Pair test_resume guard has an unsafe owner or mode")
  proof_boot_id = guard.read_text().strip()
  if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", proof_boot_id) is None:
    raise ValueError("Pair test_resume guard has a malformed boot ID")
  attempt = directory / "attempts" / proof_boot_id / "attempt.json"
  record = private_evidence(attempt, root, "Pair test_resume attempt")
  proof_restore_hash = TEST.candidate_hash(record.get("restore_uki_sha256"))
  restore_only_revision = proof_restore_hash != evidence["restore_uki_sha256"]
  if restore_only_revision and not allow_restore_only_revision:
    raise ValueError("Pair test_resume proof mismatch: restore_uki_sha256")
  expected = {
    "boot_id": proof_boot_id,
    "entry_id": evidence["source_entry_id"],
    "candidate_uki_sha256": source_hash,
    "source_uki_sha256": source_hash,
    "runtime_stack_sha256": evidence["runtime_stack_sha256"],
    "cmdline_sha256": evidence["cmdline_sha256"],
    "kernel_release": evidence["kernel_release"],
    "transition_vector": source_hash,
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "state": "returned-and-cleaned",
    "hibernate_attempted": True,
    "physical_input_confirmed": not input_event_waiver,
    "hardware_qualified": False,
  }
  for key, value in expected.items():
    if record.get(key) != value:
      raise ValueError("Pair test_resume proof mismatch: " + key)
  if record.get("cleanup_errors"):
    raise ValueError("Pair test_resume proof has cleanup errors")
  if input_event_waiver:
    if post_input_path is not None:
      raise ValueError("Input event waiver cannot be combined with post-test input evidence")
    if record.get("input_event_waiver") != INPUT_EVENT_WAIVER:
      raise ValueError("Pair test_resume proof lacks the exact input event waiver")
    if not has_both_internal_inputs(record):
      raise ValueError("Pair test_resume proof lacks both internal input interfaces")
    return {
      "test_resume_boot_id": proof_boot_id,
      "test_resume_source_uki_sha256": source_hash,
      "test_resume_attempt": str(attempt),
      "test_resume_runtime_stack_sha256": evidence["runtime_stack_sha256"],
      "test_resume_proof_restore_uki_sha256": proof_restore_hash,
      "restore_only_revision": restore_only_revision,
      "input_event_waiver": INPUT_EVENT_WAIVER,
    }
  if post_input_path is None:
    raise ValueError("Post-test_resume input evidence is required without an explicit waiver")
  post_path = S4.supplied_path(root, post_input_path)
  post_input = private_evidence(post_path, root, "Post-test_resume input evidence")
  if post_input.get("boot_id") != proof_boot_id or post_input.get("entry_id") != evidence["source_entry_id"]:
    raise ValueError("Post-test_resume input evidence names another boot or entry")
  if post_input.get("keyboard_seen") is not True or post_input.get("trackpad_seen") is not True:
    raise ValueError("Post-test_resume input evidence is incomplete")
  return {
    "test_resume_boot_id": proof_boot_id,
    "test_resume_source_uki_sha256": source_hash,
    "test_resume_attempt": str(attempt),
    "test_resume_runtime_stack_sha256": evidence["runtime_stack_sha256"],
    "test_resume_proof_restore_uki_sha256": proof_restore_hash,
    "restore_only_revision": restore_only_revision,
    "post_test_resume_input": str(post_path),
  }


def preflight(
  root,
  source_directory,
  restore_directory,
  proof_directory,
  post_input_path,
  pre_s4_input_path,
  disk_mode,
  platform_preflight=source_platform_preflight,
  proof_verifier=verify_pair_test_resume_proof,
  current_input_verifier=S4.verify_current_input,
  require_efi_marker=False,
  marker_backend=MARKER,
  input_event_waiver=False,
  allow_restore_only_revision=False,
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

  if input_event_waiver:
    if post_input_path is not None or pre_s4_input_path is not None:
      raise ValueError("Input event waiver cannot be combined with physical evidence")
    if not has_both_internal_inputs(evidence):
      raise ValueError("Input event waiver still requires both current internal interfaces")
    if allow_restore_only_revision and not isinstance(marker_backend, POSTWRITE.PostwriteRestoreEfiBackend):
      raise ValueError("Restore-only revision requires paired EFI restore instrumentation")
    proof = proof_verifier(
      root, evidence, post_input_path, source_directory, proof_directory,
      allow_matching_early_source=True, input_event_waiver=True,
      **({"allow_restore_only_revision": True} if allow_restore_only_revision else {}),
    )
    current_input = {"input_event_waiver": INPUT_EVENT_WAIVER}
  else:
    if allow_restore_only_revision and not isinstance(marker_backend, POSTWRITE.PostwriteRestoreEfiBackend):
      raise ValueError("Restore-only revision requires paired EFI restore instrumentation")
    proof = proof_verifier(
      root, evidence, post_input_path, source_directory, proof_directory,
      allow_matching_early_source=True,
      **({"allow_restore_only_revision": True} if allow_restore_only_revision else {}),
    )
    if pre_s4_input_path is None:
      raise ValueError("Pre-S4 input evidence is required without an explicit waiver")
    current_input = current_input_verifier(root, evidence, pre_s4_input_path)
  vector = pair_vector(receipt)
  attempts, guard = vector_paths(root, vector)
  if guard.exists() or attempts.exists():
    raise ValueError("The pair-wide S4 vector already has an attempt or guard")
  if require_efi_marker:
    if isinstance(marker_backend, POSTWRITE.PostwriteEfiBackend):
      restore_private = PAIR.AUDIT.load_candidate(Path(restore_directory), "restore")
      marker = restore_private.get("restore_marker")
      restore_marker_sha256 = getattr(marker_backend, "restore_module_sha256", None)
      if restore_marker_sha256 is None:
        if marker is not None:
          raise ValueError("Instrumented restore UKI requires the paired EFI restore marker backend")
      elif (not isinstance(marker, dict) or
            marker.get("sha256") != restore_marker_sha256 or
            marker.get("srcversion") != marker_backend.restore_module_srcversion or
            marker.get("version", "v1") != marker_backend.restore_variable_version or
            marker.get("efi_variable") != marker_backend.restore_variable.name):
        raise ValueError("Private restore UKI does not embed the exact EFI restore marker")
    marker_backend.require_kernel_available(root)
    if marker_backend.inspect(root, vector) is not None:
      raise ValueError("A stage marker already exists; preserve it and do not retry")
  return {
    **evidence,
    **proof,
    **current_input,
    "physical_input_confirmed": not input_event_waiver,
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
  proof_verifier=verify_pair_test_resume_proof,
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
  marker_backend=MARKER,
  operator_attended=False,
  input_event_waiver=False,
  allow_restore_only_revision=False,
):
  evidence = preflight(
    root, source_directory, restore_directory, proof_directory,
    post_input_path, pre_s4_input_path, disk_mode,
    platform_preflight, proof_verifier, current_input_verifier,
    require_efi_marker=True,
    marker_backend=marker_backend,
    input_event_waiver=input_event_waiver,
    allow_restore_only_revision=allow_restore_only_revision,
  )
  if getattr(marker_backend, "NAME", None) == "rtc" and not getattr(marker_backend, "EXECUTION_QUALIFIED", False):
    raise ValueError("RTC marker did not survive the MacBookAir9,1 forced-power return; this backend cannot qualify another S4 execution")
  if getattr(marker_backend, "NAME", None) == "ftrace-efi" and not getattr(marker_backend, "EXECUTION_QUALIFIED", False):
    raise ValueError("EFI ftrace marker lacks forced-power persistence and independent recovery proof; this backend cannot qualify S4 execution")
  operator_acceptance_sha256 = None
  if getattr(marker_backend, "NAME", None) == "postwrite-efi" and not operator_attended:
    raise ValueError("Post-write EFI S4 requires an operator at the physical power button")
  if getattr(marker_backend, "NAME", None) == "postwrite-efi":
    receipt = PAIR.load_receipt(root)
    operator_acceptance_sha256 = marker_backend.require_operator_acceptance(
      root, evidence["transition_vector"], evidence["boot_id"], receipt["production_uki_sha256"],
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
  if getattr(marker_backend, "NAME", None) == "postwrite-efi":
    record["recovery_method"] = "operator-attended-cold-power"
    record["operator_recovery_acceptance_sha256"] = operator_acceptance_sha256
  TEST.save_attempt(attempt, record)

  power = S4.confined(root, TEST.POWER)
  bluetooth_was_powered = None
  bolt_was_active = False
  wifi_prepare_started = False
  guard_consumed = False
  restore_arm_started = False
  transition_started = False
  marker_started = False
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
    power_writer(power / "pm_trace", getattr(marker_backend, "PM_TRACE_VALUE", "1"))
    record["state"] = "isolated"
    TEST.save_attempt(attempt, record)

    TEST.create_guard(guard, boot_id)
    guard_consumed = True
    record["state"] = "guard-consumed"
    TEST.save_attempt(attempt, record)
    marker_started = True
    before_arm = getattr(marker_backend, "before_arm", None)
    if before_arm is not None:
      before_arm(root, evidence["transition_vector"], boot_id, attempt_directory)
    marker_backend.enable(root)
    marker_path = marker_backend.prearm(root, evidence["transition_vector"])
    backend_name = getattr(marker_backend, "NAME", "efi")
    record[backend_name + "_stage_marker"] = marker_path
    restore_marker_path = getattr(marker_backend, "restore_marker_path", None)
    if restore_marker_path is not None:
      record["restore-efi_stage_marker"] = restore_marker_path
    record["state"] = backend_name + "-marker-armed"
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
    backend_name = getattr(marker_backend, "NAME", "efi")
    returned_stage = marker_backend.inspect(root, evidence["transition_vector"])
    record[backend_name + "_stage"] = returned_stage
    inspect_restore = getattr(marker_backend, "inspect_restore", None)
    if inspect_restore is not None:
      record["restore-efi_stage"] = inspect_restore(root, evidence["transition_vector"])
    inspect_restore_hook = getattr(marker_backend, "inspect_restore_hook", None)
    if inspect_restore_hook is not None:
      record["restore-hook-efi_stage"] = inspect_restore_hook(root, evidence["transition_vector"])
    TEST.save_attempt(attempt, record)
    if returned_stage is None or returned_stage < getattr(marker_backend, "MIN_RETURN_STAGE", 2):
      raise RuntimeError("Returned S4 without the source snapshot " + backend_name.upper() + " stage marker")
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
    cleanup_marker = getattr(marker_backend, "cleanup", None)
    if marker_started and cleanup_marker is not None:
      try:
        cleanup_marker(root, evidence["transition_vector"], boot_id, attempt_directory)
      except Exception as error:
        cleanup_errors.append("stage-marker: " + str(error))
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
  parser.add_argument("--post-resume-input-evidence", type=Path)
  parser.add_argument("--pre-s4-input-evidence", type=Path)
  parser.add_argument("--waive-input-events", action="store_true", help="record the operator's explicit choice to skip manual keyboard/trackpad events")
  parser.add_argument("--allow-restore-only-revision", action="store_true", help="reuse exact source test_resume proof when only the isolated restore UKI changed")
  parser.add_argument("--disk-mode", choices=("platform", "shutdown"), required=True)
  parser.add_argument("--validate-only", action="store_true")
  parser.add_argument("--execute", action="store_true")
  parser.add_argument("--expected-pair-vector")
  parser.add_argument("--marker-backend", choices=("efi", "rtc", "ftrace-efi", "postwrite-efi"), default="efi")
  parser.add_argument("--operator-attended", action="store_true")
  parser.add_argument("--rtc-marker-module", type=Path)
  parser.add_argument("--expected-rtc-marker-sha256")
  parser.add_argument("--ftrace-efi-marker-module", type=Path)
  parser.add_argument("--expected-ftrace-efi-marker-sha256")
  parser.add_argument("--expected-ftrace-efi-marker-srcversion")
  parser.add_argument("--postwrite-efi-marker-module", type=Path)
  parser.add_argument("--postwrite-source-marker-version", choices=("v1", "v2", "v3"), default="v1")
  parser.add_argument("--expected-postwrite-efi-marker-sha256")
  parser.add_argument("--expected-postwrite-efi-marker-srcversion")
  parser.add_argument("--restore-efi-marker-module", type=Path)
  parser.add_argument("--expected-restore-efi-marker-sha256")
  parser.add_argument("--expected-restore-efi-marker-srcversion")
  parser.add_argument("--restore-efi-marker-version", choices=("v1", "v2"), default="v1")
  arguments = parser.parse_args()
  if arguments.validate_only == arguments.execute:
    parser.error("select exactly one of --validate-only or --execute")
  if arguments.execute and arguments.expected_pair_vector is None:
    parser.error("--execute requires --expected-pair-vector")
  if arguments.waive_input_events:
    if arguments.post_resume_input_evidence is not None or arguments.pre_s4_input_evidence is not None:
      parser.error("--waive-input-events cannot be combined with physical input evidence")
  elif arguments.post_resume_input_evidence is None or arguments.pre_s4_input_evidence is None:
    parser.error("both input evidence paths are required without --waive-input-events")
  if arguments.marker_backend == "rtc":
    if arguments.rtc_marker_module is None or arguments.expected_rtc_marker_sha256 is None:
      parser.error("RTC backend requires --rtc-marker-module and --expected-rtc-marker-sha256")
    marker_backend = RTC.RTCBackend(arguments.rtc_marker_module, arguments.expected_rtc_marker_sha256)
  elif arguments.marker_backend == "ftrace-efi":
    if (arguments.ftrace_efi_marker_module is None or
        arguments.expected_ftrace_efi_marker_sha256 is None or
        arguments.expected_ftrace_efi_marker_srcversion is None):
      parser.error("Ftrace EFI backend requires exact module path, SHA-256 and source version")
    marker_backend = FTRACE.FtraceEfiBackend(
      arguments.ftrace_efi_marker_module,
      arguments.expected_ftrace_efi_marker_sha256,
      arguments.expected_ftrace_efi_marker_srcversion,
    )
  elif arguments.marker_backend == "postwrite-efi":
    if (arguments.postwrite_efi_marker_module is None or
        arguments.expected_postwrite_efi_marker_sha256 is None or
        arguments.expected_postwrite_efi_marker_srcversion is None):
      parser.error("Post-write EFI backend requires exact module path, SHA-256 and source version")
    restore_options = (
      arguments.restore_efi_marker_module,
      arguments.expected_restore_efi_marker_sha256,
      arguments.expected_restore_efi_marker_srcversion,
    )
    if all(value is None for value in restore_options):
      marker_backend = POSTWRITE.PostwriteEfiBackend(
        arguments.postwrite_efi_marker_module,
        arguments.expected_postwrite_efi_marker_sha256,
        arguments.expected_postwrite_efi_marker_srcversion,
        source_variable_version=arguments.postwrite_source_marker_version,
      )
    elif all(value is not None for value in restore_options):
      marker_backend = POSTWRITE.PostwriteRestoreEfiBackend(
        arguments.postwrite_efi_marker_module,
        arguments.expected_postwrite_efi_marker_sha256,
        arguments.expected_postwrite_efi_marker_srcversion,
        *restore_options,
        source_variable_version=arguments.postwrite_source_marker_version,
        restore_variable_version=arguments.restore_efi_marker_version,
      )
    else:
      parser.error("Restore EFI backend requires exact module path, SHA-256 and source version together")
  else:
    marker_backend = MARKER
  if arguments.marker_backend != "rtc" and (arguments.rtc_marker_module is not None or arguments.expected_rtc_marker_sha256 is not None):
    parser.error("RTC module arguments require --marker-backend rtc")
  if arguments.marker_backend != "ftrace-efi" and (arguments.ftrace_efi_marker_module is not None or arguments.expected_ftrace_efi_marker_sha256 is not None or arguments.expected_ftrace_efi_marker_srcversion is not None):
    parser.error("Ftrace EFI module arguments require --marker-backend ftrace-efi")
  if arguments.marker_backend != "postwrite-efi" and (arguments.postwrite_efi_marker_module is not None or arguments.expected_postwrite_efi_marker_sha256 is not None or arguments.expected_postwrite_efi_marker_srcversion is not None):
    parser.error("Post-write EFI module arguments require --marker-backend postwrite-efi")
  if arguments.marker_backend != "postwrite-efi" and arguments.postwrite_source_marker_version != "v1":
    parser.error("Post-write source marker version requires --marker-backend postwrite-efi")
  if arguments.marker_backend != "postwrite-efi" and (arguments.restore_efi_marker_module is not None or arguments.expected_restore_efi_marker_sha256 is not None or arguments.expected_restore_efi_marker_srcversion is not None):
    parser.error("Restore EFI module arguments require --marker-backend postwrite-efi")
  if arguments.restore_efi_marker_version != "v1" and (arguments.marker_backend != "postwrite-efi" or arguments.restore_efi_marker_module is None):
    parser.error("V2 restore EFI variable requires the paired restore marker module")
  if arguments.operator_attended and arguments.marker_backend != "postwrite-efi":
    parser.error("--operator-attended is reserved for the post-write EFI backend")
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
      result = preflight(*paths, require_efi_marker=arguments.marker_backend in ("rtc", "ftrace-efi", "postwrite-efi"), marker_backend=marker_backend, input_event_waiver=arguments.waive_input_events, allow_restore_only_revision=arguments.allow_restore_only_revision)
    else:
      result = execute(*paths, arguments.expected_pair_vector, marker_backend=marker_backend, operator_attended=arguments.operator_attended, input_event_waiver=arguments.waive_input_events, allow_restore_only_revision=arguments.allow_restore_only_revision)
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Pair cold-boot hibernation refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
