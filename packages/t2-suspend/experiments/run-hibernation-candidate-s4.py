#!/usr/bin/env python3
"""Run one guarded real-S4 attempt after an exact runtime-stack test_resume.

The resume boot is armed to the exact running candidate UKI immediately before
entering ACPI S4. A prior candidate may supply test_resume proof only when its
kernel, command line, production PE sections and complete module stack are
identical. Limine consumes the one-shot before loading the image, so a failed
resume falls back to the unchanged production default on the next boot.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


TEST = import_path("candidate_test_resume_runner", HERE / "run-hibernation-candidate-test.py")
VERIFIER = TEST.VERIFIER
STAGER = TEST.STAGER
WIFI = TEST.WIFI
S4_VECTORS = STAGER.STATE / "s4-vectors"
REQUIRED_SERVICES = ("NetworkManager.service", "bluetooth.service", "systemd-logind.service", "display-manager.service", "bolt.service")
RUNTIME_MODULES = frozenset((
  "brcmfmac",
  "brcmfmac-bca",
  "brcmfmac-cyw",
  "brcmfmac-wcc",
  "hci_bcm4377",
  "t2bce_dma",
  "t2bce_core",
  "t2bce_vhci",
  "t2bce_audio",
  "t2bce_ave",
))
RUNTIME_SECTIONS = frozenset((
  ".text",
  ".rodata",
  ".data",
  ".sbat",
  ".sdmagic",
  ".reloc",
  ".uname",
  ".osrel",
  ".cmdline",
  ".linux",
))


def confined(root, relative):
  return VERIFIER.confined(root, relative)


def run(arguments, check=True, capture=False):
  return subprocess.run(
    [str(argument) for argument in arguments],
    check=check,
    text=True,
    capture_output=capture,
  )


def supplied_path(root, path):
  relative = path.relative_to("/") if path.is_absolute() else path
  return confined(root, relative)


def load_json_file(path, description):
  if path.is_symlink() or not path.is_file():
    raise ValueError(description + " is missing or symlinked")
  try:
    return json.loads(path.read_text())
  except json.JSONDecodeError as error:
    raise ValueError(description + " is malformed") from error


def vector_paths(root, evidence):
  identity = TEST.candidate_hash(evidence.get("candidate_uki_sha256"))
  directory = confined(root, S4_VECTORS / identity)
  return directory / "attempts", directory / "s4-attempted"


def runtime_stack_identity(provenance):
  modules = provenance.get("modules")
  sections = provenance.get("unchanged_production_sections_sha256")
  if not isinstance(modules, dict) or set(modules) != RUNTIME_MODULES:
    raise ValueError("Candidate provenance has an incomplete runtime module stack")
  if not isinstance(sections, dict) or set(sections) != RUNTIME_SECTIONS:
    raise ValueError("Candidate provenance has an incomplete production PE identity")
  if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in sections.values()):
    raise ValueError("Candidate production PE identity is malformed")
  normalized_modules = {}
  for name, metadata in modules.items():
    if not isinstance(metadata, dict):
      raise ValueError("Candidate runtime module metadata is malformed: " + name)
    normalized = {key: metadata.get(key) for key in ("source", "sha256", "srcversion", "vermagic")}
    if not all(isinstance(value, str) and value for value in normalized.values()):
      raise ValueError("Candidate runtime module metadata is incomplete: " + name)
    if re.fullmatch(r"[0-9a-f]{64}", normalized["sha256"]) is None:
      raise ValueError("Candidate runtime module hash is malformed: " + name)
    normalized_modules[name] = normalized
  descriptor = {
    "cmdline": provenance.get("cmdline"),
    "kernel_release": provenance.get("kernel_release"),
    "modules": normalized_modules,
    "production_sections": sections,
    "production_uki_sha256": provenance.get("production_uki_sha256"),
    "source_provenance_sha256": provenance.get("source_provenance_sha256"),
  }
  for name in ("cmdline", "kernel_release", "production_uki_sha256", "source_provenance_sha256"):
    if not isinstance(descriptor[name], str) or not descriptor[name]:
      raise ValueError("Candidate runtime identity omits: " + name)
  encoded = json.dumps(descriptor, separators=(",", ":"), sort_keys=True).encode()
  return hashlib.sha256(encoded).hexdigest()


def verify_test_resume_proof(root, evidence, post_input_path, candidate_directory, proof_candidate_directory):
  current_provenance = VERIFIER.load_provenance(candidate_directory)
  proof_provenance = VERIFIER.load_provenance(proof_candidate_directory)
  current_hash = TEST.candidate_hash(evidence.get("candidate_uki_sha256"))
  proof_hash = TEST.candidate_hash(proof_provenance.get("candidate_uki_sha256"))
  if current_provenance.get("candidate_uki_sha256") != current_hash:
    raise ValueError("Running candidate differs from its runtime-stack provenance")
  current_stack = runtime_stack_identity(current_provenance)
  proof_stack = runtime_stack_identity(proof_provenance)
  if proof_stack != current_stack:
    raise ValueError("test_resume proof candidate has a different runtime stack")
  if proof_hash != current_hash and current_provenance.get("pre_restore_module_policy") != "root-only-no-t2-radio":
    raise ValueError("Cross-image test_resume proof requires the isolated pre-restore policy")

  proof_evidence = {"candidate_uki_sha256": proof_hash}
  attempts, guard = TEST.vector_paths(root, proof_evidence)
  if guard.is_symlink() or not guard.is_file():
    raise ValueError("Successful test_resume guard is missing or symlinked")
  proof_boot_id = guard.read_text().strip()
  if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", proof_boot_id) is None:
    raise ValueError("Successful test_resume guard has a malformed boot ID")
  attempt = attempts / proof_boot_id / "attempt.json"
  record = load_json_file(attempt, "test_resume attempt evidence")
  proof_entry_id = STAGER.entry_id(proof_hash)
  expected = {
    "boot_id": proof_boot_id,
    "entry_id": proof_entry_id,
    "candidate_uki_sha256": proof_hash,
    "transition_vector": proof_hash,
    "state": "returned-and-cleaned",
    "hibernate_attempted": True,
    "physical_input_confirmed": True,
  }
  for key, value in expected.items():
    if record.get(key) != value:
      raise ValueError("test_resume proof mismatch: " + key)

  post_input = load_json_file(supplied_path(root, post_input_path), "post-test_resume input evidence")
  if post_input.get("boot_id") != proof_boot_id or post_input.get("entry_id") != proof_entry_id:
    raise ValueError("Post-test_resume input evidence names another boot or entry")
  if post_input.get("keyboard_seen") is not True or post_input.get("trackpad_seen") is not True:
    raise ValueError("Post-test_resume input evidence is incomplete")
  return {
    "test_resume_boot_id": proof_boot_id,
    "test_resume_candidate_uki_sha256": proof_hash,
    "test_resume_attempt": str(attempt),
    "test_resume_runtime_stack_sha256": proof_stack,
    "post_test_resume_input": str(supplied_path(root, post_input_path)),
  }


def verify_current_input(root, evidence, pre_s4_input_path):
  path = supplied_path(root, pre_s4_input_path)
  pre_s4_input = load_json_file(path, "pre-S4 input evidence")
  if pre_s4_input.get("boot_id") != evidence["boot_id"] or pre_s4_input.get("entry_id") != evidence["entry_id"]:
    raise ValueError("Pre-S4 input evidence names another boot or entry")
  if pre_s4_input.get("keyboard_seen") is not True or pre_s4_input.get("trackpad_seen") is not True:
    raise ValueError("Pre-S4 input evidence is incomplete")
  return {"pre_s4_input": str(path)}


def verify_staging(root, evidence):
  receipt = STAGER.load_receipt(root)
  if receipt.get("state") != "arming":
    raise ValueError("Candidate staging receipt is not in the consumed-arm state")
  STAGER.verify_staged(root, receipt)
  if receipt.get("entry_id") != evidence["entry_id"]:
    raise ValueError("Staged entry differs from the running candidate")
  if receipt.get("candidate_uki_sha256") != evidence["candidate_uki_sha256"]:
    raise ValueError("Staged UKI differs from the running candidate")
  if STAGER.rooted(root, STAGER.ONESHOT).exists():
    raise ValueError("Another one-shot boot is already armed")
  if STAGER.rooted(root, STAGER.DEFAULT).exists():
    raise ValueError("Persistent LoaderEntryDefault would weaken production fallback")
  return receipt


def preflight(
  root,
  candidate_directory,
  proof_candidate_directory,
  post_input_path,
  pre_s4_input_path,
  platform_preflight=TEST.platform_preflight,
  proof_verifier=verify_test_resume_proof,
  current_input_verifier=verify_current_input,
  staging_verifier=verify_staging,
):
  evidence = platform_preflight(root, candidate_directory)
  identity = TEST.candidate_hash(evidence.get("candidate_uki_sha256"))
  power = confined(root, TEST.POWER)
  if not TEST.available(power / "disk", "platform"):
    raise ValueError("Kernel does not advertise platform hibernation")
  if TEST.selected_value(power / "disk") != "platform":
    raise ValueError("Platform hibernation is not selected")
  staging_verifier(root, evidence)
  proof = proof_verifier(root, evidence, post_input_path, candidate_directory, proof_candidate_directory)
  current_input = current_input_verifier(root, evidence, pre_s4_input_path)
  attempts, guard = vector_paths(root, evidence)
  if guard.exists():
    raise ValueError("The candidate real-S4 attempt was already consumed")
  return {
    **evidence,
    **proof,
    **current_input,
    "transition_vector": identity,
    "s4_attempts": str(attempts),
    "real_s4_attempted": False,
  }


def service_active(name, runner=run):
  result = runner(("systemctl", "is-active", name), check=False, capture=True)
  return result.returncode == 0 and result.stdout.strip() == "active"


def verify_services(runner=run):
  inactive = [name for name in REQUIRED_SERVICES if not service_active(name, runner)]
  if inactive:
    raise ValueError("Required services are not active: " + ", ".join(inactive))


def arm_resume_entry(root, entry_id, runner=run, sync=os.sync):
  one_shot = STAGER.rooted(root, STAGER.ONESHOT)
  if one_shot.exists():
    raise ValueError("Another one-shot boot is already armed")
  sync()
  runner(("bootctl", "set-oneshot", entry_id))
  if not one_shot.is_file() or STAGER.read_efi_string(one_shot) != entry_id:
    raise ValueError("Resume LoaderEntryOneShot verification failed")


def clear_resume_entry(root, entry_id, runner=run):
  one_shot = STAGER.rooted(root, STAGER.ONESHOT)
  if not one_shot.exists():
    return
  if not one_shot.is_file() or STAGER.read_efi_string(one_shot) != entry_id:
    raise ValueError("Refusing to clear an unknown LoaderEntryOneShot")
  runner(("bootctl", "set-oneshot", ""))
  if one_shot.exists():
    raise ValueError("Owned LoaderEntryOneShot was not cleared")


def execute(
  root,
  candidate_directory,
  proof_candidate_directory,
  post_input_path,
  pre_s4_input_path,
  platform_preflight=TEST.platform_preflight,
  proof_verifier=verify_test_resume_proof,
  current_input_verifier=verify_current_input,
  staging_verifier=verify_staging,
  wifi_prepare=WIFI.prepare,
  wifi_restore=WIFI.restore,
  power_writer=TEST.write_power,
  runner=run,
  sync=os.sync,
  sleeper=TEST.time.sleep,
  resume_armer=arm_resume_entry,
  resume_clearer=clear_resume_entry,
  services_verifier=verify_services,
):
  evidence = preflight(
    root,
    candidate_directory,
    proof_candidate_directory,
    post_input_path,
    pre_s4_input_path,
    platform_preflight,
    proof_verifier,
    current_input_verifier,
    staging_verifier,
  )
  services_verifier(runner)
  boot_id = evidence["boot_id"]
  attempts, guard = vector_paths(root, evidence)
  attempt_directory = attempts / boot_id
  attempt_directory.mkdir(parents=True, mode=0o700)
  attempt = attempt_directory / "attempt.json"
  record = {
    **evidence,
    "state": "preparing",
    "physical_input_confirmed": True,
    "hibernate_attempted": False,
    "real_s4_attempted": False,
    "hardware_qualified": False,
  }
  TEST.save_attempt(attempt, record)

  power = confined(root, TEST.POWER)
  bluetooth_was_powered = None
  bolt_was_active = False
  wifi_prepare_started = False
  resume_armed = False
  transition_started = False
  try:
    bolt_was_active = service_active("bolt.service", runner)
    if bolt_was_active:
      runner(("systemctl", "stop", "bolt.service"))
    bluetooth_was_powered = TEST.bluetooth_powered(runner)
    if bluetooth_was_powered:
      TEST.set_bluetooth(False, runner, sleeper)
    wifi_prepare_started = True
    wifi_prepare(root)
    power_writer(power / "pm_test", "none")
    power_writer(power / "disk", "platform")
    power_writer(power / "pm_trace", "1")
    record["state"] = "isolated"
    TEST.save_attempt(attempt, record)

    resume_armer(root, evidence["entry_id"], runner, sync)
    resume_armed = True
    record["state"] = "resume-entry-armed"
    TEST.save_attempt(attempt, record)
    print(
      "omarchy-t2-hibernation-candidate: starting guarded real S4 "
      f"boot={boot_id} entry={evidence['entry_id']}",
      flush=True,
    )
    sync()
    TEST.create_guard(guard, boot_id)
    transition_started = True
    record["hibernate_attempted"] = True
    record["real_s4_attempted"] = True
    record["state"] = "transition-armed"
    TEST.save_attempt(attempt, record)
    sync()
    power_writer(power / "state", "disk")
    print("omarchy-t2-hibernation-candidate: real S4 returned", flush=True)
    record["state"] = "returned"
    TEST.save_attempt(attempt, record)

    one_shot = STAGER.rooted(root, STAGER.ONESHOT)
    if one_shot.exists():
      raise RuntimeError("Resume LoaderEntryOneShot was not consumed")
    selected = STAGER.rooted(root, STAGER.SELECTED)
    if not selected.is_file() or STAGER.read_efi_string(selected) != evidence["entry_id"]:
      raise RuntimeError("Resume boot did not select the exact candidate entry")
  except Exception as error:
    record["state"] = "transition-failed" if transition_started else "preflight-cleanup"
    record["hibernate_attempted"] = transition_started
    record["real_s4_attempted"] = transition_started
    record["error"] = str(error)
    TEST.save_attempt(attempt, record)
    raise
  finally:
    cleanup_errors = []
    if resume_armed and STAGER.rooted(root, STAGER.ONESHOT).exists():
      try:
        resume_clearer(root, evidence["entry_id"], runner)
      except Exception as error:
        cleanup_errors.append("resume-entry: " + str(error))
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
    raise RuntimeError("Real S4 returned but cleanup failed: " + "; ".join(record["cleanup_errors"]))
  record["state"] = "returned-and-cleaned"
  TEST.save_attempt(attempt, record)
  print("omarchy-t2-hibernation-candidate: real S4 cleanup complete", flush=True)
  return record


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  parser.add_argument("--test-resume-proof-source", type=Path)
  parser.add_argument("--post-resume-input-evidence", type=Path, required=True)
  parser.add_argument("--pre-s4-input-evidence", type=Path, required=True)
  parser.add_argument("--validate-only", action="store_true")
  parser.add_argument("--execute", action="store_true")
  args = parser.parse_args()
  if args.validate_only == args.execute:
    parser.error("select exactly one of --validate-only or --execute")
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    proof_candidate = (args.test_resume_proof_source or args.candidate_source).resolve()
    if args.validate_only:
      verify_services()
      result = preflight(
        Path("/"),
        args.candidate_source.resolve(),
        proof_candidate,
        args.post_resume_input_evidence,
        args.pre_s4_input_evidence,
      )
    else:
      result = execute(
        Path("/"),
        args.candidate_source.resolve(),
        proof_candidate,
        args.post_resume_input_evidence,
        args.pre_s4_input_evidence,
      )
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Candidate real-S4 refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
