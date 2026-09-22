#!/usr/bin/env python3
"""Run the sole guarded test-resume attempt from a qualified candidate boot.

Validation is read-only. Execution requires an explicit flag, records a durable
no-repeat guard immediately before the transition, and never enters ACPI S4.
"""

import argparse
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time


HERE = Path(__file__).resolve().parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


VERIFIER = import_path("candidate_boot_verifier", HERE / "verify-hibernation-candidate-boot.py")
STAGER = VERIFIER.STAGER
WIFI = import_path(
  "candidate_wifi_isolation",
  HERE / "0008-wifi-hibernate-isolation/omarchy-t2-hibernate-wifi",
)

POWER = Path("sys/power")
SWAPS = Path("proc/swaps")
ATTEMPTS = STAGER.STATE / "test-resume-attempts"
GUARD = STAGER.STATE / "test-resume-attempted"
VECTORS = STAGER.STATE / "test-resume-vectors"
RECOVERY_UNIT = "omarchy-t2-hibernation-candidate-recovery"


def confined(root, relative):
  return VERIFIER.confined(root, relative)


def selected_value(path):
  match = re.search(r"\[([^]]+)\]", path.read_text())
  if match is None:
    raise ValueError("No selected value in " + str(path))
  return match.group(1)


def available(path, wanted):
  return wanted in path.read_text().replace("[", "").replace("]", "").split()


def write_power(path, value):
  path.write_text(value + "\n")


def run(arguments, check=True, capture=False):
  return subprocess.run(
    [str(argument) for argument in arguments],
    check=check,
    text=True,
    capture_output=capture,
  )


def bluetooth_powered(runner=run):
  result = runner(("timeout", "5s", "bluetoothctl", "show"), check=True, capture=True)
  if re.search(r"^\s*Powered:\s+yes\s*$", result.stdout, re.M):
    return True
  if re.search(r"^\s*Powered:\s+no\s*$", result.stdout, re.M):
    return False
  raise ValueError("Bluetooth power state is unavailable")


def set_bluetooth(powered, runner=run, sleeper=time.sleep):
  target = "on" if powered else "off"
  attempts = 3 if powered else 1
  for attempt in range(attempts):
    result = runner(("timeout", "5s", "bluetoothctl", "power", target), check=False, capture=True)
    if result.returncode == 0 and bluetooth_powered(runner) is powered:
      return
    if attempt + 1 < attempts:
      sleeper(1)
  raise ValueError("Bluetooth did not power " + target)


def create_guard(path, boot_id):
  path.parent.mkdir(parents=True, exist_ok=True)
  descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, "w") as stream:
    stream.write(boot_id + "\n")
    stream.flush()
    os.fsync(stream.fileno())
  STAGER.fsync_directory(path.parent)


def save_attempt(path, data):
  STAGER.atomic_write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def candidate_hash(value):
  if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
    raise ValueError("Candidate UKI hash is malformed")
  return value


def vector_paths(root, evidence):
  identity = candidate_hash(evidence.get("candidate_uki_sha256"))
  directory = confined(root, VECTORS / identity)
  return directory / "attempts", directory / "test-resume-attempted"


def legacy_consumed_hash(root):
  guard = confined(root, GUARD)
  if not guard.exists():
    return None
  boot_id = guard.read_text().strip()
  if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is None:
    raise ValueError("Legacy test-resume guard is malformed")
  attempt = confined(root, ATTEMPTS / boot_id / "attempt.json")
  if not attempt.is_file():
    raise ValueError("Legacy test-resume guard has no matching attempt evidence")
  try:
    record = json.loads(attempt.read_text())
  except json.JSONDecodeError as error:
    raise ValueError("Legacy test-resume attempt evidence is malformed") from error
  if record.get("boot_id") != boot_id:
    raise ValueError("Legacy test-resume attempt names a different boot")
  return candidate_hash(record.get("candidate_uki_sha256"))


def platform_preflight(root, candidate_directory, inspector=VERIFIER.inspect):
  boot = inspector(root, candidate_directory)
  identity = candidate_hash(boot.get("candidate_uki_sha256"))
  power = confined(root, POWER)
  required = ("state", "disk", "pm_test", "pm_trace", "resume", "resume_offset", "pm_async")
  for name in required:
    if not (power / name).is_file():
      raise ValueError("Missing hibernation interface: " + name)
  if not available(power / "state", "disk"):
    raise ValueError("Kernel does not advertise the disk power state")
  if not available(power / "disk", "test_resume"):
    raise ValueError("Kernel does not advertise test_resume")
  if not available(power / "pm_test", "none"):
    raise ValueError("Kernel does not advertise the no-test PM level")
  if (power / "resume").read_text().strip() == "0:0":
    raise ValueError("Kernel resume device is unset")
  try:
    resume_offset = int((power / "resume_offset").read_text().strip())
  except ValueError as error:
    raise ValueError("Kernel resume offset is malformed") from error
  if resume_offset <= 0:
    raise ValueError("Kernel resume offset is unset")
  if (power / "pm_async").read_text().strip() != "0":
    raise ValueError("Asynchronous PM must remain disabled for the candidate")
  swaps = [line.split() for line in confined(root, SWAPS).read_text().splitlines()[1:]]
  file_swaps = [fields for fields in swaps if len(fields) >= 2 and fields[1] == "file"]
  if len(file_swaps) != 1:
    raise ValueError("Exactly one active swap file is required")
  _directory, wifi_marker = WIFI.state_paths(root)
  if wifi_marker.exists():
    raise ValueError("A prior Wi-Fi isolation cleanup is pending")
  return {
    **boot,
    "transition_vector": identity,
    "resume": (power / "resume").read_text().strip(),
    "resume_offset": resume_offset,
    "swap_file": file_swaps[0][0],
    "pm_test_before": selected_value(power / "pm_test"),
    "disk_before": selected_value(power / "disk"),
    "pm_trace_before": (power / "pm_trace").read_text().strip(),
  }


def preflight(root, candidate_directory, inspector=VERIFIER.inspect):
  evidence = platform_preflight(root, candidate_directory, inspector)
  identity = candidate_hash(evidence.get("candidate_uki_sha256"))
  if legacy_consumed_hash(root) == identity:
    raise ValueError("The candidate test-resume attempt was already consumed by the legacy guard")
  _attempts, guard = vector_paths(root, evidence)
  if guard.exists():
    raise ValueError("The candidate test-resume attempt was already consumed")
  return evidence


def arm_recovery_timer(runner=run):
  runner((
    "systemd-run",
    "--quiet",
    "--unit=" + RECOVERY_UNIT,
    "--on-active=5min",
    "--timer-property=AccuracySec=1s",
    "/usr/bin/systemctl",
    "reboot",
  ))


def disarm_recovery_timer(runner=run):
  runner(("systemctl", "stop", RECOVERY_UNIT + ".timer", RECOVERY_UNIT + ".service"), check=False)


def execute(
  root,
  candidate_directory,
  physical_input_confirmed,
  inspector=VERIFIER.inspect,
  wifi_prepare=WIFI.prepare,
  wifi_restore=WIFI.restore,
  power_writer=write_power,
  runner=run,
  sync=os.sync,
  sleeper=time.sleep,
):
  if not physical_input_confirmed:
    raise ValueError("Physical keyboard and trackpad confirmation is required")
  evidence = preflight(root, candidate_directory, inspector)
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
    "hardware_qualified": False,
  }
  save_attempt(attempt, record)

  power = confined(root, POWER)
  bluetooth_was_powered = None
  timer_armed = False
  wifi_prepare_started = False
  transition_started = False
  try:
    bluetooth_was_powered = bluetooth_powered(runner)
    if bluetooth_was_powered:
      set_bluetooth(False, runner, sleeper)
    wifi_prepare_started = True
    wifi_prepare(root)
    power_writer(power / "pm_test", "none")
    power_writer(power / "disk", "test_resume")
    power_writer(power / "pm_trace", "1")
    timer_armed = True
    arm_recovery_timer(runner)
    record["state"] = "isolated"
    save_attempt(attempt, record)
    print(
      "omarchy-t2-hibernation-candidate: starting guarded test-resume "
      f"boot={boot_id} entry={evidence['entry_id']}",
      flush=True,
    )
    sync()

    create_guard(guard, boot_id)
    transition_started = True
    power_writer(power / "state", "disk")
    print("omarchy-t2-hibernation-candidate: test-resume returned", flush=True)
    record["state"] = "returned"
    record["hibernate_attempted"] = True
    save_attempt(attempt, record)
  except Exception as error:
    record["state"] = "transition-failed" if transition_started else "preflight-cleanup"
    record["hibernate_attempted"] = transition_started
    record["error"] = str(error)
    save_attempt(attempt, record)
    raise
  finally:
    cleanup_errors = []
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
        set_bluetooth(True, runner, sleeper)
      except Exception as error:
        cleanup_errors.append("bluetooth: " + str(error))
    if not cleanup_errors and timer_armed:
      disarm_recovery_timer(runner)
    if cleanup_errors:
      record["cleanup_errors"] = cleanup_errors
      record["state"] = "cleanup-failed"
      save_attempt(attempt, record)

  if record.get("cleanup_errors"):
    raise RuntimeError("Candidate test returned but cleanup failed: " + "; ".join(record["cleanup_errors"]))
  record["state"] = "returned-and-cleaned"
  save_attempt(attempt, record)
  print("omarchy-t2-hibernation-candidate: cleanup complete", flush=True)
  return record


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  parser.add_argument("--validate-only", action="store_true")
  parser.add_argument("--execute", action="store_true")
  parser.add_argument("--physical-input-confirmed", action="store_true")
  args = parser.parse_args()
  if args.validate_only == args.execute:
    parser.error("select exactly one of --validate-only or --execute")
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  candidate = args.candidate_source.resolve()
  try:
    if args.validate_only:
      result = preflight(Path("/"), candidate)
    else:
      result = execute(Path("/"), candidate, args.physical_input_confirmed)
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Candidate test-resume refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
