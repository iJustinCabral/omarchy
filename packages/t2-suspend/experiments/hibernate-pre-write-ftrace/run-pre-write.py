#!/usr/bin/env python3
"""Run one guarded candidate snapshot boundary probe without writing an image.

The armed ftrace module replaces swsusp_write() with -ECANCELED. This runner
requires an exact qualified candidate boot, previous matching-stack test_resume
proof, current physical-input evidence, and an independent durable guard.
"""

import argparse
import errno
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess


HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


TEST = import_path("candidate_test_resume_runner", EXPERIMENTS / "run-hibernation-candidate-test.py")
S4 = import_path("candidate_s4_runner", EXPERIMENTS / "run-hibernation-candidate-s4.py")
HEADER = import_path("hibernate_swap_header", EXPERIMENTS / "audit-hibernation-swap-header.py")
STAGER = TEST.STAGER
WIFI = TEST.WIFI
STATE = Path("var/lib/codex-mba-pre-write-ftrace")
MODULE_NAME = "mba_hibernate_pre_write_ftrace"
MARKER = "mba-hibernate-pre-write: snapshot returned; aborting before image write"
RECOVERY_UNIT = "omarchy-t2-pre-write-recovery"


def run(arguments, check=True, capture=False):
  return subprocess.run(
    [str(argument) for argument in arguments],
    check=check,
    text=True,
    capture_output=capture,
  )


def verify_module(module_path, expected_sha256):
  if module_path.is_symlink() or not module_path.is_file():
    raise ValueError("Probe module is missing or symlinked")
  if module_path.parent != Path("/var/lib/codex-mba-pre-write-ftrace"):
    raise ValueError("Probe module must be deployed in its root-owned state directory")
  if module_path.parent.is_symlink():
    raise ValueError("Probe module directory must not be symlinked")
  parent = module_path.parent.stat()
  if parent.st_uid != 0 or parent.st_mode & 0o077:
    raise ValueError("Probe module directory must be root-owned and private")
  metadata = module_path.stat()
  if metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
    raise ValueError("Probe module must be root-owned and not group/world writable")
  if hashlib.sha256(module_path.read_bytes()).hexdigest() != expected_sha256:
    raise ValueError("Probe module hash differs from the pinned build")
  vermagic = run(("modinfo", "-F", "vermagic", module_path), capture=True).stdout.strip()
  if vermagic != os.uname().release + " SMP preempt mod_unload":
    raise ValueError("Probe module vermagic differs from the running kernel")
  if Path("/sys/module", MODULE_NAME).exists():
    raise ValueError("Probe module was already loaded")
  return {"probe_module": str(module_path), "probe_module_sha256": expected_sha256}


def vector_paths(root, evidence):
  identity = TEST.candidate_hash(evidence.get("candidate_uki_sha256"))
  directory = STAGER.rooted(root, STATE / "vectors" / identity)
  return directory / "attempts", directory / "pre-write-attempted"


def verify_swap_header(evidence, resume_device):
  device = resume_device.resolve()
  metadata = device.stat()
  if not stat.S_ISBLK(metadata.st_mode):
    raise ValueError("Resume device is not a block device")
  identity = f"{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}"
  if identity != evidence["resume"]:
    raise ValueError("Resume device differs from the candidate's active resume control")
  offset = evidence["resume_offset"]
  mapped = run(("btrfs", "inspect-internal", "map-swapfile", "-r", evidence["swap_file"]), capture=True).stdout.strip()
  if mapped != str(offset):
    raise ValueError("Active swap file does not map to the configured resume offset")
  header = HEADER.read_header(device, offset)
  if header["marker"] != "normal-swap-signature":
    raise ValueError("Resume swap header is not in the normal state")
  return {"device": str(device), "page_offset": offset, **header}


def preflight(
  root,
  candidate_directory,
  proof_candidate_directory,
  post_input_path,
  current_input_path,
  module_path,
  module_sha256,
  resume_device,
  platform_preflight=TEST.platform_preflight,
  proof_verifier=S4.verify_test_resume_proof,
  current_input_verifier=S4.verify_current_input,
  staging_verifier=S4.verify_staging,
  module_verifier=verify_module,
  header_verifier=verify_swap_header,
  services_verifier=S4.verify_services,
):
  evidence = platform_preflight(root, candidate_directory)
  power = TEST.confined(root, TEST.POWER)
  if not TEST.available(power / "disk", "test_resume"):
    raise ValueError("Kernel does not advertise test_resume hibernation mode")
  staging_verifier(root, evidence)
  proof = proof_verifier(root, evidence, post_input_path, candidate_directory, proof_candidate_directory)
  current_input = current_input_verifier(root, evidence, current_input_path)
  module = module_verifier(module_path, module_sha256)
  header = header_verifier(evidence, resume_device)
  services_verifier()
  attempts, guard = vector_paths(root, evidence)
  if guard.exists() or guard.is_symlink():
    raise ValueError("This candidate pre-write boundary was already attempted")
  if attempts.is_symlink() or (attempts.exists() and any(attempts.iterdir())):
    raise ValueError("Prior pre-write attempt evidence exists without a guard")
  return {
    **evidence,
    **proof,
    **current_input,
    **module,
    "swap_header_before": header,
    "pre_write_attempts": str(attempts),
    "requested_disk_mode": "test_resume",
    "pre_write_attempted": False,
  }


def module_parameters(root):
  module = TEST.confined(root, Path("sys/module") / MODULE_NAME)
  return module / "parameters" / "armed", module / "parameters" / "interceptions"


def load_disarmed(root, module_path, runner=run):
  armed, interceptions = module_parameters(root)
  runner(("insmod", module_path))
  if armed.read_text().strip() != "N" or interceptions.read_text().strip() != "0":
    raise RuntimeError("Probe did not load disarmed with zero interceptions")
  trace = TEST.confined(root, Path("sys/kernel/tracing/enabled_functions"))
  if not any(line.split()[:1] == ["swsusp_write"] for line in trace.read_text().splitlines()):
    raise RuntimeError("swsusp_write ftrace hook is not enabled")


def unload(root, runner=run):
  armed, _interceptions = module_parameters(root)
  if armed.exists():
    armed.write_text("N\n")
    runner(("rmmod", MODULE_NAME))


def execute(
  root,
  candidate_directory,
  proof_candidate_directory,
  post_input_path,
  current_input_path,
  module_path,
  module_sha256,
  resume_device,
  preflight_check=preflight,
  runner=run,
  wifi_prepare=WIFI.prepare,
  wifi_restore=WIFI.restore,
  power_writer=TEST.write_power,
  module_loader=load_disarmed,
  module_unloader=unload,
  header_verifier=verify_swap_header,
  sync=os.sync,
):
  evidence = preflight_check(
    root, candidate_directory, proof_candidate_directory, post_input_path,
    current_input_path, module_path, module_sha256, resume_device,
  )
  boot_id = evidence["boot_id"]
  attempts, guard = vector_paths(root, evidence)
  attempt_directory = attempts / boot_id
  attempt_directory.mkdir(parents=True, mode=0o700)
  attempt = attempt_directory / "attempt.json"
  record = {**evidence, "state": "preparing", "pre_write_attempted": False, "hardware_qualified": False}
  TEST.save_attempt(attempt, record)

  power = TEST.confined(root, TEST.POWER)
  armed, interceptions = module_parameters(root)
  bluetooth_was_powered = False
  bluetooth_known = False
  bolt_was_active = False
  wifi_prepare_started = False
  module_loaded = False
  timer_armed = False
  transition_started = False
  expected_abort = False
  try:
    bolt_was_active = S4.service_active("bolt.service", runner)
    if bolt_was_active:
      runner(("systemctl", "stop", "bolt.service"))
    bluetooth_was_powered = TEST.bluetooth_powered(runner)
    bluetooth_known = True
    if bluetooth_was_powered:
      TEST.set_bluetooth(False, runner)
    wifi_prepare_started = True
    wifi_prepare(root)
    power_writer(power / "pm_test", "none")
    power_writer(power / "disk", "test_resume")
    if TEST.selected_value(power / "disk") != "test_resume":
      raise RuntimeError("test_resume mode did not select")
    power_writer(power / "pm_trace", "1")
    module_loader(root, module_path, runner)
    module_loaded = True
    runner((
      "systemd-run", "--quiet", "--unit=" + RECOVERY_UNIT,
      "--on-active=5min", "--timer-property=AccuracySec=1s",
      "/usr/bin/systemctl", "reboot",
    ))
    timer_armed = True
    record["state"] = "isolated"
    TEST.save_attempt(attempt, record)
    sync()

    TEST.create_guard(guard, boot_id)
    record["state"] = "transition-armed"
    record["pre_write_attempted"] = True
    TEST.save_attempt(attempt, record)
    armed.write_text("Y\n")
    if armed.read_text().strip() != "Y":
      raise RuntimeError("Probe did not arm")
    print(f"omarchy-t2-pre-write: guarded snapshot boundary boot={boot_id} entry={evidence['entry_id']}", flush=True)
    sync()
    transition_started = True
    try:
      power_writer(power / "state", "disk")
    except OSError as error:
      if error.errno not in (errno.ECANCELED, errno.EIO):
        raise
      record["power_write_errno"] = error.errno
    else:
      raise RuntimeError("Power transition returned without the expected controlled error")
    finally:
      armed.write_text("N\n")

    count = int(interceptions.read_text().strip())
    record["interceptions"] = count
    if count != 1:
      raise RuntimeError("Pre-write boundary was not intercepted exactly once")
    kernel_log = runner(("journalctl", "-b", "-k", "--no-pager"), capture=True).stdout
    if MARKER not in kernel_log:
      raise RuntimeError("Pre-write kernel marker is absent")
    after = header_verifier(evidence, resume_device)
    record["swap_header_after"] = after
    if after["page_sha256"] != evidence["swap_header_before"]["page_sha256"]:
      raise RuntimeError("Swap header changed during the pre-write boundary probe")
    expected_abort = True
    record["state"] = "boundary-returned"
    TEST.save_attempt(attempt, record)
  except Exception as error:
    record["state"] = "transition-failed" if transition_started else "preflight-cleanup"
    record["error"] = str(error)
    TEST.save_attempt(attempt, record)
    raise
  finally:
    cleanup_errors = []
    if module_loaded or armed.exists():
      try:
        module_unloader(root, runner)
      except Exception as error:
        cleanup_errors.append("module: " + str(error))
    for name, value in (
      ("pm_test", evidence["pm_test_before"]),
      ("disk", evidence["disk_before"]),
      ("pm_trace", evidence["pm_trace_before"]),
    ):
      try:
        power_writer(power / name, value)
      except Exception as error:
        cleanup_errors.append(name + ": " + str(error))
    if wifi_prepare_started:
      try:
        wifi_restore(root)
      except Exception as error:
        cleanup_errors.append("wifi: " + str(error))
    if bluetooth_known and bluetooth_was_powered:
      try:
        TEST.set_bluetooth(True, runner)
      except Exception as error:
        cleanup_errors.append("bluetooth: " + str(error))
    if bolt_was_active:
      try:
        runner(("systemctl", "start", "bolt.service"))
      except Exception as error:
        cleanup_errors.append("bolt: " + str(error))
    if not cleanup_errors and timer_armed:
      try:
        runner(("systemctl", "stop", RECOVERY_UNIT + ".timer"))
        runner(("systemctl", "stop", RECOVERY_UNIT + ".service"), check=False)
        active = runner(("systemctl", "is-active", RECOVERY_UNIT + ".timer"), check=False, capture=True)
        if active.returncode == 0:
          raise RuntimeError("Recovery timer remained active")
      except Exception as error:
        cleanup_errors.append("recovery timer: " + str(error))
    if cleanup_errors:
      record["cleanup_errors"] = cleanup_errors
      record["state"] = "cleanup-failed"
      TEST.save_attempt(attempt, record)

  if record.get("cleanup_errors"):
    raise RuntimeError("Pre-write boundary cleanup failed: " + "; ".join(record["cleanup_errors"]))
  if not expected_abort:
    raise RuntimeError("Pre-write boundary did not return as expected")
  record["state"] = "returned-and-cleaned"
  TEST.save_attempt(attempt, record)
  return record


def main():
  os.umask(0o077)
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  parser.add_argument("--proof-candidate-source", type=Path, required=True)
  parser.add_argument("--post-test-resume-input", type=Path, required=True)
  parser.add_argument("--current-input", type=Path, required=True)
  parser.add_argument("--module", type=Path, required=True)
  parser.add_argument("--module-sha256", required=True)
  parser.add_argument("--resume-device", type=Path, required=True)
  mode = parser.add_mutually_exclusive_group(required=True)
  mode.add_argument("--validate-only", action="store_true")
  mode.add_argument("--execute", action="store_true")
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  try:
    module_sha256 = TEST.candidate_hash(args.module_sha256)
    candidate = args.candidate_source.resolve()
    proof = args.proof_candidate_source.resolve()
    if args.validate_only:
      result = preflight(
        Path("/"), candidate, proof, args.post_test_resume_input,
        args.current_input, args.module, module_sha256, args.resume_device,
      )
    else:
      result = execute(
        Path("/"), candidate, proof, args.post_test_resume_input,
        args.current_input, args.module, module_sha256, args.resume_device,
      )
  except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
    raise SystemExit("Pre-write boundary refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
