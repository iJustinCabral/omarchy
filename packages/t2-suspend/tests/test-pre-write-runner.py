#!/usr/bin/env python3
"""Exercise the guarded pre-image-write runner with synthetic power interfaces."""

import errno
import importlib.util
import json
from pathlib import Path
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/hibernate-pre-write-ftrace/run-pre-write.py"
spec = importlib.util.spec_from_file_location("pre_write_runner", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

BOOT_ID = "22222222-3333-4444-5555-666666666666"
CANDIDATE_HASH = "01234567" * 8
ENTRY_ID = "MBA-T2-hibernation-candidate-0123456701234567"
MODULE_HASH = "abcdef01" * 8


def write(path, content):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(content)


def fixture(base):
  root = base / "root"
  power = root / probe.TEST.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown reboot suspend test_resume\n")
  write(power / "pm_test", "[none] core processors platform devices freezer\n")
  write(power / "pm_trace", "0\n")
  armed, interceptions = probe.module_parameters(root)
  write(armed, "N\n")
  write(interceptions, "0\n")
  write(root / "sys/kernel/tracing/enabled_functions", "swsusp_write (1)\n")
  return root


def platform_preflight(_root, _candidate):
  return {
    "boot_id": BOOT_ID,
    "entry_id": ENTRY_ID,
    "candidate_uki_sha256": CANDIDATE_HASH,
    "pm_test_before": "none",
    "disk_before": "platform",
    "pm_trace_before": "0",
  }


def proof_verifier(_root, _evidence, _post_input, _candidate, _proof_candidate):
  return {"test_resume_boot_id": "11111111-2222-3333-4444-555555555555"}


def input_verifier(_root, _evidence, _input):
  return {"pre_s4_input": "/proof/current-input.json"}


def staging_verifier(_root, _evidence):
  return {"state": "arming"}


def module_verifier(module_path, expected):
  assert expected == MODULE_HASH
  return {"probe_module": str(module_path), "probe_module_sha256": expected}


def header_verifier(_evidence, _device):
  return {"marker": "normal-swap-signature", "page_sha256": "12345678" * 8}


def check(root):
  return probe.preflight(
    root, Path("candidate"), Path("proof"), Path("post-input"),
    Path("current-input"), Path("probe.ko"), MODULE_HASH, Path("resume-device"),
    platform_preflight=platform_preflight,
    proof_verifier=proof_verifier,
    current_input_verifier=input_verifier,
    staging_verifier=staging_verifier,
    module_verifier=module_verifier,
    header_verifier=header_verifier,
    services_verifier=lambda: None,
  )


class Result:
  def __init__(self, stdout="", returncode=0):
    self.stdout = stdout
    self.returncode = returncode


def exercise(root, intercept, header_changed=False):
  evidence = check(root)
  power = root / probe.TEST.POWER
  armed, interceptions = probe.module_parameters(root)
  events = []
  header_reads = [0]
  probe.TEST.bluetooth_powered = lambda _runner: False
  probe.S4.service_active = lambda _service, _runner: False

  def runner(arguments, check=True, capture=False):
    arguments = tuple(arguments)
    events.append(("command", arguments))
    if arguments[:3] == ("journalctl", "-b", "-k"):
      return Result(probe.MARKER + "\n")
    if arguments == ("systemctl", "is-active", probe.RECOVERY_UNIT + ".timer"):
      return Result("inactive\n", 3)
    return Result()

  def power_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "state":
      assert value == "disk"
      assert armed.read_text().strip() == "Y"
      assert (probe.vector_paths(root, evidence)[1]).is_file()
      if intercept:
        interceptions.write_text("1\n")
      raise OSError(errno.EIO, "controlled sysfs error")
    if path.name == "disk":
      alternatives = "shutdown reboot suspend test_resume" if value == "platform" else "platform reboot suspend test_resume"
      write(path, f"[{value}] {alternatives}\n")
    elif path.name == "pm_test":
      write(path, f"[{value}] core processors platform devices freezer\n")
    else:
      write(path, value + "\n")

  def load_disarmed(_root, _module, _runner):
    assert armed.read_text().strip() == "N"
    events.append(("module", "loaded-disarmed"))

  def unload(_root, _runner):
    armed.write_text("N\n")
    events.append(("module", "unloaded"))

  def read_header(_evidence, _device):
    header_reads[0] += 1
    suffix = "87654321" if header_changed and header_reads[0] > 0 else "12345678"
    return {"marker": "normal-swap-signature", "page_sha256": suffix * 8}

  try:
    result = probe.execute(
      root, Path("candidate"), Path("proof"), Path("post-input"),
      Path("current-input"), Path("probe.ko"), MODULE_HASH, Path("resume-device"),
      preflight_check=lambda *_args: evidence,
      runner=runner,
      wifi_prepare=lambda _root: events.append(("wifi", "detached")),
      wifi_restore=lambda _root: events.append(("wifi", "restored")),
      power_writer=power_writer,
      module_loader=load_disarmed,
      module_unloader=unload,
      header_verifier=read_header,
      sync=lambda: None,
    )
  except RuntimeError:
    if intercept and not header_changed:
      raise
    result = json.loads((probe.vector_paths(root, evidence)[0] / BOOT_ID / "attempt.json").read_text())
  return result, events


with tempfile.TemporaryDirectory(prefix="t2-pre-write-") as directory:
  base = Path(directory)
  success = fixture(base / "success")
  result, events = exercise(success, True)
  attempts, guard = probe.vector_paths(success, result)
  assert result["state"] == "returned-and-cleaned"
  assert result["interceptions"] == 1
  assert result["power_write_errno"] == errno.EIO
  assert result["swap_header_before"] == result["swap_header_after"]
  assert guard.read_text().strip() == BOOT_ID
  assert (attempts / BOOT_ID / "attempt.json").is_file()
  assert ("wifi", "detached") in events and ("wifi", "restored") in events
  assert ("module", "unloaded") in events
  assert ("power", "state", "disk") in events
  assert ("power", "disk", "test_resume") in events
  assert ("power", "disk", "platform") in events
  try:
    check(success)
  except ValueError as error:
    assert "already attempted" in str(error)
  else:
    raise AssertionError("A consumed pre-write vector was accepted")

  failure = fixture(base / "no-interception")
  result, events = exercise(failure, False)
  assert result["state"] == "transition-failed"
  assert "not intercepted exactly once" in result["error"]
  assert probe.vector_paths(failure, result)[1].is_file()
  assert ("wifi", "restored") in events
  assert ("module", "unloaded") in events

  changed = fixture(base / "header-changed")
  result, events = exercise(changed, True, header_changed=True)
  assert result["state"] == "transition-failed"
  assert "Swap header changed" in result["error"]
  assert probe.vector_paths(changed, result)[1].is_file()
  assert ("module", "unloaded") in events

  detached = fixture(base / "missing-hook")
  write(detached / "sys/kernel/tracing/enabled_functions", "unrelated_function (1)\n")
  try:
    probe.load_disarmed(detached, Path("probe.ko"), lambda _arguments: Result())
  except RuntimeError as error:
    assert "not enabled" in str(error)
  else:
    raise AssertionError("A missing ftrace attachment was accepted")

print("PASS: pre-write runner binds candidate proof and input, consumes guard once, and cleans up")
