#!/usr/bin/env python3
"""Exercise the guarded candidate test-resume runner without touching hardware."""

import importlib.util
import json
from pathlib import Path
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/run-hibernation-candidate-test.py"
spec = importlib.util.spec_from_file_location("candidate_runner", script)
candidate_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate_runner)


BOOT_ID = "11111111-2222-3333-4444-555555555555"
CANDIDATE_HASH = "deadbeef" * 8


def write(path, data):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(data)


def fixture(directory):
  root = directory / "root"
  power = root / candidate_runner.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown reboot suspend test_resume\n")
  write(power / "pm_test", "[none] core processors platform devices freezer\n")
  write(power / "pm_trace", "0\n")
  write(power / "resume", "254:0\n")
  write(power / "resume_offset", "42\n")
  write(power / "pm_async", "0\n")
  write(root / candidate_runner.SWAPS, "Filename Type Size Used Priority\n/dev/mapper/root file 8388604 0 -2\n")
  return root


def inspect(_root, _candidate):
  return {
    "qualification": "candidate-boot-preflight-passed",
    "boot_id": BOOT_ID,
    "entry_id": "MBA-T2-hibernation-candidate-deadbeefdeadbeef",
    "candidate_uki_sha256": CANDIDATE_HASH,
    "physical_input_confirmed": False,
    "hibernate_attempted": False,
    "hardware_qualified": False,
  }


class Result:
  def __init__(self, stdout="", returncode=0):
    self.stdout = stdout
    self.returncode = returncode


with tempfile.TemporaryDirectory(prefix="t2-candidate-runner-") as directory:
  base = Path(directory)
  root = fixture(base / "success")
  candidate = base / "candidate"
  candidate.mkdir()
  events = []
  bluetooth = [True]
  timer = [False]
  vector = root / candidate_runner.VECTORS / CANDIDATE_HASH

  def runner(arguments, check=True, capture=False):
    arguments = tuple(arguments)
    events.append(("command", arguments))
    if "bluetoothctl" in arguments and "show" in arguments:
      return Result("\tPowered: " + ("yes" if bluetooth[0] else "no") + "\n")
    if "bluetoothctl" in arguments and "power" in arguments:
      bluetooth[0] = arguments[-1] == "on"
      return Result()
    if arguments[0] == "systemd-run":
      timer[0] = True
      return Result()
    if arguments[:2] == ("systemctl", "stop"):
      timer[0] = False
      return Result()
    raise AssertionError("unexpected command: " + repr(arguments))

  def wifi_prepare(_root):
    events.append(("wifi", "prepare"))

  def wifi_restore(_root):
    events.append(("wifi", "restore"))

  def power_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "state":
      assert timer[0]
      assert (vector / "test-resume-attempted").read_text().strip() == BOOT_ID

  result = candidate_runner.preflight(root, candidate, inspector=inspect)
  assert result["resume_offset"] == 42
  assert result["swap_file"] == "/dev/mapper/root"
  assert result["pm_test_before"] == "none"
  assert result["disk_before"] == "platform"
  assert result["transition_vector"] == CANDIDATE_HASH

  try:
    candidate_runner.execute(root, candidate, False, inspector=inspect)
    raise AssertionError("runner accepted execution without physical input confirmation")
  except ValueError as error:
    assert "Physical keyboard" in str(error)

  result = candidate_runner.execute(
    root,
    candidate,
    True,
    inspector=inspect,
    wifi_prepare=wifi_prepare,
    wifi_restore=wifi_restore,
    power_writer=power_writer,
    runner=runner,
    sync=lambda: events.append(("sync",)),
    sleeper=lambda _seconds: None,
  )
  assert result["state"] == "returned-and-cleaned"
  assert result["physical_input_confirmed"] is True
  assert result["hibernate_attempted"] is True
  assert result["hardware_qualified"] is False
  assert bluetooth == [True]
  assert timer == [False]
  assert events.index(("wifi", "prepare")) < events.index(("power", "state", "disk"))
  assert events.index(("power", "state", "disk")) < events.index(("wifi", "restore"))
  attempt = vector / "attempts" / BOOT_ID / "attempt.json"
  assert json.loads(attempt.read_text())["state"] == "returned-and-cleaned"

  try:
    candidate_runner.preflight(root, candidate, inspector=inspect)
    raise AssertionError("consumed transition guard allowed a repeat")
  except ValueError as error:
    assert "already consumed" in str(error)

  root = fixture(base / "trace-off")
  vector = root / candidate_runner.VECTORS / CANDIDATE_HASH
  bluetooth = [True]
  timer = [False]
  events = []
  trace_off = candidate_runner.execute(
    root,
    candidate,
    True,
    inspector=inspect,
    wifi_prepare=wifi_prepare,
    wifi_restore=wifi_restore,
    power_writer=lambda path, value: events.append(("power", path.name, value)),
    runner=runner,
    sync=lambda: None,
    sleeper=lambda _seconds: None,
    pm_trace_value="0",
  )
  assert trace_off["state"] == "returned-and-cleaned"
  assert ("power", "pm_trace", "0") in events
  assert ("power", "pm_trace", "1") not in events
  assert (vector / "test-resume-attempted").exists()

  root = fixture(base / "failure")
  vector = root / candidate_runner.VECTORS / CANDIDATE_HASH
  bluetooth = [True]
  timer = [False]
  events = []

  def failing_power_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "state":
      assert (vector / "test-resume-attempted").exists()
      raise OSError("injected transition rejection")

  try:
    candidate_runner.execute(
      root,
      candidate,
      True,
      inspector=inspect,
      wifi_prepare=wifi_prepare,
      wifi_restore=wifi_restore,
      power_writer=failing_power_writer,
      runner=runner,
      sync=lambda: None,
      sleeper=lambda _seconds: None,
    )
    raise AssertionError("transition rejection was ignored")
  except OSError as error:
    assert "injected transition rejection" in str(error)
  failure = json.loads((vector / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert failure["state"] == "transition-failed"
  assert failure["hibernate_attempted"] is True
  assert (vector / "test-resume-attempted").exists()
  assert bluetooth == [True]
  assert timer == [False]
  assert ("wifi", "restore") in events

  root = fixture(base / "cleanup-failure")
  vector = root / candidate_runner.VECTORS / CANDIDATE_HASH
  bluetooth = [True]
  timer = [False]
  events = []

  def failing_wifi_restore(_root):
    events.append(("wifi", "restore-failed"))
    raise OSError("injected Wi-Fi cleanup failure")

  try:
    candidate_runner.execute(
      root,
      candidate,
      True,
      inspector=inspect,
      wifi_prepare=wifi_prepare,
      wifi_restore=failing_wifi_restore,
      power_writer=lambda path, value: events.append(("power", path.name, value)),
      runner=runner,
      sync=lambda: None,
      sleeper=lambda _seconds: None,
    )
    raise AssertionError("cleanup failure was ignored")
  except RuntimeError as error:
    assert "cleanup failed" in str(error)
  cleanup_failure = json.loads((vector / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert cleanup_failure["state"] == "cleanup-failed"
  assert "wifi" in cleanup_failure["cleanup_errors"][0]
  assert timer == [True]
  assert (vector / "test-resume-attempted").exists()

  root = fixture(base / "legacy-same-candidate")
  write(root / candidate_runner.GUARD, BOOT_ID + "\n")
  legacy_attempt = root / candidate_runner.ATTEMPTS / BOOT_ID / "attempt.json"
  write(legacy_attempt, json.dumps({
    "boot_id": BOOT_ID,
    "candidate_uki_sha256": CANDIDATE_HASH,
  }) + "\n")
  try:
    candidate_runner.preflight(root, candidate, inspector=inspect)
    raise AssertionError("legacy guard allowed the same candidate to repeat")
  except ValueError as error:
    assert "legacy guard" in str(error)

  root = fixture(base / "legacy-other-candidate")
  write(root / candidate_runner.GUARD, BOOT_ID + "\n")
  legacy_attempt = root / candidate_runner.ATTEMPTS / BOOT_ID / "attempt.json"
  write(legacy_attempt, json.dumps({
    "boot_id": BOOT_ID,
    "candidate_uki_sha256": "01234567" * 8,
  }) + "\n")
  result = candidate_runner.preflight(root, candidate, inspector=inspect)
  assert result["transition_vector"] == CANDIDATE_HASH
  assert (root / candidate_runner.GUARD).read_text().strip() == BOOT_ID

print("PASS: candidate runner validates read-only, executes once, recovers devices and preserves failed-attempt evidence")
