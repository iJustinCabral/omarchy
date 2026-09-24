#!/usr/bin/python3
"""Exercise the paired source test-resume guard without touching host PM."""

import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/run-hibernation-uki-pair-test-resume.py"
spec = importlib.util.spec_from_file_location("hibernation_pair_test_resume", script)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

BOOT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ENTRY = "MBA-T2-hibernation-source-" + "a" * 16
SOURCE_SHA = "a" * 64
RESTORE_SHA = "b" * 64


def write(path, data):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(data)


def fixture(directory):
  root = directory / "root"
  power = root / runner.TEST.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown test_resume\n")
  write(power / "pm_test", "[none] devices freezer\n")
  write(power / "pm_trace", "0\n")
  write(power / "resume", "254:0\n")
  write(power / "resume_offset", "42\n")
  write(power / "pm_async", "0\n")
  write(root / runner.TEST.SWAPS, "Filename Type Size Used Priority\n/swap/swapfile file 8388604 0 -2\n")
  write(root / "proc/cmdline", "root=/dev/mapper/root resume=/dev/mapper/root resume_offset=42\n")
  evidence = root / "var/lib/physical-input/evidence.json"
  write(evidence, json.dumps({
    "boot_id": BOOT_ID,
    "entry_id": ENTRY,
    "keyboard_seen": True,
    "trackpad_seen": True,
  }) + "\n")
  evidence.chmod(0o600)
  return root, Path("/var/lib/physical-input/evidence.json")


def inspect(_root, _source, _restore):
  return {
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "boot_id": BOOT_ID,
    "source_entry_id": ENTRY,
    "source_uki_sha256": SOURCE_SHA,
    "restore_entry_id": "MBA-T2-hibernation-restore-" + "b" * 16,
    "restore_uki_sha256": RESTORE_SHA,
    "devices": {"internal_input_interfaces": 2},
  }


original_inspect = runner.SOURCE.inspect
runner.SOURCE.inspect = inspect


def expect_refusal(operation, message):
  try:
    operation()
    raise AssertionError("unsafe pair test-resume state passed")
  except ValueError as error:
    assert message in str(error), str(error)


try:
  with tempfile.TemporaryDirectory(prefix="t2-pair-test-resume-") as directory:
    base = Path(directory)
    source = base / "source"
    restore = base / "restore"
    source.mkdir()
    restore.mkdir()

    root, input_path = fixture(base / "success")
    evidence = runner.preflight(root, source, restore, input_path)
    assert evidence["candidate_uki_sha256"] == SOURCE_SHA
    assert evidence["physical_input_confirmed"] is True
    assert evidence["pm_trace_before"] == "0"
    assert evidence["pre_test_input_sha256"]
    assert runner.TEST.VECTORS == runner.PAIR.STATE / "test-resume-vectors"

    calls = []

    def fake_execute(host, candidate, confirmed, inspector, pm_trace_value, label, physical_input_waiver):
      calls.append((host, candidate, confirmed, pm_trace_value, label, physical_input_waiver))
      assert inspector(host, candidate)["pre_test_input_sha256"] == evidence["pre_test_input_sha256"]
      return {"state": "returned-and-cleaned"}

    expect_refusal(lambda: runner.execute(root, source, restore, input_path, SOURCE_SHA, False, candidate_execute=fake_execute), "operator")
    expect_refusal(lambda: runner.execute(root, source, restore, input_path, RESTORE_SHA, True, candidate_execute=fake_execute), "Explicit source")
    result = runner.execute(root, source, restore, input_path, SOURCE_SHA, True, candidate_execute=fake_execute)
    assert result["state"] == "returned-and-cleaned"
    assert calls == [(root, source, True, "0", "omarchy-t2-hibernation-pair", False)]

    guard = root / runner.TEST.VECTORS / SOURCE_SHA / "test-resume-attempted"
    write(guard, BOOT_ID + "\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "already consumed")

    root, input_path = fixture(base / "synthetic-transition")
    commands = []
    power_writes = []
    bluetooth = [True]

    class Result:
      def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode

    def command(arguments, check=True, capture=False):
      arguments = tuple(arguments)
      commands.append(arguments)
      if "bluetoothctl" in arguments and "show" in arguments:
        return Result("Powered: " + ("yes" if bluetooth[0] else "no") + "\n")
      if "bluetoothctl" in arguments and "power" in arguments:
        bluetooth[0] = arguments[-1] == "on"
      return Result()

    def power_writer(path, value):
      power_writes.append((path.name, value))
      if path.name == "state":
        assert (root / runner.TEST.VECTORS / SOURCE_SHA / "test-resume-attempted").is_file()

    def synthetic_execute(host, candidate, confirmed, inspector, pm_trace_value, label, physical_input_waiver):
      return runner.TEST.execute(
        host, candidate, confirmed, inspector=inspector,
        wifi_prepare=lambda _root: None,
        wifi_restore=lambda _root: None,
        power_writer=power_writer,
        runner=command,
        sync=lambda: None,
        sleeper=lambda _seconds: None,
        pm_trace_value=pm_trace_value,
        label=label,
        physical_input_waiver=physical_input_waiver,
      )

    result = runner.execute(root, source, restore, input_path, SOURCE_SHA, True, candidate_execute=synthetic_execute)
    assert result["state"] == "returned-and-cleaned"
    assert result["entry_id"] == ENTRY
    assert result["pre_test_input_sha256"]
    assert ("pm_trace", "1") not in power_writes
    assert ("pm_trace", "0") in power_writes
    assert ("state", "disk") in power_writes
    assert bluetooth == [True]
    assert any(arguments[0] == "systemd-run" for arguments in commands)
    attempt = root / runner.TEST.VECTORS / SOURCE_SHA / "attempts" / BOOT_ID / "attempt.json"
    assert json.loads(attempt.read_text())["state"] == "returned-and-cleaned"
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "already consumed")

    root, _input_path = fixture(base / "explicit-input-waiver")
    waived = runner.preflight(root, source, restore, None, input_event_waiver=True)
    assert waived["physical_input_confirmed"] is False
    assert waived["input_event_waiver"] == "operator-declined-manual-events-v1"
    expect_refusal(lambda: runner.preflight(root, source, restore, None), "required without an explicit waiver")
    expect_refusal(lambda: runner.preflight(root, source, restore, _input_path, input_event_waiver=True), "cannot be combined")
    result = runner.execute(root, source, restore, None, SOURCE_SHA, True,
                            candidate_execute=synthetic_execute, input_event_waiver=True)
    assert result["state"] == "returned-and-cleaned"
    assert result["physical_input_confirmed"] is False
    assert result["input_event_waiver"] == "operator-declined-manual-events-v1"
    attempt = root / runner.TEST.VECTORS / SOURCE_SHA / "attempts" / BOOT_ID / "attempt.json"
    stored = json.loads(attempt.read_text())
    assert stored["physical_input_confirmed"] is False
    assert stored["input_event_waiver"] == "operator-declined-manual-events-v1"
    expect_refusal(lambda: runner.preflight(root, source, restore, None, input_event_waiver=True), "already consumed")

    root, input_path = fixture(base / "prepared-no-guard")
    (root / runner.TEST.VECTORS / SOURCE_SHA / "attempts").mkdir(parents=True)
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "already been prepared")

    root, input_path = fixture(base / "wrong-boot")
    evidence_file = runner.supplied_path(root, input_path)
    recorded = json.loads(evidence_file.read_text())
    recorded["boot_id"] = "11111111-2222-3333-4444-555555555555"
    evidence_file.write_text(json.dumps(recorded))
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "another boot")

    root, input_path = fixture(base / "unsafe-mode")
    runner.supplied_path(root, input_path).chmod(0o644)
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "unsafe owner or mode")

    root, input_path = fixture(base / "pm-trace-on")
    write(root / runner.TEST.POWER / "pm_trace", "1\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "PM tracing must be off")

    root, input_path = fixture(base / "changed-offset")
    write(root / runner.TEST.POWER / "resume_offset", "43\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "Runtime resume target")

    root, input_path = fixture(base / "changed-swap")
    write(root / runner.TEST.SWAPS, "Filename Type Size Used Priority\n/swap/other file 8388604 0 -2\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "Primary production swap")

    root, input_path = fixture(base / "changed-pm-mode")
    write(root / runner.TEST.POWER / "pm_test", "none [devices] freezer\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "PM controls")

    root, input_path = fixture(base / "efi-default")
    write(root / runner.PAIR.SINGLE.DEFAULT, "unowned\n")
    expect_refusal(lambda: runner.preflight(root, source, restore, input_path), "Persistent EFI default")
finally:
  runner.SOURCE.inspect = original_inspect

print("PASS: pair test-resume requires exact input, source identity, clean PM tracing and one-use vector")
