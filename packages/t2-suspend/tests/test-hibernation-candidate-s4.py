#!/usr/bin/env python3
"""Exercise the guarded real-S4 runner without touching power or EFI hardware."""

import importlib.util
import json
from pathlib import Path
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/run-hibernation-candidate-s4.py"
spec = importlib.util.spec_from_file_location("candidate_s4_runner", script)
s4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s4)


BOOT_ID = "22222222-3333-4444-5555-666666666666"
PROOF_BOOT_ID = "11111111-2222-3333-4444-555555555555"
CANDIDATE_HASH = "01234567" * 8
ENTRY_ID = "MBA-T2-hibernation-candidate-0123456701234567"


def write(path, data):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(data)


def write_efi(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le"))


def fixture(directory):
  root = directory / "root"
  power = root / s4.TEST.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown reboot suspend test_resume\n")
  write(power / "pm_test", "[none] core processors platform devices freezer\n")
  write(power / "pm_trace", "0\n")
  write(power / "resume", "254:0\n")
  write(power / "resume_offset", "42\n")
  write(power / "pm_async", "0\n")
  write_efi(root / s4.STAGER.SELECTED, ENTRY_ID)
  return root


def platform_preflight(_root, _candidate):
  return {
    "qualification": "candidate-boot-preflight-passed",
    "boot_id": BOOT_ID,
    "entry_id": ENTRY_ID,
    "candidate_uki_sha256": CANDIDATE_HASH,
    "physical_input_confirmed": False,
    "hibernate_attempted": False,
    "hardware_qualified": False,
    "resume": "254:0",
    "resume_offset": 42,
    "swap_file": "/swap/swapfile",
    "pm_test_before": "none",
    "disk_before": "platform",
    "pm_trace_before": "0",
  }


def proof_verifier(_root, _evidence, _post_input):
  return {
    "test_resume_boot_id": PROOF_BOOT_ID,
    "test_resume_attempt": "/proof/test-resume.json",
    "post_test_resume_input": "/proof/post-input.json",
  }


def current_input_verifier(_root, _evidence, _pre_s4_input):
  return {"pre_s4_input": "/proof/pre-s4-input.json"}


def staging_verifier(_root, _evidence):
  return {"state": "arming"}


class Result:
  def __init__(self, stdout="", returncode=0):
    self.stdout = stdout
    self.returncode = returncode


with tempfile.TemporaryDirectory(prefix="t2-candidate-s4-") as directory:
  base = Path(directory)
  root = fixture(base / "success")
  candidate = base / "candidate"
  candidate.mkdir()
  events = []
  bluetooth = [True]
  bolt = [True]
  vector = root / s4.S4_VECTORS / CANDIDATE_HASH

  def runner(arguments, check=True, capture=False):
    arguments = tuple(arguments)
    events.append(("command", arguments))
    if arguments[:2] == ("systemctl", "is-active"):
      return Result("active\n" if bolt[0] else "inactive\n", 0 if bolt[0] else 3)
    if arguments[:2] == ("systemctl", "stop"):
      bolt[0] = False
      return Result()
    if arguments[:2] == ("systemctl", "start"):
      bolt[0] = True
      return Result()
    if "bluetoothctl" in arguments and "show" in arguments:
      return Result("\tPowered: " + ("yes" if bluetooth[0] else "no") + "\n")
    if "bluetoothctl" in arguments and "power" in arguments:
      bluetooth[0] = arguments[-1] == "on"
      return Result()
    if arguments[:2] == ("bootctl", "set-oneshot"):
      if arguments[-1]:
        write_efi(root / s4.STAGER.ONESHOT, arguments[-1])
      else:
        (root / s4.STAGER.ONESHOT).unlink()
      return Result()
    raise AssertionError("unexpected command: " + repr(arguments))

  def wifi_prepare(_root):
    events.append(("wifi", "prepare"))

  def wifi_restore(_root):
    events.append(("wifi", "restore"))

  def power_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "state":
      assert (vector / "s4-attempted").read_text().strip() == BOOT_ID
      armed = json.loads((vector / "attempts" / BOOT_ID / "attempt.json").read_text())
      assert armed["state"] == "transition-armed"
      assert armed["real_s4_attempted"] is True
      assert s4.STAGER.read_efi_string(root / s4.STAGER.ONESHOT) == ENTRY_ID
      (root / s4.STAGER.ONESHOT).unlink()

  result = s4.preflight(
    root,
    candidate,
    Path("proof/post-input.json"),
    Path("proof/pre-s4-input.json"),
    platform_preflight,
    proof_verifier,
    current_input_verifier,
    staging_verifier,
  )
  assert result["transition_vector"] == CANDIDATE_HASH
  assert result["real_s4_attempted"] is False

  result = s4.execute(
    root,
    candidate,
    Path("proof/post-input.json"),
    Path("proof/pre-s4-input.json"),
    platform_preflight,
    proof_verifier,
    current_input_verifier,
    staging_verifier,
    wifi_prepare,
    wifi_restore,
    power_writer,
    runner,
    sync=lambda: events.append(("sync",)),
    sleeper=lambda _seconds: None,
    services_verifier=lambda _runner: None,
  )
  assert result["state"] == "returned-and-cleaned"
  assert result["hibernate_attempted"] is True
  assert result["real_s4_attempted"] is True
  assert result["hardware_qualified"] is False
  assert bluetooth == [True]
  assert bolt == [True]
  assert not (root / s4.STAGER.ONESHOT).exists()
  assert events.index(("command", ("systemctl", "stop", "bolt.service"))) < events.index(("wifi", "prepare"))
  assert events.index(("wifi", "prepare")) < events.index(("command", ("bootctl", "set-oneshot", ENTRY_ID)))
  assert events.index(("command", ("bootctl", "set-oneshot", ENTRY_ID))) < events.index(("power", "state", "disk"))
  assert events.index(("power", "state", "disk")) < events.index(("wifi", "restore"))
  attempt = vector / "attempts" / BOOT_ID / "attempt.json"
  assert json.loads(attempt.read_text())["state"] == "returned-and-cleaned"

  try:
    s4.preflight(
      root,
      candidate,
      Path("proof/post-input.json"),
      Path("proof/pre-s4-input.json"),
      platform_preflight,
      proof_verifier,
      current_input_verifier,
      staging_verifier,
    )
    raise AssertionError("runner accepted a consumed real-S4 vector")
  except ValueError as error:
    assert "already consumed" in str(error)

with tempfile.TemporaryDirectory(prefix="t2-candidate-s4-failure-") as directory:
  base = Path(directory)
  root = fixture(base)
  candidate = base / "candidate"
  candidate.mkdir()
  bluetooth = [True]
  bolt = [True]

  def runner(arguments, check=True, capture=False):
    arguments = tuple(arguments)
    if arguments[:2] == ("systemctl", "is-active"):
      return Result("active\n")
    if arguments[:2] == ("systemctl", "stop"):
      bolt[0] = False
      return Result()
    if arguments[:2] == ("systemctl", "start"):
      bolt[0] = True
      return Result()
    if "bluetoothctl" in arguments and "show" in arguments:
      return Result("\tPowered: " + ("yes" if bluetooth[0] else "no") + "\n")
    if "bluetoothctl" in arguments and "power" in arguments:
      bluetooth[0] = arguments[-1] == "on"
      return Result()
    if arguments[:2] == ("bootctl", "set-oneshot"):
      if arguments[-1]:
        write_efi(root / s4.STAGER.ONESHOT, arguments[-1])
      else:
        (root / s4.STAGER.ONESHOT).unlink()
      return Result()
    raise AssertionError("unexpected command: " + repr(arguments))

  def fail_state(path, value):
    if path.name == "state":
      raise OSError("synthetic transition failure")

  try:
    s4.execute(
      root,
      candidate,
      Path("proof/post-input.json"),
      Path("proof/pre-s4-input.json"),
      platform_preflight,
      proof_verifier,
      current_input_verifier,
      staging_verifier,
      lambda _root: None,
      lambda _root: None,
      fail_state,
      runner,
      sync=lambda: None,
      sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None,
    )
    raise AssertionError("runner hid a real-S4 transition failure")
  except OSError as error:
    assert "synthetic transition failure" in str(error)
  assert not (root / s4.STAGER.ONESHOT).exists()
  assert bluetooth == [True]
  assert bolt == [True]
  attempt = root / s4.S4_VECTORS / CANDIDATE_HASH / "attempts" / BOOT_ID / "attempt.json"
  record = json.loads(attempt.read_text())
  assert record["state"] == "transition-failed"
  assert record["hibernate_attempted"] is True
  assert record["real_s4_attempted"] is True

with tempfile.TemporaryDirectory(prefix="t2-candidate-s4-proof-") as directory:
  root = fixture(Path(directory))
  evidence = platform_preflight(root, Path("candidate"))
  attempts, guard = s4.TEST.vector_paths(root, evidence)
  write(guard, PROOF_BOOT_ID + "\n")
  write(
    attempts / PROOF_BOOT_ID / "attempt.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": ENTRY_ID,
      "candidate_uki_sha256": CANDIDATE_HASH,
      "transition_vector": CANDIDATE_HASH,
      "state": "returned-and-cleaned",
      "hibernate_attempted": True,
      "physical_input_confirmed": True,
    }),
  )
  write(
    root / "proof/post-input.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": ENTRY_ID,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  write(
    root / "proof/pre-s4-input.json",
    json.dumps({
      "boot_id": BOOT_ID,
      "entry_id": ENTRY_ID,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  proof = s4.verify_test_resume_proof(root, evidence, Path("proof/post-input.json"))
  assert proof["test_resume_boot_id"] == PROOF_BOOT_ID
  assert PROOF_BOOT_ID != BOOT_ID
  current = s4.verify_current_input(root, evidence, Path("proof/pre-s4-input.json"))
  assert current["pre_s4_input"].endswith("proof/pre-s4-input.json")
  write(
    root / "proof/pre-s4-input.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": ENTRY_ID,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  try:
    s4.verify_current_input(root, evidence, Path("proof/pre-s4-input.json"))
    raise AssertionError("runner accepted pre-S4 input evidence from an earlier boot")
  except ValueError as error:
    assert "another boot or entry" in str(error)

print("PASS: real-S4 runner arms exact resume UKI, executes once and restores isolated devices")
