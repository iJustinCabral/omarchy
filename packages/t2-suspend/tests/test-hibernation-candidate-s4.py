#!/usr/bin/env python3
"""Exercise the guarded real-S4 runner without touching power or EFI hardware."""

import hashlib
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


def proof_verifier(_root, _evidence, _post_input, _candidate, _proof_candidate):
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
    if path.name == "disk":
      write(path, " ".join("[" + mode + "]" if mode == value else mode for mode in ("platform", "shutdown", "reboot", "suspend", "test_resume")) + "\n")
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
  assert result["physical_input_confirmed"] is True

  result = s4.execute(
    root,
    candidate,
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
  try:
    s4.preflight(
      root,
      candidate,
      candidate,
      Path("proof/post-input.json"),
      Path("proof/pre-s4-input.json"),
      platform_preflight,
      proof_verifier,
      current_input_verifier,
      staging_verifier,
      disk_mode="shutdown",
    )
    raise AssertionError("runner allowed a consumed UKI to switch cold-boot mode")
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
    if path.name == "disk":
      write(path, " ".join("[" + mode + "]" if mode == value else mode for mode in ("platform", "shutdown", "reboot", "suspend", "test_resume")) + "\n")
    if path.name == "state":
      raise OSError("synthetic transition failure")

  try:
    s4.execute(
      root,
      candidate,
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

with tempfile.TemporaryDirectory(prefix="t2-candidate-shutdown-") as directory:
  base = Path(directory)
  root = fixture(base)
  candidate = base / "candidate"
  candidate.mkdir()
  vector = root / s4.S4_VECTORS / CANDIDATE_HASH
  modes_written = []

  def runner(arguments, check=True, capture=False):
    arguments = tuple(arguments)
    if arguments[:2] == ("systemctl", "is-active"):
      return Result("active\n")
    if arguments[:2] in (("systemctl", "stop"), ("systemctl", "start")):
      return Result()
    if "bluetoothctl" in arguments and "show" in arguments:
      return Result("\tPowered: no\n")
    if arguments[:2] == ("bootctl", "set-oneshot"):
      if arguments[-1]:
        write_efi(root / s4.STAGER.ONESHOT, arguments[-1])
      else:
        (root / s4.STAGER.ONESHOT).unlink()
      return Result()
    raise AssertionError("unexpected command: " + repr(arguments))

  def power_writer(path, value):
    if path.name == "disk":
      modes_written.append(value)
      write(path, " ".join("[" + mode + "]" if mode == value else mode for mode in ("platform", "shutdown", "reboot", "suspend", "test_resume")) + "\n")
    if path.name == "state":
      assert s4.TEST.selected_value(root / s4.TEST.POWER / "disk") == "shutdown"
      assert (vector / "s4-attempted").read_text().strip() == BOOT_ID
      (root / s4.STAGER.ONESHOT).unlink()

  result = s4.preflight(
    root, candidate, candidate, Path("proof/post-input.json"), Path("proof/pre-s4-input.json"),
    platform_preflight, proof_verifier, current_input_verifier, staging_verifier, disk_mode="shutdown",
  )
  assert result["requested_disk_mode"] == "shutdown"
  write(root / s4.TEST.POWER / "disk", "[platform] reboot suspend test_resume\n")
  try:
    s4.preflight(
      root, candidate, candidate, Path("proof/post-input.json"), Path("proof/pre-s4-input.json"),
      platform_preflight, proof_verifier, current_input_verifier, staging_verifier, disk_mode="shutdown",
    )
    raise AssertionError("runner accepted unavailable shutdown hibernation")
  except ValueError as error:
    assert "does not advertise requested" in str(error)
  write(root / s4.TEST.POWER / "disk", "[platform] shutdown reboot suspend test_resume\n")

  try:
    s4.execute(
      root, candidate, candidate, Path("proof/post-input.json"), Path("proof/pre-s4-input.json"),
      platform_preflight, proof_verifier, current_input_verifier, staging_verifier,
      lambda _root: None, lambda _root: None, lambda _path, _value: None, runner,
      sync=lambda: None, sleeper=lambda _seconds: None, services_verifier=lambda _runner: None,
      disk_mode="shutdown",
    )
    raise AssertionError("runner accepted a shutdown mode that did not select")
  except RuntimeError as error:
    assert "did not select" in str(error)
  assert not (vector / "s4-attempted").exists()

  root = fixture(base / "verified-mode")
  vector = root / s4.S4_VECTORS / CANDIDATE_HASH
  result = s4.execute(
    root, candidate, candidate, Path("proof/post-input.json"), Path("proof/pre-s4-input.json"),
    platform_preflight, proof_verifier, current_input_verifier, staging_verifier,
    lambda _root: None, lambda _root: None, power_writer, runner,
    sync=lambda: None, sleeper=lambda _seconds: None, services_verifier=lambda _runner: None,
    disk_mode="shutdown",
  )
  assert result["state"] == "returned-and-cleaned"
  assert result["requested_disk_mode"] == "shutdown"
  assert modes_written == ["shutdown", "platform"]
  assert s4.TEST.selected_value(root / s4.TEST.POWER / "disk") == "platform"

with tempfile.TemporaryDirectory(prefix="t2-candidate-s4-proof-") as directory:
  base = Path(directory)
  root = fixture(base)
  candidate = base / "candidate"
  proof_candidate = base / "proof-candidate"
  candidate.mkdir()
  proof_candidate.mkdir()
  (candidate / "mba-t2-hibernation-candidate.efi").write_bytes(b"isolated candidate")
  (proof_candidate / "mba-t2-hibernation-candidate.efi").write_bytes(b"successful proof candidate")
  candidate_hash = hashlib.sha256((candidate / "mba-t2-hibernation-candidate.efi").read_bytes()).hexdigest()
  proof_hash = hashlib.sha256((proof_candidate / "mba-t2-hibernation-candidate.efi").read_bytes()).hexdigest()
  candidate_entry = s4.STAGER.entry_id(candidate_hash)
  proof_entry = s4.STAGER.entry_id(proof_hash)
  modules = {
    name: {
      "source": "modules/" + name + ".ko",
      "sha256": hashlib.sha256(name.encode()).hexdigest(),
      "srcversion": "SRC_" + name,
      "vermagic": "7.2.6-test-t2 SMP preempt mod_unload",
    }
    for name in s4.RUNTIME_MODULES
  }
  sections = {
    ".linux": "1" * 64,
    ".cmdline": "2" * 64,
    ".uname": "3" * 64,
    ".osrel": "4" * 64,
    ".text": "7" * 64,
    ".rodata": "8" * 64,
    ".data": "9" * 64,
    ".sbat": "a" * 64,
    ".sdmagic": "b" * 64,
    ".reloc": "c" * 64,
  }
  shared_provenance = {
    "candidate": "mba-t2-hibernation-module-overlay",
    "cmdline": "resume=/dev/mapper/root resume_offset=42",
    "kernel_release": "7.2.6-test-t2",
    "modules": modules,
    "production_uki_sha256": "5" * 64,
    "source_provenance_sha256": "6" * 64,
    "unchanged_production_sections_sha256": sections,
  }
  candidate_provenance = {
    **shared_provenance,
    "candidate_uki_sha256": candidate_hash,
    "pre_restore_module_policy": "root-only-no-t2-radio",
  }
  proof_provenance = {**shared_provenance, "candidate_uki_sha256": proof_hash}
  (candidate / "provenance.json").write_text(json.dumps(candidate_provenance))
  (proof_candidate / "provenance.json").write_text(json.dumps(proof_provenance))

  evidence = platform_preflight(root, Path("candidate"))
  evidence["candidate_uki_sha256"] = candidate_hash
  evidence["entry_id"] = candidate_entry
  attempts, guard = s4.TEST.vector_paths(root, {"candidate_uki_sha256": proof_hash})
  write(guard, PROOF_BOOT_ID + "\n")
  write(
    attempts / PROOF_BOOT_ID / "attempt.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": proof_entry,
      "candidate_uki_sha256": proof_hash,
      "transition_vector": proof_hash,
      "state": "returned-and-cleaned",
      "hibernate_attempted": True,
      "physical_input_confirmed": True,
    }),
  )
  write(
    root / "proof/post-input.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": proof_entry,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  write(
    root / "proof/pre-s4-input.json",
    json.dumps({
      "boot_id": BOOT_ID,
      "entry_id": candidate_entry,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  proof = s4.verify_test_resume_proof(
    root,
    evidence,
    Path("proof/post-input.json"),
    candidate,
    proof_candidate,
  )
  assert proof["test_resume_boot_id"] == PROOF_BOOT_ID
  assert proof["test_resume_candidate_uki_sha256"] == proof_hash
  assert proof["test_resume_runtime_stack_sha256"] == s4.runtime_stack_identity(candidate_provenance)
  assert PROOF_BOOT_ID != BOOT_ID
  current = s4.verify_current_input(root, evidence, Path("proof/pre-s4-input.json"))
  assert current["pre_s4_input"].endswith("proof/pre-s4-input.json")
  write(
    root / "proof/pre-s4-input.json",
    json.dumps({
      "boot_id": PROOF_BOOT_ID,
      "entry_id": candidate_entry,
      "keyboard_seen": True,
      "trackpad_seen": True,
    }),
  )
  try:
    s4.verify_current_input(root, evidence, Path("proof/pre-s4-input.json"))
    raise AssertionError("runner accepted pre-S4 input evidence from an earlier boot")
  except ValueError as error:
    assert "another boot or entry" in str(error)

  no_policy = json.loads((candidate / "provenance.json").read_text())
  del no_policy["pre_restore_module_policy"]
  (candidate / "provenance.json").write_text(json.dumps(no_policy))
  try:
    s4.verify_test_resume_proof(
      root,
      evidence,
      Path("proof/post-input.json"),
      candidate,
      proof_candidate,
    )
    raise AssertionError("runner accepted cross-image proof without isolated pre-restore policy")
  except ValueError as error:
    assert "requires the isolated pre-restore policy" in str(error)
  (candidate / "provenance.json").write_text(json.dumps(candidate_provenance))

  changed_proof = json.loads((proof_candidate / "provenance.json").read_text())
  changed_proof["modules"]["t2bce_core"]["sha256"] = "f" * 64
  (proof_candidate / "provenance.json").write_text(json.dumps(changed_proof))
  try:
    s4.verify_test_resume_proof(
      root,
      evidence,
      Path("proof/post-input.json"),
      candidate,
      proof_candidate,
    )
    raise AssertionError("runner accepted test_resume proof from a different runtime stack")
  except ValueError as error:
    assert "different runtime stack" in str(error)

print("PASS: real-S4 runner accepts only exact runtime-stack proof, arms exact resume UKI and executes once")
