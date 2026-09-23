#!/usr/bin/python3
"""Test pair-wide S4 guarding and one-shot cleanup without host PM or EFI."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/run-hibernation-uki-pair-s4.py"
spec = importlib.util.spec_from_file_location("hibernation_pair_s4", script)
pair_s4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair_s4)
pair = pair_s4.PAIR
BOOT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ARMING_BOOT_ID = "11111111-2222-3333-4444-555555555555"


def write(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(value)


def write_efi(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le"))


def efi_strings(values):
  return b"\x06\x00\x00\x00" + "".join(value + "\x00" for value in values).encode("utf-16-le")


def fixture(directory):
  root = directory / "root"
  production = root / "boot/EFI/Linux/omarchy_linux-t2.efi"
  production.parent.mkdir(parents=True)
  production.write_bytes(b"production")
  write(root / pair.SINGLE.LIMINE, (
    "timeout: 3\n"
    "default_entry: 2\n"
    "/+Omarchy\n"
    "  //linux-t2\n"
    "  protocol: efi\n"
    "  path: boot():/EFI/Linux/omarchy_linux-t2.efi#"
    + hashlib.blake2b(production.read_bytes()).hexdigest() + "\n"
  ))
  write_efi(root / pair.SINGLE.SELECTED, "Omarchy.linux-t2")
  write(root / pair.BOOT_ID, ARMING_BOOT_ID + "\n")
  source = directory / "source"
  restore = directory / "restore"
  proof = directory / "proof"
  for path in (source, restore, proof):
    path.mkdir()
  source_data = b"private source"
  restore_data = b"private restore"
  images = {
    role: {
      "data": data,
      "sha256": hashlib.sha256(data).hexdigest(),
      "blake2": hashlib.blake2b(data).hexdigest(),
      "provenance_sha256": hashlib.sha256((role + "-provenance").encode()).hexdigest(),
      "experiment_id": "synthetic-" + role,
    }
    for role, data in (("source", source_data), ("restore", restore_data))
  }
  runtime = hashlib.sha256(b"common stack").hexdigest()
  original_load_pair = pair.load_pair
  original_verify_sections = pair.verify_production_boot_sections
  pair.load_pair = lambda _source, _restore: (
    {"runtime_stack_sha256": runtime}, images,
    {"production_uki_sha256": hashlib.sha256(production.read_bytes()).hexdigest()},
  )
  pair.verify_production_boot_sections = lambda _production, _images, _expected: hashlib.sha256(production.read_bytes()).hexdigest()
  try:
    receipt = pair.stage(root, source, restore)
  finally:
    pair.load_pair = original_load_pair
    pair.verify_production_boot_sections = original_verify_sections
  entries = root / pair.SINGLE.ENTRIES
  entries.parent.mkdir(parents=True, exist_ok=True)
  entries.write_bytes(efi_strings(("Omarchy.linux-t2", receipt["images"]["source"]["entry_id"], receipt["images"]["restore"]["entry_id"])))

  def source_bootctl(arguments, check):
    assert arguments == ["bootctl", "set-oneshot", receipt["images"]["source"]["entry_id"]] and check
    write_efi(root / pair.SINGLE.ONESHOT, arguments[2])

  pair.arm_source(root, runner=source_bootctl, sync=lambda: None)
  (root / pair.SINGLE.ONESHOT).unlink()
  write_efi(root / pair.SINGLE.SELECTED, receipt["images"]["source"]["entry_id"])
  write(root / pair.BOOT_ID, BOOT_ID + "\n")
  power = root / pair_s4.TEST.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown reboot suspend test_resume\n")
  write(power / "pm_test", "[none] core processors platform devices freezer\n")
  write(power / "pm_trace", "0\n")
  write(power / "resume", "254:0\n")
  write(power / "resume_offset", "42\n")
  write(power / "pm_async", "0\n")
  write(root / pair_s4.MARKER.KERNEL_PARAMETER, "N\n")
  (root / pair_s4.MARKER.VARIABLE).parent.mkdir(parents=True, exist_ok=True)
  return root, source, restore, proof, receipt, power


def platform_preflight(root, _source, _restore):
  receipt = pair.load_receipt(root)
  return {
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "boot_id": BOOT_ID,
    "entry_id": receipt["images"]["source"]["entry_id"],
    "candidate_uki_sha256": receipt["images"]["source"]["sha256"],
    "source_entry_id": receipt["images"]["source"]["entry_id"],
    "source_uki_sha256": receipt["images"]["source"]["sha256"],
    "restore_entry_id": receipt["images"]["restore"]["entry_id"],
    "restore_uki_sha256": receipt["images"]["restore"]["sha256"],
    "pm_test_before": "none",
    "disk_before": "platform",
    "pm_trace_before": "0",
    "resume": "254:0",
    "resume_offset": 42,
    "swap_file": "/swap/swapfile",
  }


def proof_verifier(_root, _evidence, _post, _source, _proof, allow_matching_early_source):
  assert allow_matching_early_source is True
  return {"test_resume_boot_id": "22222222-3333-4444-5555-666666666666"}


def input_verifier(_root, _evidence, _pre):
  return {"pre_s4_input": "/proof/pre-input.json"}


class Result:
  def __init__(self, stdout="", returncode=0):
    self.stdout = stdout
    self.returncode = returncode


def fake_runner(root, events, bluetooth, bolt):
  def run(arguments, check=True, capture=False):
    args = tuple(arguments)
    events.append(("command", args))
    if args[:2] == ("systemctl", "is-active"):
      return Result("active\n" if bolt[0] else "inactive\n", 0 if bolt[0] else 3)
    if args[:2] == ("systemctl", "stop"):
      bolt[0] = False
      return Result()
    if args[:2] == ("systemctl", "start"):
      bolt[0] = True
      return Result()
    if "bluetoothctl" in args and "show" in args:
      return Result("\tPowered: " + ("yes" if bluetooth[0] else "no") + "\n")
    if "bluetoothctl" in args and "power" in args:
      bluetooth[0] = args[-1] == "on"
      return Result()
    if args[:2] == ("bootctl", "set-oneshot"):
      if args[-1]:
        write_efi(root / pair.SINGLE.ONESHOT, args[-1])
      else:
        (root / pair.SINGLE.ONESHOT).unlink()
      return Result()
    raise AssertionError("Unexpected command: " + repr(args))

  return run


def power_writer(root, receipt, events, fail_state=False, marker_stage=2):
  def write_power(path, value):
    events.append(("power", path.name, value))
    if path.name == "disk":
      write(path, " ".join("[" + mode + "]" if mode == value else mode for mode in ("platform", "shutdown", "reboot", "suspend", "test_resume")) + "\n")
    if path.name == "state":
      vector = pair_s4.pair_vector(receipt)
      guard = root / pair_s4.VECTORS / vector / "s4-attempted"
      assert guard.read_text().strip() == BOOT_ID
      record = json.loads((guard.parent / "attempts" / BOOT_ID / "attempt.json").read_text())
      assert record["state"] == "transition-armed"
      assert pair_s4.MARKER.inspect(root, vector) == 0
      assert pair.SINGLE.read_efi_string(root / pair.SINGLE.ONESHOT) == receipt["images"]["restore"]["entry_id"]
      if fail_state:
        raise OSError("synthetic S4 failure")
      if marker_stage is not None:
        (root / pair_s4.MARKER.VARIABLE).write_bytes(pair_s4.MARKER.ATTRIBUTES + pair_s4.MARKER.payload(vector, marker_stage))
      (root / pair.SINGLE.ONESHOT).unlink()
      write_efi(root / pair.SINGLE.SELECTED, receipt["images"]["restore"]["entry_id"])

  return write_power


with tempfile.TemporaryDirectory(prefix="t2-pair-s4-") as temporary:
  base = Path(temporary)
  root, source, restore, proof, receipt, _power = fixture(base / "success")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  result = pair_s4.preflight(*inputs, platform_preflight, proof_verifier, input_verifier)
  assert result["transition_vector"] == vector
  assert result["physical_input_confirmed"] is True
  assert result["real_s4_attempted"] is False
  marker_parameter = root / pair_s4.MARKER.KERNEL_PARAMETER
  marker_parameter.unlink()
  try:
    pair_s4.execute(*inputs, vector, platform_preflight, proof_verifier, input_verifier)
    raise AssertionError("Execution accepted a kernel without the EFI marker patch")
  except ValueError as error:
    assert "no T2 EFI stage-marker parameter" in str(error)
  write(marker_parameter, "N\n")
  marker_variable = root / pair_s4.MARKER.VARIABLE
  marker_variable.write_bytes(pair_s4.MARKER.ATTRIBUTES + pair_s4.MARKER.payload(vector, 2))
  try:
    pair_s4.execute(*inputs, vector, platform_preflight, proof_verifier, input_verifier)
    raise AssertionError("Execution accepted a stale EFI marker")
  except ValueError as error:
    assert "already exists" in str(error)
  assert not (root / pair_s4.VECTORS / vector).exists()
  marker_variable.unlink()
  events = []
  bluetooth = [True]
  bolt = [True]
  runner = fake_runner(root, events, bluetooth, bolt)
  try:
    pair_s4.execute(
      *inputs, "0" * 64, platform_preflight, proof_verifier, input_verifier,
      runner=runner, services_verifier=lambda _runner: None,
    )
    raise AssertionError("Wrong explicit pair vector was accepted")
  except ValueError as error:
    assert "does not match" in str(error)
  assert not (root / pair_s4.VECTORS / vector).exists()

  result = pair_s4.execute(
    *inputs, vector, platform_preflight, proof_verifier, input_verifier,
    wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
    wifi_restore=lambda _root: events.append(("wifi", "restore")),
    power_writer=power_writer(root, receipt, events),
    runner=runner,
    sync=lambda: events.append(("sync",)),
    sleeper=lambda _seconds: None,
    services_verifier=lambda _runner: None,
  )
  assert result["state"] == "returned-and-cleaned"
  assert result["hibernate_attempted"] is True
  assert result["hardware_qualified"] is False
  assert result["efi_stage"] == 2
  assert bluetooth == [True] and bolt == [True]
  assert not (root / pair.SINGLE.ONESHOT).exists()
  arm_event = ("command", ("bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"]))
  assert events.index(("wifi", "prepare")) < events.index(arm_event)
  assert pair_s4.MARKER.inspect(root, vector) == 2
  assert events.index(arm_event) < events.index(("power", "state", "disk"))
  assert events.index(("power", "state", "disk")) < events.index(("wifi", "restore"))
  try:
    pair_s4.preflight(*inputs, platform_preflight, proof_verifier, input_verifier)
    raise AssertionError("Consumed pair vector was accepted")
  except ValueError as error:
    assert "consumed source-arm state" in str(error) or "already has an attempt or guard" in str(error)

  root, source, restore, proof, receipt, _power = fixture(base / "missing-return-marker")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  events = []
  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: None, wifi_restore=lambda _root: None,
      power_writer=power_writer(root, receipt, events, marker_stage=None),
      runner=fake_runner(root, events, [True], [True]),
      sync=lambda: None, sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None,
    )
    raise AssertionError("Returned S4 without snapshot marker was accepted")
  except RuntimeError as error:
    assert "without the source snapshot EFI stage marker" in str(error)
  assert pair_s4.MARKER.inspect(root, vector) == 0
  assert not (root / pair.SINGLE.ONESHOT).exists()
  missing_guard = root / pair_s4.VECTORS / vector / "s4-attempted"
  assert missing_guard.read_text().strip() == BOOT_ID
  missing_attempt = json.loads((missing_guard.parent / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert missing_attempt["state"] == "transition-failed"
  assert missing_attempt["real_s4_attempted"] is True

  root, source, restore, proof, receipt, _power = fixture(base / "failure")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "shutdown")
  events = []
  bluetooth = [True]
  bolt = [True]
  runner = fake_runner(root, events, bluetooth, bolt)
  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: None, wifi_restore=lambda _root: None,
      power_writer=power_writer(root, receipt, events, fail_state=True),
      runner=runner, sync=lambda: None, sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None,
    )
    raise AssertionError("Synthetic S4 failure was hidden")
  except OSError as error:
    assert "synthetic S4 failure" in str(error)
  assert not (root / pair.SINGLE.ONESHOT).exists()
  assert pair.load_receipt(root)["state"] == "restore-disarmed"
  assert bluetooth == [True] and bolt == [True]
  guard = root / pair_s4.VECTORS / vector / "s4-attempted"
  assert guard.read_text().strip() == BOOT_ID
  attempt = json.loads((guard.parent / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert attempt["state"] == "transition-failed"
  assert attempt["real_s4_attempted"] is True
  for mode in ("platform", "shutdown"):
    try:
      pair_s4.preflight(root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), mode, platform_preflight, proof_verifier, input_verifier)
      raise AssertionError("Pair mode switch bypassed the failed guard")
    except ValueError as error:
      assert "consumed source-arm state" in str(error) or "already has an attempt or guard" in str(error)

  root, source, restore, proof, receipt, _power = fixture(base / "marker-failure")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  events = []
  original_prearm = pair_s4.MARKER.prearm

  def failed_marker_readback(host, identity):
    original_prearm(host, identity)
    raise RuntimeError("injected EFI readback failure")

  pair_s4.MARKER.prearm = failed_marker_readback
  try:
    try:
      pair_s4.execute(
        *inputs, vector, platform_preflight, proof_verifier, input_verifier,
        wifi_prepare=lambda _root: None, wifi_restore=lambda _root: None,
        power_writer=power_writer(root, receipt, events),
        runner=fake_runner(root, events, [True], [True]),
        sync=lambda: None, sleeper=lambda _seconds: None,
        services_verifier=lambda _runner: None,
      )
      raise AssertionError("EFI marker failure was hidden")
    except RuntimeError as error:
      assert "injected EFI readback failure" in str(error)
  finally:
    pair_s4.MARKER.prearm = original_prearm
  assert pair_s4.MARKER.inspect(root, vector) == 0
  assert not (root / pair.SINGLE.ONESHOT).exists()
  assert not any(event == ("power", "state", "disk") for event in events)
  marker_guard = root / pair_s4.VECTORS / vector / "s4-attempted"
  assert marker_guard.read_text().strip() == BOOT_ID
  marker_attempt = json.loads((marker_guard.parent / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert marker_attempt["state"] == "guard-consumed-pretransition-failure"
  assert marker_attempt["real_s4_attempted"] is False

  root, source, restore, proof, receipt, _power = fixture(base / "arm-failure")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  events = []
  bluetooth = [True]
  bolt = [True]
  normal_runner = fake_runner(root, events, bluetooth, bolt)

  def arm_failure_runner(arguments, check=True, capture=False):
    result = normal_runner(arguments, check, capture)
    if tuple(arguments) == ("bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"]):
      raise RuntimeError("injected bootctl readback failure")
    return result

  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: None, wifi_restore=lambda _root: None,
      power_writer=power_writer(root, receipt, events),
      runner=arm_failure_runner, sync=lambda: None, sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None,
    )
    raise AssertionError("Pair runner hid a failed restore arm")
  except RuntimeError as error:
    assert "injected bootctl readback failure" in str(error)
  assert not (root / pair.SINGLE.ONESHOT).exists()
  assert pair.load_receipt(root)["state"] == "restore-disarmed"
  assert not any(event == ("power", "state", "disk") for event in events)
  arm_guard = root / pair_s4.VECTORS / vector / "s4-attempted"
  assert arm_guard.is_file()
  arm_attempt = json.loads((arm_guard.parent / "attempts" / BOOT_ID / "attempt.json").read_text())
  assert arm_attempt["state"] == "guard-consumed-pretransition-failure"
  assert arm_attempt["real_s4_attempted"] is False

print("PASS: pair S4 runner binds proof and pair-wide guard, arms only restore, and clears a failed one-shot")
