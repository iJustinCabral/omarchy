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
    "runtime_stack_sha256": receipt["runtime_stack_sha256"],
    "cmdline_sha256": hashlib.sha256(b"synthetic-cmdline").hexdigest(),
    "kernel_release": "7.2.6-arch2-Watanare-T2-2-t2",
    "pm_test_before": "none",
    "disk_before": "platform",
    "pm_trace_before": "0",
    "resume": "254:0",
    "resume_offset": 42,
    "swap_file": "/swap/swapfile",
    "devices": {"internal_input_interfaces": 2},
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
  root, source, restore, proof, receipt, _power = fixture(base / "pair-proof")
  evidence = platform_preflight(root, source, restore)
  source_hash = evidence["source_uki_sha256"]
  proof_directory = root / pair.STATE / "test-resume-vectors" / source_hash
  guard = proof_directory / "test-resume-attempted"
  write(guard, BOOT_ID + "\n")
  guard.chmod(0o600)
  attempt = proof_directory / "attempts" / BOOT_ID / "attempt.json"
  proof_record = {
    "boot_id": BOOT_ID,
    "entry_id": evidence["source_entry_id"],
    "candidate_uki_sha256": source_hash,
    "source_uki_sha256": source_hash,
    "restore_uki_sha256": evidence["restore_uki_sha256"],
    "runtime_stack_sha256": evidence["runtime_stack_sha256"],
    "cmdline_sha256": evidence["cmdline_sha256"],
    "kernel_release": evidence["kernel_release"],
    "transition_vector": source_hash,
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "state": "returned-and-cleaned",
    "hibernate_attempted": True,
    "physical_input_confirmed": True,
    "hardware_qualified": False,
  }
  write(attempt, json.dumps(proof_record))
  attempt.chmod(0o600)
  post = Path("proof/post-input.json")
  post_path = root / post
  write(post_path, json.dumps({
    "boot_id": BOOT_ID,
    "entry_id": evidence["source_entry_id"],
    "keyboard_seen": True,
    "trackpad_seen": True,
  }))
  post_path.chmod(0o600)
  verified = pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, source, True)
  assert verified["test_resume_boot_id"] == BOOT_ID
  assert verified["test_resume_attempt"] == str(attempt)
  full = pair_s4.preflight(
    root, source, restore, source, post, Path("proof/pre-input.json"), "platform",
    platform_preflight=platform_preflight, current_input_verifier=input_verifier,
  )
  assert full["test_resume_boot_id"] == BOOT_ID
  try:
    pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, proof, True)
    raise AssertionError("A different proof source was accepted")
  except ValueError as error:
    assert "exact source image" in str(error)
  proof_record["state"] = "transition-failed"
  write(attempt, json.dumps(proof_record))
  try:
    pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, source, True)
    raise AssertionError("A failed pair test_resume was accepted")
  except ValueError as error:
    assert "proof mismatch: state" in str(error)
  proof_record["state"] = "returned-and-cleaned"
  proof_record["restore_uki_sha256"] = "0" * 64
  write(attempt, json.dumps(proof_record))
  try:
    pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, source, True)
    raise AssertionError("A changed restore UKI was accepted")
  except ValueError as error:
    assert "proof mismatch: restore_uki_sha256" in str(error)
  proof_record["restore_uki_sha256"] = evidence["restore_uki_sha256"]
  write(attempt, json.dumps(proof_record))
  post_path.chmod(0o644)
  try:
    pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, source, True)
    raise AssertionError("World-readable input evidence was accepted")
  except ValueError as error:
    assert "unsafe owner or mode" in str(error)
  post_path.chmod(0o600)
  guard.unlink()
  try:
    pair_s4.verify_pair_test_resume_proof(root, evidence, post, source, source, True)
    raise AssertionError("Missing pair guard was accepted")
  except ValueError as error:
    assert "guard is missing" in str(error)

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

  root, source, restore, proof, receipt, power = fixture(base / "rtc-backend-order")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  events = []

  class RTCMarker:
    NAME = "rtc"
    PM_TRACE_VALUE = "0"
    MIN_RETURN_STAGE = 2
    EXECUTION_QUALIFIED = True

    def __init__(self):
      self.stage = None

    def require_kernel_available(self, _root):
      events.append(("rtc", "preflight"))

    def inspect(self, _root, _vector):
      return self.stage

    def require_operator_acceptance(self, _root, identity, boot, production):
      assert identity == vector and boot == BOOT_ID
      assert production == pair.load_receipt(root)["production_uki_sha256"]
      events.append(("rtc", "accepted"))
      return "f" * 64

    def before_arm(self, host, identity, boot, directory):
      assert identity == vector and boot == BOOT_ID
      assert (directory.parent.parent / "s4-attempted").read_text().strip() == BOOT_ID
      events.append(("rtc", "pointer"))

    def enable(self, _root):
      events.append(("rtc", "loaded"))

    def prearm(self, _root, _vector):
      self.stage = 0
      events.append(("rtc", "armed"))
      return "/sys/module/synthetic/armed"

    def cleanup(self, _root, _vector, _boot, _directory):
      events.append(("rtc", "cleaned"))

  rtc = RTCMarker()

  rtc.EXECUTION_QUALIFIED = False
  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
      wifi_restore=lambda _root: events.append(("wifi", "restore")),
      power_writer=lambda _path, _value: events.append(("power", "unexpected")),
      runner=fake_runner(root, events, [False], [False]),
      sync=lambda: None, sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None, marker_backend=rtc,
    )
    raise AssertionError("Unqualified RTC backend entered the S4 transaction")
  except ValueError as error:
    assert "cannot qualify another S4 execution" in str(error)
  assert not (root / pair_s4.VECTORS / vector).exists()
  assert not (root / pair.SINGLE.ONESHOT).exists()
  assert ("wifi", "prepare") not in events and ("power", "unexpected") not in events
  rtc.NAME = "ftrace-efi"
  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
      power_writer=lambda _path, _value: events.append(("power", "unexpected")),
      services_verifier=lambda _runner: None, marker_backend=rtc,
    )
    raise AssertionError("Unqualified ftrace EFI backend entered the S4 transaction")
  except ValueError as error:
    assert "lacks forced-power persistence and independent recovery proof" in str(error)
  assert not (root / pair_s4.VECTORS / vector).exists()
  assert ("wifi", "prepare") not in events and ("power", "unexpected") not in events
  rtc.NAME = "postwrite-efi"
  try:
    pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
      power_writer=lambda _path, _value: events.append(("power", "unexpected")),
      services_verifier=lambda _runner: None, marker_backend=rtc,
    )
    raise AssertionError("Unattended post-write S4 entered the transaction")
  except ValueError as error:
    assert "operator at the physical power button" in str(error)
  assert not (root / pair_s4.VECTORS / vector).exists()
  assert ("wifi", "prepare") not in events and ("power", "unexpected") not in events
  rtc.NAME = "rtc"
  rtc.EXECUTION_QUALIFIED = True
  events.clear()

  def rtc_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "disk":
      write(path, "[platform] shutdown reboot suspend test_resume\n")
    if path.name == "state":
      assert rtc.stage == 0
      assert pair.SINGLE.read_efi_string(root / pair.SINGLE.ONESHOT) == receipt["images"]["restore"]["entry_id"]
      rtc.stage = 2
      (root / pair.SINGLE.ONESHOT).unlink()
      write_efi(root / pair.SINGLE.SELECTED, receipt["images"]["restore"]["entry_id"])

  result = pair_s4.execute(
    *inputs, vector, platform_preflight, proof_verifier, input_verifier,
    wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
    wifi_restore=lambda _root: events.append(("wifi", "restore")),
    power_writer=rtc_writer,
    runner=fake_runner(root, events, [False], [False]),
    sync=lambda: None, sleeper=lambda _seconds: None,
    services_verifier=lambda _runner: None, marker_backend=rtc,
  )
  assert result["state"] == "returned-and-cleaned" and result["rtc_stage"] == 2
  assert events.index(("rtc", "pointer")) < events.index(("rtc", "armed"))
  assert events.index(("rtc", "armed")) < events.index(("command", ("bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"])))
  assert events.index(("rtc", "cleaned")) > events.index(("wifi", "restore"))

  root, source, restore, proof, receipt, _power = fixture(base / "postwrite-attended")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  events = []
  marker = RTCMarker()
  marker.NAME = "postwrite-efi"
  marker.MIN_RETURN_STAGE = 3

  def postwrite_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "disk":
      write(path, "[platform] shutdown reboot suspend test_resume\n")
    if path.name == "state":
      assert marker.stage == 0
      assert pair.SINGLE.read_efi_string(root / pair.SINGLE.ONESHOT) == receipt["images"]["restore"]["entry_id"]
      marker.stage = 3
      (root / pair.SINGLE.ONESHOT).unlink()
      write_efi(root / pair.SINGLE.SELECTED, receipt["images"]["restore"]["entry_id"])

  result = pair_s4.execute(
    *inputs, vector, platform_preflight, proof_verifier, input_verifier,
    wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
    wifi_restore=lambda _root: events.append(("wifi", "restore")),
    power_writer=postwrite_writer,
    runner=fake_runner(root, events, [False], [False]),
    sync=lambda: None, sleeper=lambda _seconds: None,
    services_verifier=lambda _runner: None, marker_backend=marker,
    operator_attended=True,
  )
  assert result["state"] == "returned-and-cleaned"
  assert result["postwrite-efi_stage"] == 3
  assert result["recovery_method"] == "operator-attended-cold-power"
  assert result["operator_recovery_acceptance_sha256"] == "f" * 64
  assert events.index(("rtc", "accepted")) < events.index(("rtc", "pointer"))
  assert events.index(("rtc", "pointer")) < events.index(("command", ("bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"])))

  root, source, restore, proof, receipt, _power = fixture(base / "dual-efi-boundary")
  vector = pair_s4.pair_vector(receipt)
  inputs = (root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform")
  source_module = root / "private-source-marker.ko"
  restore_module = root / "private-restore-marker.ko"
  source_module.write_bytes(b"source EFI module")
  restore_module.write_bytes(b"restore EFI module")
  source_hash = hashlib.sha256(source_module.read_bytes()).hexdigest()
  restore_hash = hashlib.sha256(restore_module.read_bytes()).hexdigest()
  source_version = "ECA3A5319ADB6686DD0BD88"
  restore_version = "3119365A09AED2D4CD65DD6"
  parameters = root / pair_s4.POSTWRITE.PARAMETERS
  events = []

  def marker_command(arguments):
    events.append(("marker-command", tuple(arguments)))
    if arguments[:3] == ("modinfo", "-F", "vermagic"):
      return "7.2.6-arch2-Watanare-T2-2-t2 SMP preempt mod_unload\n"
    if arguments[:3] == ("modinfo", "-F", "srcversion"):
      return (restore_version if arguments[3] == str(restore_module) else source_version) + "\n"
    if arguments == ("insmod", str(source_module)):
      write(parameters / "arm_vector", "0\n")
      write(parameters / "stage", "0\n")
      write(parameters / "last_efi_status", "0\n")
      return ""
    if arguments == ("rmmod", pair_s4.POSTWRITE.MODULE_NAME):
      for path in parameters.iterdir():
        path.unlink()
      parameters.rmdir()
      return ""
    raise AssertionError("Unexpected marker command: " + repr(arguments))

  def arm_parameter(_root, identity):
    assert identity == vector
    write(parameters / "arm_vector", "1\n")

  marker = pair_s4.POSTWRITE.PostwriteRestoreEfiBackend(
    source_module, source_hash, source_version,
    restore_module, restore_hash, restore_version,
    command=marker_command, kernel_release="7.2.6-arch2-Watanare-T2-2-t2",
    parameter_writer=arm_parameter,
  )
  acceptance = {
    "kind": "postwrite-restore-efi-attended-s4-v1",
    "boot_id": BOOT_ID,
    "transition_vector": vector,
    "module_sha256": source_hash,
    "restore_module_sha256": restore_hash,
    "production_uki_sha256": receipt["production_uki_sha256"],
    "method": "operator-attended-cold-power",
    "accepted": True,
  }
  acceptance_path = root / pair_s4.POSTWRITE.ACCEPTANCE
  write(acceptance_path, json.dumps(acceptance))
  acceptance_path.chmod(0o600)
  original_load_candidate = pair_s4.PAIR.AUDIT.load_candidate
  pair_s4.PAIR.AUDIT.load_candidate = lambda directory, role: {
    "restore_marker": {"sha256": restore_hash, "srcversion": restore_version}
  } if directory == restore and role == "restore" else None

  standalone = pair_s4.POSTWRITE.PostwriteEfiBackend(
    source_module, source_hash, source_version,
    command=marker_command, kernel_release="7.2.6-arch2-Watanare-T2-2-t2",
    parameter_writer=arm_parameter,
  )
  try:
    pair_s4.preflight(
      *inputs, platform_preflight, proof_verifier, input_verifier,
      require_efi_marker=True, marker_backend=standalone,
    )
    raise AssertionError("Instrumented restore UKI accepted the source-only marker backend")
  except ValueError as error:
    assert "requires the paired EFI restore marker backend" in str(error)

  def dual_marker_writer(path, value):
    events.append(("power", path.name, value))
    if path.name == "disk":
      write(path, "[platform] shutdown reboot suspend test_resume\n")
    if path.name == "state":
      source_efi = root / pair_s4.POSTWRITE.VARIABLE
      restore_efi = root / pair_s4.POSTWRITE.RESTORE_VARIABLE
      assert source_efi.read_bytes()[-1] == 0 and restore_efi.read_bytes()[-1] == 0
      assert pair.SINGLE.read_efi_string(root / pair.SINGLE.ONESHOT) == receipt["images"]["restore"]["entry_id"]
      source_efi.write_bytes(source_efi.read_bytes()[:-1] + b"\x04")
      restore_efi.write_bytes(restore_efi.read_bytes()[:-1] + b"\x07")
      (root / pair.SINGLE.ONESHOT).unlink()
      write_efi(root / pair.SINGLE.SELECTED, receipt["images"]["restore"]["entry_id"])

  try:
    result = pair_s4.execute(
      *inputs, vector, platform_preflight, proof_verifier, input_verifier,
      wifi_prepare=lambda _root: events.append(("wifi", "prepare")),
      wifi_restore=lambda _root: events.append(("wifi", "restore")),
      power_writer=dual_marker_writer,
      runner=fake_runner(root, events, [False], [False]),
      sync=lambda: None, sleeper=lambda _seconds: None,
      services_verifier=lambda _runner: None, marker_backend=marker,
      operator_attended=True,
    )
  finally:
    pair_s4.PAIR.AUDIT.load_candidate = original_load_candidate
  assert result["state"] == "returned-and-cleaned"
  assert result["postwrite-efi_stage"] == 4
  assert result["restore-efi_stage"] == 7
  assert result["restore-efi_stage_marker"] == str(root / pair_s4.POSTWRITE.RESTORE_VARIABLE)
  assert (root / pair_s4.POSTWRITE.RESTORE_VARIABLE).is_file()
  assert events.index(("marker-command", ("insmod", str(source_module)))) < events.index(
    ("command", ("bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"])))

  root, source, restore, proof, receipt, _power = fixture(base / "v2-retains-old-marker")
  vector = pair_s4.pair_vector(receipt)
  old_marker = root / pair_s4.POSTWRITE.VARIABLE
  old_marker.parent.mkdir(parents=True, exist_ok=True)
  old_value = pair_s4.POSTWRITE.ATTRIBUTES + pair_s4.POSTWRITE.MAGIC + bytes.fromhex(("f" * 64)[:24]) + b"\x04"
  old_marker.write_bytes(old_value)
  source_module = root / "v2-source-marker.ko"
  restore_module = root / "restore-marker.ko"
  source_module.write_bytes(b"source EFI module v2")
  restore_module.write_bytes(b"restore EFI module")
  source_hash = hashlib.sha256(source_module.read_bytes()).hexdigest()
  restore_hash = hashlib.sha256(restore_module.read_bytes()).hexdigest()
  restore_version = "3119365A09AED2D4CD65DD6"

  def v2_module_info(arguments):
    if arguments[:3] == ("modinfo", "-F", "vermagic"):
      return "7.2.6-arch2-Watanare-T2-2-t2 SMP preempt mod_unload\n"
    if arguments[:3] == ("modinfo", "-F", "srcversion"):
      return (restore_version if arguments[3] == str(restore_module) else "19F05361B80C3D339C2B0E4") + "\n"
    if arguments[:3] == ("modinfo", "-F", "mba_postwrite_variable"):
      return "v2\n"
    raise AssertionError("Unexpected module metadata query: " + repr(arguments))

  marker = pair_s4.POSTWRITE.PostwriteRestoreEfiBackend(
    source_module, source_hash, "19F05361B80C3D339C2B0E4",
    restore_module, restore_hash, restore_version,
    command=v2_module_info, kernel_release="7.2.6-arch2-Watanare-T2-2-t2",
    source_variable_version="v2",
  )
  original_load_candidate = pair_s4.PAIR.AUDIT.load_candidate
  pair_s4.PAIR.AUDIT.load_candidate = lambda directory, role: {
    "restore_marker": {"sha256": restore_hash, "srcversion": restore_version}
  } if directory == restore and role == "restore" else None
  try:
    ready = pair_s4.preflight(
      root, source, restore, proof, Path("proof/post-input.json"), Path("proof/pre-input.json"), "platform",
      platform_preflight, proof_verifier, input_verifier,
      require_efi_marker=True, marker_backend=marker,
    )
  finally:
    pair_s4.PAIR.AUDIT.load_candidate = original_load_candidate
  assert ready["transition_vector"] == vector
  assert marker.inspect(root, vector) is None
  assert old_marker.read_bytes() == old_value

  root, source, restore, _proof, receipt, _power = fixture(base / "input-waiver")
  evidence = platform_preflight(root, source, restore)
  source_hash = evidence["source_uki_sha256"]
  proof_directory = root / pair.STATE / "test-resume-vectors" / source_hash
  guard = proof_directory / "test-resume-attempted"
  write(guard, BOOT_ID + "\n")
  guard.chmod(0o600)
  attempt = proof_directory / "attempts" / BOOT_ID / "attempt.json"
  waived_record = {
    "boot_id": BOOT_ID,
    "entry_id": evidence["source_entry_id"],
    "candidate_uki_sha256": source_hash,
    "source_uki_sha256": source_hash,
    "restore_uki_sha256": evidence["restore_uki_sha256"],
    "runtime_stack_sha256": evidence["runtime_stack_sha256"],
    "cmdline_sha256": evidence["cmdline_sha256"],
    "kernel_release": evidence["kernel_release"],
    "transition_vector": source_hash,
    "qualification": "pair-source-ordinary-boot-preflight-passed",
    "state": "returned-and-cleaned",
    "hibernate_attempted": True,
    "physical_input_confirmed": False,
    "input_event_waiver": pair_s4.INPUT_EVENT_WAIVER,
    "devices": {"internal_input_interfaces": 2},
    "hardware_qualified": False,
  }
  write(attempt, json.dumps(waived_record))
  attempt.chmod(0o600)
  waived = pair_s4.verify_pair_test_resume_proof(
    root, evidence, None, source, source, True, input_event_waiver=True,
  )
  assert waived["input_event_waiver"] == pair_s4.INPUT_EVENT_WAIVER
  result = pair_s4.preflight(
    root, source, restore, source, None, None, "platform",
    platform_preflight=platform_preflight, input_event_waiver=True,
  )
  assert result["physical_input_confirmed"] is False
  assert result["real_s4_attempted"] is False
  assert result["input_event_waiver"] == pair_s4.INPUT_EVENT_WAIVER
  for post, pre in ((Path("post.json"), None), (None, Path("pre.json"))):
    try:
      pair_s4.preflight(root, source, restore, source, post, pre, "platform", platform_preflight=platform_preflight, input_event_waiver=True)
      raise AssertionError("Waiver accepted physical input paths")
    except ValueError as error:
      assert "cannot be combined" in str(error)
  for key, changed in (("input_event_waiver", "wrong-waiver"), ("physical_input_confirmed", True), ("devices", {"internal_input_interfaces": 1})):
    bad = {**waived_record, key: changed}
    write(attempt, json.dumps(bad))
    try:
      pair_s4.verify_pair_test_resume_proof(root, evidence, None, source, source, True, input_event_waiver=True)
      raise AssertionError("Invalid waiver proof was accepted: " + key)
    except ValueError:
      pass
  write(attempt, json.dumps(waived_record))
  evidence["devices"] = {"internal_input_interfaces": 1}
  try:
    pair_s4.preflight(root, source, restore, source, None, None, "platform", platform_preflight=lambda *_args: evidence, input_event_waiver=True)
    raise AssertionError("Waiver accepted missing current input interface")
  except ValueError as error:
    assert "both current internal interfaces" in str(error)

print("PASS: pair S4 runner binds proof and pair-wide guard, arms only restore, and clears a failed one-shot")
