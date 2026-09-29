#!/usr/bin/python3
"""One-use authorization and dispatcher regressions, synthetic directories only."""
import copy
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("product_trial", Path(__file__).parents[1] / "hibernate/trial.py")
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
tx = trial.TX


class Trials(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.base = Path(self.temp.name)
    self.guard = self.base / "guard"
    self.guard.mkdir(mode=0o700)
    self.ledger = tx.Ledger(self.base / "ledger")
    self.manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", **{key: str(i) * 64 for i, key in enumerate(tx.PINS, 1)}}
    self.boot = str(uuid.uuid4())
    self.authorization = {"protocol": tx.TRIAL_PROTOCOL, "qualified": False, "manifest_sha256": tx.digest(self.manifest),
      "audited_details_sha256": "a" * 64, "original_boot_id": self.boot, "authorization_id": str(uuid.uuid4()),
      "marker_pin": {"sha256": "b" * 64, "srcversion": "B" * 24, "vermagic": "synthetic-t2 SMP", "variable_version": "v3"}}
    self.authorization["physical_acceptance"] = {"boot_id": self.boot, "authorization_id": self.authorization["authorization_id"],
                                                "accepted": True, "method": "operator-attended-cold-power"}
    self.ledger.configure(self.manifest)

  def tearDown(self):
    self.temp.cleanup()

  def reserve(self):
    self.ledger.authorize_trial(self.authorization, self.guard)
    return self.ledger.begin(self.boot)

  def test_separate_authority_never_passes_qualification_parser(self):
    with self.assertRaises(ValueError): self.ledger.qualify(self.authorization)
    self.assertIs(tx.authority_value(self.authorization, self.manifest)["qualified"], False)
    for key, value in (("qualified", True), ("protocol", tx.PROTOCOL), ("manifest_sha256", "f" * 64), ("physical_acceptance", {})):
      with self.assertRaises(ValueError): self.ledger.authorize_trial({**self.authorization, key: value}, self.guard)

  def test_terminal_success_still_cannot_retry_or_copy_receipt(self):
    record = self.reserve()
    for action in ("prepared", "returned", "archive", "release", "reconcile"):
      record = self.ledger.advance(record["cycle_id"], action, "c" * 64)
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)
    copied = tx.Ledger(self.base / "copied")
    copied.configure(self.manifest)
    with self.assertRaises(ValueError): copied.authorize_trial(self.authorization, self.guard)
    altered = copy.deepcopy(self.authorization)
    altered["authorization_id"] = str(uuid.uuid4())
    altered["physical_acceptance"]["authorization_id"] = altered["authorization_id"]
    with self.assertRaises(ValueError): copied.authorize_trial(altered, self.guard)

  def test_wrong_boot_and_interrupted_allocation(self):
    self.ledger.authorize_trial(self.authorization, self.guard)
    with self.assertRaises(ValueError): self.ledger.begin(str(uuid.uuid4()))
    original = self.ledger._write
    def crash(name, record, exclusive=False):
      if name.startswith("allocation-"): raise OSError("synthetic crash after global consumption")
      return original(name, record, exclusive=exclusive)
    with patch.object(self.ledger, "_write", side_effect=crash):
      with self.assertRaises(OSError): self.ledger.begin(self.boot)
    with self.assertRaises(FileExistsError): self.ledger.begin(self.boot)

  def test_copied_pre_authorized_ledgers_cannot_race_global_guard(self):
    copied = tx.Ledger(self.base / "copied")
    copied.configure(self.manifest)
    self.ledger.authorize_trial(self.authorization, self.guard)
    copied.authorize_trial(self.authorization, self.guard)
    self.ledger.begin(self.boot)
    with self.assertRaises(FileExistsError): copied.begin(self.boot)

  def test_guard_durability_failure_preserves_consumption(self):
    self.ledger.authorize_trial(self.authorization, self.guard)
    with patch.object(tx.Ledger, "_sync", side_effect=OSError("synthetic guard fsync failure")):
      with self.assertRaises(OSError): self.ledger.begin(self.boot)
    self.assertTrue((self.guard / "trial-consumed.json").exists())
    with self.assertRaises(FileExistsError): self.ledger.begin(self.boot)

  def test_locked_capability_expires_and_returns_exact_current(self):
    cycle = self.reserve()
    captures = []
    def callback(advance):
      self.assertEqual(advance.check_current(), cycle)
      captures.append(advance.check_current)
      prepared = advance("prepared", "c" * 64)
      self.assertEqual(advance.check_current(), prepared)
    self.ledger.compare_and_run(cycle, callback)
    with self.assertRaises(ValueError): captures[0]()

  def test_help_and_nonroot_execute_never_open_or_execute_backend(self):
    with patch.object(trial, "_global_lock", side_effect=AssertionError("live access")):
      with self.assertRaises(SystemExit) as result: trial.main(["--help"])
      self.assertEqual(result.exception.code, 0)
      with patch.object(trial.os, "geteuid", return_value=1234):
        with self.assertRaises(SystemExit): trial.main(["execute"])
        with self.assertRaises(SystemExit): trial.main(["repair-constructor"])
    with self.assertRaises(SystemExit): trial.main(["execute", "--root", "/tmp"])

  def test_default_is_inspect_and_active_global_cycle_refuses_check(self):
    with patch.object(trial, "_global_lock", return_value=contextlib.nullcontext()), patch.object(trial, "_dispatch", return_value=0) as dispatch:
      self.assertEqual(trial.main([]), 0)
      dispatch.assert_called_once_with("inspect")
    lock = self.base / "physical-cycle.lock"
    lock.touch(mode=0o600)
    original_fstat = trial.os.fstat
    def owned(fd):
      info = original_fstat(fd)
      return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
    with patch.object(trial, "STATE", self.base), patch.object(trial.os, "fstat", side_effect=owned):
      with trial._global_lock(), patch.object(trial, "_dispatch", side_effect=AssertionError("entered dispatcher")):
        with self.assertRaises(BlockingIOError): trial.main(["check"])

  def test_readiness_rejects_stock_restore_old_slots_loaded_marker_and_ac_off(self):
    platform_patch = patch.object(trial, "_platform_readiness", return_value=None)
    platform_patch.start()
    self.addCleanup(platform_patch.stop)
    root = self.base / "ready"
    def write(name, raw):
      path = root / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(raw)
      return path
    source = "MBA-T2-hibernation-source-" + self.manifest["source_sha256"][:16]
    selected = write(trial.HOST.EFI / ("LoaderEntrySelected-" + trial.HOST.LOADER_GUID), b"\x06\0\0\0" + (source + "\0").encode("utf-16-le"))
    write("proc/sys/kernel/random/boot_id", self.boot.encode())
    mount = write("proc/self/mounts", b"/dev/mapper/root / btrfs rw,subvol=/@ 0 0\n")
    modules = write("proc/modules", b"nvme 0 0 - Live 0")
    write("sys/class/power_supply/AC/type", b"Mains")
    online = write("sys/class/power_supply/AC/online", b"1")
    report = {"manifest": self.manifest}
    trial.verify_readiness(root, {}, self.authorization, report)
    mount.write_bytes(b"/dev/sda1 / btrfs rw,subvol=/@ 0 0\n")
    with patch.object(trial, "validate", return_value=self.authorization), self.assertRaises(ValueError):
      trial.execute({}, self.authorization, report, ledger=self.ledger, guard_directory=self.guard, archive_directory=self.base,
                    root=root, backend_factory=lambda *args: self.fail("backend action"), sleeper=lambda delay: None, deployment_check=lambda *args: None)
    self.assertFalse((self.guard / "trial-consumed.json").exists())
    mount.write_bytes(b"/dev/mapper/root / btrfs rw,subvol=/@ 0 0\n")
    for entry in ("stock", "MBA-T2-hibernation-restore-" + self.manifest["restore_sha256"][:16]):
      selected.write_bytes(b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le"))
      with self.assertRaises(ValueError): trial.verify_readiness(root, {}, self.authorization, report)
    selected.write_bytes(b"\x06\0\0\0" + (source + "\0").encode("utf-16-le"))
    old = write(trial.HOST.EFI / trial.HOST.CT.SOURCE_VARIABLE, b"historical33a2")
    with self.assertRaises(ValueError): trial.verify_readiness(root, {}, self.authorization, report)
    self.assertEqual(old.read_bytes(), b"historical33a2")
    old.unlink()
    modules.write_bytes((trial.HOST.MARKER + " 0 0 - Live 0").encode())
    with self.assertRaises(ValueError): trial.verify_readiness(root, {}, self.authorization, report)
    modules.write_bytes(b"nvme 0 0 - Live 0")
    online.write_bytes(b"0")
    with self.assertRaises(ValueError): trial.verify_readiness(root, {}, self.authorization, report)

  def test_actual_staged_mapping_verification_detects_esp_and_limine_tamper(self):
    root = self.base / "staged"
    pair = trial.ARTIFACTS._module("test_trial_staged", trial.ARTIFACTS.HERE.parent / "experiments/stage-hibernation-uki-pair.py")
    def write(name, raw, private=False):
      path = root / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(raw)
      if private: path.chmod(0o600)
      return path
    images = {}
    for role in ("source", "restore"):
      raw = role.encode()
      digest = hashlib.sha256(raw).hexdigest()
      images[role] = {"entry_id": pair.entry_id(role, digest), "sha256": digest, "blake2": hashlib.blake2b(raw).hexdigest(), "provenance_sha256": "f" * 64}
      write(pair.IMAGES[role], raw)
    production = b"production"
    production_blake = hashlib.blake2b(production).hexdigest()
    write("boot/EFI/Linux/omarchy_linux-t2.efi", production)
    backup = b"original config"
    write(pair.BACKUP, backup)
    text = "default_entry: 2\npath: boot():/EFI/Linux/omarchy_linux-t2.efi#" + production_blake + "\n" + pair.BEGIN + "\n"
    for role in images:
      text += "/" + images[role]["entry_id"] + "\npath: boot():/EFI/Linux/" + pair.IMAGES[role].name + "#" + images[role]["blake2"] + "\n"
    text += pair.END + "\n"
    limine = write(pair.SINGLE.LIMINE, text.encode())
    receipt = {"kernel_policy": "production-linux-unchanged", "images": images,
      "original_limine_sha256": hashlib.sha256(backup).hexdigest(), "staged_limine_sha256": hashlib.sha256(text.encode()).hexdigest(),
      "production_uki_sha256": hashlib.sha256(production).hexdigest()}
    raw = json.dumps(receipt).encode()
    write(pair.RECEIPT, raw, private=True)
    write(pair.SINGLE.ENTRIES, b"\x06\0\0\0" + ("\0".join(images[role]["entry_id"] for role in images) + "\0").encode("utf-16-le"))
    write(pair.SINGLE.SELECTED, b"\x06\0\0\0" + (images["source"]["entry_id"] + "\0").encode("utf-16-le"))
    config = {"staged_receipt_sha256": hashlib.sha256(raw).hexdigest()}
    report = {"manifest": {role + "_sha256": images[role]["sha256"] for role in images},
      "audited_details": {"production_uki_sha256": receipt["production_uki_sha256"], "provenance_sha256": {role: "f" * 64 for role in images}}}
    trial.verify_deployment(root, config, report)
    write(pair.SINGLE.ONESHOT, b"\x07\0\0\0" + (images["restore"]["entry_id"] + "\0").encode("utf-16-le"))
    trial.verify_deployment(root, config, report)
    write(pair.IMAGES["restore"], b"wrong image")
    with self.assertRaises(ValueError): trial.verify_deployment(root, config, report)
    write(pair.IMAGES["restore"], b"restore")
    limine.write_text(text.replace("default_entry: 2", "default_entry: 1"))
    with self.assertRaises(ValueError): trial.verify_deployment(root, config, report)

  def test_synthetic_preparation_sampler_workflow_trial(self):
    spec = importlib.util.spec_from_file_location("trial_host_fixture", Path(__file__).with_name("test-hibernate-product-host-observation.py"))
    host_fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_fixture)
    observation = host_fixture.Observations("test_runtime_and_section_cmdline_hashes_are_distinct")
    observation.setUp()
    self.addCleanup(observation.tearDown)
    observation.marker_pin["srcversion"] = "1A72ABF3A3BFC778FC5A9C6"
    observation.write("sys/module/" + trial.HOST.MARKER + "/srcversion", observation.marker_pin["srcversion"])
    for metadata in observation.modules.values(): metadata["srcversion"] = "A" * 23
    for name in observation.selection:
      observation.write("sys/module/" + name.replace("-", "_") + "/srcversion", "A" * 23)
    provenance_raw = json.dumps(observation.provenance, sort_keys=True).encode()
    (observation.source / "provenance.json").write_bytes(provenance_raw)
    observation.report["manifest"]["runtime_sha256"] = trial.ARTIFACTS.AUDIT.S4.runtime_stack_identity(observation.provenance)
    details = observation.report["audited_details"]
    details["runtime_modules"] = copy.deepcopy(observation.modules)
    details["provenance_sha256"]["source"] = hashlib.sha256(provenance_raw).hexdigest()
    details["manifest_sha256"] = tx.digest(observation.report["manifest"])
    observation.report["audited_details_sha256"] = tx.digest(details)
    spec = importlib.util.spec_from_file_location("trial_prep_fixture", Path(__file__).with_name("test-hibernate-product-preparation.py"))
    prep_fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prep_fixture)
    authorization = copy.deepcopy(self.authorization)
    authorization.update(manifest_sha256=tx.digest(observation.report["manifest"]), audited_details_sha256=observation.report["audited_details_sha256"],
                         original_boot_id=observation.boot, marker_pin=observation.marker_pin)
    authorization["physical_acceptance"]["boot_id"] = observation.boot
    config = {"schema": trial.CONFIG_SCHEMA, "source_directory": str(observation.source), "restore_directory": str(self.base / "restore"),
      "production_uki": str(self.base / "production.efi"), "source_tree": str(observation.tree), "marker_file": str(observation.marker),
      "marker_pin": observation.marker_pin, "manifest": observation.report["manifest"],
      "audited_details_sha256": observation.report["audited_details_sha256"], "staged_receipt_sha256": "e" * 64, "retire_slots": False}
    class Backend(prep_fixture.Backend):
      def __init__(self, root, report, cycle, marker, pin):
        super().__init__(cycle, pin)
      def query(self, args): return observation.query(args)
      def command(self, args):
        super().command(args)
        if args[:2] == ("bootctl", "set-oneshot"):
          observation.write(str(trial.HOST.EFI / ("LoaderEntryOneShot-" + trial.HOST.LOADER_GUID)), b"\x07\0\0\0" + (self.restore + "\0").encode("utf-16-le"))
        if args[0] == "rmmod":
          observation.loaded.remove(trial.HOST.MARKER)
          observation.write("proc/modules", "\n".join(name + " 0 0 - Live 0" for name in observation.loaded))
      def power_writer(self, ledger, cycle, receipt):
        observation.cycle = cycle
        def write(path, value):
          observation.stage_return()
          observation.root.joinpath(trial.HOST.EFI / ("LoaderEntryOneShot-" + trial.HOST.LOADER_GUID)).unlink()
          self.values.update(oneshot=None, selected_entry=self.restore)
        return write
    archive = self.base / "archives"
    archive.mkdir(mode=0o700)
    with patch.object(trial, "verify_readiness", return_value=None):
      result = trial.execute(config, authorization, observation.report, ledger=self.ledger, guard_directory=self.guard, archive_directory=archive,
                             root=observation.root, backend_factory=Backend, sleeper=lambda duration: None, deployment_check=lambda *args: None)
    self.assertEqual(result["cycle"]["state"], "archived")
    self.assertFalse(result["usable_hibernation_qualified"])
    with self.assertRaises(ValueError): self.ledger.begin(observation.boot)
    for change in ({"audited_details_sha256": "f" * 64}, {"marker_pin": self.authorization["marker_pin"]}):
      with self.assertRaises(ValueError): trial.validate({**config, **change}, authorization, observation.report, observation.boot)

  def repair_fixture(self):
    spec = importlib.util.spec_from_file_location("trial_repair_backend_fixture", Path(__file__).with_name("test-hibernate-product-host-backend.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    host = fixture.Backends("test_fixed_keys_commands_and_unknown_power_are_rejected")
    host.setUp()
    self.addCleanup(host.doCleanups)
    observation = host.o
    observation.marker_pin["srcversion"] = "1A72ABF3A3BFC778FC5A9C6"
    for metadata in observation.modules.values(): metadata["srcversion"] = "A" * 23
    for name in observation.selection:
      observation.write("sys/module/" + name.replace("-", "_") + "/srcversion", "A" * 23)
    provenance_raw = json.dumps(observation.provenance, sort_keys=True).encode()
    (observation.source / "provenance.json").write_bytes(provenance_raw)
    observation.report["manifest"]["runtime_sha256"] = trial.ARTIFACTS.AUDIT.S4.runtime_stack_identity(observation.provenance)
    details = observation.report["audited_details"]
    details["runtime_modules"] = copy.deepcopy(observation.modules)
    details["provenance_sha256"]["source"] = hashlib.sha256(provenance_raw).hexdigest()
    details["manifest_sha256"] = tx.digest(observation.report["manifest"])
    observation.report["audited_details_sha256"] = tx.digest(details)
    authorization = copy.deepcopy(self.authorization)
    authorization.update(manifest_sha256=tx.digest(observation.report["manifest"]), audited_details_sha256=observation.report["audited_details_sha256"],
                         original_boot_id=observation.boot, marker_pin=observation.marker_pin)
    authorization["physical_acceptance"]["boot_id"] = observation.boot
    config = {"schema": trial.CONFIG_SCHEMA, "source_directory": str(observation.source), "restore_directory": str(self.base / "restore"),
      "production_uki": str(self.base / "production.efi"), "source_tree": str(observation.tree), "marker_file": str(observation.marker),
      "marker_pin": observation.marker_pin, "manifest": observation.report["manifest"],
      "audited_details_sha256": observation.report["audited_details_sha256"], "staged_receipt_sha256": "e" * 64, "retire_slots": True}
    self.ledger.configure(observation.report["manifest"])
    self.ledger.authorize_trial(authorization, self.guard)
    cycle = self.ledger.begin(observation.boot, cycle_id=trial.REPAIR_CYCLE)
    observation.cycle = cycle
    directory = self.base / "repair"
    directory.mkdir(mode=0o700)
    archive = self.base / "repair-archives"
    archive.mkdir(mode=0o700)
    def write(name, value):
      raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
      path = directory / name
      path.write_bytes(raw)
      path.chmod(0o600)
      return hashlib.sha256(raw).hexdigest()
    config_sha = write("config.json", config)
    authority_sha = write("authorization.json", authorization)
    systemd_sha = write("constructor-systemd-failure.json", {"boot_id": observation.boot, "unit": trial.REPAIR_UNIT,
      "invocation_id": trial.REPAIR_INVOCATION, "show": "Result=exit-code\nExecMainStatus=1\n", "journal": "Traceback: Invalid backend marker srcversion"})
    failure_sha = write("constructor-only-failure.json", {"schema": "omarchy-t2-constructor-only-failure-v1", "phase": "backend-constructor",
      "error": "Invalid backend marker srcversion", "prepared": False, "power_write": False, "boot_id": observation.boot,
      "cycle_id": cycle["cycle_id"], "vector": cycle["vector"], "systemd_failure_archive_sha256": systemd_sha})
    guard_raw = (self.guard / "trial-consumed.json").read_bytes()
    cycle_raw = (self.ledger.directory / ("cycle-" + cycle["cycle_id"] + ".json")).read_bytes()
    guard_sha, cycle_sha = hashlib.sha256(guard_raw).hexdigest(), hashlib.sha256(cycle_raw).hexdigest()
    receipt = {"schema": trial.REPAIR_SCHEMA, "accepted": True, "boot_id": observation.boot, "cycle_id": cycle["cycle_id"], "vector": cycle["vector"],
      "pins": {"config_sha256": config_sha, "authorization_sha256": authority_sha, "cycle_sha256": cycle_sha,
               "consumed_guard_sha256": guard_sha, "failure_evidence_sha256": failure_sha},
      "implementation_sha256": {name: trial.ARTIFACTS._file_digest(Path(trial.__file__).with_name(name)) for name in ("trial.py", "host_backend.py", "preparation.py", "continuity.py")}}
    write("constructor-repair-authorization.json", receipt)
    for name, value in (("REPAIR_BOOT", observation.boot), ("REPAIR_VECTOR", cycle["vector"]), ("REPAIR_CYCLE_SHA", cycle_sha),
                        ("REPAIR_GUARD_SHA", guard_sha), ("REPAIR_FAILURE_SHA", failure_sha), ("REPAIR_SYSTEMD_SHA", systemd_sha)):
      patcher = patch.object(trial, name, value)
      patcher.start()
      self.addCleanup(patcher.stop)
    patcher = patch.object(trial, "_platform_readiness", side_effect=lambda root, report: fixture.backend.verify_readiness(root, report, command_runner=host.command))
    patcher.start()
    self.addCleanup(patcher.stop)
    def factory(root, report, reserved, marker, pin):
      return fixture.backend.HostBackend(root, report, reserved, marker, pin, command_runner=host.command, sysfs_writer=host.write)
    arguments = {"ledger": self.ledger, "guard_directory": self.guard, "archive_directory": archive,
      "root": observation.root, "repair_directory": directory, "backend_factory": factory, "sleeper": lambda duration: None,
      "deployment_check": lambda *args: None}
    return config, authorization, observation.report, arguments, host, directory, guard_raw, cycle_raw

  def test_constructor_repair_actual23_runs_same_cycle_through_reconciled_once(self):
    config, authority, report, args, host, directory, guard_raw, cycle_raw = self.repair_fixture()
    result = trial.repair_constructor(config, authority, report, **args)
    self.assertEqual(result["retirement"]["cycle"]["state"], "reconciled")
    self.assertEqual(result["cycle"]["cycle_id"], trial.REPAIR_CYCLE)
    self.assertEqual(result["cycle"]["vector"], trial.REPAIR_VECTOR)
    self.assertEqual((self.guard / "trial-consumed.json").read_bytes(), guard_raw)
    self.assertEqual(host.power_count, 1)
    self.assertTrue((directory / "constructor-repair-intent.json").is_file())
    with self.assertRaises(ValueError): trial.repair_constructor(config, authority, report, **args)
    with self.assertRaises(ValueError): self.ledger.begin(trial.REPAIR_BOOT)

  def test_constructor_repair_code_failure_or_prep_state_tamper_blocks_backend(self):
    config, authority, report, args, host, directory, guard_raw, cycle_raw = self.repair_fixture()
    args["backend_factory"] = lambda *unused: self.fail("Backend invoked")
    target = directory / "constructor-repair-authorization.json"
    raw = target.read_bytes()
    receipt = json.loads(raw)
    receipt["implementation_sha256"]["continuity.py"] = "f" * 64
    target.write_text(json.dumps(receipt))
    with self.assertRaises(ValueError): trial.repair_constructor(config, authority, report, **args)
    target.write_bytes(raw)
    failure = directory / "constructor-systemd-failure.json"
    raw_failure = failure.read_bytes()
    failure.write_bytes(b"foreign")
    with self.assertRaises(ValueError): trial.repair_constructor(config, authority, report, **args)
    failure.write_bytes(raw_failure)
    extra = self.ledger.directory / "preparation-partial.json"
    extra.write_bytes(b"{}")
    extra.chmod(0o600)
    with self.assertRaises(ValueError): trial.repair_constructor(config, authority, report, **args)
    self.assertFalse((directory / "constructor-repair-intent.json").exists())
    self.assertEqual(host.power_count, 0)

  def test_constructor_repair_intent_fsync_failure_consumes_without_backend(self):
    config, authority, report, args, host, directory, guard_raw, cycle_raw = self.repair_fixture()
    args["backend_factory"] = lambda *unused: self.fail("Backend invoked")
    original_sync = tx.Ledger._sync
    def fail_repair_sync(ledger):
      if ledger.directory == directory: raise OSError("synthetic repair intent directory fsync failure")
      return original_sync(ledger)
    with patch.object(tx.Ledger, "_sync", new=fail_repair_sync):
      with self.assertRaises(OSError): trial.repair_constructor(config, authority, report, **args)
    self.assertTrue((directory / "constructor-repair-intent.json").exists())
    with self.assertRaises(ValueError): trial.repair_constructor(config, authority, report, **args)
    self.assertEqual((self.guard / "trial-consumed.json").read_bytes(), guard_raw)
    self.assertEqual((self.ledger.directory / ("cycle-" + trial.REPAIR_CYCLE + ".json")).read_bytes(), cycle_raw)
    self.assertEqual(host.power_count, 0)

  def test_static_backend_format_failure_never_consumes_guard(self):
    config, authority, report, args, host, directory, guard_raw, cycle_raw = self.repair_fixture()
    fresh = tx.Ledger(self.base / "fresh-ledger")
    fresh_guard = self.base / "fresh-guard"
    fresh_guard.mkdir(mode=0o700)
    malformed = copy.deepcopy(config)
    malformed["marker_pin"]["srcversion"] = "B" * 22
    changed_authority = copy.deepcopy(authority)
    changed_authority["marker_pin"] = malformed["marker_pin"]
    with self.assertRaises(ValueError):
      trial.execute(malformed, changed_authority, report, ledger=fresh, guard_directory=fresh_guard,
                    archive_directory=args["archive_directory"], root=args["root"], backend_factory=lambda *unused: self.fail("Backend invoked"),
                    sleeper=lambda duration: None, deployment_check=lambda *unused: None)
    self.assertFalse((fresh_guard / "trial-consumed.json").exists())
    self.assertFalse(any(fresh.directory.glob("cycle-*.json")))


if __name__ == "__main__":
  unittest.main()
