#!/usr/bin/python3
"""Fixed backend operations against synthetic files; never executes host commands."""
import copy
import errno
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import uuid


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


base = Path(__file__).parents[1]
backend = load("product_host_backend", base / "hibernate/host_backend.py")
trial = load("backend_test_trial", base / "hibernate/trial.py")
fixture = load("backend_observation_fixture", Path(__file__).with_name("test-hibernate-product-host-observation.py"))
tx = backend.TX


class Backends(unittest.TestCase):
  def setUp(self):
    self.observation = fixture.Observations("test_runtime_and_section_cmdline_hashes_are_distinct")
    self.observation.setUp()
    self.addCleanup(self.observation.tearDown)
    self.o = self.observation
    self.root = self.o.root
    self.marker_dir = self.root / "sys/module" / backend.MARKER
    for file in self.marker_dir.iterdir(): file.unlink()
    self.marker_dir.rmdir()
    self.o.loaded.remove(backend.MARKER)
    self.modules()
    self.bolt, self.bluetooth = True, True
    self.calls = []
    self.power_count = 0
    self.fail_power = False
    self.ledger = tx.Ledger(self.o.base / "backend-ledger")
    self.ledger.configure(self.o.report["manifest"])
    self.ledger.qualify(self.o.qualification)
    self.cycle = self.ledger.begin(self.o.boot)
    self.o.cycle = self.cycle
    source = "MBA-T2-hibernation-source-" + self.cycle["manifest"]["source_sha256"][:16]
    restore = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
    self.loader("LoaderEntries", source + "\0" + restore)
    self.o.write("sys/power/state", "freeze mem disk")
    self.o.write("sys/power/pm_async", "0")
    self.o.write("proc/swaps", "Filename Type Size Used Priority\n/swap/swapfile file 100000 0 -2\n")
    self.host = backend.HostBackend(self.root, self.o.report, self.cycle, self.o.marker, self.o.marker_pin,
                                    command_runner=self.command, sysfs_writer=self.write)

  def modules(self):
    self.o.write("proc/modules", "\n".join(name + " 0 0 - Live 0" for name in self.o.loaded))

  def loader(self, name, text):
    attributes = b"\x07\0\0\0" if name in ("LoaderEntryOneShot", "LoaderEntryDefault") else b"\x06\0\0\0"
    self.o.write(backend.HOST.EFI / (name + "-" + backend.HOST.LOADER_GUID), attributes + (text + "\0").encode("utf-16-le"))

  def command(self, args):
    self.calls.append(args)
    rc, out = 0, ""
    if args[0] == "modinfo":
      out = self.o.query(args)
    elif args[:2] == ("systemctl", "is-active"):
      if args[-1] == "bolt.service": rc, out = (0, "active") if self.bolt else (3, "inactive")
      else: out = "active"
    elif args[:2] == ("systemctl", "--failed"): pass
    elif args[0] == "lsblk": out = "253:0"
    elif args == ("btrfs", "inspect-internal", "map-swapfile", "-r", "/swap/swapfile"): out = "123"
    elif args == ("findmnt", "-n", "-o", "SOURCE,FSTYPE", "--target", "/swap/swapfile"): out = "/dev/mapper/root[/@] btrfs"
    elif args[:2] in (("systemctl", "stop"), ("systemctl", "start")):
      self.bolt = args[1] == "start"
    elif args == ("timeout", "5s", "bluetoothctl", "show"):
      out = "Controller synthetic\n\tPowered: " + ("yes" if self.bluetooth else "no")
    elif args[:4] == ("timeout", "5s", "bluetoothctl", "power"):
      self.bluetooth = args[-1] == "on"
    elif args[0] == "insmod":
      self.o.write("sys/module/" + backend.MARKER + "/srcversion", self.o.marker_pin["srcversion"])
      for name in ("arm_vector", "stage", "last_efi_status"):
        self.o.write("sys/module/" + backend.MARKER + "/parameters/" + name, "0")
      self.o.loaded.append(backend.MARKER)
      self.modules()
    elif args[0] == "rmmod":
      for file in (self.marker_dir / "parameters").iterdir(): file.unlink()
      (self.marker_dir / "parameters").rmdir()
      (self.marker_dir / "srcversion").unlink()
      self.marker_dir.rmdir()
      self.o.loaded.remove(backend.MARKER)
      self.modules()
    elif args[:2] == ("bootctl", "set-oneshot"):
      if args[-1]: self.loader("LoaderEntryOneShot", args[-1])
      else: (self.root / backend.HOST.EFI / ("LoaderEntryOneShot-" + backend.HOST.LOADER_GUID)).unlink()
    else: raise AssertionError("Unexpected synthetic command " + repr(args))
    return subprocess.CompletedProcess(args, rc, out, "")

  def write(self, path, raw):
    relative = path.relative_to(self.root)
    if relative == Path("sys/power/state"):
      self.power_count += 1
      if self.fail_power: raise OSError("synthetic power write failure")
      self.o.stage_return()
      (self.root / backend.HOST.EFI / ("LoaderEntryOneShot-" + backend.HOST.LOADER_GUID)).unlink()
      path.write_bytes(raw)
    elif relative in (Path("sys/power/pm_test"), Path("sys/power/disk")):
      path.write_bytes(b"[" + raw + b"]")
    elif relative.name in ("unbind", "bind"):
      driver = self.root / "sys/bus/pci/devices" / backend.WIFI / "driver"
      if relative.name == "unbind": driver.unlink()
      else: driver.symlink_to(self.root / "sys/bus/pci/drivers/brcmfmac")
    elif relative.name == "arm_vector": path.write_bytes(b"1")
    else: path.write_bytes(raw)

  def prepare(self):
    preparation = trial.PREPARATION.Preparation(self.ledger, self.cycle, self.host, self.o.marker, self.o.marker_pin, sleeper=lambda duration: None)
    prepared = preparation.prepare()
    self.o.cycle = prepared["cycle"]
    sampler = trial.HOST.Sampler(self.root, self.o.report, prepared["cycle"], self.o.qualification, self.o.source, self.o.tree,
                                self.o.marker, self.o.marker_pin, prepared["guard_file"], prepared["attempt_file"], query=self.host.query)
    observed = sampler.before(prepared["receipt"])
    collector = trial.WORKFLOW.CONTINUITY.Collector(prepared["cycle"], self.o.qualification, observed["source_runtime"], observed["baseline_pm"],
                                                   prepared["guard_file"].read_bytes(), prepared["attempt_file"].read_bytes())
    return preparation, prepared, sampler, collector

  def run_workflow(self, *, tamper=False):
    preparation, prepared, sampler, collector = self.prepare()
    writer = self.host.power_writer(self.ledger, prepared["cycle"], prepared["receipt"])
    if tamper: prepared["guard_file"].write_bytes(b"foreign")
    archive = self.o.base / "backend-archives"
    archive.mkdir(mode=0o700)
    result = trial.WORKFLOW.run(self.ledger, collector, archive, power_write=writer, capture=sampler.capture,
                                cleanup=preparation.cleanup, health=sampler.health)
    return result, writer, archive, sampler, collector

  def test_fixed_keys_commands_and_unknown_power_are_rejected(self):
    self.assertEqual(self.host.read("model"), "MacBookAir9,1")
    self.assertEqual(self.host.read("wifi_driver"), "brcmfmac")
    self.assertEqual(self.host.read("loader_entries")[0], self.host.read("selected_entry"))
    for operation in (lambda: self.host.command(("sh", "-c", "true")), lambda: self.host.query(("reboot",)),
                      lambda: self.host.write("state", "disk"), lambda: self.host.read_slot("foreign")):
      with self.assertRaises(ValueError): operation()
    self.assertEqual(self.calls, [])

  def test_actual_marker_hash_loaded_identity_and_efi_framing(self):
    self.assertEqual(self.host.read("marker_file_identity"), self.o.marker_pin)
    self.o.marker.write_bytes(b"substituted")
    with self.assertRaises(ValueError): self.host.read("marker_file_identity")
    self.o.write(backend.HOST.EFI / ("LoaderEntrySelected-" + backend.HOST.LOADER_GUID), b"\x07\0\0\0wrong")
    with self.assertRaises(ValueError): self.host.read("selected_entry")

  def test_exact_target_23_character_srcversion_runs_without_relaxing_pin(self):
    pin = {**self.o.marker_pin, "srcversion": "1A72ABF3A3BFC778FC5A9C6"}
    self.assertEqual(len(pin["srcversion"]), 23)
    self.o.marker_pin = pin
    self.o.file_metadata[str(self.o.marker)] = pin
    self.host = backend.HostBackend(self.root, self.o.report, self.cycle, self.o.marker, pin,
                                    command_runner=self.command, sysfs_writer=self.write)
    self.assertEqual(self.host.read("marker_file_identity"), pin)
    result, writer, archive, sampler, collector = self.run_workflow()
    self.assertEqual(result["cycle"]["state"], "archived")
    self.assertEqual(self.power_count, 1)
    self.o.file_metadata[str(self.o.marker)] = {**pin, "srcversion": "1A72ABF3A3BFC778FC5A9C7"}
    with self.assertRaises(ValueError): self.host.read("marker_file_identity")

  def test_malformed_marker_srcversion_rejected_before_backend_actions(self):
    for value in (None, "", "F" * 22, "F" * 25, "G" * 23, "f" * 24, "F" * 23 + "\n"):
      with self.subTest(value=value), self.assertRaises(ValueError):
        backend.HostBackend(self.root, self.o.report, self.cycle, self.o.marker, {**self.o.marker_pin, "srcversion": value},
                            command_runner=self.command, sysfs_writer=self.write)
    self.assertEqual(self.calls, [])

  def test_static_runtime_srcversion_admission_before_backend_actions(self):
    for value in ("1A72ABF3A3BFC778FC5A9C6", "A" * 24, None, "A" * 22, "G" * 23):
      report = copy.deepcopy(self.o.report)
      report["audited_details"]["runtime_modules"]["t2bce_core"]["srcversion"] = value
      report["audited_details_sha256"] = backend.TX.digest(report["audited_details"])
      with self.subTest(value=value):
        if value in ("1A72ABF3A3BFC778FC5A9C6", "A" * 24):
          backend.validate_static_inputs(report, self.cycle["manifest"], self.o.marker, self.o.marker_pin)
        else:
          with self.assertRaises(ValueError):
            backend.validate_static_inputs(report, self.cycle["manifest"], self.o.marker, self.o.marker_pin)
    self.assertEqual(self.calls, [])

  def test_stage_zero_is_exclusive_and_wrong_vector_cannot_arm(self):
    raw = b"\x07\0\0\0MBPW" + bytes.fromhex(self.cycle["prefix"]) + b"\0"
    self.host.write("source_stage", raw)
    with self.assertRaises(FileExistsError): self.host.write("source_stage", raw)
    self.assertEqual(self.host.read("source_stage"), raw)
    with self.assertRaises(ValueError): self.host.write("arm_vector", "f" * 64)

  def test_real_backend_preparation_sampler_workflow_and_retirement(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    self.assertEqual(result["cycle"]["state"], "archived")
    self.assertEqual(self.power_count, 1)
    self.assertFalse(self.host.read("source_marker_loaded"))
    self.assertEqual(self.host.read("wifi_driver"), "brcmfmac")
    with self.assertRaises(ValueError): writer("/sys/power/state", "disk")
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    retired = trial.RETIREMENT.retire(self.ledger, result["cycle"], archive, read_slot=read, compare_delete_slot=delete,
                                     health=self.host.retirement_health(sampler, collector.binding))
    self.assertEqual(retired["cycle"]["state"], "reconciled")
    self.assertTrue(all(self.host.read_slot(name) is None for name in backend.RETIRE.SLOTS.values()))

  def test_fresh_archived_retirement_needs_no_retained_sampler_or_collector(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    cycle = result["cycle"]
    # A new backend after the original runner exits has no Sampler/Collector.
    fresh = backend.HostBackend(self.root, self.o.report, cycle, self.o.marker, self.o.marker_pin,
                                command_runner=self.command, sysfs_writer=self.write)
    observe = fresh.archived_retirement_health(cycle, archive)
    binding = backend.RETIRE.ARCHIVE.cycle_binding(cycle)
    with patch.object(backend.HOST.Sampler, "before", side_effect=AssertionError("No reconstructed before sample")), \
         patch.object(backend.HOST.Sampler, "_binding", side_effect=AssertionError("No manufactured continuity")):
      self.assertTrue(observe(binding)["after_slot_retirement"])
      read, delete = fresh.retirement_callbacks(self.ledger, cycle, archive)
      retired = backend.RETIRE.retire(self.ledger, cycle, archive, read_slot=read, compare_delete_slot=delete, health=observe)
    self.assertEqual(retired["cycle"]["state"], "reconciled")
    self.assertEqual(self.power_count, 1)

  def test_fresh_retirement_health_rechecks_boot_pm_binding_and_archive_each_call(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    cycle = result["cycle"]
    observe = self.host.archived_retirement_health(cycle, archive)
    binding = backend.RETIRE.ARCHIVE.cycle_binding(cycle)
    observe(binding)
    with self.assertRaises(ValueError): observe({**binding, "vector": "0" * 64})
    self.o.write("proc/sys/kernel/random/boot_id", str(uuid.uuid4()))
    with self.assertRaises(ValueError): observe(binding)
    self.o.write("proc/sys/kernel/random/boot_id", cycle["original_boot_id"])
    self.o.write("sys/power/resume_offset", "999")
    with self.assertRaises(ValueError): observe(binding)
    self.o.write("sys/power/resume_offset", "123")
    self.o.write("sys/module/" + backend.MARKER + "/srcversion", self.o.marker_pin["srcversion"])
    with self.assertRaises(ValueError): observe(binding)
    (self.root / "sys/module" / backend.MARKER / "srcversion").unlink()
    (self.root / "sys/module" / backend.MARKER).rmdir()
    (archive / ("cycle-" + cycle["cycle_id"]) / "source-stage.bin").write_bytes(b"tampered")
    with self.assertRaises(ValueError): observe(binding)

  def test_battery_post_return_workflow_and_fresh_retirement_preserve_actual_power(self):
    original_writer = self.host._writer
    def return_on_battery(path, raw):
      original_writer(path, raw)
      if path == self.root / "sys/power/state":
        self.o.write("sys/class/power_supply/AC/online", "0")
    self.host._writer = return_on_battery
    result, writer, archive, sampler, collector = self.run_workflow()
    cycle = result["cycle"]
    self.assertIs(collector.retained_evidence()["write_returned"], True)
    archived = backend.RETIRE._decode((archive / ("cycle-" + cycle["cycle_id"]) / "cleanup-health.bin").read_bytes())
    self.assertIs(archived["devices"]["ac_online"], False)
    observe = self.host.archived_retirement_health(cycle, archive)
    binding = backend.RETIRE.ARCHIVE.cycle_binding(cycle)
    self.assertIs(observe(binding)["devices"]["ac_online"], False)
    read, delete = self.host.retirement_callbacks(self.ledger, cycle, archive)
    retired = backend.RETIRE.retire(self.ledger, cycle, archive, read_slot=read, compare_delete_slot=delete, health=observe)
    self.assertEqual(retired["cycle"]["state"], "reconciled")
    self.assertEqual(self.power_count, 1)
    self.assertFalse(retired["hardware_qualified"])

  def test_fresh_retirement_power_must_be_strict_boolean_and_devices_healthy(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    cycle = result["cycle"]
    observe = self.host.archived_retirement_health(cycle, archive)
    binding = backend.RETIRE.ARCHIVE.cycle_binding(cycle)
    original = backend.HOST.observe_current_health
    for value in (None, 0, 1, "false", "missing", "unhealthy"):
      with self.subTest(value=value):
        def malformed(*args, **kwargs):
          data = original(*args, **kwargs)
          data["devices"]["ac_online"] = False
          if value == "missing": data["devices"].pop("ac_online")
          elif value == "unhealthy": data["devices"]["wifi"] = False
          else: data["devices"]["ac_online"] = value
          return data
        with patch.object(backend.HOST, "observe_current_health", side_effect=malformed):
          with self.assertRaises(ValueError): observe(binding)

  def test_native_nonseekable_retirement_reopens_exact_slots(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    # Exercise native immutable/sync branches against tempdir bytes only.
    self.host.live = True
    with patch.object(backend.os, "lseek", side_effect=OSError(errno.ESPIPE, "nonseekable efivar fixture")) as seek, \
         patch.object(backend, "_clear_immutable", return_value=0), patch.object(backend.os, "sync"):
      retired = trial.RETIREMENT.retire(self.ledger, result["cycle"], archive, read_slot=read, compare_delete_slot=delete,
                                       health=self.host.retirement_health(sampler, collector.binding))
    seek.assert_not_called()
    self.assertEqual(retired["cycle"]["state"], "reconciled")
    self.assertTrue(all(self.host.read_slot(name) is None for name in backend.RETIRE.SLOTS.values()))

  def test_reopened_changed_bytes_preserve_owned_immutable_protection(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    name = backend.RETIRE.SLOTS["source"]
    path = self.root / backend.HOST.EFI / name
    expected = path.read_bytes()
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    self.host.live = True
    def clear(fd):
      path.write_bytes(b"foreign bytes")
      return backend.FS_IMMUTABLE_FL
    def execute(advance):
      delete.bind_locked(advance)
      with patch.object(backend, "_clear_immutable", side_effect=clear), patch.object(backend.fcntl, "ioctl") as restore:
        with self.assertRaises(ValueError): delete(name, expected)
        restore.assert_called_once()
        self.assertEqual(restore.call_args.args[1], backend.FS_IOC_SETFLAGS)
        self.assertEqual(restore.call_args.args[2][0], backend.FS_IMMUTABLE_FL)
    self.ledger.compare_and_run(result["cycle"], execute)
    self.assertEqual(path.read_bytes(), b"foreign bytes")

  def test_reopened_replacement_inode_refuses_even_identical_bytes(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    name = backend.RETIRE.SLOTS["source"]
    path = self.root / backend.HOST.EFI / name
    expected = path.read_bytes()
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    self.host.live = True
    def clear(fd):
      path.rename(path.with_name("preserved-original-slot"))
      path.write_bytes(expected)
      return backend.FS_IMMUTABLE_FL
    def execute(advance):
      delete.bind_locked(advance)
      with patch.object(backend, "_clear_immutable", side_effect=clear), patch.object(backend.fcntl, "ioctl") as restore:
        with self.assertRaises(ValueError): delete(name, expected)
        restore.assert_called_once()
    self.ledger.compare_and_run(result["cycle"], execute)
    self.assertEqual(path.read_bytes(), expected)
    self.assertTrue(path.with_name("preserved-original-slot").exists())

  def test_no_scope_or_expired_scope_never_writes(self):
    preparation, prepared, sampler, collector = self.prepare()
    writer = self.host.power_writer(self.ledger, prepared["cycle"], prepared["receipt"])
    with self.assertRaises(ValueError): writer("/sys/power/state", "disk")
    writer = self.host.power_writer(self.ledger, prepared["cycle"], prepared["receipt"])
    self.ledger.compare_and_run(prepared["cycle"], writer.bind_locked)
    with self.assertRaises(ValueError): writer("/sys/power/state", "disk")
    self.assertEqual(self.power_count, 0)
    self.assertEqual(preparation.cleanup(), [])

  def test_tampered_consumed_guard_blocks_power_and_still_cleans(self):
    with self.assertRaises(ValueError): self.run_workflow(tamper=True)
    self.assertEqual(self.power_count, 0)
    self.assertFalse(self.host.read("source_marker_loaded"))
    self.assertEqual(self.host.read("wifi_driver"), "brcmfmac")
    self.assertTrue(self.ledger._state()["blocked"])

  def test_failed_write_is_one_use_and_preserves_stages_guard_cleanup(self):
    self.fail_power = True
    with self.assertRaises(OSError): self.run_workflow()
    self.assertEqual(self.power_count, 1)
    self.assertFalse(self.host.read("source_marker_loaded"))
    self.assertIsNotNone(self.host.read("source_stage"))
    self.assertTrue((self.ledger.directory / ("preparation-" + self.cycle["cycle_id"] + "-guard.json")).is_file())
    self.assertTrue(self.ledger._state()["blocked"])

  def test_retirement_rejects_foreign_bytes_and_unbound_callback(self):
    result, writer, archive, sampler, collector = self.run_workflow()
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    name = backend.RETIRE.SLOTS["source"]
    expected = read(name)
    with self.assertRaises(ValueError): delete(name, expected)
    read, delete = self.host.retirement_callbacks(self.ledger, result["cycle"], archive)
    self.o.write(backend.HOST.EFI / name, b"foreign")
    def attempt(advance):
      delete.bind_locked(advance)
      with self.assertRaises(ValueError): delete(name, expected)
    self.ledger.compare_and_run(result["cycle"], attempt)
    self.assertEqual(read(name), b"foreign")

  def test_live_injected_writers_are_forbidden_before_operations(self):
    with patch.object(backend.os, "geteuid", return_value=0):
      with self.assertRaises(ValueError):
        backend.HostBackend(Path("/"), self.o.report, self.cycle, self.o.marker, self.o.marker_pin, command_runner=self.command)
    self.assertEqual(self.calls, [])

  def test_immutable_handling_changes_only_owned_bit(self):
    state = [0x30]
    def ioctl(fd, operation, flags, mutate):
      if operation == backend.FS_IOC_GETFLAGS: flags[0] = state[0]
      else: state[0] = flags[0]
    with patch.object(backend.fcntl, "ioctl", side_effect=ioctl): backend._clear_immutable(99)
    self.assertEqual(state[0], 0x20)

  def test_readiness_checks_real_fixture_before_consumption(self):
    before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}
    backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()})
    def inactive(argv):
      result = self.command(argv)
      if argv == ("systemctl", "is-active", "NetworkManager.service"): result.stdout = "inactive"
      return result
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=inactive)
    link = self.root / "sys/bus/pci/devices" / backend.WIFI / "driver"
    link.unlink()
    link.symlink_to(self.root / "sys/bus/pci/drivers/nvme")
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    link.unlink()
    link.symlink_to(self.root / "sys/bus/pci/drivers/brcmfmac")
    self.o.write("sys/power/resume_offset", "999")
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    self.o.write("sys/power/resume_offset", "123")
    self.o.write("sys/power/pm_async", "1")
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=self.command)

  def test_concrete_backend_through_trial_dispatcher(self):
    ledger = tx.Ledger(self.o.base / "dispatcher-ledger")
    guards = self.o.base / "dispatcher-guards"
    guards.mkdir(mode=0o700)
    archive = self.o.base / "dispatcher-archives"
    archive.mkdir(mode=0o700)
    authorization_id = str(uuid.uuid4())
    authorization = {"protocol": tx.TRIAL_PROTOCOL, "qualified": False, "manifest_sha256": tx.digest(self.o.report["manifest"]),
      "audited_details_sha256": self.o.report["audited_details_sha256"], "original_boot_id": self.o.boot,
      "authorization_id": authorization_id, "marker_pin": self.o.marker_pin,
      "physical_acceptance": {"boot_id": self.o.boot, "authorization_id": authorization_id,
                              "accepted": True, "method": "operator-attended-cold-power"}}
    config = {"schema": trial.CONFIG_SCHEMA, "source_directory": str(self.o.source), "restore_directory": str(self.o.base / "restore"),
      "production_uki": str(self.o.base / "production.efi"), "source_tree": str(self.o.tree), "marker_file": str(self.o.marker),
      "marker_pin": self.o.marker_pin, "manifest": self.o.report["manifest"],
      "audited_details_sha256": self.o.report["audited_details_sha256"], "staged_receipt_sha256": "e" * 64, "retire_slots": True}
    def factory(root, report, cycle, marker, pin):
      self.o.cycle = cycle
      return backend.HostBackend(root, report, cycle, marker, pin, command_runner=self.command, sysfs_writer=self.write)
    checks = []
    # Deployment has its own real-ESP fixture suite; this boundary remains synthetic.
    def deployment(*args): checks.append("deployment")
    original_ready = trial.verify_readiness
    def ready(*args):
      original_ready(*args)
      backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    with patch.object(trial, "verify_readiness", side_effect=ready), patch.object(trial, "_platform_readiness", side_effect=lambda root, report: backend.verify_readiness(root, report, command_runner=self.command)):
      result = trial.execute(config, authorization, self.o.report, ledger=ledger, guard_directory=guards, archive_directory=archive,
                             root=self.root, backend_factory=factory, sleeper=lambda duration: None, deployment_check=deployment)
    self.assertEqual(result["retirement"]["cycle"]["state"], "reconciled")
    self.assertEqual(checks, ["deployment", "deployment"])
    self.assertEqual(self.power_count, 1)
    self.assertFalse(result["usable_hibernation_qualified"])
    with self.assertRaises(ValueError): ledger.begin(self.o.boot)

  def test_readiness_swapfile_with_zram_and_exact_extent_and_backing(self):
    self.o.write("proc/swaps", "Filename Type Size Used Priority\n/swap/swapfile file 100000 0 -2\n/dev/zram0 partition 200000 0 100\n")
    backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    self.o.write("proc/swaps", "Filename Type Size Used Priority\n/other/swapfile file 100000 0 -2\n/dev/zram0 partition 200000 0 100\n")
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    self.o.write("proc/swaps", "Filename Type Size Used Priority\n/swap/swapfile file 100000 0 -2\n/other/swapfile file 100000 0 -2\n")
    with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=self.command)
    self.o.write("proc/swaps", "Filename Type Size Used Priority\n/swap/swapfile file 100000 0 -2\n/dev/zram0 partition 200000 0 100\n")
    for command, wrong in (("btrfs", "999"), ("findmnt", "/dev/mapper/other[/@] btrfs"),
                           ("findmnt", "/dev/mapper/root[/@] ext4")):
      def mismatch(argv):
        result = self.command(argv)
        if argv[0] == command: result.stdout = wrong
        return result
      with self.subTest(command=command, wrong=wrong):
        with self.assertRaises(ValueError): backend.verify_readiness(self.root, self.o.report, command_runner=mismatch)


if __name__ == "__main__":
  unittest.main()
