#!/usr/bin/python3
"""Qualified routine lifecycle fixtures; no live commands or hardware writes."""
import copy
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


base = Path(__file__).parents[1]
product = load("qualified_product_dispatch", base / "hibernate/product.py")
fixture = load("dispatch_backend_fixture", Path(__file__).with_name("test-hibernate-product-host-backend.py"))
tx = product.TX


class Dispatch(unittest.TestCase):
  def setUp(self):
    self.host = fixture.Backends("test_fixed_keys_commands_and_unknown_power_are_rejected")
    self.host.setUp()
    self.addCleanup(self.host.doCleanups)
    self.o = self.host.o
    self.root = self.host.root
    self.ledger = tx.Ledger(self.o.base / "routine-ledger")
    self.archives = self.o.base / "routine-archives"
    self.archives.mkdir(mode=0o700)
    self.qualification = copy.deepcopy(self.o.qualification)
    self.config = {"schema": product.CONFIG_SCHEMA, "source_directory": str(self.o.source), "restore_directory": str(self.o.base / "restore"),
      "production_uki": str(self.o.base / "production.efi"), "source_tree": str(self.o.tree), "marker_file": str(self.o.marker),
      "marker_pin": self.o.marker_pin, "manifest": self.o.report["manifest"],
      "audited_details_sha256": self.o.report["audited_details_sha256"], "staged_receipt_sha256": "e" * 64}
    self.deployments = []
    self.arguments = {"ledger": self.ledger, "archive_directory": self.archives, "root": self.root,
                      "query": self.host.command, "deployment_check": lambda *unused: self.deployments.append("verified")}

  def factory(self, root, report, cycle, marker, pin):
    self.o.cycle = cycle
    # Synthetic writer emulates kernel PM interfaces' advertised modes after
    # a transition; the fixture's actual power callback performs no syscall.
    def write(path, raw):
      self.host.write(path, raw)
      if path.relative_to(root) == Path("sys/power/state"): path.write_bytes(b"freeze mem disk")
    return fixture.backend.HostBackend(root, report, cycle, marker, pin, command_runner=self.host.command, sysfs_writer=write)

  def check(self, **changes):
    return product.check(self.config, changes.pop("qualification", self.qualification), self.o.report, **{**self.arguments, **changes})

  def execute(self, **changes):
    return product.execute(self.config, changes.pop("qualification", self.qualification), self.o.report,
                           **{**self.arguments, "backend_factory": self.factory, "sleeper": lambda duration: None, **changes})

  def test_check_has_no_cycle_preparation_or_power_and_requires_external_receipt(self):
    before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}
    checked = self.check()
    self.assertFalse(checked["execute"])
    self.assertIsNone(checked["predecessor_cycle_id"])
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))
    self.assertEqual(self.host.power_count, 0)
    self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()})
    for authority in (None, {**self.qualification, "qualified": False}, {**self.qualification, "protocol": tx.TRIAL_PROTOCOL}):
      with self.assertRaises(ValueError): self.check(qualification=authority)

  def battery(self, *, charge_now=70, charge_full=100, status="Discharging"):
    self.o.write("sys/class/power_supply/BAT0/type", "Battery")
    self.o.write("sys/class/power_supply/BAT0/present", "1")
    self.o.write("sys/class/power_supply/BAT0/status", status)
    self.o.write("sys/class/power_supply/BAT0/charge_now", str(charge_now))
    self.o.write("sys/class/power_supply/BAT0/charge_full", str(charge_full))
    self.o.write("sys/class/power_supply/AC/online", "0")

  def enable_battery_policy(self):
    self.config = {**self.config, "schema": product.CONFIG_SCHEMA_V2,
                   "power_policy": {"schema": product.POWER_POLICY.SCHEMA, "min_charge_percent": 30}}

  def test_v1_stays_ac_only_and_v2_admits_valid_battery_before_allocation(self):
    self.battery()
    with self.assertRaises(ValueError): self.execute()
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))
    self.enable_battery_policy()
    self.assertEqual(self.check()["power_decision"]["source"], "battery")
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))
    self.o.write("sys/class/power_supply/BAT0/charge_now", "29")
    with self.assertRaises(ValueError): self.execute()
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))

  def test_v2_unplug_during_prehooks_low_reserve_cleans_without_power(self):
    self.enable_battery_policy()
    self.battery(charge_now=29)
    self.o.write("sys/class/power_supply/AC/online", "1")
    @contextmanager
    def window(root):
      self.o.write("sys/class/power_supply/AC/online", "0")
      try: yield
      finally: self.deployments.append("thawed")
    class Gate:
      def require_secure(self, binding=None): return "session"
      def require_same_session(self, binding): pass
    with self.assertRaises(ValueError): self.execute(desktop=True, secure_gate=Gate(), desktop_window=window)
    self.assertEqual(self.host.power_count, 0)
    self.assertIn("thawed", self.deployments)
    self.assertFalse(self.host.host.read("source_marker_loaded"))
    self.assertEqual(self.host.host.read("wifi_driver"), "brcmfmac")
    self.assertTrue(self.ledger._state()["blocked"])

  def test_v2_unplug_during_prehooks_with_valid_reserve_continues(self):
    self.enable_battery_policy()
    self.battery(charge_now=70)
    self.o.write("sys/class/power_supply/AC/online", "1")
    @contextmanager
    def window(root):
      self.o.write("sys/class/power_supply/AC/online", "0")
      try: yield
      finally: self.deployments.append("thawed")
    class Gate:
      def require_secure(self, binding=None): return "session"
      def require_same_session(self, binding): pass
    result = self.execute(desktop=True, secure_gate=Gate(), desktop_window=window)
    self.assertEqual(result["cycle"]["state"], "reconciled")
    self.assertEqual(self.host.power_count, 1)
    self.assertIn("thawed", self.deployments)

  def test_v2_final_power_sample_follows_sync_and_refuses_new_low_reserve(self):
    self.enable_battery_policy()
    self.battery(charge_now=29)
    self.o.write("sys/class/power_supply/AC/online", "1")
    original_call = fixture.backend._PowerWrite.__call__
    events = []
    def synced_unplug():
      events.append("sync")
      self.o.write("sys/class/power_supply/AC/online", "0")
    def checked_call(writer, path, value):
      writer.backend.live = True
      # Only the final writer is under test. Its live marker file ownership
      # check cannot pass in this unprivileged temp-root fixture.
      try:
        with patch.object(writer.backend, "_marker_identity", return_value=None):
          return original_call(writer, path, value)
      finally: writer.backend.live = False
    with patch.object(fixture.backend._PowerWrite, "__call__", checked_call), \
         patch.object(product.BACKEND.os, "sync", side_effect=synced_unplug):
      with self.assertRaises(ValueError) as failure: self.execute()
    self.assertEqual(events, ["sync"], str(failure.exception))
    self.assertEqual(self.host.power_count, 0)
    self.assertTrue(self.ledger._state()["blocked"])
    self.assertEqual(len(list(self.ledger.directory.glob("power-admission-*.json"))), 1)
    self.assertFalse(any(self.ledger.directory.glob("power-prewrite-returned-*.json")))

  def test_cycle_power_records_preserve_distinct_native_reserves_without_return_gate(self):
    self.enable_battery_policy()
    self.battery(charge_now=70)
    events = []
    original_write, original_observe, ledger_write = self.host.write, fixture.backend.POWER_POLICY.observe, self.ledger._write
    def factory(*args):
      self.battery(charge_now=60)
      return self.factory(*args)
    def observe(*args):
      result = original_observe(*args)
      events.append("final-sample")
      return result
    def write(path, raw):
      if path.relative_to(self.root) == Path("sys/power/state"): events.append("disk")
      original_write(path, raw)
      if path.relative_to(self.root) == Path("sys/power/state"): self.battery(charge_now=20)
    def persist(name, value, **kwargs):
      if name.startswith("power-"): events.append(name.split("-")[1])
      return ledger_write(name, value, **kwargs)
    with patch.object(self.host, "write", side_effect=write), patch.object(self.ledger, "_write", side_effect=persist), \
         patch.object(fixture.backend.POWER_POLICY, "observe", side_effect=observe):
      result = self.execute(backend_factory=factory)
    cycle = result["cycle"]
    binding = {key: cycle[key] for key in product.HOST.CT.BINDING_KEYS}
    admission = self.ledger._read("power-admission-" + cycle["cycle_id"] + ".json")
    final = self.ledger._read("power-prewrite-returned-" + cycle["cycle_id"] + ".json")
    returned = self.ledger._read("power-postreturn-" + cycle["cycle_id"] + ".json")
    self.assertEqual(admission["observation"]["decision"]["reserve_now"], 70)
    self.assertEqual(final["observation"]["decision"]["reserve_now"], 60)
    self.assertEqual(final["persistence_phase"], "after-write-return")
    self.assertTrue(final["power_write_returned"])
    self.assertEqual(returned["observation"]["status"], "sampled")
    battery = next(item for item in returned["observation"]["snapshot"]["supplies"] if item["type"] == "Battery")
    self.assertEqual(battery["charge_now_uah"], 20)
    self.assertEqual(battery["charge_full_uah"], 100)
    for record in (admission, final, returned): self.assertEqual(record["binding"], binding)
    self.assertEqual(events, ["admission", "final-sample", "disk", "prewrite", "postreturn"])
    self.assertEqual(cycle["state"], "reconciled")
    self.assertEqual(product.WORKFLOW.ARCHIVE.REQUIRED_NAMES, set(path.name for path in (self.archives / ("cycle-" + cycle["cycle_id"])).iterdir()) - {"completion.json"})

  def test_postreturn_power_sample_unavailable_is_observation_not_failure(self):
    original_sample = fixture.backend.POWER_POLICY.SUPPLY.sample_power_supply
    def sample(root):
      if self.host.power_count: raise ValueError("synthetic unavailable telemetry")
      return original_sample(root)
    with patch.object(fixture.backend.POWER_POLICY.SUPPLY, "sample_power_supply", side_effect=sample):
      result = self.execute()
    record = self.ledger._read("power-postreturn-" + result["cycle"]["cycle_id"] + ".json")
    self.assertEqual(record["observation"], {"status": "unavailable", "error_type": "ValueError"})
    self.assertEqual(result["cycle"]["state"], "reconciled")

  def test_admission_power_record_sync_failure_blocks_before_preparation(self):
    sync = self.ledger._sync
    failed = False
    def fail_sync():
      nonlocal failed
      if not failed and any(self.ledger.directory.glob("power-admission-*.json")):
        failed = True
        raise OSError("synthetic admission sync failure")
      return sync()
    with patch.object(self.ledger, "_sync", side_effect=fail_sync), self.assertRaises(OSError): self.execute()
    self.assertEqual(self.host.power_count, 0)
    self.assertFalse(any(self.ledger.directory.glob("preparation-*.json")))
    self.assertTrue(self.ledger._state()["blocked"])
    self.assertEqual(self.ledger._cycles()[0]["state"], "failed")
    with self.assertRaises(ValueError): self.execute()

  def test_return_power_persistence_failures_keep_truthful_return_and_cleanup(self):
    for prefix in ("power-prewrite-returned-", "power-postreturn-"):
      with self.subTest(prefix=prefix):
        case = Dispatch("test_check_has_no_cycle_preparation_or_power_and_requires_external_receipt")
        case.setUp()
        try:
          write = case.ledger._write
          def fail(name, value, **kwargs):
            if name.startswith(prefix): raise OSError("synthetic returned evidence failure")
            return write(name, value, **kwargs)
          with patch.object(case.ledger, "_write", side_effect=fail), self.assertRaises(OSError): case.execute()
          cycle = case.ledger._cycles()[0]
          failure = case.ledger._read("workflow-failure-" + cycle["cycle_id"] + ".json")
          self.assertTrue(failure["snapshot"]["retained"]["write_returned"])
          self.assertFalse(failure["snapshot"]["retained"]["capture_valid"])
          self.assertEqual(failure["snapshot"]["cleanup_errors"], [])
          self.assertFalse(case.host.host.read("source_marker_loaded"))
          self.assertTrue(case.ledger._state()["blocked"])
          with self.assertRaises(ValueError): case.execute()
        finally: case.doCleanups()

  def test_exclusive_power_sidecars_never_overwrite_existing_evidence(self):
    for prefix in ("power-admission-", "power-prewrite-returned-", "power-postreturn-"):
      with self.subTest(prefix=prefix):
        case = Dispatch("test_check_has_no_cycle_preparation_or_power_and_requires_external_receipt")
        case.setUp()
        try:
          write = case.ledger._write
          def collide(name, value, **kwargs):
            if name.startswith(prefix): write(name, {"preserved": "existing evidence"}, exclusive=True)
            return write(name, value, **kwargs)
          with patch.object(case.ledger, "_write", side_effect=collide), self.assertRaises(FileExistsError): case.execute()
          record = next(case.ledger.directory.glob(prefix + "*.json"))
          self.assertEqual(case.ledger._read(record.name), {"preserved": "existing evidence"})
          self.assertEqual(case.host.power_count, 0 if prefix == "power-admission-" else 1)
          self.assertTrue(case.ledger._state()["blocked"])
        finally: case.doCleanups()

  def test_two_real_backend_cycles_sameboot_restore_selection_fresh_uuid_vectors(self):
    first = self.execute()
    self.assertEqual(first["cycle"]["state"], "reconciled")
    self.assertFalse(first["qualification_issued"])
    self.assertEqual(set(self.qualification), {"protocol", "manifest_sha256", "evidence_sha256", "qualified"})
    self.assertNotIn("original_boot_id", self.qualification)
    admitted = self.check()
    self.assertEqual(admitted["predecessor_cycle_id"], first["cycle"]["cycle_id"])
    second = self.execute()
    self.assertEqual(second["cycle"]["state"], "reconciled")
    self.assertEqual(second["cycle"]["original_boot_id"], first["cycle"]["original_boot_id"])
    self.assertEqual(second["cycle"]["qualification_sha256"], first["cycle"]["qualification_sha256"])
    for key in ("cycle_id", "vector", "prefix"): self.assertNotEqual(second["cycle"][key], first["cycle"][key])
    link = self.ledger._read("allocation-" + second["cycle"]["cycle_id"] + ".json")
    self.assertEqual(link["predecessor"], {"cycle_id": first["cycle"]["cycle_id"], "cycle_sha256": tx.digest(first["cycle"])})
    self.assertEqual(self.host.power_count, 2)
    self.assertTrue(all((self.archives / ("cycle-" + result["cycle"]["cycle_id"]) / "completion.json").is_file() for result in (first, second)))
    self.assertFalse((self.ledger.directory / "trial-consumed.json").exists())
    self.assertEqual(self.ledger._state()["qualification"], self.qualification)

  def test_first_restore_stock_and_wrong_boot_predecessor_rejected_before_allocation(self):
    self.o.select("restore")
    with self.assertRaises(ValueError): self.execute()
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))
    self.o.select("source")
    self.host.loader("LoaderEntrySelected", "Omarchy.linux-t2")
    with self.assertRaises(ValueError): self.execute()
    self.o.select("source")
    first = self.execute()
    self.o.write("proc/sys/kernel/random/boot_id", str(uuid.uuid4()))
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(len(list(self.ledger.directory.glob("cycle-*.json"))), 1)
    self.assertEqual(self.host.power_count, 1)

  def test_changed_authority_or_damaged_immediate_archive_cannot_authorize_restore_selection(self):
    first = self.execute()
    changed = {**self.qualification, "evidence_sha256": "f" * 64}
    with self.assertRaises(ValueError): self.execute(qualification=changed)
    archived = self.archives / ("cycle-" + first["cycle"]["cycle_id"]) / "source-stage.bin"
    archived.write_bytes(b"foreign")
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(len(list(self.ledger.directory.glob("cycle-*.json"))), 1)
    self.assertEqual(self.host.power_count, 1)

  def test_active_cycle_and_unresolved_retirement_block_routine_admission(self):
    self.ledger.configure(self.o.report["manifest"])
    self.ledger.qualify(self.qualification)
    reserved = self.ledger.begin(self.o.boot)
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(self.host.power_count, 0)
    self.assertEqual(len(list(self.ledger.directory.glob("cycle-*.json"))), 1)

  def test_unresolved_retirement_sentinel_blocks_even_reconciled_head(self):
    first = self.execute()
    self.ledger._write("slot-retirement-" + first["cycle"]["cycle_id"] + "-unresolved.json", {"ambiguous": True}, exclusive=True)
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(self.host.power_count, 1)
    self.assertEqual(len(list(self.ledger.directory.glob("cycle-*.json"))), 1)

  def test_constructor_and_write_failure_block_newcycle_no_auto_reset(self):
    def failed(*unused): raise OSError("synthetic constructor failure")
    with self.assertRaises(OSError): self.execute(backend_factory=failed)
    self.assertTrue(self.ledger._state()["blocked"])
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(self.host.power_count, 0)

  def test_failed_power_runs_cleanup_preserves_evidence_and_blocks_next(self):
    self.host.fail_power = True
    with self.assertRaises(OSError): self.execute()
    self.assertFalse(self.host.host.read("source_marker_loaded"))
    self.assertEqual(self.host.host.read("wifi_driver"), "brcmfmac")
    self.assertTrue(self.ledger._state()["blocked"])
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(self.host.power_count, 1)
    cycle = self.ledger._cycles()[0]
    self.assertTrue((self.ledger.directory / ("preparation-" + cycle["cycle_id"] + "-guard.json")).is_file())
    self.assertTrue((self.ledger.directory / ("workflow-failure-" + cycle["cycle_id"] + ".json")).is_file())
    self.assertTrue((self.ledger.directory / ("power-admission-" + cycle["cycle_id"] + ".json")).is_file())
    self.assertFalse(any(self.ledger.directory.glob("power-prewrite-returned-*.json")))

  def test_no_cli_bypass_help_or_nonroot_hibernate_has_no_global_access(self):
    with patch.object(product.TRIAL, "_global_lock", side_effect=AssertionError("Unexpected global access")):
      with self.assertRaises(SystemExit) as outcome: product.main(["--help"])
      self.assertEqual(outcome.exception.code, 0)
      with patch.object(product.os, "geteuid", return_value=1234):
        with self.assertRaises(SystemExit): product.main(["hibernate"])
      for arguments in (["hibernate", "--root", "/tmp"], ["hibernate", "--force"]):
        with self.assertRaises(SystemExit): product.main(arguments)

  def test_live_injected_admission_is_rejected_before_reads(self):
    with self.assertRaises(ValueError): self.check(root=Path("/"))

  def test_desktop_gate_rechecks_same_binding_before_freeze_and_power(self):
    events = []
    class Gate:
      def require_secure(self, binding=None):
        events.append(("secure", binding))
        return "same-session"
      def require_same_session(self, binding): events.append(("identity", binding))
    @contextmanager
    def window(root):
      events.append(("freeze", self.host.power_count))
      try: yield
      finally: events.append(("thaw", self.host.power_count))
    result = self.execute(desktop=True, secure_gate=Gate(), desktop_window=window)
    self.assertEqual(result["cycle"]["state"], "reconciled")
    self.assertEqual(events, [("secure", None), ("secure", "same-session"), ("freeze", 0),
                              ("identity", "same-session"), ("thaw", 1)])

  def test_desktop_session_failure_prevents_power_and_runs_cleanup(self):
    class Gate:
      def require_secure(self, binding=None):
        if binding is not None: raise ValueError("fixture session changed")
        return "session"
    @contextmanager
    def forbidden_window(root):
      raise AssertionError("Cannot freeze after failed secure check")
      yield
    with self.assertRaises(ValueError): self.execute(desktop=True, secure_gate=Gate(), desktop_window=forbidden_window)
    self.assertEqual(self.host.power_count, 0)
    self.assertFalse(self.host.host.read("source_marker_loaded"))
    self.assertEqual(self.host.host.read("wifi_driver"), "brcmfmac")
    self.assertTrue(self.ledger._state()["blocked"])

  def test_desktop_admission_failure_creates_no_cycle_and_live_injection_rejected(self):
    class Gate:
      def require_secure(self, binding=None): raise ValueError("fixture unsecured")
    with self.assertRaises(ValueError): self.execute(desktop=True, secure_gate=Gate())
    self.assertFalse(any(self.ledger.directory.glob("cycle-*.json")))
    with self.assertRaises(ValueError): self.execute(root=Path("/"), desktop=True, secure_gate=Gate())

  def test_desktop_post_fault_preserves_original_return_capture_and_blocks(self):
    class Gate:
      def require_secure(self, binding=None): return "session"
      def require_same_session(self, binding): pass
    @contextmanager
    def failed_post(root):
      try: yield
      finally: raise OSError("fixture post-hook fault after successful power return")
    with self.assertRaises(ValueError): self.execute(desktop=True, secure_gate=Gate(), desktop_window=failed_post)
    self.assertEqual(self.host.power_count, 1)
    self.assertTrue(self.ledger._state()["blocked"])
    self.assertFalse(self.host.host.read("source_marker_loaded"))
    cycle = self.ledger._cycles()[0]
    captured = self.ledger._read("workflow-capture-" + cycle["cycle_id"] + ".json")
    self.assertTrue(captured["retained"]["write_returned"])
    self.assertTrue(captured["retained"]["capture_valid"])
    failure = self.ledger._read("workflow-failure-" + cycle["cycle_id"] + ".json")
    self.assertEqual(failure["snapshot"]["cleanup_errors"], ["desktop-sleep-cleanup:OSError"])

  def test_desktop_session_change_during_prehooks_thaws_without_power(self):
    events = []
    class Gate:
      def require_secure(self, binding=None): return "session"
      def require_same_session(self, binding):
        events.append("identity")
        raise ValueError("fixture active session changed while pre-hooks ran")
    @contextmanager
    def window(root):
      events.append("freeze")
      try: yield
      finally: events.append("thaw")
    with self.assertRaises(ValueError): self.execute(desktop=True, secure_gate=Gate(), desktop_window=window)
    self.assertEqual(events, ["freeze", "identity", "thaw"])
    self.assertEqual(self.host.power_count, 0)
    self.assertTrue(self.ledger._state()["blocked"])
    self.assertFalse(self.host.host.read("source_marker_loaded"))

  def test_pending_boot_policy_transitions_veto_before_deployment_and_power(self):
    directory = self.root / product.BOOT_POLICY.STATE
    directory.mkdir(parents=True, mode=0o700)
    for name in ("source-default-activation.pending", "source-default-deactivation.pending", "package-maintenance.pending"):
      pending = directory / name
      for variant in ("empty", "malformed", "dangling"):
        if variant == "dangling": pending.symlink_to("missing-transition")
        else: pending.write_bytes(b"" if variant == "empty" else b"interrupted or malformed")
        with self.subTest(name=name, variant=variant), self.assertRaisesRegex(ValueError, "Incomplete source-default"):
          product.verify_deployment(self.root, {}, {})
        pending.unlink()
    directory.rmdir()
    directory.symlink_to("missing-product-state")
    with self.assertRaises(ValueError): product.verify_deployment(self.root, {}, {})
    self.assertEqual(self.host.power_count, 0)


if __name__ == "__main__": unittest.main()
