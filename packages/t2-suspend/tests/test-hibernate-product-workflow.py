#!/usr/bin/python3
"""Injected workflow integration; files live exclusively in temporary roots."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("product_workflow", Path(__file__).parents[1] / "hibernate/workflow.py")
wf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wf)
ct = wf.CONTINUITY
tx = wf.TX


class Workflows(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.root = Path(self.temp.name)
    self.archives = self.root / "archives"
    self.archives.mkdir(mode=0o700)
    self.ledger = tx.Ledger(self.root / "ledger")
    self.manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", **{key: str(i) * 64 for i, key in enumerate(tx.PINS, 1)}}
    self.qualification = {"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(self.manifest), "evidence_sha256": "a" * 64, "qualified": True}
    self.ledger.configure(self.manifest)
    self.ledger.qualify(self.qualification)
    cycle = self.ledger.begin(str(uuid.uuid4()))
    self.cycle = self.ledger.advance(cycle["cycle_id"], "prepared", "b" * 64)
    binding = {key: self.cycle[key] for key in ct.BINDING_KEYS}
    self.guard = wf.encoded({"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": binding})
    self.attempt = wf.encoded({"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": binding, "state": "transition-armed",
                               "real_s4_attempted": True, "requested_disk_mode": "platform", "consumed_guard_sha256": ct.raw_digest(self.guard)})
    self.runtime = {"kernel_release": "synthetic-t2", "cmdline_sha256": "c" * 64, "modules": {name: {"sha256": "d" * 64, "srcversion": "A" * 24} for name in ct.REQUIRED_MODULES}, "loaded_modules": sorted(ct.REQUIRED_MODULES)}
    self.pm = {"pm_test": "none", "disk": "platform", "pm_trace": "0", "resume_device": "/dev/mapper/root", "resume_offset": 123}
    self.collector = ct.Collector(self.cycle, self.qualification, self.runtime, self.pm, self.guard, self.attempt)
    self.order = []

  def tearDown(self):
    self.temp.cleanup()

  def power_write(self, path, value):
    self.assertEqual((path, value), ("/sys/power/state", "disk"))
    self.order.append("write")

  def capture(self, binding):
    self.order.append("capture")
    prefix = self.cycle["prefix"]
    return {"schema": ct.SCHEMA, "binding": binding, "boot_id": self.cycle["original_boot_id"], "manifest": self.manifest,
            "runtime_stack_sha256": self.manifest["runtime_sha256"], "source_runtime": self.runtime,
            "consumed_guard": self.guard, "consumed_attempt": self.attempt,
            "LoaderEntrySelected": b"\x06\0\0\0" + ("MBA-T2-hibernation-restore-" + self.manifest["restore_sha256"][:16] + "\0").encode("utf-16-le"),
            "efi_overrides": {"LoaderEntryOneShot": None, "LoaderEntryDefault": None},
            "markers": {ct.SOURCE_VARIABLE: b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04",
                        ct.RESTORE_VARIABLE: b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07",
                        "OmarchyT2RestoreHookEntered" + prefix + "-" + ct.GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x01",
                        "OmarchyT2RestoreHookArmed" + prefix + "-" + ct.GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x02"},
            "restore_only_modules": [], "abort_modules": [], "abort_witnesses": []}

  def cleanup(self):
    self.order.append("cleanup")
    return []

  def health(self, binding):
    self.order.append("health")
    return {"schema": ct.SCHEMA, "binding": binding, "boot_id": self.cycle["original_boot_id"], "after_cleanup": True,
            "devices": {"primary_encrypted_root": True, "internal_keyboard": True, "internal_trackpad": True, "wifi": True, "bluetooth": True, "ac_online": True},
            "services": {"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"}, "failed_units": [], "pm": self.pm}

  def run_workflow(self, **changes):
    return wf.run(self.ledger, self.collector, self.archives, **{"power_write": self.power_write, "capture": self.capture, "cleanup": self.cleanup, "health": self.health, **changes})

  def assert_blocked(self):
    with self.assertRaises(ValueError): self.ledger.begin(str(uuid.uuid4()))

  def test_success_archives_computed_bytes_but_does_not_release(self):
    result = self.run_workflow()
    self.assertEqual(self.order, ["write", "capture", "cleanup", "health"])
    self.assertEqual(result["cycle"]["state"], "archived")
    self.assertFalse(result["slot_clear_authorized"])
    archive = self.archives / ("cycle-" + self.cycle["cycle_id"])
    witness = (archive / "source-return-witness.bin").read_bytes()
    self.assertEqual(ct.raw_digest(witness), result["cycle"]["returned_evidence_sha256"])
    self.assertEqual((archive / "consumed-guard.bin").read_bytes(), self.guard)
    self.assertEqual(wf.ARCHIVE.verify_archive(self.archives, result["cycle"]), result["archive_receipt"])
    self.assert_blocked()

  def test_json_collector_and_stale_qualification_rejected_before_write(self):
    with self.assertRaises(ValueError): wf.run(self.ledger, self.collector.binding, self.archives, power_write=self.power_write, capture=self.capture, cleanup=self.cleanup, health=self.health)
    self.ledger.qualify({**self.qualification, "evidence_sha256": "e" * 64})
    with self.assertRaises(ValueError): self.run_workflow()
    self.assertEqual(self.order, [])

  def test_stale_cycle_rejected_before_write(self):
    record = self.cycle.copy()
    record["prepared_evidence_sha256"] = "e" * 64
    self.ledger._write("cycle-" + record["cycle_id"] + ".json", record)
    with self.assertRaises(ValueError): self.run_workflow()
    self.assertEqual(self.order, [])

  def test_failed_write_runs_cleanup_and_preserves_consumed_inputs(self):
    def fail(path, value):
      self.order.append("write-failed")
      raise RuntimeError("synthetic failure")
    with self.assertRaises(RuntimeError): self.run_workflow(power_write=fail)
    self.assertEqual(self.order, ["write-failed", "cleanup"])
    snapshot = self.ledger._read("workflow-failure-" + self.cycle["cycle_id"] + ".json")
    self.assertEqual(snapshot["snapshot"]["retained"]["consumed_guard"]["raw_hex"], self.guard.hex())
    self.assertEqual(self.ledger._state()["blocked"], True)
    self.assert_blocked()

  def test_invalid_capture_preserved_and_cannot_be_finished(self):
    def bad_capture(binding):
      data = self.capture(binding)
      data["markers"][ct.RESTORE_VARIABLE] += b"bad"
      return data
    with self.assertRaises(ValueError): self.run_workflow(capture=bad_capture)
    self.assertEqual(self.order, ["write", "capture", "cleanup"])
    snapshot = self.ledger._read("workflow-failure-" + self.cycle["cycle_id"] + ".json")
    self.assertFalse(snapshot["snapshot"]["retained"]["capture_valid"])
    with self.assertRaises(ValueError): self.collector.finish(self.health(self.collector.binding), [])
    self.assert_blocked()

  def test_failed_health_and_cleanup_do_not_record_return(self):
    with self.assertRaises(ValueError): self.run_workflow(cleanup=lambda: ["synthetic cleanup error"])
    self.assertEqual(self.order, ["write", "capture"])
    self.assertEqual(self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")["state"], "failed")
    self.assert_blocked()

  def test_health_failure_preserves_postcleanup_sample(self):
    def unhealthy(binding):
      data = self.health(binding)
      data["devices"]["internal_keyboard"] = False
      return data
    with self.assertRaises(ValueError): self.run_workflow(health=unhealthy)
    sample = self.ledger._read("workflow-health-" + self.cycle["cycle_id"] + ".json")
    self.assertFalse(sample["cleanup_health"]["devices"]["internal_keyboard"])
    self.assert_blocked()

  def test_archive_failure_preserves_partial_and_blocks(self):
    target = self.archives / ("cycle-" + self.cycle["cycle_id"])
    target.mkdir(mode=0o700)
    with self.assertRaises(FileExistsError): self.run_workflow()
    self.assertTrue(target.exists())
    cycle = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
    self.assertEqual(cycle["state"], "failed")
    self.assertIn("returned_evidence_sha256", cycle)
    self.assert_blocked()

  def test_archive_tamper_before_verification_cannot_mark_archived(self):
    create = wf.ARCHIVE.create_archive
    def tamper(directory, cycle, evidence):
      receipt = create(directory, cycle, evidence)
      target = directory / ("cycle-" + cycle["cycle_id"]) / "source-stage.bin"
      target.write_bytes(b"tampered")
      return receipt
    with patch.object(wf.ARCHIVE, "create_archive", side_effect=tamper):
      with self.assertRaises(ValueError): self.run_workflow()
    self.assert_blocked()

  def test_concurrent_requests_refuse_under_callback_lock(self):
    def write(path, value):
      with self.assertRaises(BlockingIOError): self.ledger.begin(str(uuid.uuid4()))
      self.power_write(path, value)
    self.run_workflow(power_write=write)

  def test_persistence_failure_blocks_even_failure_journal_failure(self):
    def fail(*args, **kwargs): raise OSError("synthetic disk failure")
    with patch.object(self.ledger, "_write", side_effect=fail):
      with self.assertRaises(OSError): self.run_workflow()
    self.assertEqual(self.order, ["cleanup"])
    self.assertEqual(self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")["state"], "prepared")
    self.assert_blocked()
    with self.assertRaises(ValueError): self.run_workflow()
    self.assertNotIn("write", self.order)

  def test_interrupted_write_runs_cleanup_and_blocks(self):
    def interrupt(path, value): raise KeyboardInterrupt("synthetic interruption")
    with self.assertRaises(KeyboardInterrupt): self.run_workflow(power_write=interrupt)
    self.assertEqual(self.order, ["cleanup"])
    self.assert_blocked()

  def test_no_saved_compare_callback_after_lock_scope(self):
    saved = []
    self.ledger.compare_and_run(self.cycle, lambda advance: saved.append(advance))
    with self.assertRaises(ValueError): saved[0]("returned", "f" * 64)

  def test_existing_prewrite_journal_from_crash_prevents_replay(self):
    name = "workflow-before-" + self.cycle["cycle_id"] + ".json"
    self.ledger._write(name, {"preserved": "interrupted original attempt"}, exclusive=True)
    with self.assertRaises(FileExistsError): self.run_workflow()
    self.assertEqual(self.order, ["cleanup"])
    self.assertEqual(self.ledger._read(name), {"preserved": "interrupted original attempt"})
    self.assert_blocked()


if __name__ == "__main__":
  unittest.main()
