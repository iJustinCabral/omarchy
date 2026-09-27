#!/usr/bin/python3
"""Injected dictionary slot retirement; all journals/archives live in tempdirs."""

import copy
import importlib.util
from pathlib import Path
import stat
import unittest
from unittest import mock
import uuid


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


HERE = Path(__file__).parent
retirement = load("product_retirement", HERE.parent / "hibernate/slot_retirement.py")
fixtures = load("retirement_workflow_fixtures", HERE / "test-hibernate-product-workflow.py")
tx = retirement.TX


class Retirement(unittest.TestCase):
  def setUp(self):
    self.fixture = fixtures.Workflows(methodName="runTest")
    self.fixture.setUp()
    result = self.fixture.run_workflow()
    self.cycle = result["cycle"]
    self.ledger = self.fixture.ledger
    self.archives = self.fixture.archives
    self.target = self.archives / ("cycle-" + self.cycle["cycle_id"])
    self.slots = dict(self.fixture.capture(self.fixture.collector.binding)["markers"])
    self.slots["OmarchyT2ColdPciPreArchReturnedHistorical"] = b"historical witness never touched"
    self.slots["consumed-guard"] = self.fixture.guard
    self.slots["consumed-attempt"] = self.fixture.attempt
    self.original_slots = self.slots.copy()
    self.deleted = []
    self.health_calls = 0

  def tearDown(self):
    self.fixture.tearDown()

  def read(self, name):
    self.assertIn(name, retirement.SLOTS.values())
    return self.slots.get(name)

  def delete(self, name, expected):
    self.assertIn(name, retirement.SLOTS.values())
    if self.slots.get(name) != expected:
      return False
    del self.slots[name]
    self.deleted.append(name)
    return True

  def health(self, binding):
    self.health_calls += 1
    self.assertTrue(all(name not in self.slots for name in retirement.SLOTS.values()))
    return retirement._health_expected(binding, self.fixture.pm.copy())

  def run_retirement(self, **changes):
    return retirement.retire(self.ledger, self.cycle, self.archives,
                              **{"read_slot": self.read, "compare_delete_slot": self.delete, "health": self.health, **changes})

  def assert_blocked(self):
    self.assertTrue(self.ledger._state()["blocked"])
    with self.assertRaises(ValueError): self.ledger.begin(str(uuid.uuid4()))

  def confirmed_crash_fixture(self, role):
    """Represent a process crash after this slot's durable absence confirmation."""
    binding, expected, _baseline = retirement._archived_evidence(self.archives, self.cycle)
    stem = "slot-retirement-" + self.cycle["cycle_id"]
    intent = {"schema": retirement.PROTOCOL, "state": "intent", "binding": binding,
              "archive_sha256": self.cycle["archive_evidence_sha256"],
              "slots": {retirement.SLOTS[item]: retirement.CONTINUITY.raw_digest(expected[item + "-stage.bin"])
                        for item in retirement.SLOTS}}
    retirement._exact_journal(self.ledger, stem + "-intent.json", intent)
    name = retirement.SLOTS[role]
    clear_intent = {"schema": retirement.PROTOCOL, "state": "clear-intent", "intent_sha256": tx.digest(intent),
                    "slot": name, "expected_sha256": retirement.CONTINUITY.raw_digest(expected[role + "-stage.bin"])}
    confirmed = {"schema": retirement.PROTOCOL, "state": "confirmed-absent", "intent_sha256": tx.digest(intent),
                 "clear_intent_sha256": tx.digest(clear_intent), "slot": name,
                 "expected_sha256": retirement.CONTINUITY.raw_digest(expected[role + "-stage.bin"])}
    self.ledger._write(stem + "-" + role + "-clear-intent.json", clear_intent, exclusive=True)
    self.ledger._write(stem + "-" + role + "-confirmed.json", confirmed, exclusive=True)
    del self.slots[name]

  def test_success_exact_two_slots_preserves_all_evidence_and_allows_next_cycle(self):
    before = {path: path.read_bytes() for path in self.target.iterdir()}
    result = self.run_retirement()
    self.assertEqual(result["cycle"]["state"], "reconciled")
    self.assertEqual(self.deleted, list(retirement.SLOTS.values()))
    self.assertEqual(self.health_calls, 2)
    for name, raw in self.original_slots.items():
      if name not in retirement.SLOTS.values(): self.assertEqual(self.slots[name], raw)
    self.assertEqual(before, {path: path.read_bytes() for path in self.target.iterdir()})
    self.assertFalse(result["hardware_qualified"])
    self.assertFalse((self.ledger.directory / ("slot-retirement-" + self.cycle["cycle_id"] + "-unresolved.json")).exists())
    next_cycle = self.ledger.begin(self.cycle["original_boot_id"])
    self.assertNotEqual(next_cycle["vector"], self.cycle["vector"])
    self.assertEqual(next_cycle["qualification_vector"], self.cycle["qualification_vector"])

  def test_nonarchived_stale_and_historical_cycles_refuse_before_delete(self):
    for changed in ({"state": "returned"}, {"protocol": "cold-pci-guard-fullrestore-v1"},
                    {"archive_evidence_sha256": "e" * 64}, {"vector": "f" * 64}):
      with self.subTest(changed=changed):
        with self.assertRaises(ValueError):
          retirement.retire(self.ledger, {**self.cycle, **changed}, self.archives,
                            read_slot=self.read, compare_delete_slot=self.delete, health=self.health)
    self.assertEqual(self.deleted, [])

  def test_foreign_restore_slot_refuses_before_any_delete(self):
    self.slots[retirement.SLOTS["restore"]] = b"foreign vector bytes"
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assertEqual(self.slots[retirement.SLOTS["source"]], self.original_slots[retirement.SLOTS["source"]])
    self.assert_blocked()

  def test_foreign_second_clear_intent_refuses_before_any_delete(self):
    stem = "slot-retirement-" + self.cycle["cycle_id"]
    self.ledger._write(stem + "-restore-clear-intent.json", {"foreign": "clear intent"}, exclusive=True)
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assertEqual(self.slots, self.original_slots)
    self.assert_blocked()

  def test_historical_v16_live_prefix_is_never_cleared(self):
    prefix = bytes.fromhex("33a2e46e7598c0737daf3eb2")
    self.slots[retirement.SLOTS["source"]] = b"\x07\0\0\0MBPW" + prefix + b"\x04"
    self.slots[retirement.SLOTS["restore"]] = b"\x07\0\0\0MBRS" + prefix + b"\x07"
    before = self.slots.copy()
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(before, self.slots)
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_missing_slot_without_confirmation_is_ambiguous(self):
    del self.slots[retirement.SLOTS["source"]]
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_confirmed_earlier_clear_resumes_only_remaining_slot(self):
    self.confirmed_crash_fixture("source")
    result = self.run_retirement()
    self.assertEqual(result["cycle"]["state"], "reconciled")
    self.assertEqual(self.deleted, [retirement.SLOTS["restore"]])

  def test_existing_journals_are_resynced_before_resumed_deletion(self):
    self.confirmed_crash_fixture("source")
    stem = "slot-retirement-" + self.cycle["cycle_id"]
    intent = self.ledger._read(stem + "-intent.json")
    sentinel = {"schema": retirement.PROTOCOL, "state": "unresolved", "binding": intent["binding"],
                "intent_sha256": tx.digest(intent)}
    self.ledger._write(stem + "-unresolved.json", sentinel, exclusive=True)
    synced = set()
    events = []
    original_sync = retirement._sync_existing_journal
    original_fsync = retirement.os.fsync
    def tracked_fsync(fd):
      events.append("file" if stat.S_ISREG(retirement.os.fstat(fd).st_mode) else "directory")
      return original_fsync(fd)
    def sync_existing(ledger, name):
      before = len(events)
      result = original_sync(ledger, name)
      self.assertEqual(events[before:], ["file", "directory"])
      synced.add(name)
      return result
    def delete_after_sync(name, expected):
      self.assertTrue({stem + "-intent.json", stem + "-unresolved.json", stem + "-source-clear-intent.json",
                       stem + "-source-confirmed.json"} <= synced)
      return self.delete(name, expected)
    with mock.patch.object(retirement.os, "fsync", side_effect=tracked_fsync), \
         mock.patch.object(retirement, "_sync_existing_journal", side_effect=sync_existing):
      self.assertEqual(self.run_retirement(compare_delete_slot=delete_after_sync)["cycle"]["state"], "reconciled")

  def test_confirmed_slot_reappeared_refuses_and_progress_tamper_blocks(self):
    self.confirmed_crash_fixture("source")
    stem = "slot-retirement-" + self.cycle["cycle_id"]
    journal = self.ledger._read(stem + "-source-confirmed.json")
    journal["expected_sha256"] = "f" * 64
    self.ledger._write(stem + "-source-confirmed.json", journal)
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_archive_tamper_refuses_before_deleting(self):
    path = self.target / "source-stage.bin"
    path.write_bytes(b"tampered")
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_archive_mutated_by_delete_callback_cannot_release(self):
    def tampering_delete(name, expected):
      result = self.delete(name, expected)
      (self.target / "source-stage.bin").write_bytes(b"tampered during deletion")
      return result
    with self.assertRaises(ValueError): self.run_retirement(compare_delete_slot=tampering_delete)
    self.assert_blocked()
    record = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
    self.assertNotIn("release_evidence_sha256", record)

  def test_archive_mutated_by_final_health_cannot_reconcile(self):
    def tampering_health(binding):
      result = self.health(binding)
      if self.health_calls == 2:
        (self.target / "restore-stage.bin").write_bytes(b"tampered during final health")
      return result
    with self.assertRaises(ValueError): self.run_retirement(health=tampering_health)
    self.assert_blocked()
    record = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
    self.assertIn("release_evidence_sha256", record)
    self.assertNotIn("reconcile_evidence_sha256", record)

  def test_compare_delete_race_does_not_remove_changed_foreign_slot(self):
    def racing_delete(name, expected):
      self.slots[name] = b"replacement foreign bytes"
      return self.delete(name, expected)
    with self.assertRaises(ValueError): self.run_retirement(compare_delete_slot=racing_delete)
    self.assertEqual(self.deleted, [])
    self.assertIn(b"replacement foreign bytes", self.slots.values())
    self.assert_blocked()

  def test_false_or_nonboolean_delete_and_failed_absence_readback_block(self):
    with self.assertRaises(ValueError):
      self.run_retirement(compare_delete_slot=lambda name, expected: 1)
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_backend_claiming_delete_without_removal_fails_readback(self):
    with self.assertRaises(ValueError):
      self.run_retirement(compare_delete_slot=lambda name, expected: True)
    self.assertEqual(self.deleted, [])
    self.assert_blocked()

  def test_journal_interruption_after_deletion_blocks_new_cycles(self):
    original = self.ledger._write
    def fail_confirmation(name, value, exclusive=False):
      if name.endswith("-source-confirmed.json"):
        raise OSError("injected confirmation persistence failure")
      return original(name, value, exclusive=exclusive)
    with mock.patch.object(self.ledger, "_write", side_effect=fail_confirmation):
      with self.assertRaises(OSError): self.run_retirement()
    self.assertEqual(self.deleted, [retirement.SLOTS["source"]])
    self.assert_blocked()
    with self.assertRaises(ValueError): self.run_retirement()

  def test_health_failure_after_clear_prevents_release_and_reconcile(self):
    def unhealthy(binding):
      data = self.health(binding)
      data["devices"]["internal_keyboard"] = False
      return data
    with self.assertRaises(ValueError): self.run_retirement(health=unhealthy)
    self.assertEqual(self.deleted, list(retirement.SLOTS.values()))
    self.assert_blocked()
    record = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
    self.assertNotIn("release_evidence_sha256", record)

  def test_second_health_failure_blocks_after_release(self):
    def unhealthy_second(binding):
      data = self.health(binding)
      if self.health_calls == 2: data["failed_units"] = ["failed.service"]
      return data
    with self.assertRaises(ValueError): self.run_retirement(health=unhealthy_second)
    self.assert_blocked()
    record = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
    self.assertIn("release_evidence_sha256", record)
    self.assertNotIn("reconcile_evidence_sha256", record)

  def test_failure_after_reconcile_record_publication_still_blocks_new_cycle(self):
    original = self.ledger._write
    def fail_after_reconciled(name, value, exclusive=False):
      result = original(name, value, exclusive=exclusive)
      if name == "cycle-" + self.cycle["cycle_id"] + ".json" and value.get("state") == "reconciled":
        raise OSError("injected post-publication reconciliation failure")
      return result
    with mock.patch.object(self.ledger, "_write", side_effect=fail_after_reconciled):
      with self.assertRaises(OSError): self.run_retirement()
    self.assert_blocked()

  def test_durable_sentinel_blocks_when_reconcile_and_all_failure_writes_fail(self):
    original = self.ledger._write
    failed = False
    def fail_terminal_and_all_latches(name, value, exclusive=False):
      nonlocal failed
      if failed:
        raise OSError("storage rejects every failure write")
      result = original(name, value, exclusive=exclusive)
      if name == "cycle-" + self.cycle["cycle_id"] + ".json" and value.get("state") == "reconciled":
        failed = True
        raise OSError("post-publication reconciliation failure")
      return result
    with mock.patch.object(self.ledger, "_write", side_effect=fail_terminal_and_all_latches):
      with self.assertRaises(OSError): self.run_retirement()
    # Deliberately show the dangerous visible state: terminal record and valid
    # qualification survive. The independent durable sentinel still refuses.
    self.assertEqual(self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")["state"], "reconciled")
    self.assertFalse(self.ledger._state()["blocked"])
    self.assertIsNotNone(self.ledger._state()["qualification"])
    with self.assertRaisesRegex(ValueError, "Unresolved retirement"):
      self.ledger.begin(str(uuid.uuid4()))

  def test_sentinel_removal_sync_failure_requires_valid_durable_terminal_chain(self):
    original = self.ledger._sync
    failed = False
    sentinel = self.ledger.directory / ("slot-retirement-" + self.cycle["cycle_id"] + "-unresolved.json")
    def fail_final_removal_sync():
      nonlocal failed
      record = self.ledger._read("cycle-" + self.cycle["cycle_id"] + ".json")
      if record["state"] == "reconciled" and not sentinel.exists() and not failed:
        failed = True
        raise OSError("sentinel removal directory sync failed")
      return original()
    with mock.patch.object(self.ledger, "_sync", side_effect=fail_final_removal_sync):
      result = self.run_retirement()
    self.assertTrue(failed)
    self.assertEqual(result["sentinel_cleanup_error"], "OSError")
    self.assertEqual(result["cycle"]["state"], "reconciled")
    # Reconciliation's fsync already succeeded before removing the sentinel;
    # allocation now independently validates its terminal receipt chain.
    self.assertEqual(self.ledger.begin(str(uuid.uuid4()))["state"], "reserved")

  def test_surviving_sentinel_after_terminal_cleanup_error_blocks_allocation(self):
    original = Path.unlink
    name = "slot-retirement-" + self.cycle["cycle_id"] + "-unresolved.json"
    def fail_sentinel_unlink(path, *args, **kwargs):
      if path.name == name:
        raise OSError("sentinel unlink failed")
      return original(path, *args, **kwargs)
    with mock.patch.object(Path, "unlink", fail_sentinel_unlink):
      result = self.run_retirement()
    self.assertEqual(result["cycle"]["state"], "reconciled")
    self.assertEqual(result["sentinel_cleanup_error"], "OSError")
    with self.assertRaisesRegex(ValueError, "Unresolved retirement"):
      self.ledger.begin(str(uuid.uuid4()))

  def test_removed_sentinel_does_not_bypass_tampered_terminal_receipts(self):
    self.run_retirement()
    name = "slot-retirement-" + self.cycle["cycle_id"] + "-complete.json"
    record = self.ledger._read(name)
    record["intent_sha256"] = "f" * 64
    self.ledger._write(name, record)
    with self.assertRaisesRegex(ValueError, "terminal receipt chain"):
      self.ledger.begin(str(uuid.uuid4()))

  def test_ledger_lock_excludes_concurrent_cycle_and_retirement(self):
    def read_locked(name):
      with self.assertRaises(BlockingIOError): self.ledger.begin(str(uuid.uuid4()))
      with self.assertRaises(BlockingIOError): self.run_retirement()
      return self.read(name)
    self.assertEqual(self.run_retirement(read_slot=read_locked)["cycle"]["state"], "reconciled")

  def test_symlinked_journal_refuses(self):
    name = "slot-retirement-" + self.cycle["cycle_id"] + "-intent.json"
    (self.ledger.directory / name).symlink_to(self.ledger.directory / "state.json")
    with self.assertRaises(ValueError): self.run_retirement()
    self.assertEqual(self.deleted, [])
    self.assert_blocked()


if __name__ == "__main__":
  unittest.main()
