#!/usr/bin/python3
"""Synthetic-only fault coverage for the offline product ledger."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("transaction", Path(__file__).parents[1] / "hibernate/transaction.py")
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)


class Transactions(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.directory = Path(self.temp.name) / "ledger"
    self.ledger = tx.Ledger(self.directory)
    self.manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", **{key: str(i) * 64 for i, key in enumerate(tx.PINS, 1)}}
    self.ledger.configure(self.manifest)
    self.receipt = {"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(self.manifest), "evidence_sha256": "a" * 64, "qualified": True}
    self.boot = str(uuid.uuid4())

  def tearDown(self):
    self.temp.cleanup()

  def begin(self):
    self.ledger.qualify(self.receipt)
    return self.ledger.begin(self.boot)

  def finish(self, record):
    for action in ("prepared", "returned", "archive", "release", "reconcile"):
      record = self.ledger.advance(record["cycle_id"], action, "b" * 64)
    return record

  def test_requires_distinct_product_qualification(self):
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)
    for change in ({"protocol": "cold-pci-guard-fullrestore-v1"}, {"qualified": 1}, {"manifest_sha256": "b" * 64}):
      with self.assertRaises(ValueError): self.ledger.qualify({**self.receipt, **change})

  def test_cycles_keep_pair_but_have_distinct_bound_vectors(self):
    first = self.finish(self.begin())
    second = self.ledger.begin(self.boot)
    self.assertEqual(first["qualification_vector"], second["qualification_vector"])
    self.assertNotEqual(first["vector"], second["vector"])
    self.assertEqual(second["prefix"], second["vector"][:24])
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)

  def test_failed_or_ambiguous_blocks_new_uuid_and_requalification(self):
    first = self.begin()
    self.ledger.advance(first["cycle_id"], "ambiguous", "b" * 64)
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)
    with self.assertRaises(ValueError): self.ledger.qualify(self.receipt)
    revised = {**self.receipt, "evidence_sha256": "c" * 64}
    with self.assertRaises(ValueError): self.ledger.qualify(revised)
    self.ledger.configure({**self.manifest, "linux_sha256": "f" * 64})
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)

  def test_update_invalidates_qualification(self):
    self.ledger.qualify(self.receipt)
    self.ledger.configure({**self.manifest, "linux_sha256": "f" * 64})
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)
    with self.assertRaises(ValueError): self.ledger.qualify(self.receipt)

  def test_archive_required_and_verified_before_release(self):
    record = self.begin()
    with self.assertRaises(ValueError): self.ledger.advance(record["cycle_id"], "release", "b" * 64)
    for action in ("prepared", "returned", "archive"):
      self.ledger.advance(record["cycle_id"], action, "b" * 64)
    archive = self.directory / ("archive-" + record["cycle_id"] + ".json")
    archive.write_text("{}")
    with self.assertRaises(ValueError): self.ledger.advance(record["cycle_id"], "release", "b" * 64)

  def test_lock_and_symlink_refuse(self):
    with self.ledger._lock():
      with self.assertRaises(BlockingIOError): self.ledger.qualify(self.receipt)
    (self.directory / "state.json").unlink()
    (self.directory / "state.json").symlink_to(self.directory / "lock")
    with self.assertRaises(ValueError): self.ledger.qualify(self.receipt)

  def test_duplicate_uuid_and_incomplete_write_refuse(self):
    first = self.finish(self.begin())
    with self.assertRaises(ValueError): self.ledger.begin(self.boot, first["cycle_id"])
    (self.directory / ".pending-crash").touch(mode=0o600)
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)

  def test_manifest_strict_and_reconciled_immutable(self):
    with self.assertRaises(ValueError): self.ledger.configure({**self.manifest, "extra": True})
    record = self.finish(self.begin())
    with self.assertRaises(ValueError): self.ledger.advance(record["cycle_id"], "failed", "b" * 64)

  def test_forged_completed_cycle_cannot_open_new_attempt(self):
    record = self.begin()
    file = self.directory / ("cycle-" + record["cycle_id"] + ".json")
    file.write_text('{"state":"reconciled"}')
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)

  def test_pending_write_blocks_release_and_archive_binds_receipt(self):
    record = self.begin()
    for action in ("prepared", "returned", "archive"):
      self.ledger.advance(record["cycle_id"], action, "b" * 64)
    archive = self.ledger._read("archive-" + record["cycle_id"] + ".json")
    self.assertEqual(archive["archive_evidence_sha256"], "b" * 64)
    (self.directory / ".pending-crash").touch(mode=0o600)
    with self.assertRaises(ValueError): self.ledger.advance(record["cycle_id"], "release", "b" * 64)

  def test_swapped_filename_cannot_advance_valid_cycle(self):
    record = self.begin()
    wrong_id = str(uuid.uuid4())
    self.ledger._write("cycle-" + wrong_id + ".json", record, exclusive=True)
    with self.assertRaises(ValueError): self.ledger.advance(wrong_id, "prepared", "b" * 64)

  def test_predecessor_is_exact_latest_private_chain_across_processes(self):
    first = self.finish(self.begin())
    second = self.ledger.begin(self.boot)
    fresh = tx.Ledger(self.directory)
    self.assertEqual(fresh.predecessor(second), first)
    with self.assertRaises(ValueError): fresh.predecessor(first)
    captured = []
    self.ledger.compare_and_run(second, lambda advance: captured.append(advance.predecessor()))
    self.assertEqual(captured, [first])

  def test_missing_head_or_orphan_link_never_migrates_old_cycles(self):
    self.finish(self.begin())
    (self.directory / "allocation-head.json").unlink()
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)

  def test_interrupted_allocation_publication_blocks_new_cycle_and_callbacks(self):
    first = self.finish(self.begin())
    self.ledger._write("allocation-" + str(uuid.uuid4()) + ".json", {}, exclusive=True)
    with self.assertRaises(ValueError): self.ledger.begin(self.boot)
    with self.assertRaises(ValueError): self.ledger.predecessor(first)

  def test_changed_terminal_predecessor_invalidates_immutable_link(self):
    first = self.finish(self.begin())
    second = self.ledger.begin(self.boot)
    changed = {**first, "reconcile_evidence_sha256": "c" * 64}
    self.ledger._write("cycle-" + first["cycle_id"] + ".json", changed)
    with self.assertRaises(ValueError): self.ledger.predecessor(second)

  def test_allocation_crash_at_each_publication_boundary_is_fail_closed(self):
    for fail_name in ("cycle-", "allocation-head.json"):
      with self.subTest(fail_name=fail_name), tempfile.TemporaryDirectory() as temporary:
        ledger = tx.Ledger(Path(temporary) / "ledger")
        ledger.configure(self.manifest)
        ledger.qualify(self.receipt)
        original = ledger._write
        def interrupted(name, record, exclusive=False):
          if name.startswith(fail_name):
            raise OSError("injected allocation publication interruption")
          return original(name, record, exclusive=exclusive)
        with patch.object(ledger, "_write", side_effect=interrupted):
          with self.assertRaises(OSError): ledger.begin(self.boot)
        with self.assertRaises(ValueError): ledger.begin(self.boot)
        for record in ledger._cycles():
          with self.assertRaises(ValueError): ledger.compare_and_run(record, lambda advance: self.fail("entered callback"))


if __name__ == "__main__":
  unittest.main()
