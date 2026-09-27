#!/usr/bin/python3
"""Exact post-return recovery faults; only synthetic private directories."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


BASE = Path(__file__).parents[1]
R = load("post_return", BASE / "hibernate/post_return_reconcile.py")
C = load("continuity_fixture", BASE / "tests/test-hibernate-product-continuity.py")
WF = load("post_return_workflow", BASE / "hibernate/workflow.py")


class Recovery(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.base = Path(self.temp.name)
    self.root = self.base / "root"
    boot = self.root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text(R.BOOT)
    self.ledger = R.TX.Ledger(self.base / "ledger")
    self.archives = self.base / "archives"
    self.archives.mkdir(mode=0o700)
    self.guards = self.base / "guards"
    self.guards.mkdir(mode=0o700)
    self.fixture = C.Continuity()
    self.fixture.setUp()
    manifest = self.fixture.cycle["manifest"]
    authorization_id = str(uuid.uuid4())
    self.authority = {"protocol": R.TX.TRIAL_PROTOCOL, "qualified": False, "manifest_sha256": R.TX.digest(manifest),
      "audited_details_sha256": "e" * 64, "original_boot_id": R.BOOT, "authorization_id": authorization_id,
      "marker_pin": {"sha256": "f" * 64, "srcversion": "1A72ABF3A3BFC778FC5A9C6", "vermagic": "synthetic-t2 SMP", "variable_version": "v3"},
      "physical_acceptance": {"boot_id": R.BOOT, "authorization_id": authorization_id, "accepted": True, "method": "operator-attended-cold-power"}}
    self.auth_file = self.base / "authorization.json"
    self.write(self.auth_file, self.authority)
    self.ledger.configure(manifest)
    self.ledger.authorize_trial(self.authority, self.guards)
    reserved = self.ledger.begin(R.BOOT, R.CYCLE)
    self.prep_file = self.ledger.directory / ("preparation-" + R.CYCLE + "-complete.json")
    self.write(self.prep_file, {"schema": "synthetic-completed-preparation", "cycle_binding": {k: reserved[k] for k in C.ct.BINDING_KEYS}})
    prepared = self.ledger.advance(R.CYCLE, "prepared", R.TX.digest(json.loads(self.prep_file.read_bytes())))
    f = self.fixture
    f.cycle, f.qualification = prepared, self.authority
    binding = {key: prepared[key] for key in C.ct.BINDING_KEYS}
    f.guard = json.dumps({"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": binding}, sort_keys=True).encode()
    f.attempt = json.dumps({"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": binding,
      "state": "transition-armed", "real_s4_attempted": True, "requested_disk_mode": "platform",
      "consumed_guard_sha256": C.ct.raw_digest(f.guard)}, sort_keys=True).encode()
    f.collector = f.new_collector()
    f.collector.write_and_capture(f.write, f.capture)
    proposal = f.collector.returned_transition(f.health(), [])
    returned = self.ledger.advance(R.CYCLE, "returned", proposal["evidence_sha256"])
    R.ARCHIVE.create_archive(self.archives, returned, WF._archive_bytes(proposal))
    failure = {"schema": "omarchy-t2-product-workflow-failure-v1", "cycle_id": R.CYCLE,
      "phase": "creating-archive", "error_type": "ValueError",
      "snapshot": {"cleanup_errors": [], "cleanup_health": f.health()}}
    self.failure_file = self.ledger.directory / ("workflow-failure-" + R.CYCLE + ".json")
    self.write(self.failure_file, failure)
    self.failed = self.ledger.advance(R.CYCLE, "failed", R.TX.digest(failure))
    self.cycle_file = self.ledger.directory / ("cycle-" + R.CYCLE + ".json")
    self.state_file = self.ledger.directory / "state.json"
    self.original_cycle = self.cycle_file.read_bytes()
    self.original_state = self.state_file.read_bytes()
    self.original_guard = (self.guards / "trial-consumed.json").read_bytes()
    self.pins = {name: R._hash(path.read_bytes()) for name, path in {
      "failed_cycle": self.cycle_file, "failed_state": self.state_file, "authorization": self.auth_file,
      "consumed_trial_guard": self.guards / "trial-consumed.json", "failure_journal": self.failure_file,
      "preparation_receipt": self.prep_file,
      "archive_completion": self.archives / ("cycle-" + R.CYCLE) / "completion.json"}.items()}
    self.receipt_file = self.base / "recovery-authority.json"
    self.receipt = {"schema": R.SCHEMA, "accepted": True, "cycle_id": R.CYCLE, "original_boot_id": R.BOOT,
      "vector": reserved["vector"], "pins": self.pins, "implementation_sha256": {name: R._code_hash(name) for name in R.CODE}}
    self.write(self.receipt_file, self.receipt)
    self.vector_patch = patch.object(R, "VECTOR", reserved["vector"])
    self.pins_patch = patch.object(R, "KNOWN_PINS", self.pins)
    self.vector_patch.start()
    self.pins_patch.start()

  def tearDown(self):
    self.vector_patch.stop()
    self.pins_patch.stop()
    self.temp.cleanup()

  def write(self, path, value):
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)

  def recover(self):
    return R.reconcile_archive(self.ledger, root=self.root, recovery_receipt=self.receipt_file,
      authorization_file=self.auth_file, guard_file=self.guards / "trial-consumed.json",
      preparation_file=self.prep_file, archive_directory=self.archives)

  def test_archives_same_cycle_preserves_failure_and_never_qualifies(self):
    result = self.recover()
    self.assertEqual(result["cycle"]["state"], "archived")
    self.assertFalse(result["qualified"])
    self.assertFalse(result["power_write"])
    self.assertEqual(result["cycle"]["failed_evidence_sha256"], self.failed["failed_evidence_sha256"])
    self.assertEqual((self.ledger.directory / (R.STEM + "-failed_cycle.bin")).read_bytes(), self.original_cycle)
    self.assertEqual((self.ledger.directory / (R.STEM + "-failed_state.bin")).read_bytes(), self.original_state)
    self.assertEqual((self.guards / "trial-consumed.json").read_bytes(), self.original_guard)
    self.assertEqual(self.ledger._state()["qualification"], self.authority)
    with self.assertRaises(ValueError): self.ledger.begin(R.BOOT)
    with self.assertRaises(ValueError): self.recover()
    self.ledger.compare_and_run(result["cycle"], lambda advance: self.assertEqual(advance.check_current(), result["cycle"]))

  def test_wrong_boot_and_authority_reject_before_any_recovery_write(self):
    (self.root / "proc/sys/kernel/random/boot_id").write_text(str(uuid.uuid4()))
    with self.assertRaises(ValueError): self.recover()
    self.assertFalse((self.ledger.directory / R.SENTINEL).exists())
    self.assertEqual(self.cycle_file.read_bytes(), self.original_cycle)

  def test_tampered_raw_archive_rejects_without_mutation(self):
    (self.archives / ("cycle-" + R.CYCLE) / "source-stage.bin").write_bytes(b"tampered")
    with self.assertRaises(ValueError): self.recover()
    self.assertFalse((self.ledger.directory / R.SENTINEL).exists())

  def test_wrong_reviewed_code_and_evidence_pins_reject(self):
    for field in ("pins", "implementation_sha256"):
      receipt = copy.deepcopy(self.receipt)
      receipt[field][next(iter(receipt[field]))] = "0" * 64
      self.write(self.receipt_file, receipt)
      with self.assertRaises(ValueError): self.recover()
    self.assertFalse((self.ledger.directory / R.SENTINEL).exists())

  def test_symlinked_receipt_refused(self):
    target = self.base / "other.json"
    self.receipt_file.rename(target)
    self.receipt_file.symlink_to(target)
    with self.assertRaises(ValueError): self.recover()

  def test_each_persistence_interruption_keeps_ordinary_apis_blocked(self):
    original = self.ledger._write
    def fail(name, value, exclusive=False):
      if name == "state.json": raise OSError("synthetic post-cycle publication failure")
      return original(name, value, exclusive=exclusive)
    with patch.object(self.ledger, "_write", side_effect=fail):
      with self.assertRaises(OSError): self.recover()
    self.assertTrue((self.ledger.directory / R.SENTINEL).exists())
    archived = self.ledger._read("cycle-" + R.CYCLE + ".json")
    with self.assertRaises(ValueError): self.ledger.begin(R.BOOT)
    with self.assertRaises(ValueError): self.ledger.compare_and_run(archived, lambda advance: None)
    with self.assertRaises(ValueError): self.recover()

  def test_failure_after_unblocked_state_still_has_durable_blocker(self):
    original = self.ledger._write
    def fail(name, value, exclusive=False):
      if name == R.STEM + "-complete.json": raise OSError("synthetic completion fsync failure")
      return original(name, value, exclusive=exclusive)
    with patch.object(self.ledger, "_write", side_effect=fail):
      with self.assertRaises(OSError): self.recover()
    self.assertFalse(self.ledger._state()["blocked"])
    with self.assertRaises(ValueError): self.ledger.compare_and_run(self.ledger._read("cycle-" + R.CYCLE + ".json"), lambda advance: None)

  def test_each_directory_fsync_fault_blocks_or_exposes_only_completed_archive(self):
    # The eleven directory sync boundaries cover sentinel, raw preservation,
    # intent, archive/cycle/state publication, completion and sentinel removal.
    for stop in range(1, 12):
      with self.subTest(stop=stop):
        fixture = Recovery("test_archives_same_cycle_preserves_failure_and_never_qualifies")
        fixture.setUp()
        try:
          original = fixture.ledger._sync
          calls = 0
          def fail_sync():
            nonlocal calls
            calls += 1
            if calls == stop: raise OSError("synthetic directory fsync fault")
            return original()
          with patch.object(fixture.ledger, "_sync", side_effect=fail_sync):
            with self.assertRaises(OSError): fixture.recover()
          self.assertEqual(calls, stop)
          with self.assertRaises(ValueError): fixture.ledger.begin(R.BOOT)
          with self.assertRaises(ValueError): fixture.recover()
          current = fixture.ledger._read("cycle-" + R.CYCLE + ".json")
          if (fixture.ledger.directory / R.SENTINEL).exists():
            with self.assertRaises(ValueError): fixture.ledger.compare_and_run(current, lambda advance: None)
          else:
            # Removal failed fsync only AFTER durable false-authority/archive
            # completion. A crash may resurrect the blocker; absence is safe.
            self.assertEqual(stop, 11)
            self.assertEqual(current["state"], "archived")
            self.assertFalse(fixture.ledger._state()["qualification"]["qualified"])
            complete = fixture.ledger._read(R.STEM + "-complete.json")
            self.assertEqual(complete["archived_cycle_sha256"], R.TX.digest(current))
            R.RETIREMENT._archived_evidence(fixture.archives, current)
            fixture.ledger.compare_and_run(current, lambda advance: advance.check_current())
          self.assertEqual((fixture.guards / "trial-consumed.json").read_bytes(), fixture.original_guard)
        finally:
          fixture.tearDown()

  def test_concurrent_ledger_owner_and_wrong_cycle_receipt_refused(self):
    with self.ledger._lock():
      with self.assertRaises(BlockingIOError): self.recover()
    receipt = {**self.receipt, "cycle_id": str(uuid.uuid4())}
    self.write(self.receipt_file, receipt)
    with self.assertRaises(ValueError): self.recover()
    self.assertFalse((self.ledger.directory / R.SENTINEL).exists())

  def test_publication_and_original_preservation_faults_never_unblock(self):
    names = (R.STEM + "-intent.json", "archive-" + R.CYCLE + ".json", "cycle-" + R.CYCLE + ".json")
    for name in (*names, "preserve-original"):
      with self.subTest(name=name):
        fixture = Recovery("test_archives_same_cycle_preserves_failure_and_never_qualifies")
        fixture.setUp()
        try:
          original = fixture.ledger._write
          def fail_publication(actual, value, exclusive=False):
            if actual == name: raise OSError("synthetic publication fault")
            return original(actual, value, exclusive=exclusive)
          if name == "preserve-original":
            context = patch.object(R, "_preserve", side_effect=OSError("synthetic original fsync fault"))
          else:
            context = patch.object(fixture.ledger, "_write", side_effect=fail_publication)
          with context:
            with self.assertRaises(OSError): fixture.recover()
          self.assertTrue((fixture.ledger.directory / R.SENTINEL).exists())
          with self.assertRaises(ValueError): fixture.ledger.begin(R.BOOT)
          with self.assertRaises(ValueError): fixture.recover()
        finally:
          fixture.tearDown()

  def test_archive_mutation_after_publication_keeps_recovery_blocked(self):
    original = R.ARCHIVE.verify_archive
    def mutate(directory, cycle, expected_receipt_sha256=None):
      if (self.ledger.directory / (R.STEM + "-complete.json")).exists():
        (self.archives / ("cycle-" + R.CYCLE) / "restore-stage.bin").write_bytes(b"tampered after state publication")
      return original(directory, cycle, expected_receipt_sha256)
    with patch.object(R.ARCHIVE, "verify_archive", side_effect=mutate):
      with self.assertRaises(ValueError): self.recover()
    self.assertTrue((self.ledger.directory / R.SENTINEL).exists())
    with self.assertRaises(ValueError): self.ledger.compare_and_run(self.ledger._read("cycle-" + R.CYCLE + ".json"), lambda advance: None)


if __name__ == "__main__": unittest.main()
