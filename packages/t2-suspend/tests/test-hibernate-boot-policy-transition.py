"""Disposable filesystem/lock fixtures only; no live root or power calls."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module
T = load("transition", HERE / "hibernate/boot_policy_transition.py")
F = load("policy_fixture", Path(__file__).with_name("test-hibernate-boot-policy.py"))


class Transitions(unittest.TestCase):
  def setUp(self):
    self.f = F.Policy("test_prepare_is_pure_unapproved_exact_single_line_change")
    self.f.setUp()
    self.addCleanup(self.f.doCleanups)
    self.root = self.f.root
    self.f.before = self.f.before.replace(b"path: boot():/EFI/Linux/omarchy_linux-t2.efi#", b"/+Omarchy\n  //linux-t2\n  protocol: efi\npath: boot():/EFI/Linux/omarchy_linux-t2.efi#", 1)
    self.f.receipt["staged_limine_sha256"] = T.P.digest(self.f.before)
    self.f.raw = json.dumps(self.f.receipt).encode()
    self.f.config["staged_receipt_sha256"] = T.P.digest(self.f.raw)
    self.f.proposal = T.P.prepare(self.f.before, self.f.raw)
    self.f.policy = {**self.f.proposal["policy"], "approved": True}
    self.f.write(T.P.RECEIPT, self.f.raw)
    self.f.write(T.P.LIMINE, self.f.before)
    self.f.write(T.REVIEW, json.dumps(self.f.policy).encode())
    self.f.write(T.OPT_IN, b"").chmod(0o644)
    self.f.write(T.PHYSICAL_LOCK, b"")
    (self.root / T.DB_LOCK).parent.mkdir(parents=True)
    ledger = T.PRODUCT.TX.Ledger(self.root / T.P.STATE / "ledger")
    with ledger._lock(): pass
    source = self.root.parent / "snapshot-source"
    for tree in T.D.TREES: (source / tree).mkdir(parents=True)
    (source / T.D.ENTRYPOINT).write_text("# reviewed fixture; never executed\n")
    (source / T.D.TREES[1] / "fixture.py").write_text("# retained fixture code\n")
    hook = (HERE / "hibernate/00-omarchy-t2-hibernate-guard.hook").read_bytes()
    (source / T.D.UPDATE_GUARD_HOOK).write_bytes(hook)
    (source / T.D.TREES[0] / "update_guard.py").write_bytes((HERE / "hibernate/update_guard.py").read_bytes())
    review = {"protocol": T.D.SCHEMA, "approved": True, "reviewed_commit": "a" * 40, "files": T.D.inventory(source)}
    self.f.write(T.P.STATE / "runtime-deployment-review.json", json.dumps(review).encode())
    T.D.deploy_snapshot(source, root=self.root)
    self.f.write(T.HOOK, hook).chmod(0o644)
    self.guards = self.f.write("var/lib/omarchy/t2-hibernate-trial/guards/trial-consumed.json", b"immutable guard")
    self.calls = []

  def check(self, root, action, phase):
    self.calls.append((action, phase))
    self.assertTrue((root / T.DB_LOCK).is_file())
    held = os.open(root / T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(held)
    source_default = (action == "activation" and phase == "after") or (action == "deactivation" and phase == "before")
    F.PRODUCT.TRIAL._verify_deployment(root, self.f.config, self.f.report, source_default=source_default)

  def run_action(self, action="activation", check=None):
    return T.transition(self.root, action, precheck=self.check if check is None else check)

  def pending(self, action): return self.root / T.PENDINGS[action]

  def test_activation_then_exact_fallback_preserves_all_authority_and_evidence(self):
    opt = (self.root / T.OPT_IN).stat().st_ino
    first = self.run_action()
    self.assertFalse(first["live_execution"])
    self.assertFalse(first["qualification_issued"])
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.proposal["after"])
    self.assertEqual((self.root / T.OPT_IN).stat().st_ino, opt)
    self.assertFalse(self.pending("activation").exists())
    second = self.run_action("deactivation")
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.before)
    self.assertFalse((self.root / T.OPT_IN).exists())
    self.assertFalse((self.root / T.P.POLICY).exists())
    self.assertFalse((self.root / T.DB_LOCK).exists())
    self.assertEqual((self.root / T.P.RECEIPT).read_bytes(), self.f.raw)
    self.assertEqual(self.guards.read_bytes(), b"immutable guard")
    self.assertEqual((self.root / T.P.BACKUP).read_bytes(), self.f.before)
    for value in (first, second):
      history = self.root / T.HISTORY / value["transition_id"]
      self.assertEqual(json.loads((history / "policy.json").read_bytes()), self.f.policy)
      self.assertTrue((history / "completion.json").is_file())
    self.assertEqual(T.G.check(self.root)["default_entry"], 2)

  def test_live_root_alias_relative_and_symlink_roots_refused_without_open(self):
    alias = self.root.parent / "root-alias"
    alias.symlink_to("/")
    with patch.object(T.os, "open", side_effect=AssertionError("no live filesystem open")):
      for root in ("/", "/tmp/..", "relative", alias):
        with self.assertRaises(ValueError): T.transition(root, "activation", precheck=lambda *args: None)

  def test_existing_pacman_lock_and_busy_physical_lock_never_deleted_or_retried(self):
    db = self.f.write(T.DB_LOCK, b"existing transaction")
    with self.assertRaises(FileExistsError): self.run_action()
    self.assertEqual(db.read_bytes(), b"existing transaction")
    db.unlink()
    held = os.open(self.root / T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with self.assertRaises(BlockingIOError): self.run_action()
    finally: os.close(held)
    self.assertFalse(db.exists())
    self.assertFalse(self.pending("activation").exists())

  def test_unreviewed_hook_invalid_policy_and_preexisting_pending_block_before_boot_write(self):
    original = (self.root / T.HOOK).read_bytes()
    (self.root / T.HOOK).write_bytes(b"modified hook")
    with self.assertRaises(ValueError): self.run_action()
    (self.root / T.HOOK).write_bytes(original)
    review = self.root / T.REVIEW
    raw = review.read_bytes()
    review.write_bytes(json.dumps({**self.f.policy, "approved": False}).encode())
    with self.assertRaises(ValueError): self.run_action()
    review.write_bytes(raw)
    self.f.write(T.PENDINGS["deactivation"], b"interrupted")
    with self.assertRaises(ValueError): self.run_action()
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.before)

  def test_efi_slots_unresolved_ledger_and_fifo_evidence_fail_before_pending(self):
    slot = self.f.write(T.G.EFI / T.PRODUCT.HOST.CT.SOURCE_VARIABLE, b"owned or foreign stage")
    with self.assertRaises(ValueError): self.run_action()
    slot.unlink()
    journal = self.f.write(T.P.STATE / "ledger/.pending-io", b"interrupted")
    with self.assertRaises(ValueError): self.run_action()
    journal.unlink()
    review = self.root / T.REVIEW
    review.unlink()
    os.mkfifo(review, mode=0o600)
    with self.assertRaises(ValueError): self.run_action()
    self.assertFalse(self.pending("activation").exists())

  def test_conf_drift_after_precheck_and_after_postcheck_preserves_pending(self):
    def before_drift(root, action, phase):
      self.check(root, action, phase)
      if phase == "before": (root / T.P.LIMINE).write_bytes(self.f.before + b"#foreign writer\n")
    with self.assertRaises(ValueError): self.run_action(check=before_drift)
    self.assertTrue(self.pending("activation").exists())
    with self.assertRaises(ValueError): self.run_action()

  def test_final_after_byte_drift_cannot_publish_completion(self):
    def drift(root, action, phase):
      self.check(root, action, phase)
      if phase == "after": (root / T.P.LIMINE).write_bytes(self.f.proposal["after"] + b"#foreign writer\n")
    with self.assertRaises(ValueError): self.run_action(check=drift)
    self.assertTrue(self.pending("activation").exists())
    self.assertFalse(any((self.root / T.HISTORY).glob("*/completion.json")))

  def test_deactivation_fault_after_marker_removal_preserves_pending(self):
    self.run_action()
    def fault(*args): raise OSError("after opt-in removal")
    with patch.object(T, "_replace", side_effect=fault):
      with self.assertRaises(OSError): self.run_action("deactivation")
    self.assertFalse((self.root / T.OPT_IN).exists())
    self.assertTrue((self.root / T.P.POLICY).exists())
    self.assertTrue(self.pending("deactivation").exists())
    with self.assertRaises(ValueError): T.G.check(self.root)

  def test_completion_fault_never_blindly_retries(self):
    original = T._new
    def fault(path, *args, **kwargs):
      if path.name == "completion.json": raise OSError("completion publication fault")
      return original(path, *args, **kwargs)
    with patch.object(T, "_new", side_effect=fault):
      with self.assertRaises(OSError): self.run_action()
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.proposal["after"])
    self.assertTrue(self.pending("activation").exists())
    with self.assertRaises(ValueError): self.run_action()

  def test_deactivation_fault_after_policy_retirement_still_blocks_updates(self):
    self.run_action()
    def fail(root, action, phase):
      self.check(root, action, phase)
      if phase == "after": raise OSError("post-retirement fault")
    with self.assertRaises(OSError): self.run_action("deactivation", check=fail)
    self.assertFalse((self.root / T.P.POLICY).exists())
    self.assertFalse((self.root / T.OPT_IN).exists())
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.before)
    self.assertTrue(self.pending("deactivation").exists())
    with self.assertRaises(ValueError): T.G.check(self.root)

  def test_conf_fsync_failure_preserves_changed_bytes_and_pending(self):
    original = T._sync
    def fail(directory):
      if directory == self.root / "boot" and (self.root / T.P.LIMINE).read_bytes() == self.f.proposal["after"]:
        raise OSError("post-replacement fsync fault")
      return original(directory)
    with patch.object(T, "_sync", side_effect=fail):
      with self.assertRaises(OSError): self.run_action()
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.proposal["after"])
    self.assertTrue(self.pending("activation").exists())

  def test_pending_cleanup_fsync_fault_restores_pending_while_both_locks_held(self):
    original = T._sync
    failed = []
    def fail(directory):
      if directory == self.root / T.P.STATE and not self.pending("activation").exists() and not failed and any((self.root / T.HISTORY).glob("*/completion.json")):
        self.assertTrue((self.root / T.DB_LOCK).is_file())
        failed.append(True)
        raise OSError("pending cleanup fsync fault")
      return original(directory)
    with patch.object(T, "_sync", side_effect=fail):
      with self.assertRaises(OSError): self.run_action()
    self.assertTrue(self.pending("activation").exists())
    self.assertFalse((self.root / T.DB_LOCK).exists())
    with self.assertRaises(ValueError): self.run_action()

  def test_foreign_pacman_lock_substitution_is_preserved_with_pending(self):
    def replace_lock(root, action, phase):
      self.check(root, action, phase)
      if phase == "after":
        (root / T.DB_LOCK).rename(root / T.DB_LOCK.with_name("owned-lock-retained"))
        (root / T.DB_LOCK).write_bytes(b"foreign transaction")
    with self.assertRaises(ValueError): self.run_action(check=replace_lock)
    self.assertEqual((self.root / T.DB_LOCK).read_bytes(), b"foreign transaction")
    self.assertTrue(self.pending("activation").exists())


if __name__ == "__main__": unittest.main()
