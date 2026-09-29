"""Disposable filesystem/lock fixtures only; no live root or power calls."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module
T = load("transition", HERE / "hibernate/boot_policy_transition.py")
SLEEP = load("transition_sleep_entry", HERE / "hibernate/sleep_entry.py")
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
    def fault(*args, **kwargs): raise OSError("after opt-in removal")
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

  def test_fixture_maintenance_reuses_deactivation_and_binds_retained_authority(self):
    self.run_action()
    policy_raw = (self.root / T.P.POLICY).read_bytes()
    runtime_raw = (self.root / T.P.STATE / "runtime-deployment-review.json").read_bytes()
    result = self.run_action("maintenance")
    self.assertEqual(result["action"], "deactivation")
    self.assertEqual(self.calls[-2:], [("deactivation", "before"), ("deactivation", "after")])
    self.assertFalse((self.root / T.OPT_IN).exists())
    self.assertFalse((self.root / T.P.POLICY).exists())
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.before)
    self.assertFalse(self.pending("deactivation").exists())
    self.assertFalse((self.root / T.DB_LOCK).exists())
    marker = (self.root / T.MAINTENANCE).read_bytes()
    archive = self.root / T.HISTORY / result["transition_id"]
    self.assertEqual((archive / "maintenance-intent.json").read_bytes(), marker)
    self.assertEqual(T.P.digest(marker), result["maintenance_intent_sha256"])
    self.assertEqual(json.loads((archive / "intent.json").read_bytes())["action"], "deactivation")
    self.assertEqual(json.loads((archive / "completion.json").read_bytes())["action"], "deactivation")
    intent = json.loads(marker)
    self.assertEqual(intent, {"protocol": T.MAINTENANCE_SCHEMA, "transition_id": result["transition_id"],
      "old_policy_sha256": T.P.digest(policy_raw), "runtime_review_sha256": T.P.digest(runtime_raw),
      "staged_receipt_sha256": T.P.digest(self.f.raw), "fallback_limine_sha256": T.P.digest(self.f.before),
      "deactivation_completion_sha256": T.P.digest((archive / "completion.json").read_bytes())})
    self.assertEqual(marker, T._encoded(intent))
    self.assertEqual(self.guards.read_bytes(), b"immutable guard")

  def test_maintenance_marker_is_refused_by_every_new_transition(self):
    marker = self.f.write(T.MAINTENANCE, b"foreign or interrupted")
    for action in ("activation", "deactivation", "maintenance"):
      with self.subTest(action=action), self.assertRaisesRegex(ValueError, "maintenance intent"):
        self.run_action(action)
      self.assertEqual(marker.read_bytes(), b"foreign or interrupted")
      self.assertFalse((self.root / T.DB_LOCK).exists())
      self.assertFalse(self.pending("activation").exists())

  def test_private_live_maintenance_refuses_before_any_host_open(self):
    with patch.object(T.os, "open", side_effect=AssertionError("no live open")):
      with self.assertRaisesRegex(ValueError, "Live maintenance entry"):
        T._transition(Path("/"), "maintenance", precheck=lambda *args: None, guard=lambda: None)

  def test_durable_veto_refuses_special_or_linked_leaf_without_opening_device(self):
    path = self.root / T.MAINTENANCE
    os.mkfifo(path, 0o600)
    try:
      with self.assertRaisesRegex(ValueError, "exact private repair"):
        T._veto(self.root, b"expected", durable=True)
      self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))
    finally: path.unlink()
    path.write_bytes(b"expected")
    path.chmod(0o600)
    link = path.with_name("foreign-link")
    os.link(path, link)
    with self.assertRaisesRegex(ValueError, "exact private repair"):
      T._veto(self.root, b"expected", durable=True)
    self.assertEqual(path.read_bytes(), b"expected")

  def test_maintenance_marker_is_durable_before_deactivation_pending_retirement(self):
    self.run_action()
    events = []
    original_new, original_sync = T._new, T._sync
    def publish(path, raw, mode=0o600):
      if path.name == "maintenance-intent.json": events.append("archived")
      if path == self.root / T.MAINTENANCE:
        self.assertEqual(events, ["archived"])
        self.assertTrue(self.pending("deactivation").exists())
        self.assertTrue((self.root / T.DB_LOCK).exists())
        events.append("marker")
      return original_new(path, raw, mode)
    def sync(directory):
      if directory == self.root / T.P.STATE and not self.pending("deactivation").exists():
        self.assertEqual(events, ["archived", "marker"])
        self.assertEqual((self.root / T.MAINTENANCE).read_bytes(), next((self.root / T.HISTORY).glob("*/maintenance-intent.json")).read_bytes())
        self.assertTrue((self.root / T.DB_LOCK).exists())
        events.append("retired")
      return original_sync(directory)
    with patch.object(T, "_new", side_effect=publish), patch.object(T, "_sync", side_effect=sync):
      self.run_action("maintenance")
    self.assertEqual(events, ["archived", "marker", "retired"])

  def test_maintenance_publication_faults_keep_old_pending_veto(self):
    for failed_name in ("maintenance-intent.json", "package-maintenance.pending"):
      with self.subTest(failed_name=failed_name):
        fixture = Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.run_action()
        original = T._new
        def fail(path, raw, mode=0o600):
          if path.name == failed_name: raise OSError("maintenance publication fault")
          return original(path, raw, mode)
        with patch.object(T, "_new", side_effect=fail), self.assertRaisesRegex(OSError, "maintenance publication fault"):
          fixture.run_action("maintenance")
        self.assertTrue(fixture.pending("deactivation").exists())
        self.assertFalse((fixture.root / T.DB_LOCK).exists())
        self.assertFalse((fixture.root / T.MAINTENANCE).exists())

  def test_maintenance_completion_readback_fault_keeps_old_pending(self):
    self.run_action()
    original = T._read
    def mismatch(root, relative, **kwargs):
      if Path(relative).name == "completion.json": return b"foreign completion"
      return original(root, relative, **kwargs)
    with patch.object(T, "_read", side_effect=mismatch), self.assertRaisesRegex(ValueError, "completion readback"):
      self.run_action("maintenance")
    self.assertTrue(self.pending("deactivation").exists())
    self.assertFalse((self.root / T.MAINTENANCE).exists())

  def test_maintenance_marker_retirement_and_db_release_faults_fail_closed(self):
    for boundary in ("marker_fsync", "pending_retirement", "db_release"):
      with self.subTest(boundary=boundary):
        fixture = Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.run_action()
        original = T._sync
        failed = []
        def fail(directory):
          marker = (fixture.root / T.MAINTENANCE).exists()
          pending = fixture.pending("deactivation").exists()
          db = (fixture.root / T.DB_LOCK).exists()
          at_marker = boundary == "marker_fsync" and directory == fixture.root / T.P.STATE and marker and pending
          at_retirement = boundary == "pending_retirement" and directory == fixture.root / T.P.STATE and marker and not pending
          at_db_release = boundary == "db_release" and directory == (fixture.root / T.DB_LOCK).parent and marker and not pending and not db
          if not failed and (at_marker or at_retirement or at_db_release):
            failed.append(True)
            raise OSError("maintenance " + boundary)
          return original(directory)
        with patch.object(T, "_sync", side_effect=fail), self.assertRaisesRegex(OSError, boundary):
          fixture.run_action("maintenance")
        self.assertTrue(failed)
        self.assertTrue(fixture.pending("deactivation").exists())
        self.assertTrue((fixture.root / T.MAINTENANCE).exists())
        self.assertFalse((fixture.root / T.DB_LOCK).exists())


class NativeMaintenance(unittest.TestCase):
  """Internal maintenance core with the native adapter's gate seam, fixtures only."""
  def setUp(self):
    self.fixture = Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.f = self.fixture.root, self.fixture.f
    self.fixture.run_action()
    self.phases, self.fail = [], {}
    self.image = False

  def gate(self, root, phase):
    self.phases.append(phase)
    if phase == "before":
      # No write of any kind may precede the first prerequisite gate.
      self.assertFalse(any(self.pending_names()))
      self.assertFalse((root / T.MAINTENANCE).exists())
    if phase == "final":
      self.assertTrue((root / T.MAINTENANCE).exists())
      self.assertTrue(self.fixture.pending("deactivation").exists())
    if phase in self.fail: raise ValueError("injected " + phase)
    T.verify_fallback(root, T._read(root, T.P.BACKUP) if phase == "before" else None)
    if self.image and phase in ("final", "retained"): raise ValueError("saved image present")

  def pending_names(self): return [self.fixture.pending(name).exists() for name in T.PENDINGS]

  def run_maintenance(self):
    return T._transition(self.root, "maintenance", precheck=self.fixture.check, guard=lambda: None, maintenance_gate=self.gate)

  def tree(self):
    return {str(path.relative_to(self.root)): path.read_bytes() for path in sorted(self.root.rglob("*"))
            if path.is_file() and path != self.root / T.DB_LOCK}

  def new(self):
    other = NativeMaintenance("test_happy_path_publishes_durable_marker_and_vetoes_every_route")
    other.setUp()
    self.addCleanup(other.doCleanups)
    return other

  def test_happy_path_publishes_durable_marker_and_vetoes_every_route(self):
    result = self.run_maintenance()
    self.assertEqual(self.phases, ["before", "after", "final"])
    self.assertTrue((self.root / T.MAINTENANCE).is_file())
    self.assertFalse(any(self.pending_names()))
    self.assertFalse((self.root / T.DB_LOCK).exists())
    self.assertEqual(stat.S_IMODE((self.root / T.MAINTENANCE).stat().st_mode), 0o600)
    self.assertEqual(T.P.digest((self.root / T.MAINTENANCE).read_bytes()), result["maintenance_intent_sha256"])
    self.assertFalse((self.root / T.OPT_IN).exists())
    self.assertFalse((self.root / T.P.POLICY).exists())
    self.assertEqual(T.verify_fallback(self.root)["classification"], "fallback-bytes-verified")
    with self.assertRaisesRegex(ValueError, "package maintenance"): SLEEP.reject_pending(self.root)
    with self.assertRaisesRegex(ValueError, "package maintenance"): F.PRODUCT.verify_deployment(self.root, self.f.config, self.f.report)
    with self.assertRaisesRegex(ValueError, "maintenance intent"): self.fixture.run_action("activation")

  def test_before_failures_write_nothing(self):
    for failure in ("gate", "image", "inventory"):
      with self.subTest(failure=failure):
        other = self.new()
        if failure == "gate": other.fail["before"] = True
        elif failure == "image":
          original = other.fixture.check
          def image(root, action, phase, original=original):
            original(root, action, phase)
            raise ValueError("saved image present before")
          other.fixture.check = image
        else: next((other.root / T.P.STATE / "runtime").rglob("fixture.py")).write_bytes(b"drifted reviewed code\n")
        before = other.tree()
        with self.assertRaises(ValueError): other.run_maintenance()
        self.assertEqual(other.tree(), before)
        self.assertFalse((other.root / T.MAINTENANCE).exists())
        self.assertFalse(any(other.pending_names()))
        self.assertFalse((other.root / T.DB_LOCK).exists())
        self.assertTrue((other.root / T.OPT_IN).exists())

  def test_after_gate_failure_retains_deactivation_pending_veto_without_marker(self):
    self.fail["after"] = True
    with self.assertRaisesRegex(ValueError, "injected after"): self.run_maintenance()
    self.assertTrue(self.fixture.pending("deactivation").exists())
    self.assertFalse((self.root / T.MAINTENANCE).exists())
    self.assertEqual((self.root / T.P.LIMINE).read_bytes(), self.f.before)
    with self.assertRaisesRegex(ValueError, "package maintenance"): SLEEP.reject_pending(self.root)
    self.assertFalse((self.root / T.DB_LOCK).exists())

  def test_final_failures_retain_marker_and_old_pending_before_retirement(self):
    for failure in ("gate", "image", "uki"):
      with self.subTest(failure=failure):
        other = self.new()
        if failure == "gate": other.fail["final"] = True
        elif failure == "image": other.image = True
        else:
          original = other.gate
          def swap(root, phase, original=original):
            if phase == "final": (root / T.PRODUCTION).write_bytes(b"different production image")
            original(root, phase)
          other.gate = swap
        with self.assertRaises(ValueError): other.run_maintenance()
        self.assertTrue((other.root / T.MAINTENANCE).exists())
        self.assertTrue(other.fixture.pending("deactivation").exists())
        self.assertFalse((other.root / T.DB_LOCK).exists())
        with self.assertRaisesRegex(ValueError, "package maintenance"): SLEEP.reject_pending(other.root)

  def test_fallback_rejects_uki_mismatch_wrong_default_and_missing_image(self):
    backup = T._read(self.root, T.P.BACKUP)
    self.assertEqual(T.verify_fallback(self.root, backup)["limine"]["sha256"], T.P.digest(self.f.before))
    original = (self.root / T.PRODUCTION).read_bytes()
    (self.root / T.PRODUCTION).write_bytes(original + b"x")
    with self.assertRaisesRegex(ValueError, "does not bind"): T.verify_fallback(self.root, backup)
    (self.root / T.PRODUCTION).write_bytes(original)
    for mutated in (backup.replace(b"default_entry: 2", b"default_entry: 3"),
                    backup.replace(b"default_entry: 2", b"default_entry: 2\nremember_last_entry: yes")):
      with self.assertRaises(ValueError): T.verify_fallback(self.root, mutated)
    (self.root / T.PRODUCTION).unlink()
    with self.assertRaises(FileNotFoundError): T.verify_fallback(self.root, backup)

  def test_lock_contention_never_publishes_anything(self):
    before = self.tree()
    held = os.open(self.root / T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with self.assertRaises(BlockingIOError): self.run_maintenance()
    finally: os.close(held)
    db = self.f.write(T.DB_LOCK, b"pacman owns this")
    with self.assertRaises(FileExistsError): self.run_maintenance()
    self.assertEqual(db.read_bytes(), b"pacman owns this")
    db.unlink()
    self.assertEqual(self.tree(), before)
    self.assertEqual(self.phases, [])

  REAL = hasattr(T.G, "_maintenance")

  def reenter(self):
    return T._verify_existing_maintenance(self.root, guard=lambda: None, gate=self.gate)

  def test_reentry_wiring_runs_guard_validator_under_locks_then_retained_gate(self):
    self.run_maintenance()
    marker = (self.root / T.MAINTENANCE).read_bytes()
    settled, events = self.tree(), []
    def validator(root):
      events.append("validator")
      self.assertTrue((root / T.DB_LOCK).is_file())
      held = os.open(root / T.PHYSICAL_LOCK, os.O_RDONLY)
      try:
        with self.assertRaises(BlockingIOError): fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(held)
      return {"transition_id": json.loads(marker)["transition_id"]}
    self.phases.clear()
    with patch.object(T.G, "_maintenance", validator, create=True):
      result = self.reenter()
    self.assertEqual((events, self.phases), (["validator"], ["retained"]))
    self.assertTrue(result["already_inactive"])
    self.assertEqual(result["maintenance_intent_sha256"], T.P.digest(marker))
    self.assertEqual(self.tree(), settled)
    self.assertFalse((self.root / T.DB_LOCK).exists())
    # Validator or retained-gate failure propagates, never touching the marker.
    with patch.object(T.G, "_maintenance", side_effect=ValueError("guard refuses"), create=True):
      with self.assertRaisesRegex(ValueError, "guard refuses"): self.reenter()
    self.fail_gate = True
    self.fail["retained"] = True
    with patch.object(T.G, "_maintenance", validator, create=True):
      with self.assertRaisesRegex(ValueError, "injected retained"): self.reenter()
    self.assertEqual(self.tree(), settled)
    self.assertFalse((self.root / T.DB_LOCK).exists())

  def test_reentry_refuses_without_guard_validator_or_marker(self):
    with patch.object(T.G, "_maintenance", None, create=True):
      with self.assertRaisesRegex(ValueError, "lacks the exact maintenance validator"): self.reenter()
    with patch.object(T.G, "_maintenance", lambda root: {}, create=True):
      with self.assertRaises(FileNotFoundError): self.reenter()
    self.assertFalse((self.root / T.MAINTENANCE).exists())
    self.assertFalse((self.root / T.DB_LOCK).exists())

  def test_idempotent_rerun_refuses_rewrite(self):
    self.run_maintenance()
    settled = self.tree()
    with self.assertRaisesRegex(ValueError, "maintenance intent"): self.run_maintenance()
    self.assertEqual(self.tree(), settled)

  def coherent_update(self):
    """Simulate an OS/kernel update: new production UKI and its matching stock entry hash."""
    old = (self.root / T.PRODUCTION).read_bytes()
    new = b"updated production image"
    limine = (self.root / T.P.LIMINE).read_bytes()
    (self.root / T.PRODUCTION).write_bytes(new)
    (self.root / T.P.LIMINE).write_bytes(limine.replace(hashlib.blake2b(old).hexdigest().encode(), hashlib.blake2b(new).hexdigest().encode()))

  @unittest.skipUnless(REAL, "requires the update guard's exact maintenance validator")
  def test_reentry_reuses_guard_validator_and_accepts_coherent_new_stock(self):
    self.run_maintenance()
    settled = self.tree()
    self.phases.clear()
    self.assertTrue(self.reenter()["already_inactive"])
    self.assertEqual((self.phases, self.tree()), (["retained"], settled))
    self.coherent_update()
    updated = self.tree()
    self.assertTrue(self.reenter()["already_inactive"])
    self.assertEqual(self.tree(), updated)
    self.assertFalse((self.root / T.DB_LOCK).exists())

  @unittest.skipUnless(REAL, "requires the update guard's exact maintenance validator")
  def test_reentry_refuses_incoherent_or_drifted_state_and_preserves_marker(self):
    self.run_maintenance()
    marker = (self.root / T.MAINTENANCE).read_bytes()
    production = (self.root / T.PRODUCTION).read_bytes()
    (self.root / T.PRODUCTION).write_bytes(b"kernel updated but stock entry not")
    with self.assertRaises(ValueError): self.reenter()
    (self.root / T.PRODUCTION).write_bytes(production)
    self.image = True
    with self.assertRaisesRegex(ValueError, "saved image"): self.reenter()
    self.image = False
    self.f.write(T.OPT_IN, b"").chmod(0o644)
    with self.assertRaises(ValueError): self.reenter()
    (self.root / T.OPT_IN).unlink()
    self.f.write(T.PENDINGS["activation"], b"partial")
    with self.assertRaises(ValueError): self.reenter()
    self.fixture.pending("activation").unlink()
    (self.root / T.MAINTENANCE).write_bytes(marker + b" ")
    with self.assertRaises(ValueError): self.reenter()
    (self.root / T.MAINTENANCE).write_bytes(marker)
    self.assertTrue(self.reenter()["already_inactive"])
    self.assertFalse((self.root / T.DB_LOCK).exists())

  def test_runtime_pending_markers_refuse_maintenance_with_no_writes(self):
    for relative in T.RUNTIME_PENDINGS:
      with self.subTest(marker=str(relative)):
        other = self.new()
        other.f.write(relative, b"interrupted")
        before = other.tree()
        with self.assertRaisesRegex(ValueError, "Runtime deployment/upgrade pending"): other.run_maintenance()
        self.assertEqual(other.tree(), before)
        self.assertEqual(other.phases, [])
        self.assertFalse((other.root / T.MAINTENANCE).exists())
        self.assertFalse(any(other.pending_names()))
        self.assertFalse((other.root / T.DB_LOCK).exists())
    self.assertEqual(T.RUNTIME_PENDINGS, (T.P.STATE / "runtime-upgrade.pending", T.P.STATE / ".runtime-pending"))

  def test_live_roots_and_arbitrary_callbacks_are_never_accepted(self):
    alias = self.root.parent / "live-alias"
    alias.symlink_to("/")
    noop = lambda *args: None
    with patch.object(T.os, "open", side_effect=AssertionError("no live filesystem open")):
      for root in ("/", "/tmp/..", "relative", alias, Path("/")):
        with self.subTest(root=str(root)):
          with self.assertRaises(ValueError): T.transition(root, "maintenance", precheck=noop)
          with self.assertRaises(ValueError): T._transition(root, "maintenance", precheck=noop, guard=noop, maintenance_gate=noop)
          with self.assertRaises(ValueError): T._transition(root, "maintenance", precheck=noop, guard=noop, maintenance_gate=noop, native=object())
          with self.assertRaises(ValueError): T._verify_existing_maintenance(root, guard=noop, gate=noop)
      with self.assertRaises(ValueError): T._transition(Path("/"), "maintenance", precheck=noop, guard=noop, native=T._NATIVE_MAINTENANCE)
    # The public API cannot receive a gate or capability at all.
    with self.assertRaises(TypeError): T.transition(self.root, "maintenance", precheck=noop, maintenance_gate=noop)
    with self.assertRaises(TypeError): T.transition(self.root, "maintenance", precheck=noop, native=T._NATIVE_MAINTENANCE)
    with self.assertRaisesRegex(ValueError, "only valid for the maintenance"):
      T._transition(self.root, "deactivation", precheck=noop, guard=noop, maintenance_gate=noop)

  def test_native_capability_passes_only_the_entry_check(self):
    # With capability and gate the live root reaches the first inspection, which
    # is stubbed to stop; nothing on the real host is opened or written.
    with patch.object(T, "_locks", side_effect=RuntimeError("stop at exclusion")), patch.object(T.G, "_ancestors", side_effect=RuntimeError("stop at ancestors")):
      with self.assertRaisesRegex(RuntimeError, "stop at"):
        T._transition(Path("/"), "maintenance", precheck=lambda *a: None, guard=lambda: None, maintenance_gate=lambda *a: None, native=T._NATIVE_MAINTENANCE)


if __name__ == "__main__": unittest.main()
