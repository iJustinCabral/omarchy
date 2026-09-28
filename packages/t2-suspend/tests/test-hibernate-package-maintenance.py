"""Fixture-only pipeline callbacks; never executes updates, EFI, devices or power."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HERE = Path(__file__).parents[1]
M = load("maintenance_fixture", HERE / "hibernate/package_maintenance.py")
F = load("maintenance_transition_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))


class Maintenance(unittest.TestCase):
  def setUp(self):
    self.fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.f = self.fixture.root, self.fixture.f
    self.boot = str(uuid.uuid4())
    self.f.write(M.BOOT, self.boot.encode())
    self.fixture.run_action()
    self.calls, self.sessions = [], []

  def phase(self, name, session):
    self.calls.append(name)
    self.sessions.append(session)
    self.assertFalse((self.root / M.T.DB_LOCK).exists())
    held = os.open(self.root / M.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(held)
    # Real ALPM pre-hooks run while pacman owns db.lck. This fixture-only seam
    # permits that state, but does not grant native authority or own this file.
    lock = self.f.write(M.T.DB_LOCK, b"simulated pacman owned lock")
    try:
      self.assertEqual(M.check_maintenance(self.root, session)["classification"], "fallback-bytes-verified")
      with self.assertRaises(ValueError): M.T.G.check(self.root)
    finally: lock.unlink()
    return 0

  def coordinate(self, phase=None):
    return M.coordinate(self.root, precheck=self.fixture.check, run_phase=self.phase if phase is None else phase)

  def archive(self):
    intent = json.loads((self.root / M.T.MAINTENANCE).read_bytes())
    return self.root / M.T.HISTORY / intent["transition_id"]

  def test_coherent_dispatch_keeps_marker_and_exact_old_evidence(self):
    receipt = (self.root / M.T.P.RECEIPT).read_bytes()
    result = self.coordinate()
    self.assertEqual(self.calls, list(M.PHASES))
    self.assertEqual(result["maintenance"]["hibernation"], "maintenance-disabled")
    self.assertFalse(result["maintenance"]["qualification_issued"])
    self.assertFalse(result["maintenance"]["reactivation_evaluated"])
    archive = self.archive()
    self.assertEqual((archive / "maintenance-intent.json").read_bytes(), (self.root / M.T.MAINTENANCE).read_bytes())
    self.assertEqual((self.root / M.T.P.RECEIPT).read_bytes(), receipt)
    self.assertEqual(self.fixture.guards.read_bytes(), b"immutable guard")
    self.assertEqual(len(list(archive.glob("package-phase-*-start.json"))), len(M.PHASES))
    self.assertEqual(len(list(archive.glob("package-phase-*-result.json"))), len(M.PHASES))
    self.assertEqual(len(list(archive.glob("package-phase-*-postcheck.json"))), len(M.PHASES))
    self.assertFalse((self.root / M.T.P.POLICY).exists())
    self.assertFalse((self.root / M.T.OPT_IN).exists())
    self.assertFalse((self.root / M.T.DB_LOCK).exists())
    for session in self.sessions:
      with self.assertRaises(ValueError): M.check_maintenance(self.root, session)
    for action in ("activation", "deactivation", "maintenance"):
      with self.assertRaises(ValueError): self.fixture.run_action(action)
    with self.assertRaises(ValueError): self.coordinate()

  def test_exclusion_guard_reaches_transition_write_boundaries(self):
    observations = []
    def guard():
      observations.append((self.root / M.T.MAINTENANCE).exists())
    M.coordinate(self.root, precheck=self.fixture.check, run_phase=self.phase, guard=guard)
    self.assertGreater(len(observations), 5)
    self.assertFalse(observations[0])
    self.assertTrue(observations[-1])
    self.assertEqual(self.calls, list(M.PHASES))

  def test_failed_initial_exclusion_prevents_transition_and_phase_launch(self):
    original = (self.root / M.T.P.LIMINE).read_bytes()
    def refuse(): raise ValueError("fixture exclusion unavailable")
    with self.assertRaisesRegex(ValueError, "exclusion unavailable"):
      M.coordinate(self.root, precheck=self.fixture.check, run_phase=self.phase, guard=refuse)
    self.assertEqual(self.calls, [])
    self.assertEqual((self.root / M.T.P.LIMINE).read_bytes(), original)
    self.assertFalse((self.root / M.T.MAINTENANCE).exists())
    self.assertFalse((self.root / M.T.DB_LOCK).exists())

  def test_snapshot_absence_and_failure_record_actual_nonfatal_status(self):
    for code, expected in ((127, "snapshot-absent"), (1, "snapshot-failed-nonfatal")):
      case = Maintenance("test_coherent_dispatch_keeps_marker_and_exact_old_evidence")
      case.setUp()
      try:
        def phase(name, session): return code if name == "snapshot" else case.phase(name, session)
        case.coordinate(phase)
        record = json.loads((case.archive() / "package-phase-01-snapshot-result.json").read_bytes())
        self.assertEqual((record["returncode"], record["outcome"]), (code, expected))
        self.assertTrue((case.archive() / "package-maintenance-complete.json").exists())
      finally: case.doCleanups()

  def test_updated_stock_bytes_may_continue_but_never_reactivate_old_pair(self):
    def phase(name, session):
      result = self.phase(name, session)
      if name == "system-pkgs":
        old = hashlib.blake2b(b"production").hexdigest().encode()
        raw = b"updated production bytes"
        (self.root / M.PRODUCTION).write_bytes(raw)
        config = self.root / M.T.P.LIMINE
        config.write_bytes(config.read_bytes().replace(old, hashlib.blake2b(raw).hexdigest().encode()))
      return result
    result = self.coordinate(phase)
    self.assertEqual(result["maintenance"]["fallback"]["production"]["sha256"], hashlib.sha256(b"updated production bytes").hexdigest())
    self.assertEqual(result["maintenance"]["fallback"]["classification"], "fallback-bytes-verified")
    self.assertTrue((self.root / M.T.MAINTENANCE).exists())
    with self.assertRaises(ValueError): self.fixture.run_action("activation")

  def test_failure_keeps_completed_deactivation_marker_and_no_replay(self):
    def phase(name, session): return 2 if name == "keyring" else self.phase(name, session)
    with self.assertRaises(RuntimeError): self.coordinate(phase)
    self.assertFalse((self.root / M.T.PENDINGS["deactivation"]).exists())
    self.assertTrue((self.archive() / "completion.json").exists())
    self.assertTrue((self.archive() / "package-maintenance-failure.json").exists())
    self.assertFalse((self.archive() / "package-maintenance-complete.json").exists())
    self.assertTrue((self.root / M.T.MAINTENANCE).exists())
    with self.assertRaises(ValueError): self.coordinate()

  def test_foreign_db_lock_is_preserved_and_stops_next_phase(self):
    def phase(name, session):
      self.f.write(M.T.DB_LOCK, b"foreign outstanding pacman lock")
      M.check_maintenance(self.root, session)
      return 0
    with self.assertRaisesRegex(ValueError, "Outstanding pacman lock"): self.coordinate(phase)
    self.assertEqual((self.root / M.T.DB_LOCK).read_bytes(), b"foreign outstanding pacman lock")
    self.assertTrue((self.root / M.T.MAINTENANCE).exists())

  def test_runtime_and_hook_drift_stop_pipeline_without_repair(self):
    for relative in (M.T.P.STATE / "runtime" / M.T.D.ENTRYPOINT, M.T.HOOK):
      case = Maintenance("test_coherent_dispatch_keeps_marker_and_exact_old_evidence")
      case.setUp()
      try:
        def phase(name, session):
          (case.root / relative).write_bytes(b"modified admission authority")
          return 0
        with self.assertRaises(ValueError): case.coordinate(phase)
        self.assertEqual((case.root / relative).read_bytes(), b"modified admission authority")
        self.assertTrue((case.root / M.T.MAINTENANCE).exists())
        self.assertFalse((case.archive() / "package-phase-01-snapshot-start.json").exists())
      finally: case.doCleanups()

  def test_deleted_marker_is_rearmed_before_exclusion_release(self):
    saved = []
    def phase(name, session):
      saved.append(session.intent)
      (self.root / M.T.MAINTENANCE).unlink()
      raise OSError("fixture deleted marker then failed")
    with self.assertRaises(OSError): self.coordinate(phase)
    self.assertEqual((self.root / M.T.MAINTENANCE).read_bytes(), saved[0])
    self.assertEqual((self.archive() / "maintenance-intent.json").read_bytes(), saved[0])

  def test_foreign_marker_is_never_overwritten_on_exit(self):
    def phase(name, session):
      (self.root / M.T.MAINTENANCE).write_bytes(b"foreign malformed presence veto")
      raise OSError("fixture foreign marker")
    with self.assertRaises(OSError): self.coordinate(phase)
    self.assertEqual((self.root / M.T.MAINTENANCE).read_bytes(), b"foreign malformed presence veto")
    with self.assertRaises(ValueError): M.T.G.check(self.root)

  def test_rearm_fsync_failure_reports_unconfirmed_durability(self):
    removed = False
    def phase(name, session):
      nonlocal removed
      (self.root / M.T.MAINTENANCE).unlink()
      removed = True
      raise OSError("fixture deleted marker")
    sync = M.T._sync
    def fail_sync(directory):
      if removed and directory == self.root / M.T.P.STATE: raise OSError("fixture rearm directory sync failure")
      return sync(directory)
    with patch.object(M.T, "_sync", side_effect=fail_sync), self.assertRaisesRegex(RuntimeError, "veto durability unconfirmed"):
      self.coordinate(phase)
    self.assertTrue((self.root / M.T.MAINTENANCE).exists())

  def test_retained_recovery_sync_and_wait_interrupt_never_release_physical(self):
    saved, sessions, attempts = [], [], []
    broken = True
    def phase(name, session):
      saved.append(session.intent)
      sessions.append(session)
      (self.root / M.T.MAINTENANCE).unlink()
      raise OSError("original phase failure")
    sync = M.T._sync
    def fail(directory):
      if saved and broken and directory == self.root / M.T.P.STATE:
        raise OSError("retained directory fault")
      return sync(directory)
    def assert_held():
      fd = os.open(self.root / M.T.PHYSICAL_LOCK, os.O_RDONLY)
      try:
        with self.assertRaises(BlockingIOError): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(fd)
      self.assertFalse(sessions[0].active)
      self.assertIsNone(sessions[0].phase)
    def recover(error, attempt):
      nonlocal broken
      assert_held()
      attempts.append(attempt)
      if attempt == 1: raise KeyboardInterrupt("notification cannot cancel retention")
      broken = False
    sleep = M.T.time.sleep
    interrupted = False
    def pause(seconds):
      nonlocal interrupted
      assert_held()
      if not interrupted:
        interrupted = True
        raise KeyboardInterrupt("retry backoff cannot cancel retention")
      return sleep(seconds)
    with patch.object(M.T, "_sync", side_effect=fail), patch.object(M.T.time, "sleep", side_effect=pause):
      with self.assertRaisesRegex(OSError, "original phase failure"):
        M.coordinate(self.root, precheck=self.fixture.check, run_phase=phase, recover=recover)
    self.assertEqual(attempts, [1, 2])
    self.assertTrue(interrupted)
    self.assertEqual((self.root / M.T.MAINTENANCE).read_bytes(), saved[0])

  def test_retained_foreign_marker_waits_for_exact_external_repair_without_overwrite(self):
    raw = []
    def phase(name, session):
      raw.append(session.intent)
      (self.root / M.T.MAINTENANCE).write_bytes(b"foreign presence veto")
      raise OSError("original foreign marker failure")
    def repair(error, attempt):
      self.assertEqual(attempt, 1)
      self.assertEqual((self.root / M.T.MAINTENANCE).read_bytes(), b"foreign presence veto")
      fd = os.open(self.root / M.T.PHYSICAL_LOCK, os.O_RDONLY)
      try:
        with self.assertRaises(BlockingIOError): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(fd)
      # Explicit trusted fixture resolution; core never overwrites foreign data.
      (self.root / M.T.MAINTENANCE).write_bytes(raw[0])
    with self.assertRaisesRegex(OSError, "original foreign marker failure"):
      M.coordinate(self.root, precheck=self.fixture.check, run_phase=phase, recover=repair)
    self.assertEqual((self.root / M.T.MAINTENANCE).read_bytes(), raw[0])

  def test_invalid_result_types_and_phase_exception_are_not_success(self):
    for result in (True, None, "0", 0.0, -1, 256):
      case = Maintenance("test_coherent_dispatch_keeps_marker_and_exact_old_evidence")
      case.setUp()
      try:
        with self.assertRaises(ValueError): case.coordinate(lambda *args: result)
        self.assertTrue((case.root / M.T.MAINTENANCE).exists())
        self.assertFalse((case.archive() / "package-maintenance-complete.json").exists())
      finally: case.doCleanups()
    def interrupt(*args): raise KeyboardInterrupt()
    with self.assertRaises(KeyboardInterrupt): self.coordinate(interrupt)
    self.assertEqual(json.loads((self.archive() / "package-maintenance-failure.json").read_bytes())["error_type"], "KeyboardInterrupt")

  def test_modified_marker_archive_chain_and_boot_refuse_active_capability(self):
    def phase(name, session):
      marker = self.root / M.T.MAINTENANCE
      raw = marker.read_bytes()
      marker.write_bytes(raw + b" ")
      with self.assertRaises(ValueError): M.check_maintenance(self.root, session)
      marker.write_bytes(raw)
      archive = self.archive()
      intent = archive / "intent.json"
      old = intent.read_bytes()
      intent.write_bytes(old + b" ")
      with self.assertRaises(ValueError): M.check_maintenance(self.root, session)
      intent.write_bytes(old)
      self.f.write(M.BOOT, str(uuid.uuid4()).encode())
      with self.assertRaises(ValueError): M.check_maintenance(self.root, session)
      self.f.write(M.BOOT, self.boot.encode())
      with self.assertRaises(ValueError): M.check_maintenance(self.root.parent, session)
      with self.assertRaises(ValueError): M.check_maintenance(self.root, {"safe": True})
      return self.phase(name, session)
    self.coordinate(phase)

  def test_physical_inode_loss_and_closed_scope_refuse_capability(self):
    captured = []
    def phase(name, session):
      captured.append(session.physical)
      lock = self.root / M.T.PHYSICAL_LOCK
      old = lock.with_name("retained-fixture-lock")
      lock.rename(old)
      self.f.write(M.T.PHYSICAL_LOCK, b"")
      with self.assertRaisesRegex(ValueError, "inode changed"): M.check_maintenance(self.root, session)
      lock.unlink()
      old.rename(lock)
      return self.phase(name, session)
    self.coordinate(phase)
    with self.assertRaisesRegex(ValueError, "scope ended"): captured[0]()

  def test_phase_publication_faults_preserve_veto_and_prior_evidence(self):
    for suffix in ("package-maintenance-start.json", "package-phase-00-pkg-prune-start.json",
                   "package-phase-00-pkg-prune-result.json", "package-phase-00-pkg-prune-postcheck.json", "package-maintenance-complete.json"):
      case = Maintenance("test_coherent_dispatch_keeps_marker_and_exact_old_evidence")
      case.setUp()
      try:
        original = M.T._new
        def fail(path, raw, *args):
          if path.name == suffix: raise OSError("fixture publication fault")
          return original(path, raw, *args)
        with patch.object(M.T, "_new", side_effect=fail), self.assertRaises(OSError): case.coordinate()
        self.assertTrue((case.root / M.T.MAINTENANCE).exists())
        self.assertTrue((case.archive() / "completion.json").exists())
        self.assertFalse((case.root / M.T.DB_LOCK).exists())
        with self.assertRaises(ValueError): case.coordinate()
      finally: case.doCleanups()

  def test_phase_result_directory_sync_failure_retains_file_and_stops_dispatch(self):
    original, fired = M.T._sync, False
    def fail_sync(directory):
      nonlocal fired
      if not fired and (directory / "package-phase-00-pkg-prune-result.json").is_file():
        fired = True
        raise OSError("fixture result directory sync failure")
      return original(directory)
    with patch.object(M.T, "_sync", side_effect=fail_sync), self.assertRaises(OSError): self.coordinate()
    self.assertTrue(fired)
    self.assertEqual(self.calls, ["pkg-prune"])
    self.assertTrue((self.archive() / "package-phase-00-pkg-prune-result.json").exists())
    self.assertFalse((self.archive() / "package-maintenance-complete.json").exists())
    self.assertTrue((self.root / M.T.MAINTENANCE).exists())

  def test_wrong_or_replaced_fallback_bytes_fail_and_cannot_start_pipeline(self):
    (self.root / M.PRODUCTION).write_bytes(b"wrong hash")
    # Existing deactivation precheck itself refuses the broken production pin.
    with self.assertRaises(ValueError): self.coordinate()
    self.assertEqual(self.calls, [])
    self.assertTrue((self.root / M.T.P.POLICY).exists())

  def test_fallback_rechecks_configuration_after_image_read_and_rejects_short_read(self):
    original = M._bytes
    def change(root, relative, limit, **kwargs):
      result = original(root, relative, limit, **kwargs)
      if relative == M.PRODUCTION:
        config = root / M.T.P.LIMINE
        config.write_bytes(config.read_bytes() + b"# changed during image read\n")
      return result
    (self.root / M.T.P.LIMINE).write_bytes(self.f.before)
    with patch.object(M, "_bytes", side_effect=change), self.assertRaisesRegex(ValueError, "configuration changed"):
      M._fallback(self.root)
    with patch.object(M.os, "read", return_value=b""), self.assertRaisesRegex(ValueError, "Short"):
      M._bytes(self.root, M.PRODUCTION, M.MAX_UKI)

  def test_public_and_private_live_entry_refuse_before_any_open(self):
    with patch.object(M.T.os, "open", side_effect=AssertionError("no live filesystem access")):
      for root in ("/", "/tmp/..", "relative"):
        with self.assertRaises(ValueError): M.coordinate(root, precheck=lambda *args: None, run_phase=lambda *args: 0)
        with self.assertRaises(ValueError): M.check_maintenance(root, {"safe": True})
      with self.assertRaises(ValueError):
        M.T._transition(Path("/"), "maintenance", precheck=lambda *args: None, guard=lambda: None, maintenance_continuation=lambda *args: None)


if __name__ == "__main__": unittest.main()
