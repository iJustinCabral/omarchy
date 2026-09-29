"""Offline contract tests; no inhibitor, package lock, EFI or power operation."""
import hashlib
import fcntl
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime_upgrade_native_fixture", HERE / "hibernate/runtime_upgrade_native.py")
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)


def digest(raw): return hashlib.sha256(raw).hexdigest()


class NativeUpgrade(unittest.TestCase):
  def approval(self):
    return {"protocol": "omarchy-t2-runtime-upgrade-approval-v2", "approved": True,
            "approval_id": "306521e4-998e-4477-b603-31b93144d101",
            "current_boot_id": "0f909934-0ecf-4407-863d-6822c81cb2df",
            "source_directory": "/reviewed/source", "reviewed_commit": "a" * 40,
            "adapter_sha256": "b" * 64, "expected": {name: "c" * 64 for name in N.HASHES},
            "unchanged": {name: "d" * 64 for name in N.UNCHANGED}}

  def test_public_adapter_is_installed_only_and_cli_takes_no_arguments(self):
    with self.assertRaisesRegex(ValueError, "Only fixed"):
      N.native()
    for args in (["--root", "/tmp"], ["--force"], ["check"], ["upgrade"]):
      with self.assertRaisesRegex(ValueError, "no arguments"):
        N.main(args)

  def test_inhibitor_command_has_fixed_root_private_script_and_no_flags(self):
    self.assertEqual(N._inhibit_command(),
      ("/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block",
       "--who=" + N.WHO, "--why=" + N.WHY, "--no-ask-password",
       "/usr/bin/python3", "-I", "-B", str(N.SCRIPT)))

  def test_external_approval_parser_rejects_unpinned_adapter_and_missing_authority(self):
    approval = self.approval()
    approval["adapter_sha256"] = digest(b"adapter")
    N._parse_approval(json.dumps(approval).encode(), b"adapter")
    with self.assertRaisesRegex(ValueError, "adapter differs"):
      N._parse_approval(json.dumps(approval).encode(), b"other")
    del approval["expected"]["old_config"]
    with self.assertRaisesRegex(ValueError, "Seven exact"):
      N._parse_approval(json.dumps(approval).encode(), b"adapter")
    approval["expected"]["old_config"] = "c" * 64
    approval["unchanged"].pop("limine")
    with self.assertRaisesRegex(ValueError, "unchanged host"):
      N._parse_approval(json.dumps(approval).encode(), b"adapter")

  def test_boot_or_unchanged_artifact_mutation_refuses(self):
    approval = self.approval()
    with patch.object(N, "_private_bytes", return_value=b"other-boot\n"), self.assertRaisesRegex(ValueError, "boot changed"):
      N._unchanged(approval)
    with patch.object(N, "_private_bytes", side_effect=[(approval["current_boot_id"] + "\n").encode(), b"wrong"]), \
         patch.object(N, "UNCHANGED", {"qualification": (Path("/test/qualification.json"), 0o600)}), \
         patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)), \
         patch.object(Path, "is_symlink", return_value=False), self.assertRaisesRegex(ValueError, "differs: qualification"):
      N._unchanged(approval)

  def test_historical_approval_and_changed_config_pin_are_rejected(self):
    approval = self.approval()
    approval["adapter_sha256"] = digest(b"adapter")
    approval["protocol"] = "omarchy-t2-runtime-upgrade-approval-v1"
    with self.assertRaisesRegex(ValueError, "external runtime"):
      N._parse_approval(json.dumps(approval).encode(), b"adapter")
    approval["protocol"] = "omarchy-t2-runtime-upgrade-approval-v2"
    approval["expected"]["new_config"] = "e" * 64
    with self.assertRaisesRegex(ValueError, "configuration pin"):
      N._parse_approval(json.dumps(approval).encode(), b"adapter")

  def test_completed_v2_recovery_binds_approval_and_consumption_without_replay(self):
    spec = importlib.util.spec_from_file_location("recovery_core", HERE / "hibernate/runtime_deployment.py")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    approval = self.approval()
    expected = approval["expected"]
    intent = {"protocol": "omarchy-t2-runtime-upgrade-intent-v2",
      "transaction_id": "706521e4-998e-4477-b603-31b93144d102", "approval_id": approval["approval_id"],
      "old_review_sha256": expected["old_review"], "new_review_sha256": expected["new_review"],
      "old_config_sha256": expected["old_config"], "new_config_sha256": expected["new_config"]}
    record = {"protocol": "omarchy-t2-runtime-upgrade-completed-v2", "intent": intent,
      "review_sha256": expected["new_review"], "config_sha256": expected["new_config"]}
    with tempfile.TemporaryDirectory() as directory:
      state = Path(directory)
      state.chmod(0o700)
      for name, value in (("runtime-upgrade-completed-aaaaaaaaaaaa.json", core._encoded(record)),
                          ("runtime-upgrade-approval-consumed-" + approval["approval_id"] + ".json", core._encoded(intent))):
        (state / name).write_bytes(value)
        (state / name).chmod(0o600)
      with patch.object(N, "STATE", state):
        N._restore_veto(core, approval)
        self.assertEqual((state / core.COMPATIBLE_BARRIER).read_bytes(), core._encoded(intent))
        N._restore_veto(core, approval)
        foreign = {**approval, "approval_id": "306521e4-998e-4477-b603-31b93144d103"}
        with self.assertRaisesRegex(ValueError, "foreign completion"):
          N._restore_veto(core, foreign)
        (state / core.COMPATIBLE_BARRIER).write_bytes(b"foreign veto")
        with self.assertRaises(ValueError):
          N._restore_veto(core, approval)
        self.assertEqual((state / core.COMPATIBLE_BARRIER).read_bytes(), b"foreign veto")
  def test_review_requires_approved_exact_inventory_and_commit(self):
    raw = json.dumps({"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True,
                      "reviewed_commit": "a" * 40, "files": {N.RUNTIME_REL: {"size": 3, "sha256": digest(b"new")}}}).encode()
    review = N._review(raw, digest(raw), "a" * 40)
    N._reviewed_code(b"new", review, N.RUNTIME_REL)
    for changed in ("b" * 64, "x"):
      with self.assertRaises(ValueError): N._review(raw, changed, "a" * 40)
    with self.assertRaises(ValueError): N._reviewed_code(b"other", review, N.RUNTIME_REL)
    with self.assertRaises(ValueError): N._review(raw, digest(raw), "b" * 40)

  def test_old_inventory_and_pinned_bootstraps_precede_import(self):
    approval = self.approval()
    old, new, old_boot, new_boot = b"old review", b"new review", b"old", b"new"
    approval["expected"].update(old_review=digest(old), new_review=digest(new),
                                old_bootstrap=digest(old_boot), new_bootstrap=digest(new_boot))
    events = []
    reviews = iter([{"files": {N.RUNTIME_REL: {"size": 3, "sha256": digest(old_boot)}}},
                    {"files": {N.RUNTIME_REL: {"size": 3, "sha256": digest(new_boot)}}}])
    native = SimpleNamespace(WHO="omarchy-t2-source-default", WHY="reviewed-boot-policy-transition")
    core = SimpleNamespace(_verify_tree=lambda *args: events.append("verify old tree"),
                           inventory=lambda *args: (events.append("inventory workspace") or {N.RUNTIME_REL: {"size": 3, "sha256": digest(new_boot)}}))
    engine = SimpleNamespace(_runtime=lambda *args: events.append("verify old engine"))
    data = {str(N.STATE / "runtime-deployment-review.json"): old,
            str(N.STATE / "runtime-upgrade-review.json"): new,
            str(N.SCRIPT): b"adapter",
            str(N.STATE / "runtime-deployment-bootstrap.py"): old_boot,
            str(N.BOOTSTRAP): new_boot,
            str(N.STATE / "runtime/packages/t2-suspend/hibernate/boot_policy_native.py"): b"guard"}
    def read(path, mode=0o600): return data[str(path)]
    def load(name, path):
      events.append("import " + name)
      return {"reviewed_upgrade_core": core, "reviewed_old_native_guard": native,
              "reviewed_old_transition": engine}[name]
    with patch.object(N, "_private_bytes", side_effect=read), patch.object(N, "_review", side_effect=lambda *args: next(reviews)), patch.object(N, "_reviewed_code") as reviewed, patch.object(N, "_load", side_effect=load):
      N._verified_engines(approval)
    self.assertEqual(events[:2], ["import reviewed_upgrade_core", "verify old tree"])
    self.assertLess(events.index("verify old tree"), events.index("import reviewed_old_native_guard"))
    self.assertLess(events.index("verify old engine"), events.index("inventory workspace"))
    self.assertEqual(native.WHO, N.WHO)
    self.assertEqual(native.WHY, N.WHY)
    self.assertEqual(reviewed.call_count, 4)

  def test_bad_bootstrap_refuses_before_any_import(self):
    approval = self.approval()
    approval["expected"]["old_review"] = digest(b"old review")
    approval["expected"]["new_review"] = digest(b"new review")
    with patch.object(N, "_private_bytes", side_effect=[b"old review", b"new review", b"adapter", b"wrong", b"new"]), patch.object(N, "_review", return_value={"files": {}}), patch.object(N, "_reviewed_code"), patch.object(N, "_load") as imported:
      with self.assertRaisesRegex(ValueError, "bootstrap"):
        N._verified_engines(approval)
    imported.assert_not_called()

  def test_barrier_postcheck_never_calls_ordinary_check(self):
    product = Mock()
    product.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore",
                                                 "production_uki": "/uki", "staged_receipt_sha256": "a" * 64}, {"receipt": True}]
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}
    product.ARTIFACTS.derive_artifacts.return_value = {"manifest": {}, "audited_details": {"restore_protocol": {"resume": resume}}}
    product.validate.return_value = "receipt"
    product.BOOT_POLICY.verify.return_value = True
    image_state = Mock()
    with patch.object(N, "_load", return_value=image_state) as load:
      N._product_check(product, barrier=True)
    load.assert_called_once_with("reviewed_upgrade_image_state", N.STATE / "runtime/packages/t2-suspend/hibernate/image_state.py")
    image_state.require_no_image.assert_called_once_with(N.ROOT, resume)
    product.check.assert_not_called()
    product.TRIAL._verify_deployment.assert_called_once()
    product._admission_state.assert_called_once()

  def test_old_and_final_check_use_full_normal_admission(self):
    product = Mock()
    product.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore",
                                                 "production_uki": "/uki"}, {"receipt": True}]
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}
    product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": resume}}}
    image_state = Mock()
    with patch.object(N, "_load", return_value=image_state):
      N._product_check(product, barrier=False)
    image_state.require_no_image.assert_called_once_with(N.ROOT, resume)
    product.check.assert_called_once()
    product._admission_state.assert_not_called()

  def test_pending_and_unknown_image_refuse_normal_and_barrier_admission(self):
    for barrier in (False, True):
      for classification in ("pending", "unknown"):
        with self.subTest(barrier=barrier, classification=classification):
          product, image_state = Mock(), Mock()
          product.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore", "production_uki": "/uki"}, {}]
          product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}}}}
          image_state.require_no_image.side_effect = ValueError(classification + " image")
          with patch.object(N, "_load", return_value=image_state), self.assertRaisesRegex(ValueError, classification):
            N._product_check(product, barrier=barrier)
          product.check.assert_not_called()
          product.validate.assert_not_called()
          product._admission_state.assert_not_called()

  def test_image_refusal_precedes_mutation_or_retains_published_barrier(self):
    spec = importlib.util.spec_from_file_location("image_upgrade_fixture", HERE / "tests/test-hibernate-product-runtime-deployment.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    for stage in ("precheck", "postcheck"):
      with self.subTest(stage=stage):
        case = fixture.Deployment(methodName="runTest")
        case.setUp()
        try:
          expected, config = case.runtime_only_fixture()
          product, image_state = Mock(), Mock()
          product.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore", "production_uki": "/uki"}, {}]
          product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}}}}
          image_state.require_no_image.side_effect = ValueError("Pending or unknown image")
          check = lambda: N._product_check(product, barrier=stage == "postcheck")
          with patch.object(N, "_load", return_value=image_state), self.assertRaisesRegex(ValueError, "Pending or unknown"):
            fixture.D.upgrade_snapshot(case.source, root=case.root, expected=expected, approval_id=case.approval_id,
              guard=lambda: None, precheck=check if stage == "precheck" else lambda: None,
              postcheck=check if stage == "postcheck" else lambda: None)
          self.assertEqual((case.state / fixture.D.CONFIG).read_bytes(), config)
          self.assertEqual((case.state / fixture.D.COMPATIBLE_BARRIER).exists(), stage == "postcheck")
          self.assertEqual((case.state / fixture.D.UPGRADE_PENDING).exists(), stage == "postcheck")
          self.assertFalse((case.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").exists())
          installed = (case.state / "runtime" / fixture.D.ENTRYPOINT).read_bytes()
          self.assertIn(b"New source" if stage == "postcheck" else b"Source must", installed)
        finally: case.tearDown()

  def test_guard_checks_parent_before_and_after_real_idle_record(self):
    native = SimpleNamespace(_power_idle=Mock())
    approval = self.approval()
    with patch.object(N.os, "getppid", return_value=321), patch.object(N, "_parent_identity", return_value="start") as parent, \
         patch.object(N.os, "pidfd_open", return_value=9), patch.object(N.select, "select", return_value=([], [], [])), \
         patch.object(N, "_unchanged") as unchanged:
      fd, guard = N._guard(native, approval)
      self.assertEqual(fd, 9)
      guard()
    self.assertEqual(parent.call_count, 3)
    native._power_idle.assert_called_once_with(321)
    unchanged.assert_called_once_with(approval)

  def test_guard_loss_refuses_before_old_or_new_checks(self):
    native = SimpleNamespace(_power_idle=Mock())
    with patch.object(N.os, "getppid", return_value=321), patch.object(N, "_parent_identity", side_effect=["start", "changed"]), \
         patch.object(N.os, "pidfd_open", return_value=9), patch.object(N.select, "select", return_value=([], [], [])), \
         patch.object(N, "_unchanged") as unchanged:
      _, guard = N._guard(native, self.approval())
      with self.assertRaisesRegex(ValueError, "changed"):
        guard()
    native._power_idle.assert_not_called()
    unchanged.assert_not_called()

  def _orchestration(self, *, fail=None):
    approval = self.approval()
    events = []
    product = object()
    core = SimpleNamespace(_upgrade_snapshot=Mock(return_value={"review_sha256": "x" * 64}), _verify_tree=Mock())
    core._upgrade_snapshot.side_effect = lambda *args, **kwargs: (events.append("core") or {"review_sha256": "x" * 64})
    release_failed = False
    def release_db(*, verify_only=False):
      nonlocal release_failed
      events.append("db_verify" if verify_only else "db_release")
      if fail in ("release", "preserved") and not verify_only and not release_failed:
        release_failed = True
        raise (N._Preserved if fail == "preserved" else ValueError)("db release failed")
    release_db.check_physical = lambda: events.append("physical_check")
    release_db.abandon = lambda: events.append("abandon")
    @contextmanager
    def locks(root):
      events.append("locks_enter")
      try: yield release_db
      finally: events.append("locks_exit")
    engine = SimpleNamespace(_locks=Mock(side_effect=AssertionError("Old engine lock API must not run")), PRODUCT=product)
    def product_check(*args, barrier):
      events.append("old_admission" if args[0] is product else "final_admission")
      if fail == "final" and args[0] is not product: raise ValueError("final admission failed")
    def restore(*args):
      events.append("restore_veto")
      self.assertNotIn("locks_exit", events)
    with patch.object(N, "_installed_approval", return_value=approval), patch.object(N, "_unchanged"), \
         patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_verified_engines", return_value=(core, object(), engine)), \
         patch.object(N, "_locks", side_effect=locks), \
         patch.object(N, "_guard", return_value=(9, lambda: events.append("guard"))), \
         patch.object(N, "_product_check", side_effect=product_check), \
         patch.object(N, "_postcheck", return_value={}), patch.object(N, "_review", return_value={"files": {}}), \
         patch.object(N, "_private_bytes", return_value=b"review"), patch.object(N, "_load", return_value=object()), \
         patch.object(N, "_restore_veto", side_effect=restore), patch.object(N.os, "close"), \
         patch.object(N.os.path, "lexists", return_value=True):
      if fail is None:
        result = N.native()
        self.assertEqual(result, {"review_sha256": "x" * 64, "live_execution": True, "power_operation": False})
      else:
        with self.assertRaises(ValueError): N.native()
    return events

  def test_successful_upgrade_checks_ordinary_admission_before_db_release(self):
    events = self._orchestration()
    self.assertLess(events.index("core"), events.index("final_admission"))
    self.assertLess(events.index("final_admission"), events.index("db_release"))
    self.assertLess(events.index("db_release"), events.index("locks_exit"))
    self.assertNotIn("restore_veto", events)

  def test_final_admission_failure_rearms_veto_inside_physical_lock(self):
    events = self._orchestration(fail="final")
    self.assertLess(events.index("restore_veto"), events.index("locks_exit"))
    self.assertLess(events.index("restore_veto"), events.index("db_release"))

  def test_db_release_failure_rearms_veto_inside_physical_lock(self):
    events = self._orchestration(fail="release")
    self.assertLess(events.index("db_release"), events.index("restore_veto"))
    self.assertLess(events.index("restore_veto"), events.index("locks_exit"))

  def test_actual_repair_faults_retain_flock_and_preserve_original_error(self):
    spec = importlib.util.spec_from_file_location("retained_upgrade_fixture", HERE / "tests/test-hibernate-product-runtime-deployment.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    for fault in ("create", "readback", "file-sync", "directory-sync", "db-sync"):
      with self.subTest(fault=fault):
        case = fixture.Deployment(methodName="runTest")
        case.setUp()
        try:
          expected, _ = case.runtime_only_fixture()
          case.runtime_only_upgrade(expected)
          approval = {**self.approval(), "expected": expected, "reviewed_commit": "b" * 40, "approval_id": case.approval_id}
          db = case.root / N.DB_LOCK
          db.parent.mkdir(parents=True)
          physical = case.root / N.PHYSICAL_LOCK
          physical.parent.mkdir(parents=True)
          physical.write_bytes(b"")
          physical.chmod(0o600)
          events, failures = [], 0
          directory_synced = False
          core = fixture.D
          original_new, original_read, original_sync = core._new_private, core._private_read, os.fsync
          def inject():
            nonlocal failures
            if failures < 2:
              failures += 1
              raise OSError("synthetic repair fault")
          def write(parent, name, raw):
            if fault == "create" and name == core.COMPATIBLE_BARRIER: inject()
            return original_new(parent, name, raw)
          def read(parent, name):
            if fault == "readback" and name == core.COMPATIBLE_BARRIER and directory_synced: inject()
            return original_read(parent, name)
          def sync(fd):
            nonlocal directory_synced
            path = Path(os.readlink("/proc/self/fd/" + str(fd)))
            if ((fault == "file-sync" and path == case.state / core.COMPATIBLE_BARRIER) or
                (fault == "directory-sync" and path == case.state) or
                (fault == "db-sync" and path == db.parent and not db.exists())): inject()
            original_sync(fd)
            if path == case.state: directory_synced = True
          adapter_locks = N._locks
          @contextmanager
          def locks(root):
            try:
              with adapter_locks(root) as release: yield release
            finally:
              events.append("physical_release")
          original_error = ValueError("original upgrade fault")
          engine = SimpleNamespace(PRODUCT=object())
          def pause(seconds):
            self.assertEqual(seconds, 1)
            self.assertNotIn("physical_release", events)
            competitor = os.open(physical, os.O_RDONLY)
            try:
              with self.assertRaises(BlockingIOError): fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(competitor)
            events.append("retained")
          guard_fd = os.open(physical, os.O_RDONLY)
          with patch.object(N, "ROOT", case.root), patch.object(N, "STATE", case.state), \
               patch.object(N, "_installed_approval", return_value=approval), patch.object(N, "_unchanged"), \
               patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
               patch.object(N, "_verified_engines", return_value=(core, object(), engine)), \
               patch.object(N, "_locks", side_effect=locks), \
               patch.object(N, "_guard", return_value=(guard_fd, lambda: None)), \
               patch.object(core, "_upgrade_snapshot", side_effect=original_error) as upgrade, \
               patch.object(core, "_new_private", side_effect=write), patch.object(core, "_private_read", side_effect=read), \
               patch.object(os, "fsync", side_effect=sync), patch.object(N.time, "sleep", side_effect=pause):
            with self.assertRaises(ValueError) as caught: N.native()
          self.assertIs(caught.exception, original_error)
          self.assertEqual(upgrade.call_count, 1)
          self.assertEqual(failures, 2)
          self.assertGreaterEqual(events.count("retained"), 2)
          self.assertEqual(events[-1], "physical_release")
          self.assertFalse(db.exists())
          self.assertTrue((case.state / core.COMPATIBLE_BARRIER).exists())
        finally: case.tearDown()

  def test_prepublication_and_partial_without_completion_have_distinct_proofs(self):
    spec = importlib.util.spec_from_file_location("partial_upgrade_fixture", HERE / "tests/test-hibernate-product-runtime-deployment.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    case = fixture.Deployment(methodName="runTest")
    case.setUp()
    try:
      expected, _ = case.runtime_only_fixture()
      approval = {**self.approval(), "expected": expected, "reviewed_commit": "b" * 40, "approval_id": case.approval_id}
      with patch.object(N, "STATE", case.state):
        N._restore_veto(fixture.D, approval)
        self.assertFalse((case.state / fixture.D.COMPATIBLE_BARRIER).exists())
        config = (case.state / fixture.D.CONFIG).read_bytes()
        (case.state / fixture.D.CONFIG).write_bytes(config + b"\n")
        with self.assertRaisesRegex(ValueError, "old authority changed"):
          N._restore_veto(fixture.D, approval)
        (case.state / fixture.D.CONFIG).write_bytes(config)
        with self.assertRaises(OSError):
          case.runtime_only_upgrade(expected, postcheck=lambda: (_ for _ in ()).throw(OSError("partial")))
        (case.state / ("runtime-upgrade-approval-consumed-" + case.approval_id + ".json")).unlink()
        N._restore_veto(fixture.D, approval)
        self.assertTrue((case.state / fixture.D.COMPATIBLE_BARRIER).exists())
        self.assertFalse((case.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").exists())
    finally: case.tearDown()

  def test_recovery_backoff_interrupt_does_not_escape_unsettled_operation(self):
    operation = Mock(side_effect=[OSError("first fault"), OSError("second fault"), None])
    with patch.object(N.time, "sleep", side_effect=[KeyboardInterrupt(), None, None]) as pause:
      N._retain_recovery(operation)
    self.assertEqual(operation.call_count, 3)
    self.assertEqual(pause.call_count, 3)

  def test_lock_entry_failure_does_not_run_repair_without_exclusion(self):
    engine = SimpleNamespace()
    with patch.object(N, "_installed_approval", return_value=self.approval()), patch.object(N, "_unchanged"), \
         patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_verified_engines", return_value=(object(), object(), engine)), \
         patch.object(N, "_locks", side_effect=ValueError("lock entry failed")), \
         patch.object(N, "_guard", return_value=(9, lambda: None)), patch.object(N.os, "close"), \
         patch.object(N, "_restore_veto") as repair, self.assertRaisesRegex(ValueError, "lock entry"):
      N.native()
    repair.assert_not_called()

  def test_old_engine_lock_api_is_not_required_or_called(self):
    self._orchestration()

  @contextmanager
  def lock_fixture(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      db, physical = root / N.DB_LOCK, root / N.PHYSICAL_LOCK
      db.parent.mkdir(parents=True)
      physical.parent.mkdir(parents=True)
      physical.write_bytes(b"")
      physical.chmod(0o600)
      yield root, db, physical

  def assert_physical_held(self, physical):
    competitor = os.open(physical, os.O_RDONLY)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(competitor)

  def test_adapter_live_lock_gate_refuses_before_opening_lock_paths(self):
    with patch.object(N, "_lock_parent") as parent, self.assertRaisesRegex(ValueError, "fixed installed"):
      with N._locks(Path("/")): self.fail("Live source lock must refuse")
    parent.assert_not_called()

  def test_adapter_locks_are_exclusive_private_and_release_is_idempotent(self):
    with self.lock_fixture() as (root, db, physical):
      with N._locks(root) as release:
        self.assertEqual(db.stat().st_mode & 0o777, 0o600)
        self.assert_physical_held(physical)
        with self.assertRaises(FileExistsError):
          with N._locks(root): self.fail("Second DB acquisition must refuse")
        release(verify_only=True)
        release()
        release()
        self.assertFalse(db.exists())
        self.assert_physical_held(physical)
        release.check_physical()
      with self.assertRaisesRegex(ValueError, "scope ended"): release()
      with self.assertRaisesRegex(ValueError, "scope ended"): release.check_physical()

  def test_adapter_preserves_foreign_db_before_and_after_own_unlink(self):
    with self.lock_fixture() as (root, db, physical):
      with N._locks(root) as release:
        retained = db.with_name("owned-retained")
        db.rename(retained)
        db.write_bytes(b"foreign before unlink")
        db.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Foreign pacman"): release()
        self.assertEqual(db.read_bytes(), b"foreign before unlink")
        db.rename(db.with_name("foreign-before-retained"))
        retained.rename(db)
        release()
        db.write_bytes(b"foreign after unlink")
        db.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Foreign pacman"): release()
        self.assertEqual(db.read_bytes(), b"foreign after unlink")
        db.rename(db.with_name("foreign-after-retained"))
        release()
      self.assertEqual(db.with_name("foreign-before-retained").read_bytes(), b"foreign before unlink")
      self.assertEqual(db.with_name("foreign-after-retained").read_bytes(), b"foreign after unlink")

  def test_adapter_physical_replacement_symlink_permissions_and_ancestry_refuse(self):
    with self.lock_fixture() as (root, db, physical):
      with N._locks(root) as release:
        retained = physical.with_name("physical-retained")
        physical.rename(retained)
        physical.write_bytes(b"foreign physical")
        physical.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "inode changed"): release.check_physical()
        physical.rename(physical.with_name("foreign-physical-retained"))
        retained.rename(physical)
        release()
      physical.chmod(0o644)
      with self.assertRaisesRegex(ValueError, "Private regular"):
        with N._locks(root): self.fail("Loose physical mode must refuse")
      self.assertFalse(db.exists())
      physical.chmod(0o600)
      retained = physical.with_name("physical-real")
      physical.rename(retained)
      physical.symlink_to(retained)
      with self.assertRaises(OSError):
        with N._locks(root): self.fail("Symlink physical lock must refuse")
      self.assertFalse(db.exists())
      db.parent.chmod(0o777)
      with self.assertRaisesRegex(ValueError, "lock ancestry"):
        with N._locks(root): self.fail("Writable ancestry must refuse")
      self.assertFalse(db.exists())

  def test_adapter_context_cleanup_sync_fault_keeps_physical_until_settled(self):
    with self.lock_fixture() as (root, db, physical):
      original_sync, failures = os.fsync, 0
      original_error = ValueError("body failure")
      def sync(fd):
        nonlocal failures
        path = Path(os.readlink("/proc/self/fd/" + str(fd)))
        if path == db.parent and not db.exists() and failures < 2:
          failures += 1
          raise OSError("cleanup directory fsync fault")
        original_sync(fd)
      def pause(seconds):
        self.assertEqual(seconds, 1)
        self.assert_physical_held(physical)
      with patch.object(os, "fsync", side_effect=sync), patch.object(N.time, "sleep", side_effect=pause) as sleep:
        with self.assertRaises(ValueError) as caught:
          with N._locks(root): raise original_error
      self.assertIs(caught.exception, original_error)
      self.assertEqual(failures, 2)
      self.assertEqual(sleep.call_count, 2)
      self.assertFalse(db.exists())


  def test_preserved_foreign_lock_in_recovery_fails_closed_without_spinning(self):
    with patch.object(N.time, "sleep", side_effect=AssertionError("must not retry a preserved foreign lock")):
      events = self._orchestration(fail="preserved")
    self.assertIn("restore_veto", events)
    self.assertLess(events.index("restore_veto"), events.index("locks_exit"))
    operation = Mock(side_effect=N._Preserved("foreign"))
    with patch.object(N.time, "sleep", side_effect=AssertionError("no retry")), self.assertRaises(N._Preserved):
      N._retain_recovery(operation)
    operation.assert_called_once()

  def test_pacman_recreating_lock_after_our_unlink_settles_without_recovery(self):
    with self.lock_fixture() as (root, db, physical):
      original_sync = os.fsync
      def sync(fd):
        original_sync(fd)
        if Path(os.readlink("/proc/self/fd/" + str(fd))) == db.parent and not db.exists():
          db.write_bytes(b"real pacman")
          db.chmod(0o644)
      with patch.object(os, "fsync", side_effect=sync), \
           patch.object(N.time, "sleep", side_effect=AssertionError("must not retry")):
        with N._locks(root) as release:
          release()
          self.assertEqual(db.read_bytes(), b"real pacman")
          self.assert_physical_held(physical)
        self.assertEqual(db.read_bytes(), b"real pacman")
        self.assertEqual(db.stat().st_mode & 0o777, 0o644)
      # mid-settlement retry (fsync fault, then pacman appears) also settles
      db.unlink()
      failures = 0
      def flaky(fd):
        nonlocal failures
        if Path(os.readlink("/proc/self/fd/" + str(fd))) == db.parent and not db.exists() and not failures:
          failures += 1
          db.write_bytes(b"real pacman 2")
          raise OSError("fsync fault")
        original_sync(fd)
      with patch.object(os, "fsync", side_effect=flaky), patch.object(N.time, "sleep", side_effect=lambda seconds: None):
        with N._locks(root) as release:
          with self.assertRaises(OSError): release()
          release()
        self.assertEqual(db.read_bytes(), b"real pacman 2")
        self.assertEqual(failures, 1)

  def test_signal_between_unlink_and_released_flag_settles_on_retry(self):
    with self.lock_fixture() as (root, db, physical):
      real_unlink = os.unlink
      def unlink(*args, **kwargs):
        real_unlink(*args, **kwargs)
        raise KeyboardInterrupt()
      with N._locks(root) as release:
        with patch.object(os, "unlink", side_effect=unlink), self.assertRaises(KeyboardInterrupt): release()
        self.assertFalse(db.exists())
        release()
        release()
      self.assertFalse(db.exists())

  def test_physical_lock_contention_leaves_no_db_lock_and_keeps_original_error(self):
    with self.lock_fixture() as (root, db, physical):
      holder = os.open(physical, os.O_RDONLY)
      try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        with self.assertRaises(BlockingIOError):
          with N._locks(root): self.fail("Contended physical lock must refuse")
        self.assertFalse(db.exists())
        original_sync, failures = os.fsync, 0
        def sync(fd):
          nonlocal failures
          if Path(os.readlink("/proc/self/fd/" + str(fd))) == db.parent and not db.exists() and failures < 2:
            failures += 1
            raise OSError("cleanup fsync fault")
          original_sync(fd)
        with patch.object(os, "fsync", side_effect=sync), self.assertRaises(BlockingIOError):
          with N._locks(root): self.fail("Contended physical lock must refuse")
        self.assertEqual(failures, 2)
        self.assertFalse(db.exists())
        # exhausted cleanup never masks the original error, and is recorded
        failures = -100
        with patch.object(os, "fsync", side_effect=sync), self.assertRaises(BlockingIOError) as caught:
          with N._locks(root): self.fail("Contended physical lock must refuse")
        self.assertTrue(any("lock cleanup failed" in note for note in caught.exception.__notes__))
        self.assertFalse(db.exists())
      finally: os.close(holder)

  def test_every_descriptor_is_closed_even_when_one_close_fails(self):
    for primary in (False, True):
      with self.subTest(primary=primary), self.lock_fixture() as (root, db, physical):
        real_close, closed = os.close, []
        def close(fd):
          try: target = Path(os.readlink("/proc/self/fd/" + str(fd)))
          except OSError: target = None
          real_close(fd)
          closed.append(target)
          if target == physical: raise OSError("close fault")
        original = ValueError("body failure")
        with patch.object(os, "close", side_effect=close):
          try:
            with N._locks(root):
              if primary: raise original
          except (OSError, ValueError) as error: caught = error
        for target in (physical.parent, db.parent):
          self.assertIn(target, closed)
        self.assertNotIn(physical, [Path(os.readlink("/proc/self/fd/" + name)) for name in os.listdir("/proc/self/fd") if os.path.islink("/proc/self/fd/" + name)])
        if primary:
          self.assertIs(caught, original)
          self.assertTrue(any("close fault" in note for note in caught.__notes__))
        else: self.assertRegex(str(caught), "close fault")
        self.assertFalse(db.exists())
        competitor = os.open(physical, os.O_RDONLY)
        try: fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(competitor)

  def test_db_lock_hardlink_wrong_mode_or_owner_refuse_without_deleting(self):
    with self.lock_fixture() as (root, db, physical):
      with N._locks(root) as release:
        link = db.with_name("db-link")
        os.link(db, link)
        with self.assertRaisesRegex(ValueError, "single-link"): release()
        self.assertTrue(db.exists())
        link.unlink()
        db.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "single-link"): release()
        self.assertTrue(db.exists())
        db.chmod(0o600)
        release()
    # ownership: chown is impossible unprivileged, so exercise the real check
    fake = SimpleNamespace(st_mode=0o100600, st_uid=os.geteuid() + 1, st_nlink=1, st_dev=1, st_ino=1, st_gid=0)
    with self.assertRaisesRegex(ValueError, "single-link"): N._lock_identity(fake)

  def test_physical_lock_hardlink_fifo_or_directory_refuse_without_db_lock(self):
    with self.lock_fixture() as (root, db, physical):
      link = physical.with_name("physical-link")
      os.link(physical, link)
      with self.assertRaisesRegex(ValueError, "single-link"):
        with N._locks(root): self.fail("Hardlinked physical lock must refuse")
      self.assertFalse(db.exists())
      link.unlink()
      physical.unlink()
      os.mkfifo(physical, 0o600)
      with self.assertRaisesRegex(ValueError, "Private regular"):
        with N._locks(root): self.fail("FIFO physical lock must refuse")
      self.assertFalse(db.exists())
      physical.unlink()
      physical.mkdir(mode=0o700)
      with self.assertRaisesRegex(ValueError, "Private regular"):
        with N._locks(root): self.fail("Directory physical lock must refuse")
      self.assertFalse(db.exists())


  @contextmanager
  def real_native(self, root, physical, *, upgrade, restore):
    """native() with the REAL adapter _locks on a temp root; everything else is stubbed."""
    core = SimpleNamespace(_upgrade_snapshot=Mock(side_effect=upgrade), _verify_tree=Mock())
    guard_fd = os.open(physical, os.O_RDONLY)  # native() closes it
    with patch.object(N, "ROOT", root), patch.object(N, "_installed_approval", return_value=self.approval()), \
         patch.object(N, "_unchanged"), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_verified_engines", return_value=(core, object(), SimpleNamespace(PRODUCT=object()))), \
         patch.object(N, "_guard", return_value=(guard_fd, lambda: None)), patch.object(N, "_product_check"), \
         patch.object(N, "_postcheck", return_value={}), patch.object(N, "_review", return_value={"files": {}}), \
         patch.object(N, "_private_bytes", return_value=b"review"), patch.object(N, "_load", return_value=object()), \
         patch.object(N, "_restore_veto", side_effect=restore) as veto:
      yield veto

  def fake_clock(self):
    clock = [0.0]
    def sleep(seconds): clock[0] += seconds
    return clock, patch.object(N.time, "sleep", side_effect=sleep), patch.object(N.time, "monotonic", side_effect=lambda: clock[0])

  def test_native_pacman_recreating_lock_after_unlink_completes_without_recovery(self):
    with self.lock_fixture() as (root, db, physical):
      original_sync = os.fsync
      def sync(fd):
        original_sync(fd)
        if Path(os.readlink("/proc/self/fd/" + str(fd))) == db.parent and not db.exists():
          db.write_bytes(b"real pacman")
          db.chmod(0o644)
      upgrade = lambda *args, **kwargs: {"review_sha256": "x" * 64}
      with self.real_native(root, physical, upgrade=upgrade, restore=lambda *args: None) as veto, \
           patch.object(os, "fsync", side_effect=sync), \
           patch.object(N.time, "sleep", side_effect=AssertionError("no retry")):
        self.assertEqual(N.native(), {"review_sha256": "x" * 64, "live_execution": True, "power_operation": False})
      veto.assert_not_called()
      self.assertEqual(db.read_bytes(), b"real pacman")
      self.assertEqual(db.stat().st_mode & 0o777, 0o644)

  def test_foreign_or_altered_db_lock_before_our_unlink_is_preserved_in_recovery(self):
    for variant in ("replaced", "chmod", "hardlink"):
      with self.subTest(variant=variant), self.lock_fixture() as (root, db, physical):
        def restore(*args):
          if variant == "replaced":
            db.rename(db.with_name("ours-retained"))
            db.write_bytes(b"real pacman")
            db.chmod(0o644)
          elif variant == "chmod": db.chmod(0o644)
          else: os.link(db, db.with_name("extra-link"))
        original = ValueError("upgrade fault")
        with self.real_native(root, physical, upgrade=original, restore=restore) as veto, \
             patch.object(N.time, "sleep", side_effect=AssertionError("must not spin")):
          with self.assertRaises(ValueError) as caught: N.native()
        self.assertIs(caught.exception, original)
        self.assertIsInstance(caught.exception.__cause__, N._Preserved)
        veto.assert_called_once()
        self.assertTrue(db.exists())
        if variant == "replaced": self.assertEqual(db.read_bytes(), b"real pacman")
        elif variant == "chmod": self.assertEqual(db.stat().st_mode & 0o777, 0o644)
        else: self.assertEqual(db.stat().st_nlink, 2)
        self.assertTrue(any("may remain and block pacman" in note for note in caught.exception.__notes__))

  def test_deterministic_fault_after_durable_veto_is_bounded_and_fails_closed(self):
    with self.lock_fixture() as (root, db, physical):
      calls = []
      def restore(*args):
        calls.append(1)
        db.parent.chmod(0o777)  # veto established, then a fault retries can never clear
      original = ValueError("upgrade fault")
      clock, sleep, mono = self.fake_clock()
      with self.real_native(root, physical, upgrade=original, restore=restore), sleep as pause, mono:
        with self.assertRaises(ValueError) as caught: N.native()
      self.assertIs(caught.exception, original)
      self.assertIsInstance(caught.exception.__cause__, ValueError)
      self.assertIn(pause.call_count, range(int(N.RECOVERY_BOUND) - 1, int(N.RECOVERY_BOUND) + 3))
      self.assertGreaterEqual(len(calls), int(N.RECOVERY_BOUND) - 1)
      self.assertTrue(any("lock cleanup failed for " + str(db) in note and "may remain and block pacman" in note
                          for note in caught.exception.__notes__))
      self.assertTrue(db.exists())

  def test_same_fault_before_veto_is_durable_keeps_retrying_past_the_bound(self):
    with self.lock_fixture() as (root, db, physical):
      failures = int(N.RECOVERY_BOUND) + 100
      calls = []
      def restore(*args):
        calls.append(1)
        if len(calls) <= failures: raise OSError("veto not yet durable")
      original = ValueError("upgrade fault")
      clock, sleep, mono = self.fake_clock()
      with self.real_native(root, physical, upgrade=original, restore=restore), sleep, mono:
        with self.assertRaises(ValueError) as caught: N.native()
      self.assertIs(caught.exception, original)
      self.assertEqual(len(calls), failures + 1)
      self.assertFalse(db.exists())

  def test_pre_acquisition_cleanup_is_paced_and_interrupt_is_reraised_after_release(self):
    with self.lock_fixture() as (root, db, physical):
      holder = os.open(physical, os.O_RDONLY)
      original_sync, faults = os.fsync, [OSError("a"), OSError("b")]
      def sync(fd):
        if Path(os.readlink("/proc/self/fd/" + str(fd))) == db.parent and not db.exists() and faults: raise faults.pop(0)
        original_sync(fd)
      try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        with patch.object(os, "fsync", side_effect=sync), patch.object(N.time, "sleep") as pause, self.assertRaises(BlockingIOError):
          with N._locks(root): self.fail("Contended physical lock must refuse")
        self.assertEqual([call.args for call in pause.call_args_list], [(0.2,), (0.2,)])
        self.assertFalse(db.exists())
        faults[:] = [KeyboardInterrupt()]
        with patch.object(os, "fsync", side_effect=sync), self.assertRaises(KeyboardInterrupt):
          with N._locks(root): self.fail("Contended physical lock must refuse")
        self.assertFalse(db.exists())
      finally: os.close(holder)


  def test_scope_exit_cleanup_with_permanent_fault_is_bounded_and_keeps_original_error(self):
    with self.lock_fixture() as (root, db, physical):
      original = ValueError("body failure")
      clock, sleep, mono = self.fake_clock()
      with sleep as pause, mono, self.assertRaises(ValueError) as caught:
        with N._locks(root):
          db.parent.chmod(0o777)
          raise original
      self.assertIs(caught.exception, original)
      self.assertGreaterEqual(pause.call_count, int(N.RECOVERY_BOUND) - 1)
      self.assertTrue(any("may remain and block pacman" in note for note in original.__notes__))


  def test_durability_is_per_attempt_so_a_later_failed_veto_is_never_bounded(self):
    with self.lock_fixture() as (root, db, physical):
      mode = db.parent.stat().st_mode & 0o777
      failures, calls = int(N.RECOVERY_BOUND) + 50, []
      def restore(*args):
        calls.append(1)
        if len(calls) == 1: db.parent.chmod(0o777)  # veto verified, but release then fails deterministically
        elif len(calls) <= failures + 1: raise ValueError("Foreign compatible veto must remain untouched")
        else: db.parent.chmod(mode)  # a veto is re-verified and the fault clears
      original = ValueError("upgrade fault")
      clock, sleep, mono = self.fake_clock()
      with self.real_native(root, physical, upgrade=original, restore=restore), sleep, mono:
        with self.assertRaises(ValueError) as caught: N.native()
      self.assertIs(caught.exception, original)
      self.assertEqual(len(calls), failures + 2)
      self.assertFalse(db.exists())

  def test_real_durable_veto_faults_keep_recovery_unbounded_until_it_succeeds(self):
    spec = importlib.util.spec_from_file_location("durable_core", HERE / "hibernate/runtime_deployment.py")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    approval = self.approval()
    expected = approval["expected"]
    intent = {"protocol": "omarchy-t2-runtime-upgrade-intent-v2",
      "transaction_id": "706521e4-998e-4477-b603-31b93144d102", "approval_id": approval["approval_id"],
      "old_review_sha256": expected["old_review"], "new_review_sha256": expected["new_review"],
      "old_config_sha256": expected["old_config"], "new_config_sha256": expected["new_config"]}
    record = {"protocol": "omarchy-t2-runtime-upgrade-completed-v2", "intent": intent,
      "review_sha256": expected["new_review"], "config_sha256": expected["new_config"]}
    real_restore = N._restore_veto
    for fault in ("directory-fsync", "file-fsync", "readback"):
      with self.subTest(fault=fault), self.lock_fixture() as (root, db, physical), tempfile.TemporaryDirectory() as directory:
        state = Path(directory)
        state.chmod(0o700)
        for name, value in (("runtime-upgrade-completed-aaaaaaaaaaaa.json", core._encoded(record)),
                            ("runtime-upgrade-approval-consumed-" + approval["approval_id"] + ".json", core._encoded(intent))):
          (state / name).write_bytes(value)
          (state / name).chmod(0o600)
        barrier = state / core.COMPATIBLE_BARRIER
        failures, attempts = int(N.RECOVERY_BOUND) + 50, []
        original_sync, original_read = os.fsync, core._private_read
        def sync(fd):
          target = Path(os.readlink("/proc/self/fd/" + str(fd)))
          if ((fault == "directory-fsync" and target == state) or (fault == "file-fsync" and target == barrier)) and len(attempts) <= failures:
            raise OSError("durability fault")
          original_sync(fd)
        def read(parent, name):
          raw = original_read(parent, name)
          if fault == "readback" and name == core.COMPATIBLE_BARRIER and len(attempts) <= failures: return raw + b" "
          return raw
        def restore(*args):
          attempts.append(1)
          return real_restore(core, approval)
        original = ValueError("upgrade fault")
        clock, sleep, mono = self.fake_clock()
        with patch.object(N, "STATE", state), patch.object(os, "fsync", side_effect=sync), \
             patch.object(core, "_private_read", side_effect=read), \
             self.real_native(root, physical, upgrade=original, restore=restore), sleep, mono:
          with self.assertRaises(ValueError) as caught: N.native()
        self.assertIs(caught.exception, original)
        self.assertGreater(len(attempts), failures)
        self.assertGreater(clock[0], N.RECOVERY_BOUND)
        self.assertEqual(barrier.read_bytes(), core._encoded(intent))
        self.assertFalse(db.exists())


  # --- pinned staged image-state helper -------------------------------------

  @contextmanager
  def as_root(self, uid=0):
    """Present opened files as owned by `uid` so the real private-bytes reader runs unprivileged."""
    real = os.fstat
    def fake(fd):
      info = real(fd)
      return SimpleNamespace(st_mode=info.st_mode, st_uid=uid, st_nlink=info.st_nlink, st_size=info.st_size)
    with patch.object(N.os, "fstat", side_effect=fake): yield

  def helper_fixture(self):
    """Temp STATE with a staged helper, an old review pinning the parser, and a matching approval."""
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    state = Path(temporary.name)
    source = (HERE / "hibernate/image_state.py").read_bytes()
    parser_sha = digest((HERE / "experiments/audit-hibernation-swap-header.py").read_bytes())
    old = json.dumps({"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True, "reviewed_commit": "e" * 40,
                      "files": {N.PARSER_REL: {"size": 1, "sha256": parser_sha}}}).encode()
    (state / "runtime-deployment-review.json").write_bytes(old)
    (state / "runtime-deployment-review.json").chmod(0o600)
    (state / "runtime-upgrade-image-state.py").write_bytes(source)
    (state / "runtime-upgrade-image-state.py").chmod(0o600)
    approval = self.approval()
    approval["expected"].update(old_review=digest(old), new_image_state=digest(source))
    review = {"files": {N.IMAGE_STATE_REL: {"size": len(source), "sha256": digest(source)}}}
    patches = (patch.object(N, "STATE", state), patch.object(N, "IMAGE_STATE", state / "runtime-upgrade-image-state.py"))
    for item in patches:
      item.start()
      self.addCleanup(item.stop)
    return state, approval, review, source, parser_sha

  def test_helper_is_executed_from_exact_pinned_bytes_with_fixed_identity_and_parser_pin(self):
    state, approval, review, source, parser_sha = self.helper_fixture()
    real_open = os.open
    opened = []
    def spy(path, *args, **kwargs):
      opened.append(str(path))
      return real_open(path, *args, **kwargs)
    with self.as_root(), patch.object(N.os, "open", side_effect=spy):
      module = N._helper_image_state(approval, review)
    self.assertEqual(module.__file__, str(N.IMAGE_STATE))
    self.assertEqual(module.PARSER_PIN, parser_sha)
    self.assertTrue(callable(module.require_no_image))
    self.assertEqual(opened.count(str(state / "runtime-upgrade-image-state.py")), 1)  # read once, never re-opened for exec
    self.assertFalse(any("/runtime/packages" in path for path in opened))

  def test_helper_wrong_pin_review_mode_owner_symlink_hardlink_and_absence_refuse(self):
    state, approval, review, source, _ = self.helper_fixture()
    helper = state / "runtime-upgrade-image-state.py"
    with self.as_root():
      with self.assertRaisesRegex(ValueError, "external approval"):
        N._helper_image_state({**approval, "expected": {**approval["expected"], "new_image_state": "0" * 64}}, review)
      with self.assertRaisesRegex(ValueError, "reviewed new runtime"):
        N._helper_image_state(approval, {"files": {N.IMAGE_STATE_REL: {"size": len(source), "sha256": "0" * 64}}})
      with self.assertRaisesRegex(ValueError, "reviewed new runtime"):
        N._helper_image_state(approval, {"files": {}})
      # Changed bytes fail the approval pin; even a re-pinned approval cannot override the reviewed inventory.
      helper.write_bytes(source + b"\n# altered\n")
      with self.assertRaisesRegex(ValueError, "external approval"):
        N._helper_image_state(approval, review)
      other = {**approval, "expected": {**approval["expected"], "new_image_state": digest(helper.read_bytes())}}
      with self.assertRaisesRegex(ValueError, "reviewed new runtime"):
        N._helper_image_state(other, review)
      helper.write_bytes(source)
      helper.chmod(0o644)
      with self.assertRaisesRegex(ValueError, "Bounded regular owned"): N._helper_image_state(approval, review)
      helper.chmod(0o600)
    with self.as_root(uid=1000), self.assertRaisesRegex(ValueError, "Bounded regular owned"):
      N._helper_image_state(approval, review)
    with self.as_root():
      os.link(helper, state / "second-link")
      with self.assertRaisesRegex(ValueError, "Bounded regular owned"): N._helper_image_state(approval, review)
      (state / "second-link").unlink()
      real = state / "real-helper"
      helper.rename(real)
      helper.symlink_to(real)
      with self.assertRaises(OSError): N._helper_image_state(approval, review)
      helper.unlink()
      with self.assertRaises(FileNotFoundError): N._helper_image_state(approval, review)

  def test_helper_requires_old_review_parser_pin(self):
    state, approval, review, _, _ = self.helper_fixture()
    old = json.dumps({"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True, "reviewed_commit": "e" * 40, "files": {}}).encode()
    (state / "runtime-deployment-review.json").write_bytes(old)
    (state / "runtime-deployment-review.json").chmod(0o600)
    approval["expected"]["old_review"] = digest(old)
    with self.as_root(), self.assertRaisesRegex(ValueError, "parser"):
      N._helper_image_state(approval, review)

  def test_precheck_uses_pinned_helper_and_never_loads_the_installed_image_state(self):
    product, helper = Mock(), Mock()
    product.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore", "production_uki": "/uki"}, {}]
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}
    product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": resume}}}
    with patch.object(N, "_load", side_effect=AssertionError("must not import installed image_state")):
      N._product_check(product, barrier=False, image_state=helper)
    helper.require_no_image.assert_called_once_with(N.ROOT, resume)
    product.check.assert_called_once()

  def test_core_receives_only_its_six_pins(self):
    self.assertEqual(N.HASHES, N.CORE_HASHES | {"new_image_state"})
    approval = self.approval()
    self.assertEqual(set(approval["expected"]), N.HASHES)
    approval["adapter_sha256"] = digest(b"adapter")
    N._parse_approval(json.dumps(approval).encode(), b"adapter")
    del approval["expected"]["new_image_state"]
    with self.assertRaisesRegex(ValueError, "Seven exact"):
      N._parse_approval(json.dumps(approval).encode(), b"adapter")

  # --- old-generation regression ----------------------------------------------

  OLD_COMMIT = "e489bab7"

  def old_generation(self, *, stage_helper=True):
    """Installed tree from the real e489bab7 blobs (no image_state.py) plus a new tree from this checkout."""
    repository = HERE.parents[1]
    try:
      commit = subprocess.run(["git", "-C", str(repository), "rev-parse", "--verify", self.OLD_COMMIT + "^{commit}"],
                              capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError): self.skipTest("e489bab7 history is not available")
    spec = importlib.util.spec_from_file_location("old_generation_core", HERE / "hibernate/runtime_deployment.py")
    D = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(D)
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    base = Path(temporary.name)
    old_src, new_src, root = base / "old", base / "new", base / "root"
    old_src.mkdir()
    archive = subprocess.run(["git", "-C", str(repository), "archive", commit, "packages/t2-suspend/hibernate", "packages/t2-suspend/experiments"],
                             capture_output=True, check=True, timeout=60).stdout
    subprocess.run(["tar", "-x", "-C", str(old_src)], input=archive, check=True, timeout=60)
    self.assertFalse((old_src / D.TREES[0] / "image_state.py").exists())
    for tree in D.TREES:
      shutil.copytree(repository / tree, new_src / tree, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    state = root / D.STATE.relative_to("/")
    state.mkdir(parents=True)
    state.chmod(0o700)
    def write(path, raw):
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(raw)
      path.chmod(0o600)
    old_review = {"protocol": D.SCHEMA, "approved": True, "reviewed_commit": commit, "files": D.inventory(old_src)}
    write(state / D.REVIEW.name, D._encoded(old_review))
    D.deploy_snapshot(old_src, root=root)
    old_bootstrap = (old_src / D.TREES[0] / "runtime_deployment.py").read_bytes()
    write(state / D.BOOTSTRAP, old_bootstrap)
    config = D._encoded({"schema": "omarchy-t2-qualified-product-config-v2",
                         "power_policy": {"schema": "omarchy-t2-attended-battery-policy-v1", "min_charge_percent": 30}})
    write(state / D.CONFIG, config)
    write(state / D.CANDIDATE_CONFIG, config)
    hook = root / D.HOOK
    write(hook, (old_src / D.UPDATE_GUARD_HOOK).read_bytes())
    hook.chmod(0o644)
    new_review = {"protocol": D.SCHEMA, "approved": True, "reviewed_commit": "b" * 40, "files": D.inventory(new_src)}
    new_raw, new_bootstrap = D._encoded(new_review), (new_src / D.TREES[0] / "runtime_deployment.py").read_bytes()
    write(state / D.CANDIDATE_REVIEW, new_raw)
    write(state / D.CANDIDATE_BOOTSTRAP, new_bootstrap)
    helper = (new_src / D.TREES[0] / "image_state.py").read_bytes()
    if stage_helper: write(state / "runtime-upgrade-image-state.py", helper)
    old_raw = (state / D.REVIEW.name).read_bytes()
    approval = {**self.approval(), "source_directory": str(new_src), "reviewed_commit": "b" * 40,
                "approval_id": "306521e4-998e-4477-b603-31b93144d101",
                "expected": {"old_review": digest(old_raw), "old_bootstrap": digest(old_bootstrap), "old_config": digest(config),
                             "new_review": digest(new_raw), "new_bootstrap": digest(new_bootstrap), "new_config": digest(config),
                             "new_image_state": digest(helper)}}
    physical, db = root / N.PHYSICAL_LOCK, root / N.DB_LOCK
    db.parent.mkdir(parents=True)
    write(physical, b"")
    return SimpleNamespace(D=D, root=root, state=state, approval=approval, physical=physical, db=db, old_src=old_src,
                           config=config, old_raw=old_raw, new_review=new_review)

  def run_old_generation(self, case, events):
    """native() with real locks, real core and real helper loading; only host probes are stubbed."""
    D = case.D
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}
    def product():
      item = Mock()
      item.TRIAL._private_json.side_effect = [{"source_directory": "/source", "restore_directory": "/restore", "production_uki": "/uki"}, {}]
      item.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": resume}}}
      return item
    old_product, final_product = product(), product()
    old_product.check.side_effect = lambda *args, **kwargs: events.append("old_admission")
    final_product.check.side_effect = lambda *args, **kwargs: events.append("final_admission")
    real_private, real_helper = N._private_bytes, N._helper_image_state
    def private(path, mode=0o600):
      with self.as_root(): return real_private(path, mode)
    def helper(approval, review):
      module = real_helper(approval, review)
      module.require_no_image = lambda root, target: events.append("helper_no_image") or {}
      return module
    def load(name, path):
      if name == "reviewed_final_product": return final_product
      if name == "reviewed_upgrade_image_state":
        events.append("runtime_image_state:" + str(Path(path).relative_to(case.state)))
        return SimpleNamespace(require_no_image=lambda root, target: events.append("final_no_image"))
      raise AssertionError("Unexpected import " + name)
    def postcheck(core, approval):
      events.append("postcheck")
      self.assertTrue((case.state / D.COMPATIBLE_BARRIER).exists())
      self.assertTrue((case.state / "runtime" / D.TREES[0] / "image_state.py").exists())
    physical = os.open(case.physical, os.O_RDONLY)  # native() closes it
    with patch.object(N, "ROOT", case.root), patch.object(N, "STATE", case.state), \
         patch.object(N, "IMAGE_STATE", case.state / "runtime-upgrade-image-state.py"), \
         patch.object(N, "_installed_approval", return_value=case.approval), patch.object(N, "_unchanged"), \
         patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_verified_engines", return_value=(D, object(), SimpleNamespace(PRODUCT=old_product))), \
         patch.object(N, "_guard", return_value=(physical, lambda: None)), patch.object(N, "_private_bytes", side_effect=private), \
         patch.object(N, "_helper_image_state", side_effect=helper), patch.object(N, "_load", side_effect=load), \
         patch.object(N, "_postcheck", side_effect=postcheck):
      return N.native()

  def test_installed_e489bab7_runtime_upgrades_v2_to_v2_through_pinned_staged_helper(self):
    case = self.old_generation()
    D, events = case.D, []
    result = self.run_old_generation(case, events)
    self.assertEqual(result["review_sha256"], case.approval["expected"]["new_review"])
    # The pre-barrier image check ran on the pinned helper before postcheck, and nothing was
    # imported from the old runtime (which has no image_state.py).
    self.assertEqual(events, ["helper_no_image", "old_admission", "postcheck", "runtime_image_state:runtime/packages/t2-suspend/hibernate/image_state.py",
                              "final_no_image", "final_admission"])
    consumed = case.state / ("runtime-upgrade-approval-consumed-" + case.approval["approval_id"] + ".json")
    completed = json.loads((case.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").read_bytes())
    self.assertEqual(completed["protocol"], "omarchy-t2-runtime-upgrade-completed-v2")
    self.assertEqual(completed["intent"], json.loads(consumed.read_bytes()))
    self.assertFalse((case.state / D.COMPATIBLE_BARRIER).exists())
    self.assertFalse((case.state / D.UPGRADE_PENDING).exists())
    self.assertEqual(D.inventory(case.state / "runtime"), case.new_review["files"])
    self.assertEqual((case.state / D.CONFIG).read_bytes(), case.config)
    self.assertFalse(case.db.exists())
    # Replaying the consumed approval is refused and cannot re-publish.
    before = consumed.read_bytes()
    with self.assertRaises(ValueError): self.run_old_generation(case, [])
    self.assertEqual(consumed.read_bytes(), before)
    self.assertEqual(D.inventory(case.state / "runtime"), case.new_review["files"])

  def test_missing_helper_refuses_before_barrier_with_old_generation_intact(self):
    case = self.old_generation(stage_helper=False)
    D, events = case.D, []
    old_inventory = D.inventory(case.state / "runtime")
    with self.assertRaises(FileNotFoundError): self.run_old_generation(case, events)
    self.assertEqual(events, [])
    self.assertEqual(D.inventory(case.state / "runtime"), old_inventory)
    self.assertFalse((case.state / "runtime" / D.TREES[0] / "image_state.py").exists())
    self.assertEqual((case.state / D.REVIEW.name).read_bytes(), case.old_raw)
    self.assertEqual((case.state / D.CONFIG).read_bytes(), case.config)
    for name in (D.COMPATIBLE_BARRIER, D.UPGRADE_PENDING, "runtime-upgrade-completed-bbbbbbbbbbbb.json",
                 "runtime-upgrade-approval-consumed-" + case.approval["approval_id"] + ".json"):
      self.assertFalse((case.state / name).exists(), name)
    self.assertFalse(case.db.exists())

  def test_helper_mismatch_with_approval_refuses_before_barrier_with_old_generation_intact(self):
    case = self.old_generation()
    D = case.D
    case.approval["expected"]["new_image_state"] = "0" * 64
    with self.assertRaisesRegex(ValueError, "external approval"): self.run_old_generation(case, [])
    self.assertFalse((case.state / D.COMPATIBLE_BARRIER).exists())
    self.assertEqual((case.state / D.REVIEW.name).read_bytes(), case.old_raw)


if __name__ == "__main__": unittest.main()
