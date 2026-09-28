"""Offline contract tests; no inhibitor, package lock, EFI or power operation."""
import hashlib
import importlib.util
import json
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
    with self.assertRaisesRegex(ValueError, "Six exact"):
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
        with self.assertRaisesRegex(ValueError, "invalid intent"):
          N._restore_veto(core, foreign)
        (state / core.COMPATIBLE_BARRIER).write_bytes(b"foreign veto")
        with self.assertRaisesRegex(ValueError, "Foreign compatible"):
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
    def release_db(*, verify_only=False):
      events.append("db_verify" if verify_only else "db_release")
      if fail == "release" and not verify_only: raise ValueError("db release failed")
    @contextmanager
    def locks(root):
      events.append("locks_enter")
      try: yield release_db
      finally: events.append("locks_exit")
    engine = SimpleNamespace(_locks=locks, PRODUCT=product)
    def product_check(*args, barrier):
      events.append("old_admission" if args[0] is product else "final_admission")
      if fail == "final" and args[0] is not product: raise ValueError("final admission failed")
    def restore(*args):
      events.append("restore_veto")
      self.assertNotIn("locks_exit", events)
    with patch.object(N, "_installed_approval", return_value=approval), patch.object(N, "_unchanged"), \
         patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_verified_engines", return_value=(core, object(), engine)), \
         patch.object(N, "_guard", return_value=(9, lambda: events.append("guard"))), \
         patch.object(N, "_product_check", side_effect=product_check), \
         patch.object(N, "_postcheck", return_value={}), patch.object(N, "_review", return_value={"files": {}}), \
         patch.object(N, "_private_bytes", return_value=b"review"), patch.object(N, "_load", return_value=object()), \
         patch.object(N, "_restore_veto", side_effect=restore), patch.object(N.os, "close"):
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
    self.assertNotIn("db_release", events)

  def test_db_release_failure_rearms_veto_inside_physical_lock(self):
    events = self._orchestration(fail="release")
    self.assertLess(events.index("db_release"), events.index("restore_veto"))
    self.assertLess(events.index("restore_veto"), events.index("locks_exit"))


if __name__ == "__main__": unittest.main()
