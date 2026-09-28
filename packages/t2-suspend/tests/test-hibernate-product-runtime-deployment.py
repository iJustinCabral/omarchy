#!/usr/bin/python3
"""Snapshot deployment uses tempdirs only; no live deployment or power commands."""
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("runtime_deployment", REPO / "packages/t2-suspend/hibernate/runtime_deployment.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


class Deployment(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.base = Path(self.temp.name)
    self.root = self.base / "root"
    self.state = self.root / D.STATE.relative_to("/")
    self.state.mkdir(parents=True, mode=0o700)
    self.source = self.base / "source"
    for tree in D.TREES:
      (self.source / tree).mkdir(parents=True)
    self.code = self.source / D.ENTRYPOINT
    self.code.write_text("raise RuntimeError('Source must never execute')\n")
    (self.source / D.TREES[1] / "dependency.py").write_text("VALUE = 1\n")
    hook = self.source / D.TREES[1] / "protocol/hooks/resume"
    hook.parent.mkdir(parents=True)
    hook.write_text("preserved source hook\n")
    self.review = {"protocol": D.SCHEMA, "approved": True, "reviewed_commit": "a" * 40, "files": D.inventory(self.source)}
    self.review_file = self.state / D.REVIEW.name
    self.write_review()

  def tearDown(self): self.temp.cleanup()

  def write_review(self):
    self.review_file.write_text(json.dumps(self.review))
    self.review_file.chmod(0o600)

  def deploy(self): return D.deploy_snapshot(self.source, root=self.root)

  def test_exact_private_snapshot_preserves_layout_and_never_executes_source(self):
    receipt = self.deploy()
    runtime = self.state / "runtime"
    self.assertEqual(receipt["files"], self.review["files"])
    self.assertEqual(D.inventory(runtime), D.inventory(self.source))
    self.assertEqual((runtime / D.ENTRYPOINT).read_bytes(), self.code.read_bytes())
    self.assertEqual(json.loads((runtime / D.MANIFEST).read_bytes()), receipt)
    self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
    for file in runtime.rglob("*"):
      self.assertEqual(file.stat().st_uid, os.geteuid())
      self.assertEqual(file.stat().st_mode & 0o777, 0o700 if file.is_dir() else 0o600)
    with self.assertRaises(ValueError): self.deploy()

  def test_no_approval_wrong_hash_or_omitted_resource_refused_before_staging(self):
    for modify in (lambda review: review.update(approved=False),
                   lambda review: review["files"][D.ENTRYPOINT].update(sha256="0" * 64),
                   lambda review: review["files"].pop(next(name for name in review["files"] if name.endswith("/resume")))):
      original = copy.deepcopy(self.review)
      modify(self.review)
      self.write_review()
      with self.assertRaises(ValueError): self.deploy()
      self.assertFalse((self.state / D.PENDING).exists())
      self.review = original

  def test_source_and_authority_symlinks_and_unsafe_review_mode_refused(self):
    self.review_file.chmod(0o644)
    with self.assertRaises(ValueError): self.deploy()
    self.review_file.chmod(0o600)
    original = self.code.read_bytes()
    self.code.unlink()
    outside = self.base / "foreign.py"
    outside.write_bytes(original)
    self.code.symlink_to(outside)
    with self.assertRaises(OSError): self.deploy()

  def test_non_source_unlock_assets_cannot_enter_inventory(self):
    forbidden = self.source / D.TREES[0] / "cryptroot.key"
    forbidden.write_bytes(b"never copy unlock assets")
    with self.assertRaises(ValueError): D.inventory(self.source)
    self.assertFalse((self.state / "runtime").exists())

  def test_only_exact_update_guard_hook_template_enters_reviewed_snapshot(self):
    hook = self.source / D.UPDATE_GUARD_HOOK
    raw = b"[Action]\nWhen = PreTransaction\nAbortOnFail\n"
    hook.write_bytes(raw)
    files = D.inventory(self.source)
    self.assertEqual(files[D.UPDATE_GUARD_HOOK], {"size": len(raw), "sha256": D.hashlib.sha256(raw).hexdigest()})
    self.review["files"] = files
    self.write_review()
    receipt = self.deploy()
    installed = self.state / "runtime" / D.UPDATE_GUARD_HOOK
    self.assertEqual(installed.read_bytes(), raw)
    self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
    self.assertEqual(receipt["files"][D.UPDATE_GUARD_HOOK], files[D.UPDATE_GUARD_HOOK])

  def test_other_hook_locations_extensions_and_assets_remain_refused(self):
    for name in (D.TREES[0] + "/other.hook", D.TREES[1] + "/00-omarchy-t2-hibernate-guard.hook",
                 D.TREES[0] + "/nested/00-omarchy-t2-hibernate-guard.hook", D.TREES[0] + "/asset.png"):
      with self.subTest(name=name):
        with self.assertRaises(ValueError): D._source_name(name)

  def test_changed_source_during_copy_leaves_preserved_partial_blocker(self):
    original = D._source_fd
    def change(source, name):
      if (self.state / D.PENDING).exists() and name == D.ENTRYPOINT:
        self.code.write_text("changed source\n")
      return original(source, name)
    with patch.object(D, "_source_fd", side_effect=change):
      with self.assertRaises(ValueError): self.deploy()
    self.assertTrue((self.state / D.PENDING).exists())
    self.assertFalse((self.state / "runtime").exists())
    with self.assertRaises(ValueError): self.deploy()

  def test_fsync_failure_cannot_publish_runtime(self):
    with patch.object(D.os, "fsync", side_effect=OSError("synthetic storage fault")):
      with self.assertRaises(OSError): self.deploy()
    self.assertTrue((self.state / D.PENDING).exists())
    self.assertFalse((self.state / "runtime").exists())

  def test_concurrent_deployer_refused(self):
    lock = os.open(self.state / "runtime-deployment.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
      fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with self.assertRaises(BlockingIOError): self.deploy()
    finally: os.close(lock)

  def test_actual_source_transitive_imports_and_resources_survive_snapshot(self):
    self.source = REPO
    self.review["files"] = D.inventory(REPO)
    self.write_review()
    receipt = self.deploy()
    runtime = self.state / "runtime"
    script = "import importlib.util, pathlib; p=pathlib.Path(" + repr(str(runtime / D.ENTRYPOINT)) + "); s=importlib.util.spec_from_file_location('snapshot',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.ARTIFACTS.AUDIT.RESTORE_MARKER_HOOK_SOURCE.is_file(); assert m.ARTIFACTS.SOURCE.CONFIG.is_file(); print('transitive-imports-pass')"
    result = subprocess.run(("/usr/bin/python3", "-B", "-c", script), capture_output=True, text=True, timeout=30)
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "transitive-imports-pass")
    self.assertGreater(len(receipt["files"]), 180)
    self.assertTrue(D.UPDATE_GUARD_HOOK in receipt["files"], "Actual reviewed inventory must include the exact update guard hook")
    self.assertEqual((runtime / D.UPDATE_GUARD_HOOK).read_bytes(), (REPO / D.UPDATE_GUARD_HOOK).read_bytes())

  def upgrade_fixture(self):
    old_bootstrap = b"old reviewed bootstrap\n"
    runtime_bootstrap = self.source / D.TREES[0] / "runtime_deployment.py"
    runtime_bootstrap.write_bytes(old_bootstrap)
    hook = self.source / D.UPDATE_GUARD_HOOK
    hook.write_bytes(b"[Action]\nWhen = PreTransaction\nAbortOnFail\n")
    self.review["files"] = D.inventory(self.source)
    self.write_review()
    self.deploy()
    old_review = self.review_file.read_bytes()
    old_config = {"schema": "omarchy-t2-qualified-product-config-v1", "manifest": {"pinned": True}}
    old_config_raw = D._encoded(old_config)
    (self.state / D.CONFIG).write_bytes(old_config_raw)
    (self.state / D.CONFIG).chmod(0o600)
    (self.state / D.BOOTSTRAP).write_bytes(old_bootstrap)
    (self.state / D.BOOTSTRAP).chmod(0o600)
    installed_hook = self.root / D.HOOK
    installed_hook.parent.mkdir(parents=True, exist_ok=True)
    installed_hook.write_bytes(hook.read_bytes())
    installed_hook.chmod(0o644)
    opt_in = self.root / "etc/omarchy/t2-hibernate-product.enabled"
    opt_in.parent.mkdir(parents=True, exist_ok=True)
    opt_in.write_bytes(b"")
    opt_in.chmod(0o644)
    (self.state / "boot-policy.json").write_bytes(b"existing active policy bytes")
    (self.state / "boot-policy.json").chmod(0o600)
    efi = self.root / "sys/firmware/efi/efivars/existing-boot-variable"
    efi.parent.mkdir(parents=True, exist_ok=True)
    efi.write_bytes(b"unchanged EFI bytes")
    self.code.write_text("raise RuntimeError('New source must never execute')\n")
    new_bootstrap = b"new reviewed bootstrap\n"
    runtime_bootstrap.write_bytes(new_bootstrap)
    new_review = {"protocol": D.SCHEMA, "approved": True, "reviewed_commit": "b" * 40, "files": D.inventory(self.source)}
    new_review_raw = D._encoded(new_review)
    new_config = {**old_config, "schema": "omarchy-t2-qualified-product-config-v2",
                  "power_policy": {"schema": "omarchy-t2-attended-battery-policy-v1", "min_charge_percent": 30}}
    new_config_raw = D._encoded(new_config)
    for name, raw in ((D.CANDIDATE_REVIEW, new_review_raw), (D.CANDIDATE_BOOTSTRAP, new_bootstrap),
                      (D.CANDIDATE_CONFIG, new_config_raw)):
      (self.state / name).write_bytes(raw)
      (self.state / name).chmod(0o600)
    def digest(raw): return D.hashlib.sha256(raw).hexdigest()
    expected = {"old_review": digest(old_review), "old_bootstrap": digest(old_bootstrap), "old_config": digest(old_config_raw),
                "new_review": digest(new_review_raw), "new_bootstrap": digest(new_bootstrap), "new_config": digest(new_config_raw)}
    return expected, old_review, old_bootstrap, old_config_raw, new_review_raw, new_bootstrap, new_config_raw

  def test_upgrade_preserves_old_authority_and_blocks_existing_sleep_entry_until_verified(self):
    expected, old_review, old_bootstrap, old_config, new_review, new_bootstrap, new_config = self.upgrade_fixture()
    sleep_spec = importlib.util.spec_from_file_location("upgrade_sleep_entry", REPO / "packages/t2-suspend/hibernate/sleep_entry.py")
    sleep = importlib.util.module_from_spec(sleep_spec)
    sleep_spec.loader.exec_module(sleep)
    events = []
    def guard(): events.append("guard")
    def precheck():
      events.append("precheck")
      self.assertEqual((self.state / D.CONFIG).read_bytes(), old_config)
    def postcheck():
      events.append("postcheck")
      with self.assertRaisesRegex(ValueError, "Incomplete source-default transition"):
        sleep.reject_pending(self.root)
      self.assertEqual((self.state / D.CONFIG).read_bytes(), new_config)
      self.assertEqual((self.state / D.REVIEW.name).read_bytes(), new_review)
      self.assertEqual((self.state / D.BOOTSTRAP).read_bytes(), new_bootstrap)
      self.assertEqual(D.inventory(self.state / "runtime"), D.inventory(self.source))
    result = D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=guard,
                                precheck=precheck, postcheck=postcheck)
    self.assertEqual(events[0:2], ["guard", "guard"])
    self.assertEqual(events.count("precheck"), 1)
    self.assertEqual(events.count("postcheck"), 1)
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())
    self.assertFalse((self.state / D.UPGRADE_PENDING).exists())
    self.assertEqual(result["review_sha256"], expected["new_review"])
    self.assertEqual((self.state / "runtime-retained-aaaaaaaaaaaa-before-bbbbbbbbbbbb" / D.ENTRYPOINT).read_bytes(), b"raise RuntimeError('Source must never execute')\n")
    self.assertEqual((self.state / "runtime-review-retained-aaaaaaaaaaaa-before-bbbbbbbbbbbb.json").read_bytes(), old_review)
    self.assertEqual((self.state / "runtime-bootstrap-retained-aaaaaaaaaaaa-before-bbbbbbbbbbbb.py").read_bytes(), old_bootstrap)
    self.assertEqual((self.state / "config-retained-aaaaaaaaaaaa-before-bbbbbbbbbbbb.json").read_bytes(), old_config)
    self.assertEqual((self.state / D.CONFIG).read_bytes(), new_config)
    self.assertTrue((self.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").is_file())
    self.assertEqual((self.state / "boot-policy.json").read_bytes(), b"existing active policy bytes")
    self.assertEqual((self.root / "etc/omarchy/t2-hibernate-product.enabled").read_bytes(), b"")
    self.assertEqual((self.root / "sys/firmware/efi/efivars/existing-boot-variable").read_bytes(), b"unchanged EFI bytes")
    completed = json.loads((self.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").read_bytes())
    self.assertEqual(completed["intent"]["new_review_sha256"], expected["new_review"])

  def test_upgrade_partial_config_publication_keeps_compatible_admission_barrier(self):
    expected, *_ = self.upgrade_fixture()
    original = D._new_private
    def fail_config(parent, name, raw):
      if name == D.CONFIG: raise OSError("Synthetic interruption before new config publication")
      return original(parent, name, raw)
    with patch.object(D, "_new_private", side_effect=fail_config):
      with self.assertRaises(OSError):
        D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                           precheck=lambda: None, postcheck=lambda: self.fail("Must not postcheck partial upgrade"))
    self.assertTrue((self.state / D.COMPATIBLE_BARRIER).is_file())
    self.assertTrue((self.state / D.UPGRADE_PENDING).is_file())
    self.assertFalse((self.state / D.CONFIG).exists())
    with self.assertRaises(ValueError):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)

  def test_upgrade_existing_barrier_and_wrong_new_config_refuse_without_renames(self):
    expected, *_ = self.upgrade_fixture()
    (self.state / D.COMPATIBLE_BARRIER).write_bytes(b"foreign pending transition")
    with self.assertRaises(ValueError):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)
    self.assertTrue((self.state / "runtime").is_dir())
    (self.state / D.COMPATIBLE_BARRIER).unlink()
    candidate = self.state / D.CANDIDATE_CONFIG
    config = json.loads(candidate.read_bytes())
    config["manifest"] = {"changed": True}
    raw = D._encoded(config)
    candidate.write_bytes(raw)
    expected["new_config"] = D.hashlib.sha256(raw).hexdigest()
    with self.assertRaisesRegex(ValueError, "non-policy"):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)
    self.assertTrue((self.state / "runtime").is_dir())

  def test_upgrade_reviewed_bootstrap_hook_and_live_root_boundaries(self):
    expected, *_ = self.upgrade_fixture()
    with self.assertRaisesRegex(ValueError, "refuses live root"):
      D.upgrade_snapshot(self.source, root=Path("/"), expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)
    candidate = self.state / D.CANDIDATE_BOOTSTRAP
    candidate.write_bytes(b"unreviewed bootstrap")
    expected["new_bootstrap"] = D.hashlib.sha256(candidate.read_bytes()).hexdigest()
    with self.assertRaisesRegex(ValueError, "Authority bytes differ"):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)
    candidate.write_bytes(b"new reviewed bootstrap\n")
    expected["new_bootstrap"] = D.hashlib.sha256(candidate.read_bytes()).hexdigest()
    hook = self.root / D.HOOK
    hook.write_bytes(b"unreviewed hook")
    with self.assertRaisesRegex(ValueError, "Authority bytes differ"):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)
    self.assertTrue((self.state / "runtime").is_dir())
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())

  def test_upgrade_guard_loss_and_postcheck_fault_keep_compatible_veto(self):
    for fail_at, runtime_present in ((1, True), (4, True), (6, False), (100, True)):
      with self.subTest(fail_at=fail_at):
        case = Deployment(methodName="runTest")
        case.setUp()
        try:
          expected, *_ = case.upgrade_fixture()
          calls = 0
          def guard():
            nonlocal calls
            calls += 1
            if calls == fail_at: raise ValueError("Guard lost")
          def postcheck():
            if fail_at == 100: raise ValueError("Postcheck refuses partial authority")
          with self.assertRaises(ValueError):
            D.upgrade_snapshot(case.source, root=case.root, expected=expected, guard=guard,
                               precheck=lambda: None, postcheck=postcheck)
          self.assertEqual((case.state / "runtime").is_dir(), runtime_present)
          if fail_at == 100:
            self.assertEqual((case.state / "runtime" / D.ENTRYPOINT).read_bytes(), case.code.read_bytes())
          if fail_at > 2:
            self.assertTrue((case.state / D.COMPATIBLE_BARRIER).is_file())
          if fail_at > 4:
            self.assertTrue((case.state / D.UPGRADE_PENDING).is_file())
          self.assertEqual((case.state / "boot-policy.json").read_bytes(), b"existing active policy bytes")
          self.assertEqual((case.root / "etc/omarchy/t2-hibernate-product.enabled").read_bytes(), b"")
        finally: case.tearDown()

  def test_upgrade_publication_faults_preserve_compatible_veto_and_no_retry(self):
    for name in ("runtime", "retain-review", "retain-bootstrap", "retain-config", "publish-runtime",
                 D.REVIEW.name, D.BOOTSTRAP, D.CONFIG, "completed"):
      with self.subTest(name=name):
        case = Deployment(methodName="runTest")
        case.setUp()
        try:
          expected, *_ = case.upgrade_fixture()
          original_new = D._new_private
          original_rename = D.os.rename
          def faulty_new(parent, target, raw):
            if target == name or (name == "completed" and target.startswith("runtime-upgrade-completed-")):
              raise OSError("Injected publication failure")
            return original_new(parent, target, raw)
          def faulty_rename(source, target, *args, **kwargs):
            if name == "runtime" and source == "runtime": raise OSError("Injected retention failure")
            if name == "retain-review" and source == D.REVIEW.name: raise OSError("Injected review retention failure")
            if name == "retain-bootstrap" and source == D.BOOTSTRAP: raise OSError("Injected bootstrap retention failure")
            if name == "retain-config" and source == D.CONFIG: raise OSError("Injected config retention failure")
            if name == "publish-runtime" and source == D.PENDING and target == "runtime": raise OSError("Injected runtime publication failure")
            return original_rename(source, target, *args, **kwargs)
          with patch.object(D, "_new_private", side_effect=faulty_new), patch.object(D.os, "rename", side_effect=faulty_rename):
            with self.assertRaises(OSError):
              D.upgrade_snapshot(case.source, root=case.root, expected=expected, guard=lambda: None,
                                 precheck=lambda: None, postcheck=lambda: None)
          self.assertTrue((case.state / D.COMPATIBLE_BARRIER).is_file())
          self.assertTrue((case.state / D.UPGRADE_PENDING).is_file())
          with self.assertRaises(ValueError):
            D.upgrade_snapshot(case.source, root=case.root, expected=expected, guard=lambda: None,
                               precheck=lambda: None, postcheck=lambda: None)
        finally: case.tearDown()

  def test_upgrade_interruption_after_intent_retirement_keeps_compatible_veto(self):
    expected, *_ = self.upgrade_fixture()
    original_unlink = D.os.unlink
    def fail_after_intent_removal(name, *args, **kwargs):
      result = original_unlink(name, *args, **kwargs)
      if name == D.UPGRADE_PENDING: raise OSError("Interrupted after intent retirement")
      return result
    with patch.object(D.os, "unlink", side_effect=fail_after_intent_removal):
      with self.assertRaises(OSError):
        D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                           precheck=lambda: None, postcheck=lambda: None)
    self.assertFalse((self.state / D.UPGRADE_PENDING).exists())
    self.assertTrue((self.state / D.COMPATIBLE_BARRIER).is_file())
    self.assertTrue((self.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").is_file())
    with self.assertRaises(ValueError):
      D.upgrade_snapshot(self.source, root=self.root, expected=expected, guard=lambda: None,
                         precheck=lambda: None, postcheck=lambda: None)

  def runtime_only_fixture(self):
    expected, _, _, _, _, _, config = self.upgrade_fixture()
    (self.state / D.CONFIG).write_bytes(config)
    expected["old_config"] = expected["new_config"]
    self.approval_id = "306521e4-998e-4477-b603-31b93144d101"
    # Evidence from a consumed historical deployment remains untouched.
    self.historical = self.state / "runtime-upgrade-completed-cccccccccccc.json"
    self.historical.write_bytes(b"consumed v1-to-v2 evidence")
    self.historical.chmod(0o600)
    return expected, config

  def runtime_only_upgrade(self, expected, **kwargs):
    return D.upgrade_snapshot(self.source, root=self.root, expected=expected,
      approval_id=self.approval_id, guard=lambda: None, precheck=lambda: None,
      postcheck=kwargs.get("postcheck", lambda: None))

  def test_v2_runtime_upgrade_preserves_exact_config_and_consumes_fresh_approval(self):
    expected, config = self.runtime_only_fixture()
    self.runtime_only_upgrade(expected)
    self.assertEqual((self.state / D.CONFIG).read_bytes(), config)
    self.assertEqual((self.state / "config-retained-aaaaaaaaaaaa-before-bbbbbbbbbbbb.json").read_bytes(), config)
    self.assertEqual(self.historical.read_bytes(), b"consumed v1-to-v2 evidence")
    consumed = (self.state / ("runtime-upgrade-approval-consumed-" + self.approval_id + ".json")).read_bytes()
    completed = json.loads((self.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").read_bytes())
    self.assertEqual(completed["protocol"], "omarchy-t2-runtime-upgrade-completed-v2")
    self.assertEqual(completed["intent"], json.loads(consumed))
    self.assertEqual(completed["intent"]["approval_id"], self.approval_id)
    self.assertNotEqual(completed["intent"]["transaction_id"], self.approval_id)
    self.assertEqual(completed["intent"]["old_config_sha256"], completed["intent"]["new_config_sha256"])
    with self.assertRaises(ValueError): self.runtime_only_upgrade(expected)

  def test_v2_config_mutation_and_equivalent_reencoding_refuse_before_barrier(self):
    expected, config = self.runtime_only_fixture()
    for changed in (config + b"\n", config.replace(b'"min_charge_percent":30', b'"min_charge_percent":40')):
      with self.subTest(changed=changed):
        (self.state / D.CANDIDATE_CONFIG).write_bytes(changed)
        expected["new_config"] = D.hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError, "exact configuration bytes"):
          self.runtime_only_upgrade(expected)
        self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())
        self.assertEqual((self.state / D.CONFIG).read_bytes(), config)

  def test_v2_missing_reused_and_malformed_approval_refuse_before_retention(self):
    expected, _ = self.runtime_only_fixture()
    for identity in (None, "not-an-id", "306521e4-998e-1477-b603-31b93144d101"):
      with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "UUID4"):
        D.upgrade_snapshot(self.source, root=self.root, expected=expected, approval_id=identity,
          guard=lambda: None, precheck=lambda: None, postcheck=lambda: None)
    consumed = self.state / ("runtime-upgrade-approval-consumed-" + self.approval_id + ".json")
    consumed.write_bytes(b"already consumed")
    consumed.chmod(0o600)
    with self.assertRaisesRegex(ValueError, "automatic retry"):
      self.runtime_only_upgrade(expected)
    self.assertEqual(consumed.read_bytes(), b"already consumed")
    self.assertTrue((self.state / "runtime").is_dir())
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())

  def test_v2_maintenance_marker_vetoes_even_with_unaware_old_consumers(self):
    expected, _ = self.runtime_only_fixture()
    marker = self.state / D.MAINTENANCE_PENDING
    marker.write_bytes(b"original maintenance intent")
    with self.assertRaisesRegex(ValueError, "automatic retry"):
      self.runtime_only_upgrade(expected, postcheck=lambda: self.fail("Must not admit maintenance"))
    self.assertEqual(marker.read_bytes(), b"original maintenance intent")
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())

  def test_v2_consumption_fault_and_postcheck_fault_keep_veto_without_replay(self):
    for fault in ("consume", "postcheck"):
      with self.subTest(fault=fault):
        case = Deployment(methodName="runTest")
        case.setUp()
        try:
          expected, _ = case.runtime_only_fixture()
          original = D._new_private
          def write(parent, name, raw):
            if fault == "consume" and name.startswith("runtime-upgrade-approval-consumed-"):
              raise OSError("consumption fault")
            return original(parent, name, raw)
          def postcheck(): raise OSError("postcheck fault")
          with patch.object(D, "_new_private", side_effect=write), self.assertRaises(OSError):
            case.runtime_only_upgrade(expected, postcheck=postcheck)
          self.assertTrue((case.state / D.COMPATIBLE_BARRIER).exists())
          self.assertTrue((case.state / D.UPGRADE_PENDING).exists())
          self.assertEqual(case.historical.read_bytes(), b"consumed v1-to-v2 evidence")
          with self.assertRaises(ValueError): case.runtime_only_upgrade(expected)
        finally: case.tearDown()


if __name__ == "__main__": unittest.main()
