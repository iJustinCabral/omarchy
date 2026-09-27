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


if __name__ == "__main__": unittest.main()
