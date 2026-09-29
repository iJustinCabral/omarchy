#!/usr/bin/python3
"""Offline guard-only artifact and closed protocol rejection fixtures."""
import copy
import importlib.util
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent / "experiments"
spec = importlib.util.spec_from_file_location("restore_image_fixtures", HERE / "test-cold-pre-cpu-uki.py")
images = importlib.util.module_from_spec(spec)
spec.loader.exec_module(images)
builder, auditor = images.builder, images.auditor
R = auditor.RESTORE


class RestoreToolingTests(unittest.TestCase):
  def setUp(self):
    images.ColdPreCpuImageTests.setUp(self)
    self.guard = self.root / "guard.ko"
    self.guard.write_bytes(b"offline synthetic corrected guard")
    self.guard.chmod(0o600)
    self.guard_identity = {"sha256": R.GUARD_SHA256, "srcversion": R.GUARD_SRCVERSION,
                           "vermagic": self.identity["vermagic"]}

  def metadata(self, command, **kwargs):
    return SimpleNamespace(stdout={"name": R.PROFILE["guard_module"], **self.guard_identity}[command[2]] + "\n")

  def hash(self, path):
    # Synthetic module alone stands in for the exact protected real guard.
    if path.name == "guard.ko" and path.read_bytes() == self.guard.read_bytes():
      return R.GUARD_SHA256
    return self.real_hash(path)

  def prepare(self, **changes):
    args = {"work": self.root, "guard": self.guard, "guard_sha256": R.GUARD_SHA256,
            "guard_srcversion": R.GUARD_SRCVERSION, "helper": self.helper,
            "helper_sha256": builder.digest(self.helper), "release": self.release, "restore_marker": self.marker}
    args.update(changes)
    self.real_hash = builder.digest
    with mock.patch.object(builder, "validate_cold_private_file"), mock.patch.object(builder, "module_metadata", return_value=self.guard_identity), mock.patch.object(builder, "run", side_effect=self.metadata), mock.patch.object(builder, "digest", side_effect=self.hash):
      return builder.prepare_cold_pci_restore(**args)

  def tree(self):
    prepared = self.prepare()
    tree = self.root / "restore-extracted"
    directory = tree / R.PROFILE["directory"]
    directory.mkdir(parents=True)
    for path in prepared["bundle"].iterdir():
      shutil.copyfile(path, directory / path.name)
      (directory / path.name).chmod(path.stat().st_mode & 0o777)
    (tree / "hooks").mkdir()
    for hook in R.hooks(R.KEY):
      shutil.copyfile(R.PROFILE["source"] / "hooks" / hook, tree / "hooks" / hook)
    hook = R.PROFILE["hook"]
    (tree / "config").write_text('HOOKS="udev encrypt ' + hook + ' omarchy-t2-restore-marker resume ' + hook + '-stop"\n'
                                 'EARLYHOOKS="udev"\nLATEHOOKS="omarchy-t2-candidate-modules"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS=""\n')
    return tree, {R.KEY: prepared["provenance"], "kernel_release": self.release,
                  "experiment_id": R.PROFILE["version"],
                  "restore_marker": {"version": "v2", "efi_variable": R.RESTORE_VARIABLE}}

  def verify(self, tree, report):
    self.real_hash = R.sha256
    with mock.patch.object(R, "sha256", side_effect=self.hash), mock.patch.object(R.subprocess, "run", side_effect=self.metadata):
      auditor.verify_cold_pre_cpu_tree(tree, report)

  def test_closed_guard_only_profile_preserves_historical_sources(self):
    for key in builder.PCI.PROFILES:
      self.assertEqual(builder.RESTORE.sources(key), builder.PCI.sources(key))
    tree, report = self.tree()
    self.verify(tree, report)
    self.assertEqual(R.select(report), R.KEY)
    self.assertEqual(set(path.name for path in (tree / R.PROFILE["directory"]).iterdir()), set(R.BUNDLE_FILES))
    self.assertNotIn("guard_observations", report[R.KEY])
    self.assertNotIn("module_sha256", report[R.KEY])
    missing = copy.deepcopy(report)
    missing.pop(R.KEY)
    with self.assertRaisesRegex(ValueError, "lacks its protocol metadata"):
      R.select(missing)

  def test_builder_extracted_verification_forwards_v2_marker(self):
    tree, report = self.tree()
    # The builder reloads the independent auditor. Keep its real verifier and
    # inject only the synthetic-module fixture into this otherwise real path.
    loader = SimpleNamespace(exec_module=lambda module: None)
    with mock.patch.object(builder.importlib.util, "spec_from_file_location", return_value=SimpleNamespace(loader=loader)), mock.patch.object(builder.importlib.util, "module_from_spec", return_value=auditor):
      self.real_hash = R.sha256
      with mock.patch.object(R, "sha256", side_effect=self.hash), mock.patch.object(R.subprocess, "run", side_effect=self.metadata):
        builder.verify_cold_pre_cpu_tree(tree, report[R.KEY], self.release, self.marker, R.KEY)

  def test_partial_wrong_guard_and_marker_fail(self):
    for field in ("guard", "guard_sha256", "guard_srcversion", "helper", "helper_sha256", "restore_marker"):
      with self.subTest(field=field), self.assertRaisesRegex(ValueError, "together"):
        self.prepare(**{field: None})
    with self.assertRaisesRegex(ValueError, "V2"):
      self.prepare(restore_marker={"version": "v1"})
    with self.assertRaisesRegex(ValueError, "corrected guard"):
      self.prepare(guard_sha256="0" * 64)
    with self.assertRaisesRegex(ValueError, "production ABI"):
      self.prepare(release="wrong-release")

  def test_all_source_and_file_identities_fail_closed(self):
    tree, report = self.tree()
    for group in ("source_sha256", "files_sha256"):
      for key in report[R.KEY][group]:
        bad = copy.deepcopy(report)
        bad[R.KEY][group][key] = "0" * 64
        with self.subTest(group=group, key=key), self.assertRaises(ValueError):
          self.verify(tree, bad)
    for field, value in (("guard_module_sha256", "0" * 64), ("guard_module_srcversion", "ABC123"),
                         ("guard_module_vermagic", "bad"), ("version", "cold-pci-guard-pre-arch-abort-v1")):
      bad = copy.deepcopy(report)
      bad[R.KEY][field] = value
      with self.subTest(field=field), self.assertRaises(ValueError):
        self.verify(tree, bad)

  def test_unannounced_mixed_orphan_abort_and_symlinks_fail(self):
    tree, report = self.tree()
    with self.assertRaisesRegex(ValueError, "Unannounced"):
      auditor.verify_no_unannounced_cold_tree(tree)
    for key in builder.PCI.PROFILES:
      bad = copy.deepcopy(report)
      bad[key] = {}
      with self.subTest(key=key), self.assertRaisesRegex(ValueError, "mutually exclusive"):
        self.verify(tree, bad)
    directory = tree / R.PROFILE["directory"]
    for name in ("abort.ko", "renamed-abort.ko", "extra.txt", "nested"):
      extra = directory / name
      extra.write_bytes(b"unannounced")
      with self.subTest(name=name), self.assertRaisesRegex(ValueError, "orphan"):
        self.verify(tree, report)
      extra.unlink()
    duplicate = tree / "usr/lib/modules/test/guard.ko.zst"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_bytes(b"duplicate")
    with self.assertRaisesRegex(ValueError, "orphan guard"):
      self.verify(tree, report)
    duplicate.unlink()
    renamed = duplicate.with_name("renamed.ko")
    renamed.write_bytes(b"renamed module")
    with self.assertRaisesRegex(ValueError, "renamed abort"):
      self.verify(tree, report)
    renamed.unlink()
    path = directory / "functions"
    original = path.read_bytes()
    path.unlink()
    target = self.root / "other-functions"
    target.write_bytes(original)
    path.symlink_to(target)
    with self.assertRaisesRegex(ValueError, "embedded file"):
      self.verify(tree, report)

  def test_hook_phases_order_and_alternative_resume_fail(self):
    tree, report = self.tree()
    config = (tree / "config").read_text()
    for field in ("EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
      (tree / "config").write_text(config.replace(field + '="', field + '="' + R.PROFILE["hook"] + ' '))
      with self.subTest(field=field), self.assertRaisesRegex(ValueError, "outside synchronous"):
        self.verify(tree, report)
    (tree / "config").write_text(config.replace("encrypt " + R.PROFILE["hook"], R.PROFILE["hook"] + " encrypt"))
    with self.assertRaisesRegex(ValueError, "after encrypt"):
      self.verify(tree, report)
    (tree / "config").write_text(config)
    alternate = tree / "usr/lib/systemd/systemd-hibernate-resume"
    alternate.parent.mkdir(parents=True)
    alternate.write_bytes(b"alternate")
    with self.assertRaisesRegex(ValueError, "alternative"):
      self.verify(tree, report)

  def test_real_config_and_cli_dispatch(self):
    base = self.root / "base.conf"
    base.write_text("HOOKS=(udev encrypt omarchy-t2-restore-marker resume)\n")
    script = builder.cold_pre_cpu_config(base, R.KEY) + '\nprintf "%s\\n" "${HOOKS[*]}"\n'
    configured = subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True)
    self.assertEqual(configured.stdout.strip(), "udev encrypt " + R.PROFILE["hook"] +
                     " omarchy-t2-restore-marker resume " + R.PROFILE["hook"] + "-stop")
    for hook in (R.PROFILE["hook"], builder.PCI.PROFILE["hook"]):
      base.write_text("HOOKS=(encrypt " + hook + " omarchy-t2-restore-marker resume)\n")
      refused = subprocess.run(["bash", "-c", builder.cold_pre_cpu_config(base, R.KEY)], capture_output=True)
      self.assertEqual(refused.returncode, 1)
    command = ["python3", str(EXPERIMENTS / "build-hibernation-candidate-uki.py"), "--candidate-source", str(self.root),
               "--output", str(self.root / "never-created"), "--cold-pci-restore-guard-module", str(self.guard)]
    for extra in ([], ["--cold-pre-arch-module", str(self.module)]):
      refused = subprocess.run(command + extra, capture_output=True, text=True)
      self.assertEqual(refused.returncode, 2)
      self.assertFalse((self.root / "never-created").exists())

  def test_install_hook_embeds_only_guard_bundle(self):
    prepared = self.prepare()
    script = r'''
add_file() { printf '%s\n' "$2"; }
add_binary() { printf '%s\n' "$2"; }
add_runscript() { :; }
. "$1"
build
'''
    command = ["bash", "-c", script, "bash", str(R.PROFILE["source"] / "install" / R.PROFILE["hook"])]
    installed = subprocess.run(command, check=True, capture_output=True, text=True,
                               env={"OMARCHY_T2_COLD_PCI_RESTORE_BUNDLE": str(prepared["bundle"])})
    self.assertEqual(set(installed.stdout.splitlines()), {"/" + R.PROFILE["directory"] + name for name in R.BUNDLE_FILES})
    (prepared["bundle"] / "abort.ko").write_bytes(b"abort")
    refused = subprocess.run(command, capture_output=True,
                             env={"OMARCHY_T2_COLD_PCI_RESTORE_BUNDLE": str(prepared["bundle"])})
    self.assertNotEqual(refused.returncode, 0)


if __name__ == "__main__":
  unittest.main()
