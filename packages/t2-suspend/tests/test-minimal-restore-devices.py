#!/usr/bin/python3
"""Offline configuration and fail-closed audits for isolated restore devices."""

import copy
import importlib.util
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock


EXPERIMENTS = Path(__file__).resolve().parents[1] / "experiments"


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, EXPERIMENTS / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


builder = load("minimal_restore_builder", "build-hibernation-candidate-uki.py")
auditor = load("minimal_restore_auditor", "audit-hibernation-uki-pair.py")


class MinimalRestoreTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix="t2-minimal-restore-tests-")
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.release = "test-t2"
    self.report = {
      "kernel_release": self.release,
      "minimal_restore_policy": copy.deepcopy(auditor.MINIMAL_RESTORE_POLICY),
    }
    self.config = (
      'MODULES="nvme dm-crypt"\n'
      'HOOKS="udev encrypt omarchy-t2-restore-marker resume"\n'
      'EARLYHOOKS="udev"\n'
      'LATEHOOKS="btrfs-overlayfs omarchy-t2-candidate-modules"\n'
      'CLEANUPHOOKS="udev"\n'
      'EMERGENCYHOOKS=""\n'
    )
    (self.root / "config").write_text(self.config)
    for name in ("nvme", "nvme-core", "dm-crypt", "dm-mod"):
      self.module("kernel/drivers/storage/" + name + ".ko.zst")
    for name in ("usr/bin/cryptsetup", "usr/bin/btrfs", "etc/cryptsetup-keys.d/root.key"):
      path = self.root / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(b"private fixture")

  def module(self, relative):
    path = self.root / "usr/lib/modules" / self.release / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"module fixture")
    return path

  def verify(self):
    builder.verify_minimal_restore_tree(self.root, self.release)
    auditor.verify_minimal_restore_tree(self.root, self.report)

  def test_transform_keeps_root_marker_microcode_and_payload(self):
    base = self.root / "base ' $(false) config"
    original = (
      'HOOKS=(base udev plymouth keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems fsck btrfs-overlayfs omarchy-t2-restore-marker resume omarchy-t2-candidate-modules)\n'
      'MODULES=(nvme nvme_core dm_crypt thunderbolt hid_apple i915 xe)\n'
      'FILES=(/private/root.key)\n'
    )
    base.write_text(original)
    wrapper = self.root / "private.conf"
    wrapper.write_text(builder.minimal_restore_config(base))
    completed = subprocess.run(
      ("bash", "-euo", "pipefail", "-c",
       'source "$1"; printf "%s\\n" "${HOOKS[*]}" "${MODULES[*]}" "${FILES[*]}"',
       "bash", str(wrapper)), check=True, capture_output=True, text=True,
    )
    hooks, modules, files = completed.stdout.splitlines()
    self.assertEqual(hooks.split(), ["base", "udev",
      "keyboard", "autodetect", "microcode", "modconf", "keymap", "consolefont", "block", "encrypt", "filesystems", "fsck", "btrfs-overlayfs", "omarchy-t2-restore-marker", "resume", "omarchy-t2-candidate-modules",
    ])
    self.assertEqual(modules, "nvme nvme_core dm_crypt hid_apple")
    self.assertEqual(files, "/private/root.key")
    self.assertEqual(base.read_text(), original)

  def test_isolated_tree_passes_both_audits(self):
    self.verify()

  def test_independent_extraction_audits_modules_in_early_archive(self):
    (self.root / "early_cpio").write_text("1\n")
    early_names = ["early_cpio"]
    main_names = []
    for path in sorted(self.root.rglob("*")):
      name = str(path.relative_to(self.root))
      if name == "early_cpio":
        continue
      if path.is_dir():
        early_names.append(name)
        main_names.append(name)
        continue
      if name.startswith("usr/lib/modules") or name in ("usr", "usr/lib"):
        early_names.append(name)
      else:
        main_names.append(name)

    def archive(names):
      return subprocess.run(
        ("bsdcpio", "--create", "--format=newc"), cwd=self.root,
        input=("\n".join(names) + "\n").encode(), capture_output=True, check=True,
      ).stdout

    initrd = self.root / "split.initrd"
    initrd.write_bytes(archive(early_names) + archive(main_names))
    main_only = self.root / "main-only"
    main_only.mkdir()
    subprocess.run(("lsinitcpio", "--cpio", "--extract", str(initrd)), cwd=main_only,
                   check=True, capture_output=True)
    with self.assertRaisesRegex(ValueError, "root-critical module"):
      auditor.verify_minimal_restore_tree(main_only, self.report)

    combined = self.root / "combined"
    combined.mkdir()
    with mock.patch.object(auditor.subprocess, "run", wraps=subprocess.run) as commands:
      auditor.extract_restore_initramfs(initrd, combined)
    self.assertEqual([call.args[0] for call in commands.call_args_list], [
      ("lsinitcpio", "--early", "--extract", str(initrd)),
      ("lsinitcpio", "--cpio", "--extract", str(initrd)),
    ])
    auditor.verify_minimal_restore_tree(combined, self.report)
    for name in ("nvme", "nvme-core", "dm-crypt", "dm-mod"):
      path = combined / "usr/lib/modules" / self.release / "kernel/drivers/storage" / (name + ".ko.zst")
      self.assertEqual(path.read_bytes(), b"module fixture")

  def test_real_candidate_config_filters_after_late_host_dropins(self):
    stock = self.root / "stock.conf"
    stock.write_text('HOOKS=(base udev microcode modconf block encrypt filesystems)\nMODULES=(nvme dm_crypt)\nFILES=(/private/key)\n')
    drops = self.root / "host drops"
    drops.mkdir()
    (drops / "10-resume.conf").write_text('HOOKS+=(resume)\n')
    (drops / "99-late.conf").write_text('HOOKS+=(kms plymouth)\nMODULES+=(thunderbolt i915 xe)\n')
    base = self.root / "candidate.conf"
    base.write_text(builder.CONFIG.read_text().replace(
      "source /etc/mkinitcpio.conf", "source " + shlex.quote(str(stock)),
    ).replace("/etc/mkinitcpio.conf.d/*.conf", shlex.quote(str(drops)) + "/*.conf"))
    wrapper = self.root / "private.conf"
    wrapper.write_text(builder.minimal_restore_config(base))
    completed = subprocess.run(
      ("bash", "-euo", "pipefail", "-c",
       'source "$1"; printf "%s\\n" "${HOOKS[*]}" "${MODULES[*]}" "${FILES[*]}"', "bash", str(wrapper)),
      env={"PATH": "/usr/bin", "OMARCHY_T2_RESTORE_MARKER_MODULE": "/private/marker.ko"},
      check=True, capture_output=True, text=True,
    )
    hooks, modules, files = completed.stdout.splitlines()
    self.assertEqual(hooks, "base udev microcode modconf block encrypt filesystems omarchy-t2-restore-marker resume omarchy-t2-candidate-modules")
    self.assertEqual(modules, "nvme dm_crypt")
    self.assertIn("/private/key", files.split())

  def test_minimal_cli_requires_explicit_marker_before_work(self):
    output = self.root / "never-created"
    result = subprocess.run(
      ("python3", str(EXPERIMENTS / "build-hibernation-candidate-uki.py"),
       "--candidate-source", str(self.root), "--output", str(output), "--minimal-restore-devices"),
      capture_output=True, text=True,
    )
    self.assertEqual(result.returncode, 2)
    self.assertIn("requires an explicit --restore-marker-module", result.stderr)
    self.assertFalse(output.exists())

  def test_excluded_driver_and_drm_dependency_fail_both_audits(self):
    for relative in (
      "updates/dkms/i915.ko", "updates/thunderbolt.ko.xz", "updates/xe.ko.gz",
      "kernel/drivers/gpu/drm/drm_display_helper.ko.zst",
      "kernel/drivers/thunderbolt/unexpected-helper.ko",
    ):
      with self.subTest(relative=relative):
        path = self.module(relative)
        with self.assertRaises(ValueError):
          builder.verify_minimal_restore_tree(self.root, self.release)
        with self.assertRaises(ValueError):
          auditor.verify_minimal_restore_tree(self.root, self.report)
        path.unlink()

  def test_resolved_hook_and_module_leaks_fail_both_audits(self):
    for before, after in (
      ('MODULES="', 'MODULES="thunderbolt '),
      ('HOOKS="', 'HOOKS="kms '),
      ('EARLYHOOKS="', 'EARLYHOOKS="plymouth '),
      ('LATEHOOKS="', 'LATEHOOKS="plymouth '),
      ('EMERGENCYHOOKS="', 'EMERGENCYHOOKS="plymouth '),
      ('udev encrypt', 'udev'),
      ('omarchy-t2-candidate-modules', 'unrelated'),
      ('MODULES="nvme dm-crypt"', 'MODULES=malformed'),
    ):
      with self.subTest(after=after):
        (self.root / "config").write_text(self.config.replace(before, after))
        with self.assertRaises(ValueError):
          builder.verify_minimal_restore_tree(self.root, self.release)
        with self.assertRaises(ValueError):
          auditor.verify_minimal_restore_tree(self.root, self.report)

  def test_independent_audit_requires_policy_and_root_assets(self):
    for malformed in (None, {}, {**self.report["minimal_restore_policy"], "version": "unknown"}):
      with self.subTest(policy=malformed):
        with self.assertRaises(ValueError):
          auditor.verify_minimal_restore_tree(self.root, {**self.report, "minimal_restore_policy": malformed})
    module = self.root / "usr/lib/modules" / self.release / "kernel/drivers/storage/dm-mod.ko.zst"
    module.unlink()
    with self.assertRaisesRegex(ValueError, "root-critical module"):
      auditor.verify_minimal_restore_tree(self.root, self.report)
    self.module("kernel/drivers/storage/dm-mod.ko.zst")
    key = self.root / "etc/cryptsetup-keys.d/root.key"
    key.unlink()
    key.symlink_to("/nonexistent")
    with self.assertRaisesRegex(ValueError, "root-critical file"):
      auditor.verify_minimal_restore_tree(self.root, self.report)

  def test_minimal_policy_is_for_restore_only(self):
    with self.assertRaisesRegex(ValueError, "Source image"):
      auditor.audit(self.report, {})
    with self.assertRaisesRegex(ValueError, "malformed minimal restore"):
      auditor.audit({}, {"minimal_restore_policy": None})
    with self.assertRaisesRegex(ValueError, "requires the restore marker"):
      auditor.audit({}, self.report)


if __name__ == "__main__":
  unittest.main()
