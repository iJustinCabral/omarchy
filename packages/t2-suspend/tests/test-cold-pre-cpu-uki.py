#!/usr/bin/python3
"""Private cold-preCPU image construction and independent bundle fault tests."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


EXPERIMENTS = Path(__file__).resolve().parents[1] / "experiments"


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, EXPERIMENTS / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


builder = load("cold_pre_cpu_builder", "build-hibernation-candidate-uki.py")
auditor = load("cold_pre_cpu_auditor", "audit-hibernation-uki-pair.py")


def elf_helper(program_type=1):
  ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
  header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
  return ident + header + struct.pack("<IIQQQQQQ", program_type, 5, 0, 0, 0, 120, 120, 4096)


class ColdPreCpuImageTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix="cold-pre-cpu-uki-test-")
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.release = "7.2.6-test-t2"
    self.module = self.root / "abort.ko"
    self.module.write_bytes(b"offline synthetic module")
    self.module.chmod(0o600)
    self.helper = self.root / "header-reader"
    self.helper.write_bytes(elf_helper())
    self.helper.chmod(0o700)
    self.identity = {"sha256": builder.digest(self.module), "srcversion": "ABC123", "vermagic": self.release + " SMP preempt mod_unload"}
    self.marker = {"version": "v2"}

  def prepare(self, **changes):
    args = {
      "work": self.root, "module": self.module, "module_sha256": builder.digest(self.module),
      "srcversion": "ABC123", "helper": self.helper, "helper_sha256": builder.digest(self.helper),
      "release": self.release, "restore_marker": self.marker,
    }
    args.update(changes)
    # Simulate root ownership only; actual module bytes and per-file pinning
    # are retained. Direct metadata/file security faults are covered below.
    with mock.patch.object(builder, "validate_cold_private_file"), mock.patch.object(builder, "module_metadata", return_value=self.identity), mock.patch.object(builder, "run", return_value=SimpleNamespace(stdout="mba_hibernate_cold_pre_cpu\n")):
      return builder.prepare_cold_pre_cpu(**args)

  def extracted(self):
    prepared = self.prepare()
    tree = self.root / "extracted"
    directory = tree / auditor.COLD_DIRECTORY
    directory.mkdir(parents=True)
    for path in prepared["bundle"].iterdir():
      target = directory / path.name
      target.write_bytes(path.read_bytes())
      target.chmod(path.stat().st_mode & 0o777)
    hooks = tree / "hooks"
    hooks.mkdir()
    for hook in auditor.COLD_HOOKS:
      (hooks / hook).write_bytes((builder.COLD_PRE_CPU / "hooks" / hook).read_bytes())
    config = (
      'HOOKS="udev encrypt omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker resume omarchy-t2-cold-pre-cpu-return"\n'
      'EARLYHOOKS="udev"\nLATEHOOKS="omarchy-t2-candidate-modules"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS=""\n'
    )
    (tree / "config").write_text(config)
    report = {"cold_pre_cpu": prepared["provenance"], "kernel_release": self.release,
              "restore_marker": {"efi_variable": prepared["provenance"]["restore_variable"]}}
    return tree, report

  def verify(self, tree, report):
    def metadata(command, **kwargs):
      self.assertEqual(command[0], "modinfo")
      return SimpleNamespace(stdout=("mba_hibernate_cold_pre_cpu" if command[2] == "name" else self.identity[command[2]]) + "\n")
    with mock.patch.object(auditor.subprocess, "run", side_effect=metadata):
      auditor.verify_cold_pre_cpu_tree(tree, report)

  def test_default_is_inert_and_partial_pins_refused(self):
    self.assertIsNone(builder.prepare_cold_pre_cpu(self.root, None, None, None, None, None, self.release, None))
    for missing in ("module", "module_sha256", "srcversion", "helper", "helper_sha256", "restore_marker"):
      with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "together"):
        self.prepare(**{missing: None})

  def test_exact_bundle_and_provenance_pass_independent_audit(self):
    tree, report = self.extracted()
    self.verify(tree, report)
    self.assertEqual(report["cold_pre_cpu"]["files_sha256"][auditor.COLD_DIRECTORY + "abort.ko"], builder.digest(self.module))

  def test_wrong_production_abi_or_source_version_refused(self):
    with self.assertRaisesRegex(ValueError, "production ABI"):
      self.prepare(release="other-release")
    with self.assertRaisesRegex(ValueError, "source version"):
      self.prepare(srcversion="ABC456")

  def test_private_inputs_check_owner_mode_hash_and_elf(self):
    path = mock.Mock()
    path.is_absolute.return_value = True
    path.is_symlink.return_value = False
    path.is_file.return_value = True
    path.resolve.return_value = Path("/tmp/protected-cold-test")
    path.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100700)
    path.read_bytes.return_value = self.helper.read_bytes()
    builder.validate_cold_private_file(path, builder.digest(self.helper), executable=True)
    for metadata in (SimpleNamespace(st_uid=1000, st_mode=0o100700), SimpleNamespace(st_uid=0, st_mode=0o100755)):
      path.stat.return_value = metadata
      with self.assertRaisesRegex(ValueError, "root-owned"):
        builder.validate_cold_private_file(path, builder.digest(self.helper), executable=True)
    path.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100700)
    with self.assertRaisesRegex(ValueError, "SHA-256"):
      builder.validate_cold_private_file(path, "0" * 64, executable=True)
    path.read_bytes.return_value = b"#!/bin/bash\n"
    with self.assertRaisesRegex(ValueError, "ELF"):
      builder.validate_cold_private_file(path, builder.digest(path), executable=True)

  def test_dynamic_or_malformed_header_helper_refused_independently(self):
    for validator in (builder.validate_static_header_helper, auditor.validate_static_header_helper):
      validator(elf_helper())
      with self.assertRaisesRegex(ValueError, "PT_INTERP"):
        validator(elf_helper(program_type=3))
      with self.assertRaisesRegex(ValueError, "program headers"):
        validator(elf_helper()[:100])

  def test_script_or_identity_tampering_and_source_role_refused(self):
    tree, report = self.extracted()
    for name in ("functions", "abort.sha256", "header-reader.sha256", "resume.offset", "stock-resume"):
      path = tree / auditor.COLD_DIRECTORY / name
      original = path.read_bytes()
      path.write_bytes(b"tampered")
      with self.subTest(name=name), self.assertRaises(ValueError):
        self.verify(tree, report)
      path.write_bytes(original)
    with self.assertRaisesRegex(ValueError, "Source image"):
      auditor.audit(report, {})
    bad = copy.deepcopy(report)
    bad["cold_pre_cpu"]["restore_variable"] = "other-variable"
    with self.assertRaisesRegex(ValueError, "selector"):
      self.verify(tree, bad)

  def test_wrong_order_duplicate_hooks_and_alternative_resume_refused(self):
    tree, report = self.extracted()
    config = (tree / "config").read_text()
    for changed in (
      config.replace("omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker", "omarchy-t2-restore-marker omarchy-t2-cold-pre-cpu"),
      config.replace('HOOKS="udev ', 'HOOKS="resume udev ', 1),
      config.replace('LATEHOOKS="', 'LATEHOOKS="omarchy-t2-cold-pre-cpu-return '),
      config.replace('HOOKS="udev encrypt', 'HOOKS="udev'),
      config + 'HOOKS="resume"\n',
      config.replace('EARLYHOOKS="udev"', 'EARLYHOOKS="udev omarchy-t2-restore-marker"'),
    ):
      (tree / "config").write_text(changed)
      with self.assertRaises(ValueError):
        self.verify(tree, report)
    (tree / "config").write_text(config)
    alternate = tree / "usr/lib/systemd/systemd-hibernate-resume"
    alternate.parent.mkdir(parents=True)
    alternate.write_bytes(b"alternative")
    with self.assertRaisesRegex(ValueError, "alternative effective resume"):
      self.verify(tree, report)

  def test_ordinary_build_hooks_between_encrypt_and_diagnostic_are_retained(self):
    tree, report = self.extracted()
    config = (tree / "config").read_text()
    (tree / "config").write_text(config.replace("encrypt omarchy-t2-cold-pre-cpu", "encrypt filesystems fsck btrfs-overlayfs omarchy-t2-cold-pre-cpu"))
    self.verify(tree, report)

  def test_unannounced_bundle_hooks_and_module_are_forbidden(self):
    tree = self.root / "ordinary"
    tree.mkdir()
    auditor.verify_no_unannounced_cold_tree(tree)
    for name in (auditor.COLD_DIRECTORY + "functions", "hooks/omarchy-t2-cold-pre-cpu", "usr/lib/modules/test/mba_hibernate_cold_pre_cpu.ko.zst", "hooks/resume"):
      path = tree / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_text("omarchy-t2-cold-pre-cpu")
      with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unannounced"):
        auditor.verify_no_unannounced_cold_tree(tree)
      path.unlink()
      if name.startswith(auditor.COLD_DIRECTORY):
        path.parent.rmdir()

  def test_config_transform_preserves_marker_adjacency(self):
    base = self.root / "base.conf"
    base.write_text('HOOKS=(base udev encrypt omarchy-t2-restore-marker resume other)\n')
    config = self.root / "cold.conf"
    config.write_text(builder.cold_pre_cpu_config(base))
    result = subprocess.run(("bash", "-euo", "pipefail", "-c", 'source "$1"; printf "%s\\n" "${HOOKS[*]}"', "bash", str(config)), capture_output=True, text=True, check=True)
    self.assertEqual(result.stdout.strip(), "base udev encrypt omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker resume omarchy-t2-cold-pre-cpu-return other")
    base.write_text('HOOKS=(encrypt omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker resume)\n')
    failed = subprocess.run(("bash", "-euo", "pipefail", str(config)), capture_output=True)
    self.assertNotEqual(failed.returncode, 0)

  def test_cli_partial_diagnostic_refused_before_any_build(self):
    result = subprocess.run(("python3", str(EXPERIMENTS / "build-hibernation-candidate-uki.py"),
                             "--candidate-source", str(self.root), "--output", str(self.root / "never-created"),
                             "--cold-pre-cpu-module", str(self.module)), capture_output=True, text=True)
    self.assertEqual(result.returncode, 2)
    self.assertIn("complete module/helper pins", result.stderr)
    self.assertFalse((self.root / "never-created").exists())

  def test_only_opt_in_build_selects_diagnostic_hook_and_install_paths(self):
    class StopBeforeMkinitcpio(Exception):
      pass

    captured = []

    def stop(command, **kwargs):
      captured.append(command)
      raise StopBeforeMkinitcpio()

    with mock.patch.object(builder, "run", side_effect=stop):
      with self.assertRaises(StopBeforeMkinitcpio):
        builder.build_initrd(self.root, self.root, self.root, self.release, {})
      with self.assertRaises(StopBeforeMkinitcpio):
        builder.build_initrd(self.root, self.root, self.root, self.release, {},
                             minimal_restore_devices=True, cold_pre_cpu={"bundle": self.root})
    normal, diagnostic = captured
    self.assertNotIn("OMARCHY_T2_COLD_PRE_CPU_BUNDLE=" + str(self.root), normal)
    self.assertIn("OMARCHY_T2_COLD_PRE_CPU_BUNDLE=" + str(self.root), diagnostic)
    for field, directory in (("MKINITCPIO_HOOKS", "hooks"), ("MKINITCPIO_INSTALL", "install")):
      expected = field + "=" + str(builder.COLD_PRE_CPU / directory) + ":"
      self.assertTrue(any(str(item).startswith(expected) for item in diagnostic))
      self.assertFalse(any(str(item).startswith(expected) for item in normal))
    self.assertEqual(normal[normal.index("--config") + 1], builder.CONFIG)
    self.assertEqual(diagnostic[diagnostic.index("--config") + 1], self.root / "cold-pre-cpu-mkinitcpio.conf")


if __name__ == "__main__":
  unittest.main()
