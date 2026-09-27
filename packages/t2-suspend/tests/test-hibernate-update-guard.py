"""Offline update admission fixtures; never run pacman, power or boot tools."""
import configparser
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("update_guard", HERE / "hibernate/update_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Updates(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name) / "root"
    self.root.mkdir(mode=0o700)
    (self.root / guard.EFI).mkdir(parents=True, mode=0o700)
    self.stock = ("timeout: 3\ndefault_entry: 2\n/+Omarchy\n  //linux-t2\n  comment: Kernel version: 7.1.1-test\n"
                  "  comment: kernel-id=linux-t2\n  protocol: efi\n  path: " + guard.PRODUCTION + "#" + "a" * 128 + "\n")
    self.write(guard.LIMINE, self.stock)

  def write(self, relative, raw):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
      if parent == self.root.parent: break
      parent.chmod(0o700)
    path.write_text(raw)
    path.chmod(0o600)
    return path

  def test_inactive_stock_and_updated_production_hash_are_read_only(self):
    self.write(guard.STATE / "history/boot-policy.json", '{"approved":true}')
    self.write(guard.STATE / "limine.conf.before-source-default", "retained immutable evidence")
    self.write(guard.STATE / "ledger/consumed-guard.json", "retained consumed guard")
    before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
    self.assertEqual(guard.check(self.root)["default_entry"], 2)
    self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
    self.write(guard.LIMINE, self.stock.replace("a" * 128, "b" * 128).replace("7.1.1-test", "7.2.0-test"))
    self.assertEqual(guard.check(self.root)["classification"], "inactive-stock-update-admitted")

  def test_all_active_artifacts_block_even_invalid_empty_or_dangling(self):
    self.assertIn(guard.STATE / "package-maintenance.pending", guard.ACTIVE)
    for relative in guard.ACTIVE:
      for content in ("", "malformed", '{"approved":false}'):
        with self.subTest(relative=relative, content=content):
          path = self.write(relative, content)
          with self.assertRaises(ValueError): guard.check(self.root)
          path.unlink()
      path = self.root / relative
      path.symlink_to(path.with_name("missing"))
      with self.assertRaises(ValueError): guard.check(self.root)
      path.unlink()

  def test_partial_deactivation_does_not_release_until_all_active_artifacts_absent(self):
    paths = [self.write(relative, "pending") for relative in guard.ACTIVE]
    for path in paths:
      with self.assertRaises(ValueError): guard.check(self.root)
      path.unlink()
    self.assertEqual(guard.check(self.root)["default_entry"], 2)

  def test_source_foreign_or_ambiguous_defaults_block_without_policy(self):
    for text in (
      self.stock.replace("default_entry: 2", "default_entry: MBA-T2-hibernation-source-c5e6f0c9"),
      self.stock.replace("default_entry: 2", "default_entry: 3"),
      "default_entry: 2\n" + self.stock,
      "remember_last_entry: yes\n" + self.stock,
      self.stock.replace("//linux-t2", "//MBA-T2-hibernation-source-c5e6f0c9"),
      self.stock.replace("/+Omarchy", "/+Foreign"),
      self.stock.replace(guard.PRODUCTION, "boot():/EFI/Linux/mba-t2-source.efi"),
      self.stock.replace("protocol: efi", "protocol: linux"),
      self.stock.replace("a" * 128, "bad-hash"),
      self.stock + "  protocol: efi\n",
      self.stock + "  protocol : efi\n",
      self.stock + "  image_path: boot():/alternate\n",
      self.stock + "  kernel_path: boot():/alternate\n",
    ):
      with self.subTest(text=text[:80]):
        self.write(guard.LIMINE, text)
        with self.assertRaises(ValueError): guard.check(self.root)

  def test_missing_writable_symlinked_and_oversized_configuration_fail_closed(self):
    path = self.root / guard.LIMINE
    path.chmod(0o666)
    with self.assertRaises(ValueError): guard.check(self.root)
    path.unlink()
    with self.assertRaises(FileNotFoundError): guard.check(self.root)
    path.symlink_to("missing")
    with self.assertRaises(ValueError): guard.check(self.root)
    path.unlink()
    self.write(guard.LIMINE, "x" * (guard.MAX_BYTES + 1))
    with self.assertRaises(ValueError): guard.check(self.root)

  def test_fifo_configuration_rejected_before_open_can_block(self):
    path = self.root / guard.LIMINE
    path.unlink()
    os.mkfifo(path, mode=0o600)
    with patch.object(guard.os, "open", side_effect=AssertionError("FIFO must not be opened")):
      with self.assertRaises(ValueError): guard.check(self.root)

  def test_dangling_symlink_and_writable_active_state_ancestors_fail_closed(self):
    state = self.root / guard.STATE
    state.parent.mkdir(parents=True)
    state.symlink_to(state.with_name("missing"))
    with self.assertRaises(ValueError): guard.check(self.root)
    state.unlink()
    state.mkdir(mode=0o777)
    state.chmod(0o777)
    with self.assertRaises(ValueError): guard.check(self.root)
    state.chmod(0o700)
    self.assertEqual(guard.check(self.root)["default_entry"], 2)
    omarchy = self.root / "etc/omarchy"
    omarchy.parent.mkdir()
    omarchy.symlink_to(omarchy.with_name("missing"))
    with self.assertRaises(ValueError): guard.check(self.root)

  def test_unavailable_efi_view_cannot_prove_absent_overrides(self):
    (self.root / guard.EFI).rmdir()
    with self.assertRaises(FileNotFoundError): guard.check(self.root)

  def test_cli_fixed_root_no_arguments_no_environment_bypass(self):
    bypasses = {"OMARCHY_UPDATE_PACMAN": "1", "OMARCHY_ALLOW_DIRECT_PACMAN": "1", "OMARCHY_T2_UPDATE_FORCE": "1"}
    with patch.dict(os.environ, bypasses), patch.object(guard.os, "geteuid", return_value=0):
      with patch.object(guard, "check", side_effect=ValueError("fixture active policy")) as checked:
        with self.assertRaises(ValueError): guard.main([])
        checked.assert_called_once_with(Path("/"))
      with patch.object(guard, "check", side_effect=AssertionError("no root reads")):
        for arguments in (["--root", "/tmp"], ["--force"], ["--help"]):
          with self.assertRaises(ValueError): guard.main(arguments)
    with patch.object(guard.os, "geteuid", return_value=1000), patch.object(guard, "check") as checked:
      with self.assertRaises(ValueError): guard.main([])
      checked.assert_not_called()
    with self.assertRaises(ValueError): guard.check(Path("relative"))
    with self.assertRaises(ValueError): guard.check(self.root / "..")

  def test_hook_scope_ordering_fixed_snapshot_and_fail_closed_contract(self):
    filename = HERE / "hibernate/00-omarchy-t2-hibernate-guard.hook"
    parser = configparser.ConfigParser(allow_no_value=True)
    # ALPM permits repeated Operation fields; inspect their exact set separately.
    text = filename.read_text()
    operations = [line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("Operation =")]
    parser.read_string("\n".join(line for line in text.splitlines() if not line.startswith("Operation =")))
    self.assertEqual(set(operations), {"Install", "Upgrade", "Remove"})
    self.assertEqual(parser["Trigger"]["Type"], "Package")
    self.assertEqual(parser["Trigger"]["Target"], "*")
    self.assertEqual(parser["Action"]["When"], "PreTransaction")
    self.assertIn("AbortOnFail", parser["Action"])
    self.assertEqual(parser["Action"]["Exec"], "/usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py")
    self.assertNotIn("NeedsTargets", parser["Action"])
    self.assertLess(filename.name, "10-linux-modules-pre.hook")
    self.assertLess(filename.name, "11-glibc-remove-ldconfig-cache.hook")


if __name__ == "__main__": unittest.main()
