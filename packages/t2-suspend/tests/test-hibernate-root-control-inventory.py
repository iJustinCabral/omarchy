"""Synthetic control inventories only; no live commands, devices or config evaluation."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("root_control_fixture", Path(__file__).parents[1] / "hibernate/root_control_inventory.py")
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)


class RootControls(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name) / "root"
    self.root.mkdir()

  def write(self, name, raw=b"control bytes", mode=0o644):
    path = self.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path

  def link(self, name, target):
    path = self.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return path

  def capture(self): return I.capture(self.root)

  def test_deterministic_fixed_scope_absent_and_empty_are_distinct(self):
    absent = self.capture()
    self.assertEqual(absent, self.capture())
    self.assertEqual(set(absent["files"]), set(I.FILES))
    self.assertEqual(set(absent["directories"]), set(I.TREES))
    self.assertEqual(absent["directories"]["etc/modprobe.d"], {"kind": "absent"})
    (self.root / "etc/modprobe.d").mkdir(parents=True)
    empty = self.capture()
    self.assertEqual(empty["directories"]["etc/modprobe.d"]["entries"], {})
    self.assertNotEqual(absent, empty)
    self.assertNotIn("safe", empty)

  def test_empty_config_reuses_reader_without_relaxing_driver_default(self):
    path = self.write("etc/crypttab", b"")
    record = self.capture()["files"]["etc/crypttab"]
    self.assertEqual(record, {"kind": "file", "size": 0, "sha256": hashlib.sha256(b"").hexdigest(), "mode": 0o644})
    with self.assertRaises(ValueError): I.DRIVER._file(self.root, path, os.geteuid())

  def test_add_remove_same_size_bytes_and_executable_modes_change_inventory(self):
    path = self.write("etc/modprobe.d/added.conf", b"first")
    first = self.capture()
    path.write_bytes(b"other")
    changed = self.capture()
    self.assertNotEqual(first, changed)
    path.chmod(0o755)
    executable = self.capture()
    self.assertNotEqual(changed, executable)
    self.assertEqual(executable["directories"]["etc/modprobe.d"]["entries"][path.name]["mode"], 0o755)
    path.unlink()
    self.assertNotEqual(executable, self.capture())

  def test_mask_records_exact_link_without_opening_dev_null(self):
    self.link("etc/systemd/system/systemd-hibernate.service", "/dev/null")
    with patch.object(I.DRIVER.os, "open", side_effect=AssertionError("mask must never open a device")):
      record = self.capture()["files"]["etc/systemd/system/systemd-hibernate.service"]
    self.assertEqual(record["kind"], "symlink")
    self.assertEqual(record["target"], {"kind": "mask"})
    self.assertEqual(record["links"][0]["target"], "/dev/null")

  def test_declared_bluetooth_wants_link_binds_selection_and_bytes(self):
    name = "etc/systemd/system/multi-user.target.wants/bluetooth-after-wifi.service"
    self.write("etc/systemd/system/bluetooth-after-wifi.service", b"gate one")
    link = self.link(name, "/etc/systemd/system/bluetooth-after-wifi.service")
    first = self.capture()["files"][name]
    self.assertEqual(first["resolved"], "/etc/systemd/system/bluetooth-after-wifi.service")
    self.write("usr/lib/systemd/system/bluetooth-after-wifi.service", b"gate two")
    link.unlink()
    link.symlink_to("/usr/lib/systemd/system/bluetooth-after-wifi.service")
    second = self.capture()["files"][name]
    self.assertNotEqual(first, second)
    self.assertNotEqual(first["target"]["sha256"], second["target"]["sha256"])

  def test_control_links_cannot_read_keys_or_escape_fixture_root(self):
    name = "etc/crypttab"
    for target in ("/etc/shadow", "/keys/unlock.key", "../../outside.key", str(self.root.parent / "secret")):
      with self.subTest(target=target):
        link = self.link(name, target)
        with patch.object(I.DRIVER.os, "open", side_effect=AssertionError("out-of-scope target must not be opened")):
          with self.assertRaisesRegex(ValueError, "outside declared scope"): self.capture()
        link.unlink()

  def test_baseline_records_out_of_scope_link_text_without_following_it(self):
    for name, target in (("etc/boot/hooks/pre.d/10-limine-reset-enroll", "/usr/bin/limine-reset-enroll"),
                         ("etc/boot/hooks/post.d/90-limine-enroll-config", "../../../../usr/bin/limine-enroll-config"),
                         ("etc/crypttab", "/keys/unlock.key")):
      with self.subTest(name=name):
        link = self.link(name, target)
        with self.assertRaisesRegex(ValueError, "outside declared scope"): self.capture()  # default unchanged
        with patch.object(I.DRIVER.os, "open", side_effect=AssertionError("out-of-scope target must not be opened")):
          first = I.capture(self.root, baseline=True)
        self.assertEqual(first, I.capture(self.root, baseline=True))
        node = first["files"][name] if name in I.FILES else first["directories"][name.rsplit("/", 1)[0]]["entries"][name.rsplit("/", 1)[1]]
        self.assertEqual(node, {"kind": "symlink", "links": [{"path": "/" + name, "target": target}], "target": {"kind": "out-of-scope"}})
        link.unlink()

  def test_baseline_leaves_in_scope_links_and_default_output_unchanged(self):
    self.write("usr/lib/systemd/system/bluetooth.service", b"unit")
    self.link("etc/systemd/system/bluetooth.service", "/usr/lib/systemd/system/bluetooth.service")
    self.write("etc/fstab", b"fstab")
    default = self.capture()
    self.assertEqual(default["files"]["etc/systemd/system/bluetooth.service"]["kind"], "symlink")
    based = I.capture(self.root, baseline=True)
    self.assertEqual(based["files"]["etc/systemd/system/bluetooth.service"]["links"], default["files"]["etc/systemd/system/bluetooth.service"]["links"])
    self.assertEqual(based["files"]["etc/systemd/system/bluetooth.service"]["resolved"], "/usr/lib/systemd/system/bluetooth.service")
    self.assertEqual(based["files"]["etc/fstab"], {**default["files"]["etc/fstab"], "nlink": 1})  # only addition: the link count

  def test_hardlinked_control_file_refused_by_default_and_recorded_in_baseline(self):
    path = self.write("etc/fstab", b"fstab")
    os.link(path, self.root / "etc/fstab-alias")
    with self.assertRaisesRegex(ValueError, "Bounded owned regular"): self.capture()
    self.assertEqual(I.capture(self.root, baseline=True)["files"]["etc/fstab"]["nlink"], 2)

  def test_dangling_declared_link_is_explicit_and_link_loop_refuses(self):
    name = "etc/systemd/system/bluetooth.service"
    link = self.link(name, "/usr/lib/systemd/system/bluetooth.service")
    record = self.capture()["files"][name]
    self.assertEqual(record["target"], {"kind": "absent"})
    link.unlink()
    self.link(name, "bluetooth.service")
    with self.assertRaisesRegex(ValueError, "chain exceeds"): self.capture()

  def test_directory_symlinks_and_missing_path_ancestor_symlinks_refuse(self):
    outside = self.root.parent / "outside"
    outside.mkdir()
    link = self.link("etc/modprobe.d", str(outside))
    with self.assertRaisesRegex(ValueError, "real directory"): self.capture()
    link.unlink()
    (self.root / "etc").rmdir()
    (self.root / "etc").symlink_to(outside)
    with patch.object(I.DRIVER.os, "open", side_effect=AssertionError("fixture ancestor cannot reach host")):
      with self.assertRaisesRegex(ValueError, "nonsymlink control ancestry"): self.capture()

  def test_writable_ancestors_files_and_special_nodes_refuse_before_read(self):
    path = self.write("etc/fstab")
    path.chmod(0o666)
    with self.assertRaises(ValueError): self.capture()
    path.chmod(0o644)
    path.parent.chmod(0o777)
    with self.assertRaisesRegex(ValueError, "ancestry"): self.capture()
    path.parent.chmod(0o755)
    path.unlink()
    os.mkfifo(path)
    with patch.object(I.DRIVER.os, "open", side_effect=AssertionError("must not open special file")):
      with self.assertRaisesRegex(ValueError, "regular driver bytes"): self.capture()

  def test_short_read_and_changed_target_refuse(self):
    path = self.write("etc/fstab")
    with patch.object(I.DRIVER.os, "read", return_value=b""), self.assertRaisesRegex(ValueError, "Short"):
      self.capture()
    original = I.DRIVER._file
    def changed(root, target, owner, **kwargs):
      result = original(root, target, owner, **kwargs)
      path.chmod(0o600)
      return result
    with patch.object(I.DRIVER, "_file", side_effect=changed), self.assertRaisesRegex(ValueError, "target changed"):
      self.capture()

  def test_link_replacement_during_read_refuses(self):
    self.write("usr/lib/systemd/system/bluetooth.service")
    link = self.link("etc/systemd/system/bluetooth.service", "/usr/lib/systemd/system/bluetooth.service")
    original = I.DRIVER._file
    def replace(root, target, owner, **kwargs):
      result = original(root, target, owner, **kwargs)
      link.unlink()
      link.symlink_to("/dev/null")
      return result
    with patch.object(I.DRIVER, "_file", side_effect=replace), self.assertRaisesRegex(ValueError, "link changed"):
      self.capture()

  def test_changes_between_whole_inventory_reads_refuse(self):
    path = self.write("etc/fstab", b"before")
    original = I._scan
    def changed(root, owner, *rest):
      result = original(root, owner, *rest)
      path.write_bytes(b"after")
      return result
    with patch.object(I, "_scan", side_effect=changed), self.assertRaisesRegex(ValueError, "across capture"):
      self.capture()

  def test_entry_depth_and_total_byte_bounds(self):
    self.write("etc/modprobe.d/nested/a.conf")
    for constant, bound in (("MAX_ENTRIES", 1), ("MAX_DEPTH", 0), ("MAX_TOTAL", 1)):
      with self.subTest(constant=constant), patch.object(I, constant, bound), self.assertRaisesRegex(ValueError, "bound"):
        self.capture()

  def test_live_and_noncanonical_roots_refuse_before_scan(self):
    with patch.object(I, "_scan", side_effect=AssertionError("live source cannot scan")):
      with self.assertRaisesRegex(ValueError, "installed live"): I.capture(Path("/"))
      with self.assertRaises(ValueError): I.capture(Path("relative"))
    alias = self.root.parent / "alias"
    alias.symlink_to(self.root)
    with self.assertRaisesRegex(ValueError, "Canonical"): I.capture(alias)

  def test_baseline_capture_omits_volatile_roots_and_default_keeps_them(self):
    self.write("run/systemd/system/bluetooth-after-wifi.service.d/a.conf")
    self.write("etc/systemd/system/bluetooth-after-wifi.service.d/a.conf")
    default, baseline = I.capture(self.root), I.capture(self.root, baseline=True)
    self.assertEqual(set(default["directories"]), set(I.TREES))
    self.assertEqual(set(default["files"]), set(I.FILES))
    self.assertEqual(set(baseline["directories"]), {name for name in I.TREES if not I.volatile(name)})
    self.assertEqual(set(baseline["files"]), {name for name in I.FILES if not I.volatile(name)})

  def test_actual_selector_scope_and_no_commands(self):
    for name in ("usr/lib/systemd/systemd-sleep", "usr/lib/initcpio/functions", "etc/crypttab.initramfs", "etc/default/limine"):
      self.assertIn(name, I.FILES)
    for name in ("usr/local/lib/modprobe.d", "usr/local/lib/depmod.d", "etc/initcpio/post", "usr/lib/initcpio/post",
                 "etc/boot/hooks/pre.d", "etc/boot/hooks/post.d", "etc/cmdline.d", "etc/dkms/framework.conf.d"):
      self.assertIn(name, I.TREES)
    for prefix in I.PREFIXES:
      for name in ("service", "systemd-.service", "bluetooth-.service", "bluetooth-after-.service"):
        self.assertIn(prefix + "/systemd/system/" + name + ".d", I.TREES)
    with patch.object(I.DRIVER, "_query", side_effect=AssertionError("no external query or evaluation")):
      self.capture()


if __name__ == "__main__": unittest.main()
