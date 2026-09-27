"""Synthetic T2 root-driver byte inventory; no live modinfo or device access."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("root_driver_inventory_fixture", HERE / "hibernate/root_driver_inventory.py")
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)


class RootDrivers(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name) / "root"
    self.root.mkdir()
    (self.root / "lib").symlink_to("usr/lib")
    self.release = "7.2.6-arch2-Watanare-T2-2-t2"
    self.modules = self.root / "usr/lib/modules" / self.release / "updates/dkms"
    self.modules.mkdir(parents=True)
    for name in I.MODULES:
      (self.modules / (name + ".ko.zst")).write_bytes((name + " exact module bytes").encode())
    self.firmware = self.root / "usr/lib/firmware/brcm"
    self.firmware.mkdir(parents=True)
    for suffix in I.SUFFIXES:
      (self.firmware / (I.FORMOSA + suffix)).write_bytes(("firmware " + suffix).encode())
    self.query_calls = []
    self.select = {}

  def query(self, argv):
    self.query_calls.append(argv)
    if argv[1] == "-b":
      name = argv[-1]
      return self.select.get(name, str(self.root / "lib/modules" / self.release / "updates/dkms" / (name + ".ko.zst")))
    if argv[2] == "srcversion": return "A1B2C3D4E5F60718293A4B5C"
    if argv[2] == "vermagic": return self.release + " SMP preempt mod_unload"
    raise AssertionError("Unexpected command")

  def capture(self): return I.capture(self.root, self.release, query=self.query)

  def test_deterministic_exact_selection_and_complete_firmware_set(self):
    first, second = self.capture(), self.capture()
    self.assertEqual(first, second)
    self.assertEqual(first["protocol"], "omarchy-t2-root-driver-inventory-v1")
    self.assertEqual(set(first["modules"]), set(I.MODULES))
    self.assertEqual(len(first["firmware"]), 5)
    self.assertEqual(first["lib_alias"], "usr/lib")
    self.assertTrue(all(argv[0] == "/usr/bin/modinfo" for argv in self.query_calls))
    self.assertTrue(all(argv[2] == str(self.root) for argv in self.query_calls if argv[1] == "-b"))
    self.assertNotIn("safe", first)

  def test_same_srcversion_changed_bytes_are_detected(self):
    first = self.capture()
    (self.modules / "t2bce_core.ko.zst").write_bytes(b"different but same srcversion")
    second = self.capture()
    self.assertEqual(first["modules"]["t2bce_core"]["srcversion"], second["modules"]["t2bce_core"]["srcversion"])
    self.assertNotEqual(first["modules"]["t2bce_core"]["sha256"], second["modules"]["t2bce_core"]["sha256"])

  def test_selector_path_change_and_wrong_abi(self):
    first = self.capture()
    alternate = self.root / "usr/lib/modules" / self.release / "extra/brcmfmac.ko.zst"
    alternate.parent.mkdir()
    alternate.write_bytes((self.modules / "brcmfmac.ko.zst").read_bytes())
    self.select["brcmfmac"] = str(self.root / "lib/modules" / self.release / "extra/brcmfmac.ko.zst")
    second = self.capture()
    self.assertNotEqual(first["modules"]["brcmfmac"]["selected"], second["modules"]["brcmfmac"]["selected"])
    def wrong_abi(argv):
      if argv[1:3] == ("-F", "vermagic"): return "other-kernel SMP"
      return self.query(argv)
    with self.assertRaisesRegex(ValueError, "source/ABI"):
      I.capture(self.root, self.release, query=wrong_abi)

  def test_firmware_missing_additional_link_and_changed_target_bytes(self):
    baseline = self.capture()
    extra = self.firmware / "brcmfmac4377b3-pcie.apple,fiji.bin"
    extra.symlink_to(I.FORMOSA + ".bin")
    linked = self.capture()
    self.assertEqual(len(linked["firmware"]), 6)
    self.assertEqual(linked["firmware"][extra.name]["links"][0]["target"], I.FORMOSA + ".bin")
    self.assertNotEqual(baseline, linked)
    (self.firmware / (I.FORMOSA + ".bin")).write_bytes(b"changed target bytes")
    changed = self.capture()
    self.assertNotEqual(linked["firmware"][extra.name]["sha256"], changed["firmware"][extra.name]["sha256"])
    (self.firmware / (I.FORMOSA + ".bin")).unlink()
    with self.assertRaises((FileNotFoundError, ValueError)):
      self.capture()

  def test_escaping_firmware_link_and_fixture_root_escape_refuse(self):
    extra = self.firmware / "brcmfmac4377b3-escape.bin"
    extra.symlink_to("../../../../../../etc/passwd")
    with self.assertRaisesRegex(ValueError, "escaped"):
      self.capture()
    extra.unlink()
    self.select["brcmfmac"] = "/usr/lib/modules/" + self.release + "/updates/dkms/brcmfmac.ko.zst"
    with self.assertRaisesRegex(ValueError, "escaped its root"):
      self.capture()

  def test_fixture_usr_symlink_cannot_reach_host_tree(self):
    (self.root / "usr").rename(self.root / "fixture-usr")
    (self.root / "usr").symlink_to("/usr")
    with patch.object(I.os, "open", side_effect=AssertionError("must not open host module")):
      with self.assertRaisesRegex(ValueError, "nonsymlink inventory ancestry"):
        self.capture()

  def test_malformed_selection_release_alias_and_live_injection_refuse(self):
    for invalid in ("relative.ko", "//usr/lib/modules/x/a.ko", str(self.root) + "/lib/modules/../escape.ko", "x\ny"):
      with self.subTest(invalid=invalid):
        self.select["brcmfmac"] = invalid
        with self.assertRaises(ValueError): self.capture()
    self.select.clear()
    for release in (".", "..", "bad/release"):
      with self.assertRaises(ValueError): I.capture(self.root, release, query=self.query)
    (self.root / "lib").unlink()
    (self.root / "lib").symlink_to("/usr/lib")
    with self.assertRaisesRegex(ValueError, "alias"):
      self.capture()
    with self.assertRaisesRegex(ValueError, "installed live"):
      I.capture(Path("/"), self.release, query=self.query)

  def test_short_or_changed_read_refuses(self):
    path = self.modules / "brcmfmac.ko.zst"
    original = os.read
    calls = []
    def short(fd, count):
      calls.append(True)
      return b"x" if len(calls) == 1 else b""
    with patch.object(I.os, "read", side_effect=short), self.assertRaisesRegex(ValueError, "Short"):
      I._file(self.root, path, os.geteuid())
    def changed(fd, count):
      raw = original(fd, count)
      if raw: path.write_bytes(b"mutated in place")
      return raw
    with patch.object(I.os, "read", side_effect=changed), self.assertRaisesRegex(ValueError, "changed"):
      I._file(self.root, path, os.geteuid())

  def test_native_double_slash_lib_selection_normalizes_only_observed_form(self):
    selected = "//lib/modules/" + self.release + "/updates/dkms/brcmfmac.ko.zst"
    self.assertEqual(I._selected(Path("/"), self.release, "brcmfmac", selected),
                     Path("/usr/lib/modules") / self.release / "updates/dkms/brcmfmac.ko.zst")
    with self.assertRaisesRegex(ValueError, "double-slash"):
      I._selected(Path("/"), self.release, "brcmfmac", selected.replace("//lib", "//usr/lib"))

  def test_mid_capture_selection_change_is_detected(self):
    alternate = self.root / "usr/lib/modules" / self.release / "extra/brcmfmac.ko.zst"
    alternate.parent.mkdir()
    alternate.write_bytes((self.modules / "brcmfmac.ko.zst").read_bytes())
    counts = []
    def change(argv):
      if argv[1] == "-b" and argv[-1] == "brcmfmac":
        counts.append(True)
        if len(counts) == 3:
          return str(self.root / "lib/modules" / self.release / "extra/brcmfmac.ko.zst")
      return self.query(argv)
    with self.assertRaisesRegex(ValueError, "changed across inventory"):
      I.capture(self.root, self.release, query=change)


if __name__ == "__main__": unittest.main()
