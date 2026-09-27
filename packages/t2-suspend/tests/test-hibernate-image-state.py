"""Synthetic read-only image-header checks; never open the host resume block."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("image_state_fixture", HERE / "hibernate/image_state.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class ImageState(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name) / "root"
    (self.root / "dev/mapper").mkdir(parents=True)
    page = bytearray(4096)
    page[1024] = 1
    page[-10:] = b"SWAPSPACE2"
    (self.root / "dev/dm-0").write_bytes(b"\0" * 4096 + page)
    (self.root / "dev/mapper/root").symlink_to("../dm-0")
    (self.root / "sys/power").mkdir(parents=True)
    (self.root / "sys/power/resume").write_text("253:0\n")
    (self.root / "sys/power/resume_offset").write_text("1\n")
    self.resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1}
    self.calls = []

  def query(self, argv):
    self.calls.append(argv)
    if argv[0] == "/usr/bin/btrfs": return "1"
    return "/dev/mapper/root[/@] btrfs"

  def check(self, *, identity=lambda fd: (253, 0), query=None):
    return S.require_no_image(self.root, self.resume, query=self.query if query is None else query,
                              fixture_identity=identity)

  def header(self, signature):
    path = self.root / "dev/dm-0"
    raw = path.read_bytes()
    path.write_bytes(raw[:8192 - 10] + signature)

  def test_exact_normal_header_and_stable_readback(self):
    result = self.check()
    self.assertEqual(result["classification"], "no-image-at-qualified-resume-page")
    self.assertEqual(result["devnum"], "253:0")
    self.assertEqual(len(self.calls), 4)
    self.assertEqual(result["offset"], 1)

  def test_pending_and_unknown_signatures_refuse(self):
    for signature in (b"S1SUSPEND\0", b"SWAP-SPACE", b"??????????"):
      with self.subTest(signature=signature):
        self.header(signature)
        with self.assertRaisesRegex(ValueError, "Pending or unknown"):
          self.check()

  def test_swapspace2_without_exact_version_one_refuses(self):
    path = self.root / "dev/dm-0"
    raw = bytearray(path.read_bytes())
    raw[4096 + 1024] = 0
    path.write_bytes(raw)
    with self.assertRaisesRegex(ValueError, "Pending or unknown"):
      self.check()

  def test_wrong_sysfs_or_btrfs_offset_refuses_before_read(self):
    (self.root / "sys/power/resume_offset").write_text("2\n")
    with self.assertRaisesRegex(ValueError, "kernel resume target"):
      self.check()
    (self.root / "sys/power/resume_offset").write_text("1\n")
    with self.assertRaisesRegex(ValueError, "Btrfs swapfile mapping"):
      self.check(query=lambda argv: "2" if argv[0] == "/usr/bin/btrfs" else "/dev/mapper/root[/@] btrfs")
    (self.root / "sys/power/resume").write_text("253:1\n")
    with self.assertRaisesRegex(ValueError, "kernel resume target"):
      self.check()

  def test_wrong_opened_descriptor_or_backing_refuses(self):
    with self.assertRaisesRegex(ValueError, "opened resume identity"):
      self.check(identity=lambda fd: (253, 1))
    with self.assertRaisesRegex(ValueError, "qualified encrypted Btrfs"):
      self.check(query=lambda argv: "1" if argv[0] == "/usr/bin/btrfs" else "/dev/other xfs")

  def test_target_replacement_after_read_refuses(self):
    original = os.pread
    path = self.root / "dev/dm-0"
    def replaced(fd, length, offset):
      page = original(fd, length, offset)
      path.unlink()
      path.write_bytes(b"\0" * 8192)
      return page
    with patch.object(S.os, "pread", side_effect=replaced), self.assertRaisesRegex(ValueError, "replaced"):
      self.check()

  def test_truncated_page_refuses(self):
    (self.root / "dev/dm-0").write_bytes(b"\0" * 4096)
    with self.assertRaisesRegex(ValueError, "Truncated"):
      self.check()

  def test_synthetic_dev_symlink_cannot_escape_to_host(self):
    (self.root / "dev").rename(self.root / "fixture-dev")
    (self.root / "dev").symlink_to("/dev")
    with patch.object(S.os, "open", side_effect=AssertionError("must never open host device")):
      with self.assertRaisesRegex(ValueError, "nonsymlink mapper"):
        self.check()

  def test_malformed_inputs_and_live_workspace_refuse(self):
    with self.assertRaisesRegex(ValueError, "qualified resume target"):
      S.require_no_image(self.root, {**self.resume, "offset": True}, query=self.query,
                         fixture_identity=lambda fd: (253, 0))
    with self.assertRaisesRegex(ValueError, "Synthetic root"):
      S.require_no_image(self.root, self.resume)
    with self.assertRaisesRegex(ValueError, "root-private live"):
      S.require_no_image(Path("/"), self.resume, query=self.query, fixture_identity=lambda fd: (253, 0))


if __name__ == "__main__": unittest.main()
