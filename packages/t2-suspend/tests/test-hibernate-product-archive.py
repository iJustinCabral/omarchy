#!/usr/bin/python3
"""Product byte archival fault tests; all filesystem mutations use tempdirs."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import uuid


spec = importlib.util.spec_from_file_location("product_archive", Path(__file__).parents[1] / "hibernate/evidence_archive.py")
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)
tx = archive.TX


class Archives(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.parent = Path(self.temp.name) / "archives"
    self.parent.mkdir(mode=0o700)
    self.ledger = tx.Ledger(Path(self.temp.name) / "ledger")
    manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1",
                **{key: str(index) * 64 for index, key in enumerate(tx.PINS, 1)}}
    self.ledger.configure(manifest)
    self.ledger.qualify({"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(manifest),
                         "evidence_sha256": "a" * 64, "qualified": True})
    cycle = self.ledger.begin(str(uuid.uuid4()))
    self.evidence = {name: b"\x00raw evidence\xff " + name.encode() for name in archive.REQUIRED_NAMES}
    for action in ("prepared", "returned"):
      evidence_sha256 = archive._digest(self.evidence["source-return-witness.bin"]) if action == "returned" else "b" * 64
      cycle = self.ledger.advance(cycle["cycle_id"], action, evidence_sha256)
    self.cycle = cycle
    self.target = self.parent / ("cycle-" + cycle["cycle_id"])

  def tearDown(self):
    self.temp.cleanup()

  def create(self):
    return archive.create_archive(self.parent, self.cycle, self.evidence)

  def test_exact_bytes_private_modes_readback_and_ledger_binding(self):
    receipt = self.create()
    self.assertFalse(receipt["slot_clear_authorized"])
    self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
    for name, raw in self.evidence.items():
      self.assertEqual((self.target / name).read_bytes(), raw)
      self.assertEqual(stat.S_IMODE((self.target / name).stat().st_mode), 0o600)
      self.assertEqual(receipt["files"][name]["sha256"], archive._digest(raw))
    self.assertEqual(receipt, archive.verify_archive(self.parent, self.cycle, receipt["manifest_sha256"]))
    updated = self.ledger.advance(self.cycle["cycle_id"], "archive", receipt["manifest_sha256"])
    self.assertEqual(updated["archive_evidence_sha256"], receipt["manifest_sha256"])
    self.assertEqual(receipt, archive.verify_archive(self.parent, updated, receipt["manifest_sha256"]))

  def test_optional_acceptance_is_preserved(self):
    self.evidence["recovery-acceptance.bin"] = b"attended acceptance"
    self.assertIn("recovery-acceptance.bin", self.create()["files"])

  def test_witness_bytes_must_match_ledger_return_receipt(self):
    evidence = {**self.evidence, "source-return-witness.bin": b"unrelated witness"}
    with self.assertRaises(ValueError):
      archive.create_archive(self.parent, self.cycle, evidence)
    self.assertFalse(self.target.exists())
    self.create()
    witness_path = self.target / "source-return-witness.bin"
    witness_path.write_bytes(evidence[witness_path.name])
    manifest_path = self.target / archive.COMPLETION
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"][witness_path.name] = {"size": len(evidence[witness_path.name]),
                                          "sha256": archive._digest(evidence[witness_path.name])}
    manifest_path.write_bytes(archive._encoded(manifest))
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)

  def test_fixed_names_and_only_nonempty_bounded_bytes(self):
    mutations = ({"../escape": b"bad"}, {"/tmp/escape": b"bad"}, {"other.bin": b"bad"},
                 {"source-stage.bin": "/sys/firmware/efi/efivars/example"},
                 {"source-stage.bin": b""}, {"source-stage.bin": b"x" * (archive.MAX_BYTES + 1)},
                 {"source-stage.bin": bytearray(b"bytes")})
    for mutation in mutations:
      with self.subTest(mutation=list(mutation)):
        with self.assertRaises(ValueError):
          archive.create_archive(self.parent, self.cycle, {**self.evidence, **mutation})
    missing = dict(self.evidence)
    missing.pop("cleanup-health.bin")
    with self.assertRaises(ValueError):
      archive.create_archive(self.parent, self.cycle, missing)
    self.assertFalse(self.target.exists())

  def test_exact_cycle_state_identity_and_completion_binding(self):
    for change in ({"state": "prepared"}, {"vector": "0" * 64}, {"prefix": "0" * 24},
                   {"qualification_vector": "0" * 64}, {"original_boot_id": str(uuid.uuid4())}):
      with self.subTest(change=change):
        with self.assertRaises(ValueError):
          archive.create_archive(self.parent, {**self.cycle, **change}, self.evidence)
    receipt = self.create()
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle, "f" * 64)
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, {**self.cycle, "returned_evidence_sha256": "f" * 64})
    manifest_path = self.target / archive.COMPLETION
    manifest = json.loads(manifest_path.read_bytes())
    manifest["binding"]["original_boot_id"] = str(uuid.uuid4())
    manifest_path.write_bytes(archive._encoded(manifest))
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle, receipt["manifest_sha256"])

  def test_complete_and_partial_targets_cannot_replay(self):
    self.create()
    with self.assertRaises(FileExistsError):
      self.create()
    another = self.parent / "partial-parent"
    another.mkdir(mode=0o700)
    (another / self.target.name).mkdir(mode=0o700)
    with self.assertRaises(FileExistsError):
      archive.create_archive(another, self.cycle, self.evidence)
    with self.assertRaises(FileNotFoundError):
      archive.verify_archive(another, self.cycle)

  def test_unsafe_parent_missing_relative_root_and_symlinked_ancestor(self):
    for directory in (Path("relative"), Path("/"), self.parent / "missing"):
      with self.assertRaises((ValueError, OSError)):
        archive.create_archive(directory, self.cycle, self.evidence)
    self.parent.chmod(0o755)
    with self.assertRaises(ValueError):
      self.create()
    self.parent.chmod(0o700)
    link = Path(self.temp.name) / "linked"
    link.symlink_to(self.parent, target_is_directory=True)
    with self.assertRaises(OSError):
      archive.create_archive(link, self.cycle, self.evidence)
    with self.assertRaises(ValueError):
      archive.create_archive(self.parent / ".." / "archives", self.cycle, self.evidence)

  def test_symlinked_target_or_evidence_refuses(self):
    other = Path(self.temp.name) / "other"
    other.mkdir(mode=0o700)
    self.target.symlink_to(other, target_is_directory=True)
    with self.assertRaises(FileExistsError):
      self.create()
    with self.assertRaises(OSError):
      archive.verify_archive(self.parent, self.cycle)
    self.target.unlink()
    self.create()
    path = self.target / "source-stage.bin"
    path.unlink()
    path.symlink_to(self.target / "restore-stage.bin")
    with self.assertRaises(OSError):
      archive.verify_archive(self.parent, self.cycle)

  def test_wrong_owner_private_modes_and_hard_links_refuse(self):
    with mock.patch.object(archive.os, "geteuid", return_value=os.geteuid() + 1):
      with self.assertRaises(ValueError):
        self.create()
    self.create()
    path = self.target / "source-stage.bin"
    path.chmod(0o644)
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)
    path.chmod(0o600)
    os.link(path, Path(self.temp.name) / "linked-evidence")
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)

  def test_hash_mismatch_missing_bytes_and_unexpected_entry_refuse(self):
    self.create()
    path = self.target / "source-stage.bin"
    path.write_bytes(b"corrupted")
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)
    path.write_bytes(self.evidence[path.name])
    path.unlink()
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)
    path.write_bytes(self.evidence[path.name])
    path.chmod(0o600)
    (self.target / "orphan").touch(mode=0o600)
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)

  def test_partial_evidence_failure_never_publishes_completion(self):
    original = archive._write_private
    count = 0
    def fail_second(directory, name, raw):
      nonlocal count
      count += 1
      if count == 2:
        raise OSError("injected evidence failure")
      return original(directory, name, raw)
    with mock.patch.object(archive, "_write_private", side_effect=fail_second):
      with self.assertRaises(OSError):
        self.create()
    self.assertFalse((self.target / archive.COMPLETION).exists())
    with self.assertRaises(FileExistsError):
      self.create()
    with self.assertRaises(FileNotFoundError):
      archive.verify_archive(self.parent, self.cycle)

  def test_readback_failure_never_publishes_completion(self):
    with mock.patch.object(archive, "_read_private", return_value=b"incorrect"):
      with self.assertRaises(ValueError):
        self.create()
    self.assertFalse((self.target / archive.COMPLETION).exists())

  def test_byte_fsync_failure_never_publishes_completion(self):
    original = archive.os.fsync
    def fail_regular(fd):
      if stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError("injected file fsync failure")
      return original(fd)
    with mock.patch.object(archive.os, "fsync", side_effect=fail_regular):
      with self.assertRaises(OSError):
        self.create()
    self.assertFalse((self.target / archive.COMPLETION).exists())
    with self.assertRaises(FileExistsError):
      self.create()

  def test_publication_interruption_refuses_incomplete_completion(self):
    original = archive.os.unlink
    def fail_pending(path, *args, **kwargs):
      if path == archive.PENDING:
        raise OSError("injected completion publication interruption")
      return original(path, *args, **kwargs)
    with mock.patch.object(archive.os, "unlink", side_effect=fail_pending):
      with self.assertRaises(OSError):
        self.create()
    self.assertTrue((self.target / archive.PENDING).exists())
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)

  def test_directory_syncs_precede_publication_and_final_receipt(self):
    events = []
    original_sync = archive.os.fsync
    original_link = archive.os.link
    def synced(fd):
      events.append("file-sync" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory-sync")
      return original_sync(fd)
    def linked(*args, **kwargs):
      events.append("publish")
      return original_link(*args, **kwargs)
    with mock.patch.object(archive.os, "fsync", side_effect=synced), mock.patch.object(archive.os, "link", side_effect=linked):
      self.create()
    publication = events.index("publish")
    self.assertEqual(events[:publication].count("file-sync"), len(self.evidence) + 1)
    self.assertGreaterEqual(events[:publication].count("directory-sync"), 3)
    self.assertGreaterEqual(events[publication + 1:].count("directory-sync"), 2)

  def test_duplicate_json_and_noncanonical_manifest_refuse(self):
    self.create()
    manifest_path = self.target / archive.COMPLETION
    original = manifest_path.read_bytes()
    manifest_path.write_bytes(original[:-1] + b',"protocol":"duplicate"}')
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)
    manifest_path.write_bytes(original + b"\n")
    with self.assertRaises(ValueError):
      archive.verify_archive(self.parent, self.cycle)


if __name__ == "__main__":
  unittest.main()
