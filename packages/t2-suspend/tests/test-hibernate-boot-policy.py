"""Offline source-default policy fixtures; no deployment, EFI or power calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module
P = load("default_policy", HERE / "hibernate/boot_policy.py")
PRODUCT = load("default_product", HERE / "hibernate/product.py")
PAIR = load("default_pair", HERE / "experiments/stage-hibernation-uki-pair.py")


class Policy(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name) / "root"
    self.root.mkdir(mode=0o700)
    images = {}
    for role in ("source", "restore"):
      raw = role.encode()
      images[role] = {"entry_id": PAIR.entry_id(role, P.digest(raw)), "sha256": P.digest(raw),
                      "blake2": hashlib.blake2b(raw).hexdigest(), "provenance_sha256": "f" * 64}
      self.write(PAIR.IMAGES[role], raw)
    self.write("boot/EFI/Linux/omarchy_linux-t2.efi", b"production")
    production_path = "path: boot():/EFI/Linux/omarchy_linux-t2.efi#" + hashlib.blake2b(b"production").hexdigest() + "\n"
    original = ("default_entry: 2\n" + production_path).encode()
    self.write(PAIR.BACKUP, original)
    before = "timeout: 3\ndefault_entry: 2\n" + production_path + PAIR.BEGIN + "\n"
    for role in images:
      before += "/" + images[role]["entry_id"] + "\npath: boot():/EFI/Linux/" + PAIR.IMAGES[role].name + "#" + images[role]["blake2"] + "\n"
    self.before = (before + PAIR.END + "\n").encode()
    self.receipt = {"kernel_policy": "production-linux-unchanged", "images": images,
      "original_limine_sha256": P.digest(original), "staged_limine_sha256": P.digest(self.before),
      "production_uki_sha256": P.digest(b"production")}
    self.raw = json.dumps(self.receipt).encode()
    self.write(P.RECEIPT, self.raw)
    self.write(P.LIMINE, self.before)
    self.write(PAIR.SINGLE.ENTRIES, b"\x06\0\0\0" + ("\0".join(item["entry_id"] for item in images.values()) + "\0").encode("utf-16-le"))
    self.proposal = P.prepare(self.before, self.raw)
    self.policy = {**self.proposal["policy"], "approved": True}
    self.config = {"staged_receipt_sha256": P.digest(self.raw)}
    self.report = {"manifest": {role + "_sha256": images[role]["sha256"] for role in images},
      "audited_details": {"production_uki_sha256": P.digest(b"production"), "provenance_sha256": {role: "f" * 64 for role in images}}}

  def write(self, relative, raw):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    for directory in (path.parent, *path.parent.parents):
      if directory == self.root.parent: break
      directory.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o600)
    return path

  def activate_fixture(self):
    self.write(P.POLICY, json.dumps(self.policy).encode())
    self.write(P.BACKUP, self.before)
    self.write(P.LIMINE, self.proposal["after"])

  def test_prepare_is_pure_unapproved_exact_single_line_change(self):
    self.assertFalse(self.proposal["policy"]["approved"])
    self.assertFalse(self.proposal["physical_permission"])
    self.assertEqual((self.root / P.LIMINE).read_bytes(), self.before)
    self.assertEqual((self.root / P.RECEIPT).read_bytes(), self.raw)
    self.assertEqual(P.normalize_source_default(self.proposal["after"], self.receipt), self.before)
    with self.assertRaises(ValueError): P.validate(self.proposal["policy"], self.before, self.proposal["after"], self.raw)

  def test_comments_before_active_line_are_preserved(self):
    comment = ("#default_entry: 2\n#default_entry: " + self.policy["source_entry_id"] + "\n").encode()
    before = comment + self.before
    raw = json.dumps({**self.receipt, "staged_limine_sha256": P.digest(before)}).encode()
    proposal = P.prepare(before, raw)
    self.assertTrue(proposal["after"].startswith(comment))
    self.assertEqual(P.normalize_source_default(proposal["after"], json.loads(raw)), before)

  def test_absent_policy_stock_strict_and_product_only_overlay(self):
    self.assertFalse(P.verify(self.root, P.digest(self.raw)))
    PRODUCT.verify_deployment(self.root, self.config, self.report)
    self.activate_fixture()
    self.assertTrue(P.verify(self.root, P.digest(self.raw)))
    PRODUCT.verify_deployment(self.root, self.config, self.report)
    with self.assertRaises(ValueError): PRODUCT.TRIAL.verify_deployment(self.root, self.config, self.report)
    with self.assertRaises(ValueError): PAIR.verify_staged(self.root, self.receipt)
    self.assertEqual((self.root / P.RECEIPT).read_bytes(), self.raw)

  def test_live_product_rejects_a_replaced_or_historical_deployment_callback(self):
    # The check rejects callbacks before reading live files or acquiring locks.
    for callback in (PRODUCT.TRIAL.verify_deployment, lambda *args: None):
      with self.assertRaisesRegex(ValueError, "No injected live"):
        PRODUCT.check({}, None, {}, ledger=None, archive_directory=None, root="/", deployment_check=callback)

  def test_full_checks_still_reject_image_production_originalbackup_and_efi_changes(self):
    self.activate_fixture()
    paths = (PAIR.IMAGES["source"], PAIR.IMAGES["restore"], Path("boot/EFI/Linux/omarchy_linux-t2.efi"), PAIR.BACKUP)
    for relative in paths:
      with self.subTest(relative=relative):
        path = self.root / relative
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaises(ValueError): PRODUCT.verify_deployment(self.root, self.config, self.report)
        path.write_bytes(original)
    self.write(PAIR.SINGLE.DEFAULT, b"persistent EFI default")
    with self.assertRaises(ValueError): PRODUCT.verify_deployment(self.root, self.config, self.report)

  def test_every_foreign_default_duplicate_case_and_unrelated_byte_rejected(self):
    line = ("default_entry: " + self.policy["source_entry_id"] + "\n").encode()
    alternatives = (b"default_entry: 9\n", b"default_entry: 2\n", b"default_entry: foreign\n",
      ("default_entry: " + self.receipt["images"]["restore"]["entry_id"] + "\n").encode(),
      line.replace(b"default_entry", b"Default_Entry"), b" " + line, line + b"default_entry: 2\n")
    for alternative in alternatives:
      with self.assertRaises(ValueError): P.normalize_source_default(self.proposal["after"].replace(line, alternative), self.receipt)
    for actual in (self.proposal["after"] + b"#changed\n", self.proposal["after"].replace(b"timeout: 3", b"timeout: 0")):
      with self.assertRaises(ValueError): P.validate(self.policy, self.before, actual, self.raw)
    for key in (b"DEFAULT_ENTRY: 2\n", b"default_entry: 2\r\n", b"default_entry: 2\nremember_last_entry: yes\n"):
      before = self.before.replace(b"default_entry: 2\n", key)
      receipt = {**self.receipt, "staged_limine_sha256": P.digest(before)}
      with self.assertRaises(ValueError): P.prepare(before, json.dumps(receipt).encode())

  def test_policy_pins_approval_unknown_fields_and_receipt_drift_rejected(self):
    for change in ({"approved": 1}, {"approved": False}, {"staged_receipt_sha256": "0" * 64},
      {"before_limine_sha256": "0" * 64}, {"after_limine_sha256": "0" * 64}, {"source_entry_id": "restore"}, {"extra": True}):
      with self.assertRaises(ValueError): P.validate({**self.policy, **change}, self.before, self.proposal["after"], self.raw)
    with self.assertRaises(ValueError): P.validate(self.policy, self.before, self.proposal["after"], self.raw + b" ")

  def test_private_backup_missing_symlink_writable_or_linked_evidence_rejected(self):
    self.activate_fixture()
    for relative in (P.POLICY, P.BACKUP, P.RECEIPT, P.LIMINE):
      with self.subTest(relative=relative):
        path = self.root / relative
        original = path.read_bytes()
        path.chmod(0o666)
        with self.assertRaises(ValueError): P.verify(self.root, P.digest(self.raw))
        path.chmod(0o600)
        linked = path.with_name(path.name + ".linked")
        os.link(path, linked)
        with self.assertRaises(ValueError): P.verify(self.root, P.digest(self.raw))
        linked.unlink()
        target = path.with_name(path.name + ".retained")
        path.rename(target)
        path.symlink_to(target.name)
        with self.assertRaises((ValueError, OSError)): P.verify(self.root, P.digest(self.raw))
        path.unlink()
        target.rename(path)
    (self.root / P.BACKUP).unlink()
    with self.assertRaises(FileNotFoundError): P.verify(self.root, P.digest(self.raw))

  def test_symlinked_directory_noncanonical_root_and_duplicate_json_fail(self):
    self.activate_fixture()
    with self.assertRaises(ValueError): P.verify(self.root / "..", P.digest(self.raw))
    state = self.root / P.STATE
    retained = state.with_name("retained-state")
    state.rename(retained)
    state.symlink_to(retained.name)
    with self.assertRaises(ValueError): P.verify(self.root, P.digest(self.raw))
    state.unlink()
    retained.rename(state)
    (self.root / P.POLICY).write_bytes(b'{"approved":true,"approved":false}')
    with self.assertRaises(ValueError): P.verify(self.root, P.digest(self.raw))

  def test_fifo_evidence_reads_are_nonblocking_and_fail_closed(self):
    self.activate_fixture()
    for relative in (P.POLICY, P.BACKUP, P.RECEIPT, P.LIMINE):
      path = self.root / relative
      original = path.read_bytes()
      path.unlink()
      os.mkfifo(path, mode=0o600)
      with self.assertRaises(ValueError): P.verify(self.root, P.digest(self.raw))
      path.unlink()
      self.write(relative, original)


if __name__ == "__main__": unittest.main()
