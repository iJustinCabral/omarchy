#!/usr/bin/python3
"""Generation-aware successful pair slot cleanup against a synthetic root; no real EFI."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


cleanup = load("successful_pair_cleanup", Path(__file__).parents[1] / "experiments/cleanup-successful-pair-slots.py")
PAIR, EFI = cleanup.PAIR, cleanup.EFI
BOOT = "11111111-2222-4333-8444-555555555555"
KERNEL = "7.2.7-arch1-Watanare-T2-2-t2"
LOADER = cleanup.HOST.HOST.LOADER_GUID


class Cleanup(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.root = Path(self.tmp.name)
    self.write("proc/sys/kernel/random/boot_id", BOOT)
    self.write("proc/sys/kernel/osrelease", KERNEL)
    self.write("proc/modules", "t2bce_core 0 0 - Live 0")
    (self.root / "sys/module").mkdir(parents=True)
    self.write("proc/self/mounts", "/dev/mapper/root / btrfs rw,subvol=/@ 0 0")
    images, receipt = {}, {"images": {}, "runtime_stack_sha256": "c" * 64}
    for role, relative in {**PAIR.IMAGES, "production": Path("boot/EFI/Linux/omarchy_linux-t2.efi")}.items():
      raw = ("synthetic " + role).encode()
      self.write(relative, raw)
      images[role] = hashlib.sha256(raw).hexdigest()
      if role != "production":
        receipt["images"][role] = {"sha256": images[role], "blake2": hashlib.blake2b(raw).hexdigest(), "entry_id": PAIR.entry_id(role, images[role])}
    receipt["production_uki_sha256"] = images["production"]
    before = "default_entry: 2\n/Omarchy.linux-t2\n"
    limine = before + PAIR.BEGIN + "\n"
    for role in ("source", "restore"):
      limine += PAIR.entry_block(role, receipt["images"][role]["sha256"], receipt["images"][role]["blake2"])
    limine += PAIR.END + "\n"
    self.write(PAIR.BACKUP, before)
    self.write(PAIR.SINGLE.LIMINE, limine)
    receipt.update(original_limine_sha256=hashlib.sha256(before.encode()).hexdigest(), staged_limine_sha256=hashlib.sha256(limine.encode()).hexdigest())
    self.receipt = receipt
    self.vector = cleanup.pair_vector(receipt)
    self.stages = cleanup.canonical_stages(self.vector)
    for name, raw in self.stages.items(): self.write(EFI / name, raw)
    self.select(receipt["images"]["restore"]["entry_id"])
    attempt = {"boot_id": BOOT, "transition_vector": self.vector, "state": "returned-and-cleaned", "real_s4_attempted": True,
               "hibernate_attempted": True, "source_uki_sha256": images["source"], "restore_uki_sha256": images["restore"],
               "runtime_stack_sha256": receipt["runtime_stack_sha256"], "kernel_release": KERNEL,
               "source_entry_id": receipt["images"]["source"]["entry_id"], "restore_entry_id": receipt["images"]["restore"]["entry_id"],
               "recovery_method": "operator-attended-cold-power", "postwrite-efi_stage": 4, "restore-efi_stage": 7, "restore-hook-efi_stage": 2}
    markers = {name: raw.hex() for name, raw in self.stages.items()}
    docs = {
      "attempt.json": attempt,
      "cold-pci-restore-return-raw.json": {"boot_id": BOOT, "read_errors": [], "abort_witnesses": [], "markers": markers,
                                           "efi_overrides": {"LoaderEntryDefault": None, "LoaderEntryOneShot": None}},
      "cold-pci-restored-source-witness.json": {
        "continuity": "conditional-on-trusted-original-source-runner-process",
        "proof": {"classification": "source-return-evidence-valid", "post_cleanup_health_valid": True, "boot_id": BOOT,
                  "transition_vector": self.vector, "return_nonce": "n", "usable_hibernation_qualified": False},
        "observation": {"return_capture": {"markers": markers}},
        "expected": {"boot_id": BOOT, "transition_vector": self.vector, "source_uki_sha256": images["source"], "restore_uki_sha256": images["restore"],
                     "production_uki_sha256": images["production"], "runtime_stack_sha256": receipt["runtime_stack_sha256"]}}}
    live = cleanup.VECTORS / self.vector
    for name in cleanup.ATTEMPT_FILES: self.private(live / "attempts" / BOOT / name, json.dumps(docs.get(name, {"synthetic": name}), sort_keys=True))
    self.private(live / "s4-attempted", BOOT + "\n")
    self.private(PAIR.STATE / "receipt.json", json.dumps(receipt, sort_keys=True))
    self.private(cleanup.ACCEPTANCE, json.dumps({
      "kind": "postwrite-restore-efi-attended-s4-v3", "boot_id": BOOT, "transition_vector": self.vector, "module_sha256": "a" * 64,
      "restore_module_sha256": "b" * 64, "production_uki_sha256": images["production"], "method": "operator-attended-cold-power",
      "accepted": True, "source_efi_variable": cleanup.SOURCE, "restore_efi_variable": cleanup.RESTORE}))
    self.attempt_path = self.root / live / "attempts" / BOOT / "attempt.json"
    self.docs = docs

  def write(self, relative, raw):
    target = self.root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw if type(raw) is bytes else raw.encode())

  def private(self, relative, raw):
    self.write(relative, raw)
    (self.root / relative).chmod(0o600)

  def select(self, entry):
    self.write(EFI / ("LoaderEntrySelected-" + LOADER), b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le"))

  def rewrite_attempt(self, **changes):
    self.private(self.attempt_path.relative_to(self.root), json.dumps({**self.docs["attempt.json"], **changes}, sort_keys=True))

  def archive(self):
    return self.root / cleanup.ARCHIVE_ROOT / self.vector

  def slot(self, name): return self.root / EFI / name

  def test_validate_is_readonly(self):
    before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
    self.assertEqual(cleanup.validate(self.root, self.vector)["vector"], self.vector)
    self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())

  def test_execute_archives_then_deletes_only_two_slots_and_is_idempotent(self):
    originals = {p: p.read_bytes() for p in (self.root / cleanup.VECTORS).rglob("*") if p.is_file()}
    result = cleanup.execute(self.root, self.vector)
    self.assertTrue(result["slots_cleared"])
    for name in cleanup.SLOTS:
      self.assertFalse(self.slot(name).exists())
      self.assertEqual((self.archive() / ("raw-" + name)).read_bytes(), self.stages[name])
    for name in cleanup.hooks(self.vector): self.assertEqual(self.slot(name).read_bytes(), self.stages[name])
    for p, raw in originals.items(): self.assertEqual(p.read_bytes(), raw)
    self.assertEqual(oct(self.archive().stat().st_mode & 0o777), "0o700")
    self.assertTrue((self.archive() / "vector-s4-attempted").is_file())
    self.assertEqual(cleanup.execute(self.root, self.vector), result)
    self.assertEqual(cleanup.validate(self.root, self.vector), result)

  def test_later_ordinary_source_boot_is_accepted_and_wrong_selection_refused(self):
    self.write("proc/sys/kernel/random/boot_id", "99999999-2222-4333-8444-555555555555")
    with self.assertRaises(ValueError): cleanup.validate(self.root, self.vector)  # restore still selected on a new boot
    self.select(self.receipt["images"]["source"]["entry_id"])
    cleanup.execute(self.root, self.vector)
    self.assertFalse(self.slot(cleanup.SOURCE).exists())

  def test_wrong_vector_and_wrong_kernel_refused(self):
    for vector in ("0" * 64, "xyz", self.vector.upper()):
      with self.assertRaises(ValueError): cleanup.execute(self.root, vector)
    self.write("proc/sys/kernel/osrelease", "7.2.8-other")
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.assertTrue(self.slot(cleanup.SOURCE).exists())
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())

  def test_restaged_pair_refused(self):
    self.receipt["images"]["source"]["sha256"] = "d" * 64
    self.private(PAIR.STATE / "receipt.json", json.dumps(self.receipt, sort_keys=True))
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)

  def test_failed_ambiguous_or_unreconciled_attempt_refused(self):
    for changes in ({"state": "transition-failed"}, {"state": "cleanup-failed"}, {"real_s4_attempted": False},
                    {"cleanup_errors": ["x"]}, {"error": "x"}, {"postwrite-efi_stage": 3}, {"restore-efi_stage": 6},
                    {"restore-hook-efi_stage": 1}, {"recovery_method": "other"}, {"kernel_release": "7.2.6"}):
      self.rewrite_attempt(**changes)
      with self.assertRaises(ValueError, msg=str(changes)): cleanup.execute(self.root, self.vector)
    self.rewrite_attempt()
    witness = self.docs["cold-pci-restored-source-witness.json"]
    bad = json.loads(json.dumps(witness))
    bad["proof"]["classification"] = "ambiguous"
    self.private(cleanup.VECTORS / self.vector / "attempts" / BOOT / "cold-pci-restored-source-witness.json", json.dumps(bad, sort_keys=True))
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())

  def test_missing_evidence_refused_without_writes(self):
    live = self.root / cleanup.VECTORS / self.vector
    for relative in ("attempts/%s/cold-pci-restored-source-witness.json" % BOOT, "attempts/%s/cold-pci-restore-return-raw.json" % BOOT, "s4-attempted"):
      target = live / relative
      raw = target.read_bytes()
      target.unlink()
      with self.assertRaises((ValueError, OSError)): cleanup.execute(self.root, self.vector)
      self.private(target.relative_to(self.root), raw)
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())

  def test_variable_contents_must_equal_recorded_values(self):
    for name in (*cleanup.SLOTS, *cleanup.hooks(self.vector)):
      raw = self.slot(name).read_bytes()
      self.slot(name).write_bytes(raw[:-1] + b"\x05")
      with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
      self.slot(name).write_bytes(raw)
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())
    self.assertTrue(self.slot(cleanup.RESTORE).exists())

  def test_overrides_and_loaded_writers_refused(self):
    self.write(EFI / ("LoaderEntryOneShot-" + LOADER), b"x")
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.slot("LoaderEntryOneShot-" + LOADER).unlink()
    self.write("proc/modules", "mba_hibernate_efi_postwrite_marker 0 0 - Live 0")
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)

  def test_changed_staged_image_refused(self):
    self.write(PAIR.IMAGES["restore"], "tampered")
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)

  def test_crash_after_unlink_before_absent_record_reruns_to_completion(self):
    def crash(target, raw):
      target.unlink()
      raise OSError("synthetic death after unlink")
    with self.assertRaises(OSError): cleanup.execute(self.root, self.vector, remover=crash)
    self.assertFalse(self.slot(cleanup.SOURCE).exists())
    self.assertTrue(self.slot(cleanup.RESTORE).exists())
    self.assertEqual(cleanup.validate(self.root, self.vector)["vector"], self.vector)
    result = cleanup.execute(self.root, self.vector)
    self.assertTrue(result["slots_cleared"])
    self.assertFalse(self.slot(cleanup.RESTORE).exists())

  def test_crash_during_archive_write_reruns(self):
    with patch.object(cleanup.V16, "durable_new", side_effect=OSError("synthetic archive failure")):
      with self.assertRaises(OSError): cleanup.execute(self.root, self.vector)
    for name in cleanup.SLOTS: self.assertTrue(self.slot(name).exists())
    (self.archive() / ".tmp-receipt.json").write_bytes(b"partial")
    self.assertTrue(cleanup.execute(self.root, self.vector)["slots_cleared"])

  def test_slot_removed_by_someone_else_without_journal_refused(self):
    self.slot(cleanup.SOURCE).unlink()
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.assertFalse((self.root / cleanup.ARCHIVE_ROOT).exists())

  def test_tampered_archive_blocks_resume_and_reappearing_slot_refused(self):
    def crash(target, raw):
      target.unlink()
      raise OSError("synthetic")
    with self.assertRaises(OSError): cleanup.execute(self.root, self.vector, remover=crash)
    (self.archive() / "receipt.json").write_bytes(b"foreign")
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.assertTrue(self.slot(cleanup.RESTORE).exists())
    (self.archive() / "receipt.json").write_bytes(self.docs and (self.root / PAIR.STATE / "receipt.json").read_bytes())
    (self.archive() / "receipt.json").chmod(0o600)
    cleanup.execute(self.root, self.vector)
    self.write(EFI / cleanup.SOURCE, self.stages[cleanup.SOURCE])
    with self.assertRaises(ValueError): cleanup.validate(self.root, self.vector)

  def test_symlinked_slot_refused(self):
    target = self.slot(cleanup.SOURCE)
    raw = target.read_bytes()
    target.unlink()
    foreign = self.root / "foreign"
    foreign.write_bytes(raw)
    target.symlink_to(foreign)
    with self.assertRaises(ValueError): cleanup.execute(self.root, self.vector)
    self.assertEqual(foreign.read_bytes(), raw)


if __name__ == "__main__": unittest.main()
