#!/usr/bin/python3
"""Pinned historical-success cleanup fixtures; no real EFI or command calls."""
import hashlib
import errno
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


directory = Path(__file__).parent
cleanup = load("successful_v16_cleanup", directory.parent / "experiments/cleanup-successful-v16-slots.py")
fixture = load("successful_v16_backend_fixture", directory / "test-hibernate-product-host-backend.py")


class Cleanup(unittest.TestCase):
  def setUp(self):
    self.fixture = fixture.Backends("test_fixed_keys_commands_and_unknown_power_are_rejected")
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root = self.fixture.root
    self.o = self.fixture.o
    self.o.write("proc/sys/kernel/random/boot_id", cleanup.BOOT)
    self.o.write("proc/sys/kernel/osrelease", cleanup.KERNEL)
    self.o.write("sys/power/resume_offset", "1923214")
    self.archive = self.root / cleanup.ARCHIVE
    self.archive.mkdir(parents=True, mode=0o700)
    self.pins = {}
    self.images = {}
    receipt = {"images": {}, "runtime_stack_sha256": cleanup.RUNTIME}
    for role, relative in {**cleanup.PAIR.IMAGES, "production": Path("boot/EFI/Linux/omarchy_linux-t2.efi")}.items():
      raw = ("synthetic " + role + " image").encode()
      self.o.write(relative, raw)
      identity = hashlib.sha256(raw).hexdigest()
      self.images[role] = identity
      if role != "production":
        receipt["images"][role] = {"sha256": identity, "blake2": hashlib.blake2b(raw).hexdigest(),
                                  "entry_id": cleanup.PAIR.entry_id(role, identity)}
    receipt["production_uki_sha256"] = self.images["production"]
    before = "default_entry: 2\n/Omarchy.linux-t2\n"
    limine = before + cleanup.PAIR.BEGIN + "\n"
    for role in ("source", "restore"):
      metadata = receipt["images"][role]
      limine += cleanup.PAIR.entry_block(role, metadata["sha256"], metadata["blake2"])
    limine += cleanup.PAIR.END + "\n"
    self.o.write(cleanup.PAIR.BACKUP, before)
    self.o.write(cleanup.PAIR.SINGLE.LIMINE, limine)
    receipt.update(original_limine_sha256=hashlib.sha256(before.encode()).hexdigest(), staged_limine_sha256=hashlib.sha256(limine.encode()).hexdigest())
    self.fixture.loader("LoaderEntrySelected", receipt["images"]["restore"]["entry_id"])
    attempt = {"boot_id": cleanup.BOOT, "transition_vector": cleanup.VECTOR, "state": "returned-and-cleaned", "real_s4_attempted": True,
               "modules": {name: "A" * 24 for name in ("brcmfmac", "brcmfmac-wcc", "hci_bcm4377", "t2bce_core", "t2bce_dma", "t2bce_vhci", "t2bce_audio")}}
    self.stages = {cleanup.SOURCE: b"\x07\0\0\0MBPW" + bytes.fromhex(cleanup.VECTOR[:24]) + b"\x04",
                   cleanup.RESTORE: b"\x07\0\0\0MBRS" + bytes.fromhex(cleanup.VECTOR[:24]) + b"\x07",
                   **{name: b"\x07\0\0\0MBRH" + cleanup.VECTOR[:24].encode() + bytes((i,)) for i, name in enumerate(cleanup.HOOKS, 1)}}
    for name, raw in self.stages.items(): self.o.write(cleanup.EFI / name, raw)
    witness = {"continuity": "conditional-on-trusted-original-source-runner-process", "proof": {
      "classification": "source-return-evidence-valid", "post_cleanup_health_valid": True, "boot_id": cleanup.BOOT,
      "transition_vector": cleanup.VECTOR, "return_nonce": cleanup.NONCE, "usable_hibernation_qualified": False}}
    raw_return = {"boot_id": cleanup.BOOT, "read_errors": [], "abort_witnesses": [],
      "efi_overrides": {"LoaderEntryDefault": None, "LoaderEntryOneShot": None}, "markers": {name: raw.hex() for name, raw in self.stages.items()}}
    for name in cleanup.PINS:
      if name == "receipt.json": value = receipt
      elif name == "recovery-acceptance-v3.json": value = {"accepted": True}
      elif name == "vector/s4-attempted": value = (cleanup.BOOT + "\n").encode()
      elif name.endswith("/attempt.json"): value = attempt
      elif name.endswith("/cold-pci-restored-source-witness.json"): value = witness
      elif name.endswith("/cold-pci-restore-return-raw.json"): value = raw_return
      else: value = {"synthetic_historical_filename": name}
      raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
      target = self.archive / name
      target.parent.mkdir(parents=True, exist_ok=True)
      target.write_bytes(raw)
      target.chmod(0o600)
      self.pins[name] = hashlib.sha256(raw).hexdigest()
      if name.startswith("vector/"):
        relative = cleanup.LIVE / name.removeprefix("vector/")
      elif name == "receipt.json": relative = cleanup.PAIR.STATE / name
      else: relative = Path("var/lib/omarchy-t2-postwrite-marker") / name
      self.o.write(relative, raw)
      (self.root / relative).chmod(0o600)
    self.addCleanup(patch.stopall)
    patch.object(cleanup, "PINS", self.pins).start()
    patch.object(cleanup, "IMAGE_PINS", self.images).start()
    patch.object(cleanup, "CMDLINE", hashlib.sha256((self.root / "proc/cmdline").read_bytes()).hexdigest()).start()

  def query(self, argv):
    result = self.fixture.command(argv)
    if argv[0] == "btrfs": result.stdout = "1923214"
    return result

  def validate(self):
    return cleanup.validate(self.root, query=self.query)

  def execute(self, **changes):
    return cleanup.execute(self.root, query=self.query, **changes)

  def test_validate_is_readonly_and_restored_source_selected_restore_is_expected(self):
    before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}
    result, stages = self.validate()
    self.assertFalse(result["product_qualified"])
    self.assertEqual(stages, self.stages)
    self.assertFalse((self.root / cleanup.CLEANUP).exists())
    self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()})

  def test_execute_archives_exact_raw_bytes_removes_only_two_slots_and_preserves_originals(self):
    originals = {path: path.read_bytes() for path in self.archive.rglob("*") if path.is_file()}
    result = self.execute()
    self.assertTrue(result["slots_cleared"])
    for name, raw in self.stages.items():
      self.assertEqual((self.root / cleanup.CLEANUP / name).read_bytes(), raw)
      if name in cleanup.HOOKS: self.assertEqual((self.root / cleanup.EFI / name).read_bytes(), raw)
      else: self.assertFalse((self.root / cleanup.EFI / name).exists())
    for path, raw in originals.items(): self.assertEqual(path.read_bytes(), raw)
    self.validate()
    with self.assertRaises(ValueError): self.execute()

  def test_wrong_boot_override_and_loaded_writer_rejected(self):
    self.o.write("proc/sys/kernel/random/boot_id", "00000000-0000-4000-8000-000000000000")
    with self.assertRaises(ValueError): self.validate()
    self.o.write("proc/sys/kernel/random/boot_id", cleanup.BOOT)
    self.fixture.loader("LoaderEntryOneShot", "foreign")
    with self.assertRaises(ValueError): self.validate()
    (self.root / cleanup.EFI / ("LoaderEntryOneShot-" + cleanup.HOST.HOST.LOADER_GUID)).unlink()
    self.o.write("proc/modules", "mba_hibernate_cold_pci_guard 0 0 - Live 0")
    with self.assertRaises(ValueError): self.validate()
    self.assertFalse((self.root / cleanup.CLEANUP).exists())

  def test_changed_live_attempt_archive_hook_or_reusable_slot_is_not_deleted(self):
    targets = [self.root / cleanup.LIVE / cleanup.ATTEMPT / "attempt.json", self.archive / "receipt.json",
               self.root / cleanup.EFI / cleanup.HOOKS[0], self.root / cleanup.EFI / cleanup.SOURCE]
    for target in targets:
      original = target.read_bytes()
      target.write_bytes(b"foreign")
      with self.assertRaises(ValueError): self.execute()
      self.assertEqual(target.read_bytes(), b"foreign")
      self.assertFalse((self.root / cleanup.CLEANUP).exists())
      target.write_bytes(original)

  def test_partial_deletion_without_confirmed_absence_blocks_all_retry(self):
    def crash(target, raw):
      target.unlink()
      raise OSError("synthetic death after unlink before journal")
    with self.assertRaises(OSError): self.execute(remover=crash)
    with self.assertRaises(ValueError): self.validate()
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual((self.root / cleanup.EFI / cleanup.RESTORE).read_bytes(), self.stages[cleanup.RESTORE])
    self.assertTrue((self.root / cleanup.CLEANUP / (cleanup.SOURCE + ".delete-intent.json")).is_file())

  def test_persistence_failure_happens_before_any_removal(self):
    with patch.object(cleanup, "new_json", side_effect=OSError("synthetic journal failure")):
      with self.assertRaises(OSError): self.execute()
    for name in (cleanup.SOURCE, cleanup.RESTORE): self.assertEqual((self.root / cleanup.EFI / name).read_bytes(), self.stages[name])
    with self.assertRaises(ValueError): self.execute()

  def test_nonseekable_efi_descriptors_complete_without_seek(self):
    with patch.object(cleanup.os, "lseek", side_effect=OSError(errno.ESPIPE, "synthetic efivarfs cannot seek")) as seek:
      result = self.execute()
      self.assertTrue(result["slots_cleared"])
      seek.assert_not_called()

  def test_changed_inode_on_reopen_is_preserved_not_deleted(self):
    target = self.root / cleanup.EFI / cleanup.SOURCE
    original_inode = target.stat().st_ino
    original_open = cleanup.os.open
    opens = []
    def replace_on_reopen(name, flags, *args, **kwargs):
      if Path(name) == target:
        opens.append(name)
        if len(opens) == 2:
          target.unlink()
          target.write_bytes(self.stages[cleanup.SOURCE])
      return original_open(name, flags, *args, **kwargs)
    restored = []
    def restore_flags(fd, operation, flags, mutate):
      self.assertEqual(operation, cleanup.HOST.FS_IOC_SETFLAGS)
      restored.append((cleanup.os.fstat(fd).st_ino, flags[0]))
    # Exercise the native branch only against redirected fixture files and
    # mocked ioctl/sync; not a single live filesystem operation is possible.
    with patch.object(cleanup.os, "open", side_effect=replace_on_reopen), patch.object(cleanup, "path", return_value=target), \
         patch.object(cleanup.HOST, "_clear_immutable", return_value=cleanup.HOST.FS_IMMUTABLE_FL), \
         patch.object(cleanup.fcntl, "ioctl", side_effect=restore_flags), patch.object(cleanup.os, "sync", side_effect=AssertionError("No live sync")):
      with self.assertRaises(ValueError): cleanup.owned_delete(Path("/"), cleanup.SOURCE, self.stages[cleanup.SOURCE])
    self.assertEqual(target.read_bytes(), self.stages[cleanup.SOURCE])
    self.assertEqual(restored, [(original_inode, cleanup.HOST.FS_IMMUTABLE_FL)])

  def pending_preunlink(self):
    def fail_before_unlink(target, raw):
      raise OSError(errno.ESPIPE, "known synthetic pre-unlink failure")
    with self.assertRaises(OSError): self.execute(remover=fail_before_unlink)
    directory = self.root / cleanup.CLEANUP
    patch.object(cleanup, "PREUNLINK_INTENT_SHA", hashlib.sha256((directory / "intent.json").read_bytes()).hexdigest()).start()
    patch.object(cleanup, "PREUNLINK_SOURCE_INTENT_SHA", hashlib.sha256((directory / (cleanup.SOURCE + ".delete-intent.json")).read_bytes()).hexdigest()).start()
    patch.object(cleanup, "owned_flags", return_value=cleanup.HOST.FS_IMMUTABLE_FL).start()
    return directory

  def recover(self, **changes):
    return cleanup.complete_preunlink_espipe(self.root, query=self.query, **changes)

  def test_exact_preunlink_recovery_preserves_intents_and_is_exclusive(self):
    directory = self.pending_preunlink()
    original = {name: (directory / name).read_bytes() for name in ("intent.json", cleanup.SOURCE + ".delete-intent.json")}
    with self.assertRaises(ValueError): self.execute()
    result = self.recover()
    self.assertTrue(result["slots_cleared"])
    for name, raw in original.items(): self.assertEqual((directory / name).read_bytes(), raw)
    self.assertTrue((directory / "preunlink-espipe-recovery-intent.json").is_file())
    self.validate()
    with self.assertRaises(ValueError): self.recover()

  def test_recovery_refuses_any_extra_or_missing_journal_and_changed_intent(self):
    directory = self.pending_preunlink()
    deletions = []
    for extra in (cleanup.RESTORE + ".delete-intent.json", cleanup.SOURCE + ".absent.json", "complete.json", "preunlink-espipe-recovery-intent.json", "unknown"):
      target = directory / extra
      target.write_bytes(b"{}")
      with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
      target.unlink()
    target = directory / (cleanup.SOURCE + ".delete-intent.json")
    original = target.read_bytes()
    target.unlink()
    with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
    target.write_bytes(original + b" ")
    target.chmod(0o600)
    with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
    self.assertEqual(deletions, [])

  def test_recovery_refuses_missing_changed_slots_or_missing_immutable(self):
    directory = self.pending_preunlink()
    deletions = []
    for name in (cleanup.SOURCE, cleanup.RESTORE):
      target = self.root / cleanup.EFI / name
      raw = target.read_bytes()
      target.unlink()
      with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
      target.write_bytes(b"foreign")
      with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
      target.write_bytes(raw)
    with patch.object(cleanup, "owned_flags", return_value=0):
      with self.assertRaises(ValueError): self.recover(remover=lambda *args: deletions.append(args))
    self.assertEqual(deletions, [])
    self.assertFalse((directory / "preunlink-espipe-recovery-intent.json").exists())

  def test_recovery_interrupted_after_first_delete_cannot_retry(self):
    directory = self.pending_preunlink()
    def fail_after_unlink(target, raw):
      target.unlink()
      raise OSError("synthetic interrupted recovery")
    with self.assertRaises(OSError): self.recover(remover=fail_after_unlink)
    with self.assertRaises(ValueError): self.recover()
    self.assertTrue((self.root / cleanup.EFI / cleanup.RESTORE).is_file())

  def test_archive_tamper_during_first_delete_blocks_second(self):
    def tamper(target, raw):
      target.unlink()
      (self.archive / "receipt.json").write_bytes(b"foreign")
    with self.assertRaises(ValueError): self.execute(remover=tamper)
    self.assertTrue((self.root / cleanup.EFI / cleanup.RESTORE).is_file())
    self.assertFalse((self.root / cleanup.CLEANUP / "complete.json").exists())

  def test_symlink_foreign_slot_and_reappearing_completed_slot_rejected(self):
    target = self.root / cleanup.EFI / cleanup.SOURCE
    raw = target.read_bytes()
    target.unlink()
    foreign = self.root / "foreign"
    foreign.write_bytes(raw)
    target.symlink_to(foreign)
    with self.assertRaises(ValueError): self.execute()
    self.assertEqual(foreign.read_bytes(), raw)
    target.unlink()
    target.write_bytes(raw)
    self.execute()
    target.write_bytes(raw)
    with self.assertRaises(ValueError): self.validate()


if __name__ == "__main__": unittest.main()
