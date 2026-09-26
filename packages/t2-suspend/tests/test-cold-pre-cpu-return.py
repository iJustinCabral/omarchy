#!/usr/bin/python3
"""Portable read-only evidence fixtures; never run a PM or boot operation."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[1] / "experiments/audit-cold-pre-cpu-return.py"
SPEC = importlib.util.spec_from_file_location("cold_return_audit_test", PATH)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
SOURCE_BOOT = "11111111-1111-4111-8111-111111111111"
STOCK_BOOT = "22222222-2222-4222-8222-222222222222"


class ReturnAuditTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix="cold-return-evidence-test-")
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.images = {}
    for role, token in (("source", "a"), ("restore", "b")):
      self.images[role] = {"sha256": token * 64, "blake2": token * 128,
                           "provenance_sha256": ("c" if role == "source" else "d") * 64,
                           "experiment_id": "cold-pre-cpu-abort-v1" if role == "restore" else "restore-boundary-v1"}
    self.pair = {"runtime_stack_sha256": "e" * 64,
                 "cold_pre_cpu": {"version": "cold-pre-cpu-abort-v1", "module_sha256": "f" * 64},
                 "restore_marker": {"version": "v2", "efi_variable": audit.RESTORE_VARIABLE,
                                    "sha256": "1" * 64, "srcversion": "ABC123"}}
    self.vector = hashlib.sha256(("a" * 64 + ":" + "b" * 64 + ":" + "e" * 64).encode()).hexdigest()
    self.receipt = {"kernel_policy": "production-linux-unchanged", "runtime_stack_sha256": "e" * 64,
                    "state": "restore-arming", "restore_armed_from_boot_id": SOURCE_BOOT,
                    "images": {role: {**image, "entry_id": audit.PAIR.entry_id(role, image["sha256"])}
                               for role, image in self.images.items()}}
    self.directory = audit.PAIR.STATE / "s4-vectors" / self.vector
    self.attempt_directory = self.directory / "attempts" / SOURCE_BOOT
    self.attempt = {"boot_id": SOURCE_BOOT, "candidate_uki_sha256": "a" * 64,
                    "entry_id": self.receipt["images"]["source"]["entry_id"],
                    "source_entry_id": self.receipt["images"]["source"]["entry_id"],
                    "restore_entry_id": self.receipt["images"]["restore"]["entry_id"],
                    "source_uki_sha256": "a" * 64, "restore_uki_sha256": "b" * 64,
                    "runtime_stack_sha256": "e" * 64, "transition_vector": self.vector,
                    "hardware_qualified": False, "recovery_method": "operator-attended-cold-power",
                    "requested_disk_mode": "platform", "qualification": "pair-source-ordinary-boot-preflight-passed",
                    "state": "transition-armed", "hibernate_attempted": True, "real_s4_attempted": True}
    self.identities = {
      "postwrite": {"kind": "postwrite-efi-s4-identity-v1", "vector": self.vector,
                    "source_boot_id": SOURCE_BOOT, "source_efi_variable": audit.SOURCE_VARIABLE,
                    "module_sha256": audit.SOURCE_MODULE_SHA256, "module_srcversion": audit.SOURCE_MODULE_SRCVERSION,
                    "recovery": "operator-attended-cold-power"},
      "restore": {"kind": "restore-efi-s4-identity-v1", "vector": self.vector,
                  "source_boot_id": SOURCE_BOOT, "source_efi_variable": audit.SOURCE_VARIABLE,
                  "module_sha256": self.pair["restore_marker"]["sha256"], "module_srcversion": "ABC123",
                  "efi_variable": audit.RESTORE_VARIABLE},
    }
    self.write_json(audit.PAIR.RECEIPT, self.receipt)
    self.write(audit.PAIR.BOOT_ID, (STOCK_BOOT + "\n").encode())
    self.write(audit.PAIR.SINGLE.SELECTED, audit.LOADER_ATTRIBUTES + "Omarchy.linux-t2\0".encode("utf-16-le"))

  def write(self, relative, raw, mode=0o644):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path

  def write_json(self, relative, value):
    return self.write(relative, (json.dumps(value) + "\n").encode(), 0o600)

  def marker_path(self, kind):
    if kind in ("source", "restore"):
      return audit.EFI / (audit.SOURCE_VARIABLE if kind == "source" else audit.RESTORE_VARIABLE)
    name = "OmarchyT2ColdPreCpuReturned" if kind == "returned" else "OmarchyT2RestoreHook" + kind.capitalize()
    return audit.EFI / (name + self.vector[:24] + "-" + audit.GUID)

  def write_marker(self, kind, stage=None, vector=None):
    vector = vector or self.vector
    stages = {"source": 4, "restore": 7, "entered": 1, "armed": 2, "returned": 1}
    magics = {"source": b"MBPW", "restore": b"MBRS", "entered": b"MBRH", "armed": b"MBRH", "returned": b"MBCP"}
    prefix = bytes.fromhex(vector[:24]) if kind in ("source", "restore") else vector[:24].encode()
    return self.write(self.marker_path(kind), audit.ATTRIBUTES + magics[kind] + prefix + bytes([stages[kind] if stage is None else stage]))

  def attempted(self, returned=True):
    self.write(self.directory / "s4-attempted", (SOURCE_BOOT + "\n").encode(), 0o600)
    self.write_json(self.attempt_directory / "attempt.json", self.attempt)
    for kind, identity in self.identities.items():
      self.write_json(self.attempt_directory / (kind + "-efi-identity.json"), identity)
    for kind in ("source", "restore", "entered", "armed"):
      self.write_marker(kind)
    if returned:
      self.write_marker("returned")

  def state(self):
    return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mode & 0o777)
            for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}

  def inspect(self, expected=None):
    before = self.state()
    calls = []
    def staged(root, receipt):
      self.assertEqual(root, self.root)
      self.assertEqual(receipt, self.receipt)
      calls.append("staged")
    try:
      return audit.inspect(self.root, self.root / "private-source", self.root / "private-restore", expected or self.vector,
                           pair_loader=lambda *_: (copy.deepcopy(self.pair), copy.deepcopy(self.images), {}),
                           staged_verifier=staged)
    finally:
      self.assertEqual(self.state(), before, "Audit changed evidence bytes or modes")

  def test_positive_controlled_abort_is_not_hibernation_success(self):
    self.attempted()
    report = self.inspect()
    self.assertEqual(report["classification"], "controlled-abort-return")
    self.assertEqual(report["return_boot_id"], STOCK_BOOT)
    self.assertEqual(report["source_boot_id"], SOURCE_BOOT)
    self.assertFalse(report["hibernate_success"])
    self.assertFalse(report["restored_userspace"])
    self.assertFalse(report["hardware_qualified"])
    self.assertIn("entry only", report["restore_stage_7_semantics"])
    self.assertEqual(report["markers"]["returned"]["sha256"], audit.sha256((self.root / self.marker_path("returned")).read_bytes()))
    self.assertEqual(report["images"]["source"]["provenance_sha256"], "c" * 64)

  def test_missing_return_witness_preserves_stage_seven_uncertainty(self):
    self.attempted(returned=False)
    report = self.inspect()
    self.assertEqual(report["classification"], "return-witness-missing")
    self.assertIsNone(report["return_boot_id"])
    self.assertFalse(report["hibernate_success"])

  def test_never_attempted_ignores_valid_unrelated_archived_global_markers(self):
    self.receipt.update(state="source-arming", restore_armed_from_boot_id=None)
    self.write_json(audit.PAIR.RECEIPT, self.receipt)
    self.write(audit.PAIR.BOOT_ID, (SOURCE_BOOT + "\n").encode())
    self.write(audit.PAIR.SINGLE.SELECTED, audit.LOADER_ATTRIBUTES + (self.receipt["images"]["source"]["entry_id"] + "\0").encode("utf-16-le"))
    self.write_marker("source", vector="9" * 64)
    self.write_marker("restore", vector="9" * 64)
    report = self.inspect()
    self.assertEqual(report["classification"], "never-attempted")
    self.assertFalse(report["guard_consumed"])
    self.assertFalse(report["markers"]["source"]["matching_vector"])
    self.assertEqual(report["source_boot_id"], SOURCE_BOOT)
    self.assertIsNone(report["attempt_source_boot_id"])

  def test_incomplete_attempt_and_no_pm_are_not_success(self):
    self.attempt.update(state="guard-consumed", hibernate_attempted=False, real_s4_attempted=False)
    self.attempted(returned=False)
    self.assertEqual(self.inspect()["classification"], "incomplete-attempt")
    (self.root / (self.attempt_directory / "attempt.json")).unlink()
    self.assertEqual(self.inspect()["classification"], "incomplete-attempt")

  def test_full_vector_and_receipt_provenance_binding(self):
    with self.assertRaisesRegex(ValueError, "full pair vector"):
      self.inspect(expected="0" * 64)
    for key in ("sha256", "provenance_sha256", "blake2", "experiment_id", "entry_id"):
      with self.subTest(key=key):
        original = self.receipt["images"]["source"][key]
        self.receipt["images"]["source"][key] = "wrong"
        self.write_json(audit.PAIR.RECEIPT, self.receipt)
        with self.assertRaisesRegex(ValueError, "receipt mismatch"):
          self.inspect()
        self.receipt["images"]["source"][key] = original
    self.receipt["runtime_stack_sha256"] = "0" * 64
    self.write_json(audit.PAIR.RECEIPT, self.receipt)
    with self.assertRaisesRegex(ValueError, "runtime_stack"):
      self.inspect()

  def test_raw_attributes_magic_lengths_prefix_and_stage_fail_closed(self):
    self.attempted()
    for kind in ("source", "restore", "entered", "armed", "returned"):
      path = self.root / self.marker_path(kind)
      original = path.read_bytes()
      faults = [b"\x06" + original[1:], original[:4] + b"BAD!" + original[8:], original + b"\0",
                original[:-1] + b"\xff", original[:8] + b"0" * (len(original) - 9) + original[-1:]]
      for fault in faults:
        with self.subTest(kind=kind, fault=fault.hex()):
          path.write_bytes(fault)
          with self.assertRaises(ValueError):
            self.inspect()
      path.write_bytes(original)

  def test_orphan_and_exclusive_witness_evidence_refused(self):
    self.write_marker("returned")
    with self.assertRaisesRegex(ValueError, "without an archived attempt"):
      self.inspect()
    (self.root / self.marker_path("returned")).unlink()
    self.attempted()
    (self.root / self.marker_path("entered")).unlink()
    with self.assertRaisesRegex(ValueError, "without entered"):
      self.inspect()
    self.write_marker("entered")
    (self.root / self.marker_path("restore")).unlink()
    with self.assertRaisesRegex(ValueError, "lacks the exact"):
      self.inspect()

  def test_consumed_guard_attempt_and_identities_are_exact(self):
    self.attempted()
    for kind in self.identities:
      path = self.attempt_directory / (kind + "-efi-identity.json")
      original = copy.deepcopy(self.identities[kind])
      for key in ("vector", "module_sha256", "module_srcversion", "source_boot_id"):
        with self.subTest(kind=kind, key=key):
          wrong = {**original, key: "wrong"}
          self.write_json(path, wrong)
          with self.assertRaisesRegex(ValueError, "prearm identity"):
            self.inspect()
      self.write_json(path, original)
    self.write(self.directory / "s4-attempted", (STOCK_BOOT + "\n").encode(), 0o600)
    with self.assertRaisesRegex(ValueError, "differs from archived"):
      self.inspect()

  def test_second_attempt_or_false_pm_flags_refused(self):
    self.attempted()
    self.write_json(self.directory / "attempts" / STOCK_BOOT / "attempt.json", self.attempt)
    with self.assertRaisesRegex(ValueError, "Multiple attempts"):
      self.inspect()
    (self.root / self.directory / "attempts" / STOCK_BOOT / "attempt.json").unlink()
    (self.root / self.directory / "attempts" / STOCK_BOOT).rmdir()
    self.attempt["real_s4_attempted"] = False
    self.write_json(self.attempt_directory / "attempt.json", self.attempt)
    with self.assertRaisesRegex(ValueError, "transition flags"):
      self.inspect()

  def test_attempt_state_guard_and_return_mode_conflicts_fail_closed(self):
    self.attempted()
    original = copy.deepcopy(self.attempt)
    for changes in ({"state": "unrecognized"}, {"requested_disk_mode": "shutdown"},
                    {"qualification": "hardware-qualified"}, {"error": "earlier failed transition"},
                    {"real_s4_attempted": False, "hibernate_attempted": False}):
      with self.subTest(changes=changes):
        self.write_json(self.attempt_directory / "attempt.json", {**original, **changes})
        with self.assertRaises(ValueError):
          self.inspect()
    self.write_json(self.attempt_directory / "attempt.json", original)
    self.write(self.directory / "s4-attempted", SOURCE_BOOT.encode(), 0o600)
    with self.assertRaisesRegex(ValueError, "guard encoding"):
      self.inspect()

  def test_positive_requires_distinct_stock_boot_and_no_overrides(self):
    self.attempted()
    self.write(audit.PAIR.BOOT_ID, (SOURCE_BOOT + "\n").encode())
    with self.assertRaisesRegex(ValueError, "distinct current stock"):
      self.inspect()
    self.write(audit.PAIR.BOOT_ID, (STOCK_BOOT + "\n").encode())
    self.write(audit.PAIR.SINGLE.SELECTED, audit.LOADER_ATTRIBUTES + "Wrong.entry\0".encode("utf-16-le"))
    with self.assertRaisesRegex(ValueError, "distinct current stock"):
      self.inspect()
    self.write(audit.PAIR.SINGLE.SELECTED, audit.LOADER_ATTRIBUTES + "Omarchy.linux-t2\0".encode("utf-16-le"))
    for relative in (audit.PAIR.SINGLE.ONESHOT, audit.PAIR.SINGLE.DEFAULT):
      self.write(relative, audit.ATTRIBUTES + b"stale")
      with self.assertRaisesRegex(ValueError, "boot override"):
        self.inspect()
      (self.root / relative).unlink()

  def test_loader_selected_uses_volatile_attributes_six_not_marker_seven(self):
    self.assertEqual(self.inspect()["classification"], "never-attempted")
    for attributes in (audit.ATTRIBUTES, b"\0\0\0\0", b"\x06\0\0\x01"):
      self.write(audit.PAIR.SINGLE.SELECTED, attributes + "Omarchy.linux-t2\0".encode("utf-16-le"))
      with self.subTest(attributes=attributes), self.assertRaisesRegex(ValueError, "selected EFI"):
        self.inspect()

  def test_symlink_private_mode_json_and_unannounced_diagnostic_refused(self):
    self.attempted()
    path = self.root / self.attempt_directory / "attempt.json"
    path.chmod(0o644)
    with self.assertRaisesRegex(ValueError, "Unsafe private"):
      self.inspect()
    path.chmod(0o600)
    path.write_bytes(b'{"state":"a","state":"b"}')
    with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
      self.inspect()
    self.write_json(self.attempt_directory / "attempt.json", self.attempt)
    raw = path.read_bytes()
    path.unlink()
    target = self.write(Path("other.json"), raw, 0o600)
    path.symlink_to(target)
    with self.assertRaisesRegex(ValueError, "Symlinked evidence"):
      self.inspect()
    path.unlink()
    self.write_json(self.attempt_directory / "attempt.json", self.attempt)
    del self.pair["cold_pre_cpu"]
    with self.assertRaisesRegex(ValueError, "provenance"):
      self.inspect()


if __name__ == "__main__":
  unittest.main()
