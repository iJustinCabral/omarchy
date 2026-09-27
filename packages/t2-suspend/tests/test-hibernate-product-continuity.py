#!/usr/bin/python3
"""Pure synthetic continuity faults: no host sampling or physical power writes."""
import copy
import importlib.util
import json
from pathlib import Path
import pickle
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("continuity", Path(__file__).parents[1] / "hibernate/continuity.py")
ct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ct)
tx = ct.TX


class Continuity(unittest.TestCase):
  def setUp(self):
    manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", **{key: str(i) * 64 for i, key in enumerate(tx.PINS, 1)}}
    self.qualification = {"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(manifest), "evidence_sha256": "a" * 64, "qualified": True}
    identity = {"protocol": tx.PROTOCOL, "cycle_id": str(uuid.uuid4()), "original_boot_id": str(uuid.uuid4()),
                "manifest": manifest, "qualification_sha256": tx.digest(self.qualification)}
    vector = tx.digest(identity)
    self.cycle = {**identity, "qualification_vector": tx.qualification_vector(manifest), "vector": vector,
                  "prefix": vector[:24], "state": "prepared", "prepared_evidence_sha256": "b" * 64}
    binding = {key: self.cycle[key] for key in ct.BINDING_KEYS}
    self.guard = json.dumps({"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": binding}, sort_keys=True).encode()
    self.attempt = json.dumps({"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": binding,
                               "state": "transition-armed", "real_s4_attempted": True,
                               "requested_disk_mode": "platform", "consumed_guard_sha256": ct.raw_digest(self.guard)}, sort_keys=True).encode()
    self.runtime = {"kernel_release": "synthetic-t2", "cmdline_sha256": "c" * 64,
                    "modules": {name: {"sha256": "d" * 64, "srcversion": "A" * 24} for name in ct.REQUIRED_MODULES},
                    "loaded_modules": sorted(ct.REQUIRED_MODULES | {"nvme"})}
    self.pm = {"pm_test": "none", "disk": "platform", "pm_trace": "0", "resume_device": "/dev/mapper/root", "resume_offset": 123}
    self.collector = self.new_collector()
    self.writes = []

  def new_collector(self):
    return ct.Collector(self.cycle, self.qualification, self.runtime, self.pm, self.guard, self.attempt)

  def capture(self, binding):
    prefix = self.cycle["prefix"]
    return {"schema": ct.SCHEMA, "binding": binding, "boot_id": self.cycle["original_boot_id"], "manifest": copy.deepcopy(self.cycle["manifest"]),
            "runtime_stack_sha256": self.cycle["manifest"]["runtime_sha256"], "source_runtime": copy.deepcopy(self.runtime),
            "consumed_guard": self.guard, "consumed_attempt": self.attempt,
            "LoaderEntrySelected": b"\x06\0\0\0" + ("MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16] + "\0").encode("utf-16-le"),
            "efi_overrides": {"LoaderEntryOneShot": None, "LoaderEntryDefault": None},
            "markers": {ct.SOURCE_VARIABLE: b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04",
                        ct.RESTORE_VARIABLE: b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07",
                        "OmarchyT2RestoreHookEntered" + prefix + "-" + ct.GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x01",
                        "OmarchyT2RestoreHookArmed" + prefix + "-" + ct.GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x02"},
            "restore_only_modules": [], "abort_modules": [], "abort_witnesses": []}

  def health(self):
    return {"schema": ct.SCHEMA, "binding": self.collector.binding, "boot_id": self.cycle["original_boot_id"], "after_cleanup": True,
            "devices": {"primary_encrypted_root": True, "internal_keyboard": True, "internal_trackpad": True, "wifi": True, "bluetooth": True, "ac_online": True},
            "services": {"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"}, "failed_units": [], "pm": self.pm.copy()}

  def write(self, path, value):
    self.writes.append((path, value))

  def test_retained_original_call_and_cleanup(self):
    self.collector.write_and_capture(self.write, self.capture)
    proof = self.collector.finish(self.health(), [])
    self.assertEqual(self.writes, [("/sys/power/state", "disk")])
    self.assertFalse(proof["usable_hibernation_qualified"])
    self.assertEqual(proof["binding"]["vector"], self.cycle["vector"])
    with self.assertRaises(ValueError): self.collector.finish(self.health(), [])

  def test_no_finish_before_write_and_no_serialized_context(self):
    with self.assertRaises(ValueError): self.collector.finish(self.health(), [])
    with self.assertRaises(TypeError): pickle.dumps(self.collector)
    with self.assertRaises(ValueError): ct.Collector(self.collector.binding, self.qualification, self.runtime, self.pm, self.guard, self.attempt)

  def test_fresh_collector_cannot_import_old_capture(self):
    old_capture = self.capture(self.collector.binding)
    fresh = self.new_collector()
    with self.assertRaises(ValueError): fresh.write_and_capture(self.write, lambda binding: old_capture)

  def test_failed_write_consumed_and_does_not_capture(self):
    def fail(path, value): raise RuntimeError("synthetic write failure")
    with self.assertRaises(RuntimeError): self.collector.write_and_capture(fail, lambda binding: self.fail("capture after failed write"))
    with self.assertRaises(ValueError): self.collector.write_and_capture(self.write, self.capture)
    with self.assertRaises(ValueError): self.collector.finish(self.health(), [])

  def test_capture_faults(self):
    for key, value in (("boot_id", str(uuid.uuid4())), ("schema", "cold-pci-restored-source-v1"),
                       ("runtime_stack_sha256", "f" * 64), ("abort_witnesses", ["historical-abort"]),
                       ("restore_only_modules", ["mba_hibernate_cold_pci_guard"]), ("abort_modules", ["abort"])):
      with self.subTest(key=key):
        collector = self.new_collector()
        with self.assertRaises(ValueError): collector.write_and_capture(self.write, lambda binding: {**self.capture(binding), key: value})

  def test_same_boot_wrong_nonce_and_pair_changes(self):
    for mutate in (lambda data: data["binding"].update(return_nonce="0" * 64),
                   lambda data: data["manifest"].update(linux_sha256="f" * 64),
                   lambda data: data["binding"].update(qualification_vector="f" * 64)):
      collector = self.new_collector()
      def capture(binding):
        data = self.capture(binding)
        mutate(data)
        return data
      with self.assertRaises(ValueError): collector.write_and_capture(self.write, capture)

  def test_raw_markers_exact_stages_prefix_attributes_length(self):
    for transform in (lambda raw: raw[:-1] + b"\x06", lambda raw: raw + b"\0", lambda raw: b"\x06" + raw[1:], lambda raw: raw[:8] + b"\0" * 12 + raw[20:]):
      collector = self.new_collector()
      def capture(binding):
        data = self.capture(binding)
        data["markers"][ct.RESTORE_VARIABLE] = transform(data["markers"][ct.RESTORE_VARIABLE])
        return data
      with self.assertRaises(ValueError): collector.write_and_capture(self.write, capture)

  def test_selected_source_or_override_rejected(self):
    for modify in (lambda data: data.update(LoaderEntrySelected=b"source"),
                   lambda data: data["efi_overrides"].update(LoaderEntryOneShot=b"owned")):
      collector = self.new_collector()
      def capture(binding):
        data = self.capture(binding)
        modify(data)
        return data
      with self.assertRaises(ValueError): collector.write_and_capture(self.write, capture)

  def test_runtime_identity_and_full_inventory(self):
    for modify in (lambda data: data["source_runtime"]["modules"]["t2bce_core"].update(srcversion="B" * 24),
                   lambda data: data["source_runtime"]["loaded_modules"].append("mba_hibernate_cold_abort")):
      collector = self.new_collector()
      def capture(binding):
        data = self.capture(binding)
        modify(data)
        return data
      with self.assertRaises(ValueError): collector.write_and_capture(self.write, capture)

  def test_health_requires_exact_typed_cleanup_gates(self):
    for modify in (lambda data: data.update(after_cleanup=1), lambda data: data.update(failed_units=["broken"]),
                   lambda data: data["devices"].update(internal_keyboard=False), lambda data: data["pm"].update(resume_offset=999)):
      self.collector = self.new_collector()
      self.collector.write_and_capture(self.write, self.capture)
      health = self.health()
      modify(health)
      with self.assertRaises(ValueError): self.collector.finish(health, [])

  def test_historical_qualification_and_unprepared_cycle_rejected(self):
    with self.assertRaises(ValueError): ct.Collector({**self.cycle, "state": "reserved"}, self.qualification, self.runtime, self.pm, self.guard, self.attempt)
    with self.assertRaises(ValueError): ct.Collector(self.cycle, {**self.qualification, "protocol": "cold-pci-guard-fullrestore-v1"}, self.runtime, self.pm, self.guard, self.attempt)

  def test_prewrite_consumed_guard_and_attempt_bind_cycle(self):
    for guard, attempt in ((b"historical-boot-guard", self.attempt), (self.guard, b"{}"), (self.guard, self.attempt.replace(b"true", b"1"))):
      with self.assertRaises(ValueError): ct.Collector(self.cycle, self.qualification, self.runtime, self.pm, guard, attempt)
    with self.assertRaises(ValueError): self.collector.write_and_capture(self.write, lambda binding: {**self.capture(binding), "consumed_guard": self.guard + b"\n"})

  def test_consumed_record_wrong_cycle_boot_or_artifact_refused(self):
    for name, value in (("cycle_id", str(uuid.uuid4())), ("original_boot_id", str(uuid.uuid4())), ("vector", "f" * 64)):
      data = json.loads(self.guard)
      data["cycle"][name] = value
      with self.assertRaises(ValueError): ct.Collector(self.cycle, self.qualification, self.runtime, self.pm, json.dumps(data).encode(), self.attempt)
    data = json.loads(self.attempt)
    data["cycle"]["manifest"]["source_sha256"] = "f" * 64
    with self.assertRaises(ValueError): ct.Collector(self.cycle, self.qualification, self.runtime, self.pm, self.guard, json.dumps(data).encode())

  def test_ledger_transition_uses_computed_witness_digest(self):
    self.collector.write_and_capture(self.write, self.capture)
    proposal = self.collector.returned_transition(self.health(), [])
    self.assertEqual(proposal["prepared_cycle"], self.cycle)
    self.assertEqual(proposal["evidence_sha256"], tx.digest(proposal["witness"]))
    self.assertEqual(proposal["action"], "returned")

  def test_changed_process_and_cleanup_failure_are_terminal(self):
    with patch.object(ct.os, "getpid", return_value=self.collector._pid + 1):
      with self.assertRaises(ValueError): self.collector.write_and_capture(self.write, self.capture)
    self.collector.write_and_capture(self.write, self.capture)
    with self.assertRaises(ValueError): self.collector.finish(self.health(), ["cleanup failed"])
    with self.assertRaises(ValueError): self.collector.finish(self.health(), [])


if __name__ == "__main__":
  unittest.main()
