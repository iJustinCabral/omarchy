#!/usr/bin/python3
"""Preparation/rollback fault tests: injected actions only, private temp ledger."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("product_preparation", Path(__file__).parents[1] / "hibernate/preparation.py")
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)
tx = prep.TX


class Backend:
  def __init__(self, cycle, pin):
    self.source = "MBA-T2-hibernation-source-" + cycle["manifest"]["source_sha256"][:16]
    self.restore = "MBA-T2-hibernation-restore-" + cycle["manifest"]["restore_sha256"][:16]
    self.pin = pin
    self.values = {"model": "MacBookAir9,1", "boot_id": cycle["original_boot_id"], "kernel_release": "synthetic-t2",
                   "selected_entry": self.source, "oneshot": None, "default": None,
                   "source_stage": None, "restore_stage": None, "restore_hook_entered": None, "restore_hook_armed": None,
                   "loader_entries": [self.source, self.restore], "source_marker_loaded": False,
                   "marker_file_identity": pin, "source_marker_identity": pin,
                   "source_marker_parameters": {"arm_vector": "0", "stage": "0", "last_efi_status": "0"},
                   "wifi_identity": {"vendor": "0x14e4", "device": "0x4488"}, "wifi_driver": "brcmfmac",
                   "bolt_active": True, "bluetooth_powered": True, "pm_test": "none", "disk": "platform", "pm_trace": "0"}
    self.events = []
    self.fail = None
    self.partial = False

  def read(self, key):
    return copy.deepcopy(self.values[key])

  def command(self, args):
    self.events.append(args)
    key = args[0] + ":" + (args[1] if len(args) > 1 else "")
    if self.fail == key and not self.partial:
      raise RuntimeError("synthetic command failure")
    if args[:2] == ("systemctl", "stop"): self.values["bolt_active"] = False
    elif args[:2] == ("systemctl", "start"): self.values["bolt_active"] = True
    elif args[:3] == ("timeout", "5s", "bluetoothctl"): self.values["bluetooth_powered"] = args[-1] == "on"
    elif args[0] == "insmod": self.values["source_marker_loaded"] = True
    elif args[0] == "rmmod": self.values["source_marker_loaded"] = False
    elif args[:2] == ("bootctl", "set-oneshot"): self.values["oneshot"] = args[-1] or None
    else: raise AssertionError("Unexpected injected command")
    if self.fail == key and self.partial:
      raise RuntimeError("synthetic post-action failure")

  def write(self, key, value):
    self.events.append(("write", key, value))
    if self.fail == key and not self.partial:
      raise RuntimeError("synthetic sysfs/EFI failure")
    if key == "wifi_unbind": self.values["wifi_driver"] = None
    elif key == "wifi_bind": self.values["wifi_driver"] = "brcmfmac"
    elif key == "arm_vector": self.values["source_marker_parameters"] = {"arm_vector": "1", "stage": "0", "last_efi_status": "0"}
    elif key in ("source_stage", "restore_stage"):
      if self.values[key] is not None: raise FileExistsError("occupied EFI slot")
      self.values[key] = value
    elif key in ("pm_test", "disk", "pm_trace"): self.values[key] = value
    else: raise AssertionError("Unexpected injected write")
    if self.fail == key and self.partial:
      raise RuntimeError("synthetic post-write failure")


class Preparations(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.ledger = tx.Ledger(Path(self.temp.name) / "ledger")
    manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", **{key: str(i) * 64 for i, key in enumerate(tx.PINS, 1)}}
    self.ledger.configure(manifest)
    self.ledger.qualify({"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(manifest), "evidence_sha256": "a" * 64, "qualified": True})
    self.cycle = self.ledger.begin(str(uuid.uuid4()))
    self.pin = {"sha256": "b" * 64, "srcversion": "B" * 24, "vermagic": "synthetic-t2 SMP", "variable_version": "v3"}
    self.backend = Backend(self.cycle, self.pin)
    self.sleeps = []
    self.preparation = prep.Preparation(self.ledger, self.cycle, self.backend, "/synthetic/private-marker.ko", self.pin, sleeper=self.sleeps.append)

  def tearDown(self):
    self.temp.cleanup()

  def assert_blocked(self):
    with self.assertRaises(ValueError): self.ledger.begin(str(uuid.uuid4()))

  def test_prepare_exact_order_durable_guard_attempt_and_receipt(self):
    result = self.preparation.prepare()
    self.assertEqual(result["cycle"]["state"], "prepared")
    self.assertEqual(result["cycle"]["prepared_evidence_sha256"], tx.digest(result["receipt"]))
    prep.CT.consumed_records(result["cycle"], result["guard_file"].read_bytes(), result["attempt_file"].read_bytes())
    operations = [args[:2] for args in self.backend.events]
    self.assertEqual(operations, [("systemctl", "stop"), ("timeout", "5s"), ("write", "wifi_unbind"),
                                 ("write", "pm_test"), ("write", "disk"), ("write", "pm_trace"), ("insmod", "/synthetic/private-marker.ko"),
                                 ("write", "source_stage"), ("write", "arm_vector"), ("write", "restore_stage"), ("bootctl", "set-oneshot")])
    self.assertTrue(all((self.ledger.directory / (self.preparation.stem + "-" + action["name"] + "-intent.json")).is_file() for action in result["receipt"]["actions"]))
    self.assert_blocked()

  def test_cleanup_order_and_owned_return_preserves_stage_guards(self):
    result = self.preparation.prepare()
    self.backend.events.clear()
    self.backend.values["oneshot"] = None
    self.backend.values["selected_entry"] = self.backend.restore
    source_stage = self.backend.values["source_stage"]
    self.assertEqual(self.preparation.cleanup(), [])
    self.assertEqual([args[:2] for args in self.backend.events], [("write", "pm_test"), ("write", "disk"), ("write", "pm_trace"),
                                                               ("write", "wifi_bind"), ("timeout", "5s"), ("systemctl", "start"), ("rmmod", prep.MARKER)])
    self.assertEqual(self.backend.values["source_stage"], source_stage)
    self.assertTrue(result["guard_file"].is_file())
    self.assertTrue(result["attempt_file"].is_file())

  def test_initially_off_and_unbound_stay_off_and_unbound(self):
    self.backend.values.update(bolt_active=False, bluetooth_powered=False, wifi_driver=None)
    self.preparation.prepare()
    self.assertEqual(self.preparation.cleanup(), [])
    self.assertIsNone(self.backend.values["wifi_driver"])
    self.assertFalse(self.backend.values["bluetooth_powered"])
    self.assertFalse(self.backend.values["bolt_active"])
    self.assertFalse(any(args[:2] in (("write", "wifi_bind"), ("systemctl", "start"), ("timeout", "5s")) for args in self.backend.events))

  def test_partial_detach_failure_rebinds_owned_wifi_and_blocks(self):
    self.backend.fail = "wifi_unbind"
    self.backend.partial = True
    with self.assertRaises(RuntimeError): self.preparation.prepare()
    self.assertEqual(self.backend.values["wifi_driver"], "brcmfmac")
    self.assertTrue(self.backend.values["bluetooth_powered"])
    self.assertTrue(self.backend.values["bolt_active"])
    self.assertTrue(self.ledger._state()["blocked"])
    self.assert_blocked()

  def test_restore_arming_failure_keeps_stage_evidence_and_unloads_marker(self):
    self.backend.fail = "bootctl:set-oneshot"
    with self.assertRaises(RuntimeError): self.preparation.prepare()
    self.assertIsNotNone(self.backend.values["source_stage"])
    self.assertIsNotNone(self.backend.values["restore_stage"])
    self.assertFalse(self.backend.values["source_marker_loaded"])
    self.assertFalse(self.preparation.attempt_file.exists())
    self.assertTrue(self.preparation.guard_file.exists())
    self.assert_blocked()

  def test_foreign_oneshot_cleanup_refuses_clear_but_finishes_other_cleanup(self):
    self.preparation.prepare()
    self.backend.events.clear()
    self.backend.values["oneshot"] = "foreign-entry"
    errors = self.preparation.cleanup()
    self.assertTrue(errors)
    self.assertFalse(any(args[0] == "bootctl" for args in self.backend.events))
    self.assertEqual(self.backend.values["oneshot"], "foreign-entry")
    self.assertFalse(self.backend.values["source_marker_loaded"])

  def test_stale_marker_slots_and_baseline_pm_refuse_before_actions(self):
    self.backend.values["source_stage"] = b"historical v16 evidence"
    with self.assertRaises(ValueError): self.preparation.prepare()
    self.assertEqual(self.backend.events, [])
    self.assertEqual(self.backend.values["source_stage"], b"historical v16 evidence")
    self.assert_blocked()

  def test_baseline_nonqualified_pm_is_not_normalized(self):
    self.backend.values["pm_trace"] = "1"
    with self.assertRaises(ValueError): self.preparation.prepare()
    self.assertEqual(self.backend.events, [])
    self.assertEqual(self.backend.values["pm_trace"], "1")

  def test_failed_intent_persistence_prevents_action(self):
    write = self.ledger._write
    def fail(name, value, **kwargs):
      if name.endswith("-bolt-stop-intent.json"): raise OSError("synthetic disk failure")
      return write(name, value, **kwargs)
    with patch.object(self.ledger, "_write", side_effect=fail):
      with self.assertRaises(OSError): self.preparation.prepare()
    self.assertEqual(self.backend.events, [])
    self.assertTrue(self.ledger._state()["blocked"])

  def test_partial_marker_load_failure_unloads_only_exact_owned_marker(self):
    self.backend.fail = "insmod:/synthetic/private-marker.ko"
    self.backend.partial = True
    with self.assertRaises(RuntimeError): self.preparation.prepare()
    self.assertFalse(self.backend.values["source_marker_loaded"])
    self.assertIn(("rmmod", prep.MARKER), self.backend.events)

  def test_tampered_completed_receipt_and_duplicate_prepare_refuse(self):
    self.preparation.prepare()
    with self.assertRaises(ValueError): self.preparation.prepare()
    name = self.preparation.stem + "-complete.json"
    self.ledger._write(name, {"foreign": True})
    with self.assertRaises(ValueError): self.preparation.receipt()

  def test_preparation_callbacks_hold_ledger_lock(self):
    read = self.backend.read
    def concurrent(key):
      if key == "bolt_active":
        with self.assertRaises(BlockingIOError): self.ledger.begin(str(uuid.uuid4()))
      return read(key)
    with patch.object(self.backend, "read", side_effect=concurrent):
      self.preparation.prepare()

  def test_cleanup_journal_failure_does_not_suppress_owned_recovery(self):
    self.preparation.prepare()
    write = self.ledger._write
    def fail(name, value, **kwargs):
      if "-cleanup-" in name: raise OSError("synthetic cleanup journal failure")
      return write(name, value, **kwargs)
    with patch.object(self.ledger, "_write", side_effect=fail):
      errors = self.preparation.cleanup()
    self.assertTrue(errors)
    self.assertIsNone(self.backend.values["oneshot"])
    self.assertEqual(self.backend.values["wifi_driver"], "brcmfmac")
    self.assertTrue(self.backend.values["bluetooth_powered"])
    self.assertTrue(self.backend.values["bolt_active"])
    self.assertFalse(self.backend.values["source_marker_loaded"])
    self.assert_blocked()


if __name__ == "__main__":
  unittest.main()
