#!/usr/bin/python3
"""Mocked source-return collection only; no host PM, EFI or module operations."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


BASE = Path(__file__).resolve().parents[1]


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


RUNNER = load("fullrestore_runner", BASE / "experiments/run-hibernation-uki-pair-s4.py")
COLLECT = RUNNER.FULLRESTORE
FIXTURE = load("fullrestore_fixture", BASE / "tests/test-cold-pci-restore-proof.py")


def write(root, relative, value):
  target = root / relative
  target.parent.mkdir(parents=True, exist_ok=True)
  target.write_bytes(value if isinstance(value, bytes) else value.encode())
  return target


class CollectorTests(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.expected, self.observation, _, self.health = FIXTURE.fixture()
    self.evidence = copy.deepcopy(self.expected)
    self.directory = self.root / "attempts" / self.expected["boot_id"]
    self.directory.mkdir(parents=True)
    self.guard = write(self.root, "s4-attempted", bytes.fromhex(self.observation["consumed_guard_hex"]))
    self.attempt = write(self.root, self.directory.relative_to(self.root) / "attempt.json", bytes.fromhex(self.observation["consumed_attempt_hex"]))
    self.collector = COLLECT.Collector(self.root, self.root, self.root, self.evidence, None, None,
                                      lambda source: self.expected["runtime_stack_sha256"],
                                      inventory=lambda *args: copy.deepcopy(self.expected["source_runtime"]))
    self.collector.pins = lambda: ({key: copy.deepcopy(self.expected[key]) for key in COLLECT.PIN_KEYS}, {})
    self.collector.pair = SimpleNamespace(AUDIT=SimpleNamespace(extract_restore_initramfs=lambda *args: None))
    self.collector.health = lambda: {**copy.deepcopy(self.health), "return_nonce": self.collector.expected["return_nonce"]}
    self.return_files()

  def return_files(self):
    capture = self.observation["return_capture"]
    for name, value in capture["markers"].items():
      write(self.root, COLLECT.EFI / name, bytes.fromhex(value))
    write(self.root, COLLECT.EFI / ("LoaderEntrySelected-" + COLLECT.LOADER_GUID), bytes.fromhex(capture["LoaderEntrySelected_hex"]))
    write(self.root, "proc/sys/kernel/random/boot_id", self.expected["boot_id"] + "\n")

  def prepare(self):
    self.collector.before_write(self.guard, self.attempt, self.directory)

  def test_durable_witness_requires_original_return_and_health(self):
    self.prepare()
    self.assertFalse(self.collector.context["power_write_returned"])
    self.collector.returned()
    # Later cleanup mutates both files; validator still sees original bytes.
    self.attempt.write_text('{}\n')
    result = self.collector.finish([])
    self.assertTrue(result["post_cleanup_health_valid"])
    self.assertFalse(result["hardware_qualified"])
    self.assertFalse(result["usable_hibernation_qualified"])
    witness = self.directory / "cold-pci-restored-source-witness.json"
    self.assertEqual(stat.S_IMODE(witness.stat().st_mode), 0o600)
    self.assertEqual(json.loads(witness.read_text())["observation"]["consumed_attempt_hex"], self.observation["consumed_attempt_hex"])
    with self.assertRaises(FileExistsError):
      COLLECT.private_new(witness, {})

  def test_no_later_boot_finish_import(self):
    self.prepare()
    with self.assertRaises(ValueError):
      self.collector.finish([])
    self.assertFalse((self.directory / "cold-pci-restored-source-witness.json").exists())

  def test_missing_marker_preserves_partial_raw_return(self):
    self.prepare()
    (self.root / COLLECT.EFI / COLLECT.PROOF.RESTORE_VARIABLE).unlink()
    with self.assertRaisesRegex(ValueError, "Incomplete"):
      self.collector.returned()
    raw = json.loads((self.directory / "cold-pci-restore-return-raw.json").read_text())
    self.assertIsNone(raw["markers"][COLLECT.PROOF.RESTORE_VARIABLE])
    self.assertTrue(raw["read_errors"])
    self.assertFalse((self.directory / "cold-pci-restored-source-witness.json").exists())

  def test_actual_inventory_uses_private_payload_and_source_marker(self):
    names = ["brcmfmac", "brcmfmac_wcc", "hci_bcm4377", "t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio"]
    pins = {}
    selection = {}
    source_tree = self.root / "exact-source-initrd"
    for name in names:
      canonical = "brcmfmac-wcc" if name == "brcmfmac_wcc" else name
      selection[canonical] = "usr/lib/modules/fixture-kernel/updates/" + canonical + ".ko"
      module = write(source_tree, selection[canonical], ("private-" + canonical).encode())
      if name == "hci_bcm4377":
        write(self.root, "run/omarchy-t2-hibernation-candidate/hci_bcm4377.ko", module.read_bytes())
      pins[canonical] = {"sha256": hashlib.sha256(module.read_bytes()).hexdigest(), "srcversion": "ABC123"}
      write(self.root, "sys/module/" + name + "/srcversion", "ABC123\n")
    marker = write(self.root, "private-source-marker.ko", b"private marker")
    backend = SimpleNamespace(module_path=marker, expected_sha256=hashlib.sha256(marker.read_bytes()).hexdigest(), expected_srcversion="ABC123")
    names += ["mba_hibernate_efi_postwrite_marker", "ordinary_without_srcversion"]
    write(self.root, "sys/module/mba_hibernate_efi_postwrite_marker/srcversion", "ABC123\n")
    (self.root / "sys/module/ordinary_without_srcversion").mkdir()
    write(self.root, "proc/modules", "\n".join(name + " 0 0 - Live 0" for name in names))
    write(self.root, "proc/sys/kernel/osrelease", "fixture-kernel\n")
    write(self.root, "proc/cmdline", "fixture-cmdline\n")
    provenance = {"modules": pins, "kernel_release": "fixture-kernel", "cmdline": "fixture-cmdline", "initrd_module_selection": selection}
    def query(args):
      self.assertEqual(args[:3], ("modinfo", "-F", "srcversion"))
      self.assertTrue(Path(args[3]).is_file())
      return "ABC123"
    result = COLLECT.runtime_inventory(self.root, provenance, backend, query, source_tree)
    self.assertEqual([item.name for item in (self.root / "run/omarchy-t2-hibernation-candidate").iterdir()], ["hci_bcm4377.ko"])
    self.assertEqual(result["loaded_modules"], sorted(names))
    self.assertEqual(result["modules"]["brcmfmac_wcc"], pins["brcmfmac-wcc"]["sha256"])
    self.assertNotIn("ordinary_without_srcversion", result["modules"])
    self.assertIn("mba_hibernate_efi_postwrite_marker", result["modules"])
    write(self.root, "proc/modules", "\n".join(name + " 0 0 - Live 0" for name in names if name != "t2bce_core"))
    with self.assertRaisesRegex(ValueError, "incomplete"):
      COLLECT.runtime_inventory(self.root, provenance, backend, query, source_tree)
    write(self.root, "proc/modules", "\n".join(name + " 0 0 - Live 0" for name in names))
    write(self.root, "sys/module/t2bce_core/srcversion", "WRONG\n")
    with self.assertRaisesRegex(ValueError, "differs from selected file"):
      COLLECT.runtime_inventory(self.root, provenance, backend, query, source_tree)
    write(self.root, "sys/module/t2bce_core/srcversion", "ABC123\n")
    (self.root / "sys/module/mba_hibernate_cold_pci_guard").mkdir()
    with self.assertRaisesRegex(ValueError, "Restore-only"):
      COLLECT.runtime_inventory(self.root, provenance, backend, query, source_tree)
    (self.root / "sys/module/mba_hibernate_cold_pci_guard").rmdir()
    write(source_tree, selection["t2bce_core"], b"corrupt initrd module")
    with self.assertRaisesRegex(ValueError, "Actual source initramfs module differs"):
      COLLECT.runtime_inventory(self.root, provenance, backend, query, source_tree)

  def test_wrong_boot_marker_or_cleanup_never_witness(self):
    for failure in ("boot", "stage", "abort", "inventory", "cleanup", "health"):
      with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
        # Each negative gets new exclusive evidence filenames.
        directory = Path(temporary)
        self.collector.directory = directory
        self.collector.context = None
        self.collector.capture = None
        self.return_files()
        self.collector.inventory = lambda *args: copy.deepcopy(self.expected["source_runtime"])
        self.collector.before_write(self.guard, self.attempt, directory)
        if failure == "boot":
          write(self.root, "proc/sys/kernel/random/boot_id", "33333333-3333-4333-8333-333333333333\n")
        if failure == "stage":
          write(self.root, COLLECT.EFI / COLLECT.PROOF.RESTORE_VARIABLE, b"\x07\0\0\0MBRS" + bytes.fromhex(self.expected["transition_vector"][:24]) + b"\x06")
        if failure == "abort":
          witness = write(self.root, COLLECT.EFI / ("OmarchyT2ColdPciPreArchReturned" + self.expected["transition_vector"][:24] + "-" + COLLECT.PROOF.GUID), b"MBPG")
        if failure == "inventory":
          runtime = copy.deepcopy(self.expected["source_runtime"])
          runtime["loaded_modules"].append("unexpected")
          self.collector.inventory = lambda *args: runtime
        self.collector.returned()
        old_health = self.collector.health
        if failure == "health":
          bad = old_health()
          bad["failed_units"] = ["example.service"]
          self.collector.health = lambda: bad
        with self.assertRaises(ValueError):
          self.collector.finish(["wifi: failed"] if failure == "cleanup" else [])
        self.collector.health = old_health
        self.assertTrue((directory / "cold-pci-restore-return-raw.json").exists())
        self.assertFalse((directory / "cold-pci-restored-source-witness.json").exists())
        if failure == "abort":
          witness.unlink()


class RunnerTests(unittest.TestCase):
  def run_case(self, power_failure=False, return_failure=False, cleanup_failure=False, finish_failure=False, context_failure=False):
    expected, _, _, _ = FIXTURE.fixture()
    events = []
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      for name, value in (("disk", "[platform] shutdown"), ("pm_test", "[none]"), ("pm_trace", "0")):
        write(root, RUNNER.TEST.POWER / name, value)
      evidence = {**expected, "pm_test_before": "none", "disk_before": "platform", "pm_trace_before": "0"}
      class Backend(RUNNER.POSTWRITE.PostwriteRestoreEfiBackend):
        def __init__(self):
          self.source_variable_version = "v3"
          self.restore_variable_version = "v2"
        def require_operator_acceptance(self, *args): return "f" * 64
        def before_arm(self, *args): pass
        def enable(self, *args): pass
        def prearm(self, *args): return "mock-marker"
        def inspect(self, *args): return 4
        def inspect_restore(self, *args): return 7
        def inspect_restore_hook(self, *args): return 2
        def cleanup(self, *args):
          events.append("cleanup")
          if cleanup_failure: raise RuntimeError("mock cleanup failure")
      class Collector:
        def __init__(self, *args): pass
        def before_write(self, guard, attempt, directory):
          events.append("context")
          self.context = {"power_write_returned": False}
          self.consumed = attempt.read_bytes()
          self.assert_armed = json.loads(self.consumed)["state"] == "transition-armed"
          if context_failure: raise ValueError("mock failed context")
        def returned(self):
          events.append("capture")
          self.context["power_write_returned"] = True
          if return_failure: raise ValueError("mock missing marker")
        def finish(self, errors):
          events.append("finish")
          if finish_failure: raise ValueError("mock unhealthy return")
          return {"hardware_qualified": False, "post_cleanup_health_valid": True}
      def power_write(target, value):
        if target.name == "state":
          events.append("disk-write")
          if power_failure: raise OSError("mock failed disk write")
        else:
          target.write_text("[" + value + "]" if target.name in ("pm_test", "disk") else value)
      receipt = {"production_uki_sha256": expected["production_uki_sha256"], "images": {"restore": {"experiment_id": COLLECT.PROTOCOL}}}
      with patch.object(RUNNER, "preflight", return_value=evidence), patch.object(RUNNER.PAIR, "load_receipt", return_value=receipt), patch.object(RUNNER.PAIR.AUDIT, "load_candidate", return_value={"cold_pci_restore": {"version": COLLECT.PROTOCOL}}), patch.object(RUNNER.TEST, "bluetooth_powered", return_value=False), patch.object(RUNNER.S4, "service_active", return_value=False), patch.object(RUNNER.PAIR, "selected_entry", return_value=expected["restore_entry_id"]):
        kwargs = dict(wifi_prepare=lambda root: None, wifi_restore=lambda root: None, power_writer=power_write,
                      runner=lambda *args: None, sync=lambda: None, sleeper=lambda delay: None,
                      services_verifier=lambda runner: None, restore_armer=lambda *args, **kwargs: None,
                      marker_backend=Backend(), operator_attended=True, fullrestore_collector_factory=Collector)
        if any((power_failure, return_failure, cleanup_failure, finish_failure, context_failure)):
          with self.assertRaises((RuntimeError, ValueError, OSError)):
            RUNNER.execute(root, root, root, root, None, None, "platform", expected["transition_vector"], **kwargs)
        else:
          result = RUNNER.execute(root, root, root, root, None, None, "platform", expected["transition_vector"], **kwargs)
          self.assertTrue(result["cold_pci_restore_proof"]["post_cleanup_health_valid"])
        attempts, guard = RUNNER.vector_paths(root, expected["transition_vector"])
        self.assertTrue(guard.exists())
        record = json.loads((attempts / expected["boot_id"] / "attempt.json").read_text())
        if any((power_failure, return_failure, cleanup_failure, finish_failure, context_failure)):
          self.assertNotIn("cold_pci_restore_proof", record)
        if context_failure:
          self.assertFalse(record["hibernate_attempted"])
          self.assertFalse(record["real_s4_attempted"])
          self.assertEqual(record["state"], "guard-consumed-pretransition-failure")
        if finish_failure:
          self.assertEqual(record["state"], "restored-source-proof-failed")
      return events

  def test_original_return_order(self):
    self.assertEqual(self.run_case(), ["context", "disk-write", "capture", "cleanup", "finish"])

  def test_failures_preserve_consumed_guard_and_no_proof(self):
    self.assertEqual(self.run_case(context_failure=True), ["context", "cleanup"])
    self.assertEqual(self.run_case(power_failure=True), ["context", "disk-write", "cleanup"])
    self.assertEqual(self.run_case(return_failure=True), ["context", "disk-write", "capture", "cleanup"])
    self.assertEqual(self.run_case(cleanup_failure=True), ["context", "disk-write", "capture", "cleanup"])
    self.assertEqual(self.run_case(finish_failure=True), ["context", "disk-write", "capture", "cleanup", "finish"])


if __name__ == "__main__":
  unittest.main()
