#!/usr/bin/python3
"""Synthetic roots and read-only query stubs; never samples the live host."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid

spec = importlib.util.spec_from_file_location("host_observation", Path(__file__).parents[1] / "hibernate/host_observation.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
ct = host.CT
tx = host.TX


class Observations(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.base = Path(self.temp.name)
    self.root = self.base / "host"
    self.root.mkdir()
    self.source = self.base / "source"
    self.source.mkdir()
    self.tree = self.base / "source-tree"
    self.tree.mkdir()
    self.marker = self.base / "source-marker.ko"
    self.marker.write_bytes(b"external source marker")
    self.marker_pin = {"sha256": host._digest(self.marker.read_bytes()), "srcversion": "F" * 24, "vermagic": "synthetic-t2 SMP", "variable_version": "v3"}
    self.query_calls = []
    self.file_metadata = {str(self.marker): self.marker_pin}
    module_names = host.ARTIFACTS.AUDIT.S4.RUNTIME_MODULES
    self.modules = {}
    self.selection = {}
    for name in module_names:
      raw = b"exact synthetic module " + name.encode()
      metadata = {"source": "/synthetic/" + name, "sha256": host._digest(raw), "srcversion": "A" * 24, "vermagic": "synthetic-t2 SMP"}
      self.modules[name] = metadata
      if name != "t2bce_ave":
        relative = "usr/lib/modules/synthetic-t2/" + name + ".ko"
        self.selection[name] = relative
        target = self.tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        self.file_metadata[str(target)] = metadata
        loaded = name.replace("-", "_")
        self.write("sys/module/" + loaded + "/srcversion", "A" * 24)
        if name == "hci_bcm4377":
          target = self.root / "run/omarchy-t2-hibernation-candidate/hci_bcm4377.ko"
          target.parent.mkdir(parents=True)
          target.write_bytes(raw)
          self.file_metadata[str(target)] = metadata
    self.write("sys/module/" + host.MARKER + "/srcversion", "F" * 24)
    self.loaded = sorted([name.replace("-", "_") for name in self.selection] + [host.MARKER, "nvme"])
    self.write("proc/modules", "\n".join(name + " 0 0 - Live 0" for name in self.loaded))
    self.boot = str(uuid.uuid4())
    self.write("proc/sys/kernel/random/boot_id", self.boot + "\n")
    self.write("proc/sys/kernel/osrelease", "synthetic-t2\n")
    self.write("sys/class/dmi/id/product_name", "MacBookAir9,1\n")
    self.cmdline = "root=/dev/mapper/root resume=/dev/mapper/root resume_offset=123"
    self.write("proc/cmdline", self.cmdline + "\n")
    sections = {name: host._digest(self.cmdline.encode() + b"\0") if name == ".cmdline" else host._digest(name.encode()) for name in host.ARTIFACTS.AUDIT.S4.RUNTIME_SECTIONS}
    image = b"source image"
    initrd = b"source initramfs"
    (self.source / "mba-t2-hibernation-candidate.efi").write_bytes(image)
    (self.source / "mba-t2-hibernation-candidate.initrd").write_bytes(initrd)
    self.provenance = {"candidate": "mba-t2-hibernation-early-source", "pre_restore_module_policy": "early-t2-radio",
                       "candidate_uki_sha256": host._digest(image), "candidate_initrd_sha256": host._digest(initrd),
                       "production_uki_sha256": "9" * 64, "source_provenance_sha256": "8" * 64,
                       "kernel_release": "synthetic-t2", "cmdline": self.cmdline, "modules": self.modules,
                       "initrd_module_selection": self.selection, "unchanged_production_sections_sha256": sections}
    provenance_raw = json.dumps(self.provenance, sort_keys=True).encode()
    (self.source / "provenance.json").write_bytes(provenance_raw)
    manifest = {"protocol": tx.PROTOCOL, "model": "MacBookAir9,1", "source_sha256": host._digest(image), "restore_sha256": "7" * 64,
                "runtime_sha256": host.ARTIFACTS.AUDIT.S4.runtime_stack_identity(self.provenance), "linux_sha256": sections[".linux"], "cmdline_sha256": sections[".cmdline"]}
    details = {"protocol": host.ARTIFACTS.DETAILS_PROTOCOL, "manifest_sha256": tx.digest(manifest), "production_uki_sha256": "9" * 64,
               "sections": {name: {role: identity for role in ("source", "restore", "production")} for name, identity in sections.items()},
               "provenance_sha256": {"source": host._digest(provenance_raw), "restore": "6" * 64}, "kernel_release": "synthetic-t2", "cmdline_text": self.cmdline,
               "runtime_modules": copy.deepcopy(self.modules), "source_initrd_module_selection": self.selection.copy(),
               "restore_marker": {"version": "v2"}, "restore_protocol": {"version": host.ARTIFACTS.FULLRESTORE, "resume": {"device": "/dev/mapper/root", "offset": 123, "devnum": "253:0"}},
               "external_source_marker_pin_required": True}
    details["sections"][".initrd"] = {"source": host._digest(initrd), "restore": "5" * 64, "production": "4" * 64}
    self.report = {"manifest": manifest, "audited_details": details, "audited_details_sha256": tx.digest(details),
                   "classification": "structurally-audited-artifacts-not-product-qualified", "hardware_qualified": False, "usable_hibernation_qualified": False}
    self.qualification = {"protocol": tx.PROTOCOL, "manifest_sha256": tx.digest(manifest), "evidence_sha256": "3" * 64, "qualified": True}
    identity = {"protocol": tx.PROTOCOL, "cycle_id": str(uuid.uuid4()), "original_boot_id": self.boot, "manifest": manifest, "qualification_sha256": tx.digest(self.qualification)}
    vector = tx.digest(identity)
    self.cycle = {**identity, "qualification_vector": tx.qualification_vector(manifest), "vector": vector, "prefix": vector[:24], "state": "prepared", "prepared_evidence_sha256": "2" * 64}
    binding = {key: self.cycle[key] for key in ct.BINDING_KEYS}
    self.guard = self.base / "guard.json"
    self.guard.write_bytes(json.dumps({"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": binding}).encode())
    self.guard.chmod(0o600)
    self.attempt = self.base / "attempt.json"
    self.attempt.write_bytes(json.dumps({"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": binding, "state": "transition-armed", "real_s4_attempted": True, "requested_disk_mode": "platform", "consumed_guard_sha256": host._digest(self.guard.read_bytes())}).encode())
    self.attempt.chmod(0o600)
    self.write("sys/power/pm_test", "[none] freezer devices")
    self.write("sys/power/disk", "[platform] shutdown")
    self.write("sys/power/pm_trace", "0")
    self.write("sys/power/resume", "253:0")
    self.write("sys/power/resume_offset", "123")
    self.select("source")
    for address, (vendor, device, driver) in host.PCI.items():
      self.write("sys/bus/pci/devices/" + address + "/vendor", vendor)
      self.write("sys/bus/pci/devices/" + address + "/device", device)
      if driver:
        target = self.root / "sys/bus/pci/drivers" / driver
        target.mkdir(parents=True, exist_ok=True)
        (self.root / "sys/bus/pci/devices" / address / "driver").symlink_to(target)
    (self.root / "sys/bus/pci/devices/0000:73:00.0/net/wlan0").mkdir(parents=True)
    (self.root / "sys/class/bluetooth/hci0").mkdir(parents=True)
    self.write("proc/self/mounts", "/dev/mapper/root / btrfs rw,subvol=/@ 0 0\n")
    self.write("proc/bus/input/devices", ('N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"\nPhys=usb-t2bce_vhci-\n') * 2)
    self.write("proc/asound/cards", "Apple T2 Audio")
    self.write("sys/class/power_supply/AC/type", "Mains")
    self.write("sys/class/power_supply/AC/online", "1")
    self.sampler = self.new_sampler()

  def tearDown(self):
    self.temp.cleanup()

  def write(self, relative, value):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else value.encode())

  def select(self, role):
    entry = "MBA-T2-hibernation-" + role + "-" + self.report["manifest"][role + "_sha256"][:16]
    self.write(str(host.EFI / ("LoaderEntrySelected-" + host.LOADER_GUID)), b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le"))

  def query(self, args):
    self.query_calls.append(args)
    if args[0] == "modinfo":
      if args[2] == "mba_postwrite_variable": return "v3"
      return self.file_metadata[args[3]][args[2]]
    if args[0] == "lsblk": return "253:0"
    if args[:2] == ("systemctl", "is-active"): return "active"
    if args[:2] == ("systemctl", "--failed"): return ""
    self.fail("Unexpected read-only query")

  def new_sampler(self, **changes):
    arguments = {"root": self.root, "report": self.report, "cycle": self.cycle, "qualification": self.qualification,
                 "source_directory": self.source, "source_tree": self.tree, "marker_file": self.marker, "marker_pin": self.marker_pin,
                 "guard_file": self.guard, "attempt_file": self.attempt, "query": self.query}
    return host.Sampler(**{**arguments, **changes})

  def retained(self):
    before = self.sampler.before()
    return ct.Collector(self.cycle, self.qualification, before["source_runtime"], before["baseline_pm"], self.guard.read_bytes(), self.attempt.read_bytes())

  def stage_return(self):
    self.select("restore")
    prefix = self.cycle["prefix"]
    self.write(str(host.EFI / ct.SOURCE_VARIABLE), b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04")
    self.write(str(host.EFI / ct.RESTORE_VARIABLE), b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07")
    for suffix, stage in (("Entered", 1), ("Armed", 2)):
      self.write(str(host.EFI / ("OmarchyT2RestoreHook" + suffix + prefix + "-" + ct.GUID)), b"\x07\0\0\0MBRH" + prefix.encode() + bytes((stage,)))

  def test_observation_joins_artifacts_and_continuity_without_writes(self):
    collector = self.retained()
    self.stage_return()
    before = {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file() and not path.is_symlink()}
    collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    proof = collector.finish(self.sampler.health(collector.binding), [])
    self.assertTrue(proof["post_cleanup_health_valid"])
    self.assertFalse(proof["usable_hibernation_qualified"])
    self.assertEqual(before, {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file() and not path.is_symlink()})
    paths = [args[3] for args in self.query_calls if args[0] == "modinfo"]
    self.assertTrue(all(str(self.tree) in path or path == str(self.marker) or path.startswith(str(self.root / "run")) for path in paths))

  def test_runtime_and_section_cmdline_hashes_are_distinct(self):
    before = self.sampler.before()
    self.assertNotEqual(before["source_runtime"]["cmdline_sha256"], self.report["manifest"]["cmdline_sha256"])
    self.write("proc/cmdline", self.cmdline + " wrong=1\n")
    with self.assertRaises(ValueError): self.sampler.runtime()

  def test_recomputed_report_digest_cannot_hide_changed_source_pins(self):
    report = copy.deepcopy(self.report)
    report["audited_details"]["runtime_modules"]["t2bce_core"]["sha256"] = "f" * 64
    report["audited_details_sha256"] = tx.digest(report["audited_details"])
    with self.assertRaises(ValueError): self.new_sampler(report=report)

  def test_artifact_provenance_and_detail_digest_changes_refuse(self):
    report = copy.deepcopy(self.report)
    report["audited_details_sha256"] = "f" * 64
    with self.assertRaises(ValueError): self.new_sampler(report=report)
    (self.source / "mba-t2-hibernation-candidate.efi").write_bytes(b"changed image")
    with self.assertRaises(ValueError): self.sampler.runtime()

  def test_spoofed_embedded_module_and_loaded_srcversion_refuse(self):
    path = self.tree / self.selection["t2bce_core"]
    path.write_bytes(b"stock module masquerade")
    with self.assertRaises(ValueError): self.sampler.runtime()

  def test_wrong_loaded_version_and_bluetooth_run_copy_refuse(self):
    self.write("sys/module/t2bce_core/srcversion", "B" * 24)
    with self.assertRaises(ValueError): self.sampler.runtime()
    self.write("sys/module/t2bce_core/srcversion", "A" * 24)
    self.write("run/omarchy-t2-hibernation-candidate/hci_bcm4377.ko", b"wrong Bluetooth file")
    with self.assertRaises(ValueError): self.sampler.runtime()

  def test_external_marker_pin_and_forbidden_sysmodule_refuse(self):
    self.marker.write_bytes(b"wrong source marker")
    with self.assertRaises(ValueError): self.sampler.runtime()
    self.marker.write_bytes(b"external source marker")
    self.write("sys/module/mba_hibernate_cold_pci_guard/srcversion", "A" * 24)
    with self.assertRaises(ValueError): self.sampler.runtime()

  def test_restore_selection_never_satisfies_before_source_check(self):
    self.select("restore")
    with self.assertRaises(ValueError): self.sampler.before()

  def test_different_boot_return_preserved_and_continuity_rejected(self):
    collector = self.retained()
    self.stage_return()
    changed = str(uuid.uuid4())
    self.write("proc/sys/kernel/random/boot_id", changed)
    with self.assertRaises(ValueError): collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    self.assertEqual(collector.retained_evidence()["capture"]["boot_id"], changed)

  def test_override_return_preserved_and_continuity_rejected(self):
    collector = self.retained()
    self.stage_return()
    self.write(str(host.EFI / ("LoaderEntryOneShot-" + host.LOADER_GUID)), b"foreign override")
    with self.assertRaises(ValueError): collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    self.assertEqual(collector.retained_evidence()["capture"]["efi_overrides"]["LoaderEntryOneShot"], b"foreign override")

  def test_baseline_pm_resume_location_and_health_failure(self):
    collector = self.retained()
    self.stage_return()
    collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    self.write("sys/power/resume_offset", "999")
    with self.assertRaises(ValueError): self.sampler.health(collector.binding)

  def test_postcleanup_health_does_not_require_source_marker(self):
    collector = self.retained()
    self.stage_return()
    collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    (self.root / "sys/module" / host.MARKER / "srcversion").unlink()
    (self.root / "sys/module" / host.MARKER).rmdir()
    proof = collector.finish(self.sampler.health(collector.binding), [])
    self.assertTrue(proof["post_cleanup_health_valid"])

  def test_partial_efi_reads_preserved_in_rejected_capture(self):
    collector = self.retained()
    self.stage_return()
    name = "OmarchyT2RestoreHookArmed" + self.cycle["prefix"] + "-" + ct.GUID
    (self.root / host.EFI / name).unlink()
    with self.assertRaises(ValueError): collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    capture = collector.retained_evidence()["capture"]
    self.assertIn("read_errors", capture)
    self.assertIsNone(capture["markers"][name])
    self.assertEqual(capture["markers"][ct.SOURCE_VARIABLE], (self.root / host.EFI / ct.SOURCE_VARIABLE).read_bytes())
    self.assertEqual(capture["consumed_guard"], self.guard.read_bytes())

  def test_forbidden_module_aftercleanup_refused(self):
    collector = self.retained()
    self.stage_return()
    collector.write_and_capture(lambda path, value: None, self.sampler.capture)
    self.write("sys/module/mba_hibernate_cold_pci_guard/srcversion", "A" * 24)
    with self.assertRaises(ValueError): self.sampler.health(collector.binding)

  def test_workflow_durably_preserves_partial_sampler_failure(self):
    spec = importlib.util.spec_from_file_location("observation_workflow", Path(__file__).parents[1] / "hibernate/workflow.py")
    workflow = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(workflow)
    ledger = tx.Ledger(self.base / "workflow-ledger")
    ledger.configure(self.report["manifest"])
    ledger.qualify(self.qualification)
    cycle = ledger.begin(self.boot, self.cycle["cycle_id"])
    prepared = ledger.advance(cycle["cycle_id"], "prepared", "2" * 64)
    self.assertEqual(prepared, self.cycle)
    before = self.sampler.before()
    collector = workflow.CONTINUITY.Collector(prepared, self.qualification, before["source_runtime"], before["baseline_pm"], self.guard.read_bytes(), self.attempt.read_bytes())
    archives = self.base / "archives"
    archives.mkdir(mode=0o700)
    def synthetic_write(path, value):
      self.stage_return()
      name = "OmarchyT2RestoreHookArmed" + self.cycle["prefix"] + "-" + ct.GUID
      (self.root / host.EFI / name).unlink()
    with self.assertRaises(ValueError):
      workflow.run(ledger, collector, archives, power_write=synthetic_write, capture=self.sampler.capture, cleanup=lambda: [], health=self.sampler.health)
    failure = ledger._read("workflow-failure-" + self.cycle["cycle_id"] + ".json")
    capture = failure["snapshot"]["retained"]["capture"]
    self.assertTrue(capture["read_errors"])
    self.assertEqual(capture["markers"][ct.SOURCE_VARIABLE]["raw_hex"], (self.root / host.EFI / ct.SOURCE_VARIABLE).read_bytes().hex())
    self.assertTrue(ledger._state()["blocked"])


if __name__ == "__main__":
  unittest.main()
