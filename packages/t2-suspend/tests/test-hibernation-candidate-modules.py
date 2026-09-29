#!/usr/bin/env python3
"""Exercise post-switch-root candidate loading without live hardware."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


package = Path(__file__).resolve().parents[1]
helper_path = package / "experiments/hibernate-candidate-modules.py"
spec = importlib.util.spec_from_file_location("candidate_modules", helper_path)
candidate_modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate_modules)


class Result:
  def __init__(self, stdout=""):
    self.stdout = stdout


class CandidateModuleTests(unittest.TestCase):
  release = "7.2.6-arch2-Watanare-T2-2-t2"
  boot_id = "11111111-2222-3333-4444-555555555555"
  entry_id = "MBA-T2-hibernation-candidate-deadbeefdeadbeef"
  payload_names = (*candidate_modules.LOAD_ORDER, "brcmfmac-bca", "brcmfmac-cyw", "hci_bcm4377", "t2bce_ave")

  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    base = Path(self.temporary.name)
    self.sys = base / "sys"
    self.proc = base / "proc"
    self.payload = base / "run/omarchy-t2-hibernation-candidate"
    self.payload.mkdir(parents=True)
    model = self.sys / "class/dmi/id/product_name"
    model.parent.mkdir(parents=True)
    model.write_text("MacBookAir9,1\n")
    boot_id = self.proc / "sys/kernel/random/boot_id"
    boot_id.parent.mkdir(parents=True)
    boot_id.write_text(self.boot_id + "\n")
    for address in candidate_modules.PCI_BINDINGS:
      (self.sys / "bus/pci/devices" / address).mkdir(parents=True)
    for driver in candidate_modules.PCI_BINDINGS.values():
      (self.sys / "drivers" / driver).mkdir(parents=True, exist_ok=True)

    modules = {}
    self.srcversions = {}
    for name in self.payload_names:
      module = self.payload / (name + ".ko")
      module.write_bytes(("candidate " + name).encode())
      srcversion = (name.upper().replace("-", "_") + "_SRC")
      self.srcversions[name] = srcversion
      modules[name] = {
        "file": module.name,
        "sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
        "srcversion": srcversion,
      }
    (self.payload / "manifest.json").write_text(json.dumps({
      "kernel_release": self.release,
      "modules": modules,
      "policy": "post-switch-root-only",
    }))
    self.calls = []
    self.now = 0.0
    self.bind_devices = True

  def sleep(self, seconds):
    self.now += seconds

  def command(self, arguments, **_kwargs):
    self.calls.append(arguments)
    if arguments[:3] == ["/usr/bin/modinfo", "-F", "srcversion"]:
      return Result(self.srcversions[Path(arguments[3]).stem] + "\n")
    if arguments[:3] == ["/usr/bin/modinfo", "-F", "vermagic"]:
      return Result(self.release + " SMP preempt mod_unload\n")
    if arguments[0] == "/usr/bin/insmod":
      name = Path(arguments[1]).stem
      module = self.sys / "module" / name.replace("-", "_") / "srcversion"
      module.parent.mkdir(parents=True)
      module.write_text(self.srcversions[name] + "\n")
      if self.bind_devices and name == "t2bce_core":
        (self.sys / "bus/pci/devices/0000:74:00.1/driver").symlink_to(self.sys / "drivers/t2bce_core")
      elif self.bind_devices and name == "t2bce_audio":
        (self.sys / "bus/pci/devices/0000:74:00.3/driver").symlink_to(self.sys / "drivers/t2bce_audio")
      elif self.bind_devices and name == "brcmfmac-wcc":
        wifi = self.sys / "bus/pci/devices/0000:73:00.0"
        (wifi / "driver").symlink_to(self.sys / "drivers/brcmfmac")
        (wifi / "net/wlan-test").mkdir(parents=True)
    return Result()

  def load(self):
    return candidate_modules.load_candidate(
      sys=self.sys,
      proc=self.proc,
      payload=self.payload,
      run=self.command,
      monotonic=lambda: self.now,
      sleep=self.sleep,
      release=self.release,
      entry_reader=lambda: self.entry_id,
    )

  def test_loads_exact_modules_after_switch_root(self):
    marker = self.load()
    mutation_calls = [arguments for arguments in self.calls if arguments[0] in ("/usr/bin/modprobe", "/usr/bin/insmod")]
    self.assertEqual(mutation_calls[0], ["/usr/bin/modprobe", "-a", *candidate_modules.GENERIC_DEPENDENCIES])
    self.assertEqual(
      mutation_calls[1:],
      [["/usr/bin/insmod", str(self.payload / (name + ".ko"))] for name in candidate_modules.LOAD_ORDER],
    )
    self.assertEqual(marker["boot_id"], self.boot_id)
    self.assertEqual(marker["entry_id"], self.entry_id)
    self.assertEqual(marker["policy"], "post-switch-root-only")
    self.assertEqual(marker, json.loads((self.payload / "ordinary-boot-loaded.json").read_text()))
    self.assertFalse((self.sys / "module/hci_bcm4377").exists())

  def test_rejects_changed_payload_before_loading(self):
    (self.payload / "t2bce_core.ko").write_bytes(b"changed")
    with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
      self.load()
    self.assertFalse(any(arguments[0] in ("/usr/bin/modprobe", "/usr/bin/insmod") for arguments in self.calls))

  def test_rejects_module_loaded_before_gate(self):
    (self.sys / "module/t2bce_core").mkdir(parents=True)
    with self.assertRaisesRegex(RuntimeError, "loaded before"):
      self.load()
    self.assertFalse(any(arguments[0] in ("/usr/bin/modprobe", "/usr/bin/insmod") for arguments in self.calls))

  def test_refuses_unhealthy_bindings(self):
    self.bind_devices = False
    with self.assertRaisesRegex(RuntimeError, "without healthy"):
      self.load()
    self.assertFalse((self.payload / "ordinary-boot-loaded.json").exists())


if __name__ == "__main__":
  unittest.main()
