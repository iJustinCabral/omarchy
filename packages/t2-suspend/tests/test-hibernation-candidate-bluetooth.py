#!/usr/bin/env python3
"""Exercise the candidate-only delayed Bluetooth loader without live devices."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


package = Path(__file__).resolve().parents[1]
helper_path = package / "experiments/hibernate-candidate-bluetooth.py"
spec = importlib.util.spec_from_file_location("candidate_bluetooth", helper_path)
candidate_bluetooth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate_bluetooth)


class Result:
  def __init__(self, stdout=""):
    self.stdout = stdout


class CandidateBluetoothTests(unittest.TestCase):
  release = "7.2.6-arch2-Watanare-T2-2-t2"
  srcversion = "58AC9A612284B234B28CD0B"

  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    base = Path(self.temporary.name)
    self.sys = base / "sys"
    self.payload = base / "run/omarchy-t2-hibernation-candidate"
    self.payload.mkdir(parents=True)
    self.module = self.payload / "hci_bcm4377.ko"
    self.module.write_bytes(b"candidate bluetooth module")
    (self.payload / "hci_bcm4377.sha256").write_text(hashlib.sha256(self.module.read_bytes()).hexdigest() + "\n")

    model = self.sys / "class/dmi/id/product_name"
    model.parent.mkdir(parents=True)
    model.write_text("MacBookAir9,1\n")
    wifi = self.sys / "bus/pci/devices" / candidate_bluetooth.WIFI_PCI
    wifi.mkdir(parents=True)
    (wifi / "vendor").write_text("0x14e4\n")
    (wifi / "device").write_text("0x4488\n")
    wifi_driver = self.sys / "drivers/brcmfmac"
    wifi_driver.mkdir(parents=True)
    (wifi / "driver").symlink_to(wifi_driver)
    interface = wifi / "net/wlan-renamed"
    interface.mkdir(parents=True)
    (interface / "ifindex").write_text("3\n")
    (interface / "phy80211").mkdir()

    bluetooth = self.sys / "bus/pci/devices" / candidate_bluetooth.BLUETOOTH_PCI
    bluetooth.mkdir(parents=True)
    self.bluetooth_driver = self.sys / "drivers/hci_bcm4377"
    self.bluetooth_driver.mkdir(parents=True)
    self.now = 0.0
    self.calls = []
    self.loaded_srcversion = self.srcversion

  def sleep(self, seconds):
    self.now += seconds

  def command(self, arguments, **_kwargs):
    self.calls.append(arguments)
    if arguments[:4] == ["/usr/bin/modinfo", "-F", "srcversion", str(self.module)]:
      return Result(self.srcversion + "\n")
    if arguments[:4] == ["/usr/bin/modinfo", "-F", "vermagic", str(self.module)]:
      return Result(self.release + " SMP preempt mod_unload\n")
    if arguments[0] == "/usr/bin/insmod":
      loaded = self.sys / "module/hci_bcm4377/srcversion"
      loaded.parent.mkdir(parents=True)
      loaded.write_text(self.loaded_srcversion + "\n")
      device = self.sys / "bus/pci/devices" / candidate_bluetooth.BLUETOOTH_PCI
      (device / "driver").symlink_to(self.bluetooth_driver)
      (self.sys / "class/bluetooth/hci0").mkdir(parents=True)
    return Result()

  def gate(self):
    candidate_bluetooth.gate(
      sys=self.sys,
      payload=self.payload,
      run=self.command,
      monotonic=lambda: self.now,
      sleep=self.sleep,
      release=self.release,
    )

  def test_loads_exact_payload_after_wifi(self):
    self.gate()
    self.assertEqual(self.calls, [
      ["/usr/bin/modinfo", "-F", "srcversion", str(self.module)],
      ["/usr/bin/modinfo", "-F", "vermagic", str(self.module)],
      ["/usr/bin/modprobe", "bluetooth"],
      ["/usr/bin/insmod", str(self.module)],
    ])

  def test_rejects_changed_payload(self):
    self.module.write_bytes(b"changed")
    with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
      self.gate()
    self.assertEqual(self.calls, [])

  def test_rejects_bluetooth_loaded_before_gate(self):
    (self.sys / "module/hci_bcm4377").mkdir(parents=True)
    with self.assertRaisesRegex(RuntimeError, "already loaded"):
      self.gate()
    self.assertEqual(self.calls, [])

  def test_wifi_timeout_never_loads(self):
    wifi = self.sys / "bus/pci/devices" / candidate_bluetooth.WIFI_PCI
    (wifi / "net/wlan-renamed/ifindex").write_text("0\n")
    with self.assertRaisesRegex(RuntimeError, "not ready"):
      self.gate()
    self.assertFalse(any(arguments[0] in ("/usr/bin/modprobe", "/usr/bin/insmod") for arguments in self.calls))

  def test_rejects_wrong_loaded_srcversion(self):
    self.loaded_srcversion = "WRONG"
    with self.assertRaisesRegex(RuntimeError, "without healthy"):
      self.gate()


if __name__ == "__main__":
  unittest.main()
