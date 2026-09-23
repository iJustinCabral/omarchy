"""Qualified Bluetooth gate fixtures; no live module operations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('ready', Path(__file__).resolve().parents[2]/'docs/t2-bluetooth-qualified/bluetooth-after-wifi.py')
ready = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ready)
class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        model = self.root/'class/dmi/id/product_name'
        model.parent.mkdir(parents=True)
        model.write_text('MacBookAir9,1\n')
        self.dev = self.root/'bus/pci/devices'/ready.PCI
        self.dev.mkdir(parents=True)
        (self.dev/'vendor').write_text('0x14e4')
        (self.dev/'device').write_text('0x4488')
        (self.root/'drivers/brcmfmac').mkdir(parents=True)
        (self.dev/'driver').symlink_to(self.root/'drivers/brcmfmac')
        self.now = 0
        self.calls = []
        uname = patch.object(ready.os, 'uname')
        uname.start().return_value.release = '7.2.4-arch1-Watanare-T2-1-t2'
        self.addCleanup(uname.stop)

    def net(self):
        net = self.dev/'net/wlan-renamed'
        net.mkdir(parents=True)
        (net/'ifindex').write_text('3')
        (net/'phy80211').mkdir()
        # Deliberately offline and administratively down.
        (net/'operstate').write_text('down')
        (net/'carrier').write_text('0')
        return net

    def sleep(self, seconds):
        self.now += seconds

    def gate(self, sleep=None):
        ready.gate(self.root, run=lambda *a, **k: self.calls.append(a),
                   monotonic=lambda: self.now, sleep=sleep or self.sleep)

    def test_offline_netdev_loads_once(self):
        self.net()
        self.gate()
        self.assertEqual(self.calls, [(['/usr/bin/modprobe', 'hci_bcm4377'],)])

    def test_delayed_registration(self):
        def later(seconds):
            self.sleep(seconds)
            if self.now >= 1 and not (self.dev/'net').exists(): self.net()
        self.gate(later)
        self.assertGreaterEqual(self.now, 1)
        self.assertEqual(len(self.calls), 1)

    def test_missing_interface_times_out_without_loading(self):
        with self.assertRaisesRegex(RuntimeError, 'not ready'): self.gate()
        self.assertEqual(self.calls, [])

    def test_wrong_device_not_ready(self):
        self.net()
        (self.dev/'device').write_text('0x1234')
        self.assertIsNone(ready.wifi_ready(self.root))

    def test_partial_registration_not_ready(self):
        self.net().joinpath('ifindex').write_text('0')
        self.assertIsNone(ready.wifi_ready(self.root))

    def test_premature_bluetooth_rejected(self):
        (self.root/'module/hci_bcm4377').mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, 'already loaded'): self.gate()
        self.assertEqual(self.calls, [])


unittest.main()
