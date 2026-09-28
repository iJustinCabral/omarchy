"""Transaction and firmware-readiness tests without live system changes."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[2]
def module(name, source):
  spec = importlib.util.spec_from_file_location(name, source)
  m = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(m)
  return m
m = module('installer', ROOT/'install/hardware/apple/t2-bluetooth/manage.py')
g = module('gate', ROOT/'install/hardware/apple/t2-bluetooth/gate.py')
FIXED_PCI_GATE = ROOT/'test/shell.d/fixtures/t2-bluetooth-gate-fixed-pci.py'

def pci_device(sys, name, vendor, device):
  p = sys/'bus/pci/devices'/name
  p.mkdir(parents=True)
  (p/'vendor').write_text(vendor + '\n')
  (p/'device').write_text(device + '\n')
  return p

class Transaction(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.root = Path(self.tmp.name)
    m.write(self.root, m.CONFIG, m.file(b't2bce_vhci\nhci_bcm4377\n'))
    self.before = {n: m.read(self.root, n) for n in m.payload()}
  def restored(self):
    self.assertEqual(self.before, {n: m.read(self.root, n) for n in m.payload()})
  def test_install_repeat_and_rollback(self):
    m.install(self.root)
    receipt = m.load(self.root)
    m.verify(self.root, receipt)
    m.install(self.root)
    self.assertEqual(receipt, m.load(self.root))
    m.restore(self.root, receipt)
    self.restored()
  def test_adopt_qualified_revision(self):
    for name, value in m.payload().items():
      m.write(self.root, name, value)
    m.write(self.root, m.HELPER, m.file((ROOT/'docs/t2-bluetooth-qualified/bluetooth-after-wifi.py').read_bytes(), 0o755))
    self.before = {n: m.read(self.root, n) for n in m.payload()}
    m.install(self.root)
    m.restore(self.root, m.load(self.root))
    self.restored()
  def test_unknown_config_is_not_overwritten(self):
    m.write(self.root, m.CONFIG, m.file(b'custom\n'))
    with self.assertRaisesRegex(ValueError, 'unrecognized'):
      m.install(self.root)
    self.assertIsNone(m.read(self.root, m.RECEIPT))
  def test_user_edit_prevents_all_rollback(self):
    m.install(self.root)
    m.write(self.root, m.HELPER, m.file(b'custom'))
    before = {n: m.read(self.root, n) for n in m.payload()}
    with self.assertRaisesRegex(ValueError, 'Changed transaction'):
      m.restore(self.root, m.load(self.root))
    self.assertEqual(before, {n: m.read(self.root, n) for n in m.payload()})
  def test_validation_failure_restores_every_file(self):
    with self.assertRaisesRegex(RuntimeError, 'graph'):
      m.install(self.root, Mock(side_effect=RuntimeError('graph')))
    self.restored()
  def test_each_transaction_write_failure_restores(self):
    original = m.write
    for at in range(2, 9):
      with self.subTest(write=at):
        (self.root/m.RECEIPT).unlink(missing_ok=True)
        calls = 0
        def faulty(*args):
          nonlocal calls
          calls += 1
          if calls == at:
            raise OSError('injected')
          original(*args)
        with patch.object(m, 'write', side_effect=faulty):
          with self.assertRaises(OSError):
            m.install(self.root)
        self.restored()
  def test_pending_transaction_can_be_rolled_back(self):
    files = m.payload()
    receipt = {'state': 'preparing', 'original': self.before, 'installed': files}
    m.save(self.root, receipt)
    m.write(self.root, m.BLACKLIST, files[m.BLACKLIST])
    with self.assertRaisesRegex(ValueError, 'Incomplete'):
      m.install(self.root)
    m.restore(self.root, m.load(self.root))
    self.restored()
  def test_symlink_parent_is_rejected(self):
    (self.root/'usr').mkdir()
    (self.root/'usr/local').symlink_to('/tmp')
    with self.assertRaisesRegex(ValueError, 'Symlink parent'):
      m.install(self.root)
  def test_override_is_preserved(self):
    m.write(self.root, 'etc/systemd/system/bluetooth-after-wifi.service.d/custom.conf', m.file(b'custom'))
    with self.assertRaisesRegex(ValueError, 'overrides'):
      m.install(self.root)
    self.restored()
  def test_early_module_request_is_rejected(self):
    m.write(self.root, 'etc/modules-load.d/custom.conf', m.file(b'hci_bcm4377\n'))
    with self.assertRaisesRegex(ValueError, 'early Bluetooth'):
      m.install(self.root)
  def test_image_inspection_is_mandatory_for_upgrade(self):
    with self.assertRaisesRegex(ValueError, 'No stock'):
      m.check_images(self.root, False)
    m.check_images(self.root, True)
  def test_image_with_hci_is_rejected(self):
    p = self.root/'boot/EFI/Linux/omarchy_linux-t2.efi'
    p.parent.mkdir(parents=True)
    p.touch()
    with self.assertRaisesRegex(ValueError, 'Early Bluetooth'):
      m.check_images(self.root, False, Mock(return_value=Mock(stdout='hci_bcm4377.ko.zst')))
    m.check_images(self.root, False, Mock(return_value=Mock(stdout='brcmfmac.ko.zst')))
  def test_new_override_is_rejected_on_repeat_install(self):
    m.install(self.root)
    m.write(self.root, 'etc/systemd/system/bluetooth-after-wifi.service.d/extra.conf', m.file(b'custom'))
    with self.assertRaisesRegex(ValueError, 'overrides'):
      m.install(self.root)
  def test_masked_bluez_is_preserved(self):
    p = self.root/'etc/systemd/system/bluetooth.service'
    p.parent.mkdir(parents=True)
    p.symlink_to('/dev/null')
    with self.assertRaisesRegex(ValueError, 'masked'):
      m.install(self.root)
    self.assertEqual(p.readlink(), Path('/dev/null'))
  def test_image_inspection_failure_propagates(self):
    p = self.root/'boot/initramfs-linux-t2.img'
    p.parent.mkdir(parents=True)
    p.touch()
    with self.assertRaises(OSError):
      m.check_images(self.root, False, Mock(side_effect=OSError('cannot inspect')))
  def test_readiness_policy_matches_qualified_gate_except_kernel_pin(self):
    qualified = (ROOT/'docs/t2-bluetooth-qualified/bluetooth-after-wifi.py').read_text()
    current = (ROOT/'install/hardware/apple/t2-bluetooth/gate.py').read_text()
    qualified = qualified.replace("import os\n", '').replace("    if os.uname().release != '7.2.4-arch1-Watanare-T2-1-t2':\n        raise RuntimeError('unvalidated kernel')\n", '')
    # The only other difference: the fixed PCI address became discovery by device ID.
    qualified = qualified.replace("PCI = '0000:73:00.0'\n", '')
    qualified = qualified.replace("dev = sys/'bus/pci/devices'/PCI", "dev = find_wifi(sys)\nif dev is None:\nreturn None")
    start, end = current.index("WIFI = ("), current.index("def wifi_ready(")
    current = current[:start] + current[end:]
    self.assertEqual(''.join(qualified.split()), ''.join(current.split()))
  def test_only_validated_model_supported(self):
    dmi = self.root/'class/dmi/id'
    dmi.mkdir(parents=True)
    (dmi/'sys_vendor').write_text('Apple Inc.')
    (dmi/'product_name').write_text('MacBookAir9,1')
    pci = self.root/'bus/pci/devices'
    for name, vendor, device in [('0000:73:00.0', '0x14e4', '0x4488'), ('0000:74:00.0', '0x106b', '0x1801')]:
      p = pci/name
      p.mkdir(parents=True)
      (p/'vendor').write_text(vendor)
      (p/'device').write_text(device)
    self.assertTrue(m.supported(self.root))
    (dmi/'product_name').write_text('MacBookPro16,1')
    self.assertFalse(m.supported(self.root))
    (dmi/'product_name').write_text('MacBookAir9,1')
    (pci/'0000:73:00.0').rename(pci/'0000:7a:00.0')
    self.assertTrue(m.supported(self.root), 'Wi-Fi is found by ID at another address')
    pci_device(self.root, '0000:7b:00.0', '0x14e4', '0x4488')
    self.assertFalse(m.supported(self.root), 'two BCM4377 Wi-Fi functions are ambiguous')
    for p in pci.glob('0000:7?:00.0'):
      if p.name != '0000:74:00.0':
        (p/'device').write_text('0x4464')
    self.assertFalse(m.supported(self.root), 'BCM4364 is not eligible')


class Discovery(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.sys = Path(self.tmp.name)
    (self.sys/'bus/pci/devices').mkdir(parents=True)
  def ready_wifi(self, name):
    dev = pci_device(self.sys, name, '0x14e4', '0x4488')
    (self.sys/'drivers/brcmfmac').mkdir(parents=True, exist_ok=True)
    (dev/'driver').symlink_to(self.sys/'drivers/brcmfmac')
    net = dev/'net/wlan0'
    (net/'phy80211').mkdir(parents=True)
    (net/'ifindex').write_text('3\n')
    return dev
  def test_ready_at_any_address(self):
    pci_device(self.sys, '0000:74:00.0', '0x106b', '0x1801')
    self.ready_wifi('0000:7a:00.0')
    self.assertEqual(g.wifi_ready(self.sys), 'wlan0')
  def test_absent_or_ambiguous_wifi_is_not_ready(self):
    self.assertIsNone(g.wifi_ready(self.sys))
    self.ready_wifi('0000:73:00.0')
    self.ready_wifi('0000:7a:00.0')
    self.assertIsNone(g.find_wifi(self.sys))
    self.assertIsNone(g.wifi_ready(self.sys))
  def test_other_driver_is_not_ready(self):
    dev = self.ready_wifi('0000:73:00.0')
    (dev/'driver').unlink()
    (self.sys/'drivers/other').mkdir()
    (dev/'driver').symlink_to(self.sys/'drivers/other')
    self.assertIsNone(g.wifi_ready(self.sys))
  def test_missing_pci_tree_is_not_ready(self):
    self.assertIsNone(g.find_wifi(self.sys/'absent'))


class Upgrade(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.root = Path(self.tmp.name)
    m.write(self.root, m.CONFIG, m.file(b't2bce_vhci\nhci_bcm4377\n'))
    self.before = {n: m.read(self.root, n) for n in m.payload()}
    self.old = dict(m.payload())
    self.old[m.HELPER] = m.file(FIXED_PCI_GATE.read_bytes(), 0o755)
    with patch.object(m, 'payload', return_value=self.old):
      m.install(self.root)
  def test_fixture_is_the_recognized_previous_gate(self):
    self.assertIn(hashlib.sha256(FIXED_PCI_GATE.read_bytes()).hexdigest(), m.PREVIOUS_HELPERS)
  def test_previous_gate_upgrades_in_place_and_still_rolls_back(self):
    m.install(self.root)
    receipt = m.load(self.root)
    self.assertEqual(receipt['installed'], m.payload())
    self.assertNotIn('previous', receipt)
    self.assertEqual(m.read(self.root, m.HELPER), m.payload()[m.HELPER])
    m.install(self.root)
    self.assertEqual(receipt, m.load(self.root))
    m.restore(self.root, m.load(self.root))
    self.assertEqual(self.before, {n: m.read(self.root, n) for n in m.payload()})
  def test_failed_upgrade_keeps_previous_revision(self):
    with self.assertRaisesRegex(RuntimeError, 'graph'):
      m.install(self.root, Mock(side_effect=RuntimeError('graph')))
    receipt = m.load(self.root)
    self.assertEqual(receipt['state'], 'installed')
    self.assertEqual(receipt['installed'], self.old)
    m.verify(self.root, receipt)
  def test_interrupted_upgrade_can_be_rolled_back(self):
    receipt = m.load(self.root)
    receipt.update(state='preparing', installed=m.payload(), previous={m.HELPER: self.old[m.HELPER]})
    m.save(self.root, receipt)
    with self.assertRaisesRegex(ValueError, 'Incomplete'):
      m.install(self.root)
    m.restore(self.root, m.load(self.root))
    self.assertEqual(self.before, {n: m.read(self.root, n) for n in m.payload()})
  def test_edited_previous_helper_is_preserved(self):
    m.write(self.root, m.HELPER, m.file(b'custom', 0o755))
    with self.assertRaisesRegex(ValueError, 'Changed owned'):
      m.install(self.root)
    self.assertEqual(m.read(self.root, m.HELPER), m.file(b'custom', 0o755))
  def test_unknown_revision_is_still_refused(self):
    receipt = m.load(self.root)
    unknown = m.file(b'#!/usr/bin/python3\n# unknown\n', 0o755)
    receipt['installed'][m.HELPER] = unknown
    m.write(self.root, m.HELPER, unknown)
    m.save(self.root, receipt)
    with self.assertRaisesRegex(ValueError, 'Installed revision differs'):
      m.install(self.root)
    self.assertEqual(m.read(self.root, m.HELPER), unknown)
  def test_upgrade_action_only_touches_installed_gates(self):
    self.assertTrue(m.upgrade_installed(self.root))
    self.assertEqual(m.load(self.root)['installed'], m.payload())
    m.restore(self.root, m.load(self.root))
    after_rollback = {n: m.read(self.root, n) for n in m.payload()}
    self.assertFalse(m.upgrade_installed(self.root))
    self.assertEqual(after_rollback, {n: m.read(self.root, n) for n in m.payload()})
    empty = Path(self.tmp.name)/'empty'
    empty.mkdir()
    self.assertFalse(m.upgrade_installed(empty))
    self.assertIsNone(m.read(empty, m.RECEIPT))
  def test_other_file_changes_are_not_upgraded(self):
    receipt = m.load(self.root)
    receipt['installed'][m.BLACKLIST] = m.file(b'blacklist hci_bcm4377\n')
    m.write(self.root, m.BLACKLIST, receipt['installed'][m.BLACKLIST])
    m.save(self.root, receipt)
    with self.assertRaisesRegex(ValueError, 'Installed revision differs'):
      m.install(self.root)

unittest.main()
