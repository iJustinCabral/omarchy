"""Transaction and firmware-readiness tests without live system changes."""
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

unittest.main()
