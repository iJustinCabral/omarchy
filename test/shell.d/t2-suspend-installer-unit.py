import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('manager', REPO / 'packages/t2-suspend/installer/manage.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RELEASE = '7.2.4-arch1-Watanare-T2-1-t2'

class Installer(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    for name, data in {
      f'usr/lib/modules/{RELEASE}/pkgbase': b'linux-t2\n',
      f'usr/lib/modules/{RELEASE}/build/Makefile': b'headers',
      'boot/EFI/Linux/test-linux-t2.efi': b'original boot image',
      'boot/limine.conf': b'original menu',
      'etc/modules-load.d/t2.conf': b't2bce_vhci\nhci_bcm4377\n',
      'etc/bluetooth/main.conf': b'# retain comment\n[General]\nName = Mine\n[Policy]\n#ResumeDelay = 2\n',
    }.items():
      p = self.root / name
      p.parent.mkdir(parents=True, exist_ok=True)
      p.write_bytes(data)
    m.bt.install(self.root)
    self.calls = []
    self.fail = None
    self.preparer = patch.object(m.prepare, 'prepare', self.prepare)
    self.preparer.start()
    self.addCleanup(self.preparer.stop)

  def prepare(self, wifi, bluetooth, output, profile):
    self.assertEqual(profile, 'wifi-reenable')
    output.mkdir()
    (output / 'source.c').write_text('verified source')

  def runner(self, args, **kwargs):
    self.calls.append(args)
    if args[:2] == ['dkms', 'build']:
      self.assertIsNone(m.bt.read(self.root, 'etc/modprobe.d/omarchy-t2-suspend.conf'))
    if args[0] == 'limine-mkinitcpio':
      (self.root / 'boot/limine.conf').write_text('generated menu')
      (self.root / 'boot/EFI/Linux/test-linux-t2.efi').write_text('generated image')
      (self.root / 'boot/new-file').write_text('new')
    if self.fail and args[:len(self.fail)] == self.fail:
      raise subprocess.CalledProcessError(1, args, stderr='injected failure')
    listing = 'etc/omarchy-t2-radio-source.json\n' + '\n'.join('/updates/dkms/' + n + '.ko' for n in m.MODULES[:-1])
    listing += '\n' + '\n'.join('usr/lib/firmware/brcm/brcmfmac4377b3-pcie.apple,formosa' + s for s in ('.bin', '-SPPR-m.txt', '-SPPR-u.txt', '.clm_blob', '.txcap_blob'))
    return subprocess.CompletedProcess(args, 0, stdout=listing if args[0] == '/usr/bin/lsinitcpio' else '', stderr='')

  def install(self):
    return m.install(self.root, self.runner, lambda *_: None, lambda *_: None)

  def test_install_idempotent_and_rollback(self):
    original = (self.root / 'etc/bluetooth/main.conf').read_bytes()
    self.install()
    self.assertEqual(m.load(self.root)['state'], 'installed')
    self.assertIn('ResumeDelay = 5', (self.root / 'etc/bluetooth/main.conf').read_text())
    calls = list(self.calls)
    self.install()
    self.assertEqual([c for c in self.calls if c[0] != '/usr/bin/lsinitcpio'], [c for c in calls if c[0] != '/usr/bin/lsinitcpio'])
    m.rollback(self.root, self.runner)
    self.assertEqual((self.root / 'etc/bluetooth/main.conf').read_bytes(), original)
    self.assertFalse((self.root / m.SOURCE).exists())
    self.assertIsNone(m.bt.read(self.root, 'etc/modprobe.d/omarchy-t2-suspend.conf'))

  def test_all_failure_stages_restore_boot_and_config(self):
    original = (self.root / 'etc/bluetooth/main.conf').read_bytes()
    for failure in (['dkms', 'add'], ['dkms', 'build'], ['dkms', 'install'], ['limine-mkinitcpio']):
      with self.subTest(failure=failure):
        self.fail = failure
        with self.assertRaises(subprocess.CalledProcessError): self.install()
        self.assertEqual(m.load(self.root)['state'], 'rolled-back')
        self.assertEqual((self.root / 'boot/limine.conf').read_bytes(), b'original menu')
        self.assertEqual((self.root / 'boot/EFI/Linux/test-linux-t2.efi').read_bytes(), b'original boot image')
        self.assertFalse((self.root / 'boot/new-file').exists())
        self.assertEqual((self.root / 'etc/bluetooth/main.conf').read_bytes(), original)

  def test_admin_config_refused(self):
    p = self.root / 'etc/modprobe.d/omarchy-t2-suspend.conf'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('custom')
    with self.assertRaises(ValueError): self.install()
    self.assertEqual(p.read_text(), 'custom')
    self.assertFalse(any(c[0] != '/usr/bin/lsinitcpio' for c in self.calls))

  def test_rollback_preserves_admin_edits(self):
    self.install()
    p = self.root / 'etc/bluetooth/main.conf'
    p.write_text('user edit')
    with self.assertRaises(ValueError): m.rollback(self.root, self.runner)
    self.assertEqual(p.read_text(), 'user edit')

  def test_missing_headers(self):
    (self.root / f'usr/lib/modules/{RELEASE}/build/Makefile').unlink()
    with self.assertRaises(ValueError): self.install()
    self.assertFalse(any(c[0] != '/usr/bin/lsinitcpio' for c in self.calls))

  def test_source_drift(self):
    self.install()
    (self.root / m.SOURCE / 'source.c').write_text('changed')
    with self.assertRaises(ValueError): m.verify(self.root, self.runner, lambda *_: None)
    with self.assertRaises(ValueError): m.rollback(self.root, self.runner)

  def test_live_dkms_loading_refused(self):
    p = self.root / 'etc/dkms/framework.conf'
    p.parent.mkdir(parents=True)
    p.write_text('modprobe_on_install="true"\n')
    with self.assertRaises(ValueError): self.install()
    self.assertFalse(any(c[0] != '/usr/bin/lsinitcpio' for c in self.calls))

  def test_boot_contains_early_bluetooth(self):
    def image_runner(args, **kwargs):
      return subprocess.CompletedProcess(args, 0, stdout='hci_bcm4377.ko', stderr='')
    with self.assertRaises(ValueError): m.install(self.root, image_runner, lambda *_: None, lambda *_: None)
    self.assertFalse((self.root / m.SOURCE).exists())

  def test_no_power_or_radio_commands(self):
    self.install()
    m.rollback(self.root, self.runner)
    self.assertFalse(any(c[0] in ('modprobe', 'rmmod', 'bluetoothctl', 'nmcli', 'reboot', 'systemctl') for c in self.calls))

  def test_exact_bluetooth_sibling_scope(self):
    sys = self.root / 'sys'
    sibling = sys / 'bus/pci/devices/0000:73:00.1'
    sibling.mkdir(parents=True)
    (sibling / 'vendor').write_text('0x14e4')
    (sibling / 'device').write_text('0x5fa0')
    with patch.object(m.bt, 'supported', return_value=True):
      self.assertTrue(m.supported(sys))
      (sibling / 'device').write_text('0x4364')
      self.assertFalse(m.supported(sys))
      (sibling / 'device').unlink()
      self.assertFalse(m.supported(sys))
    with patch.object(m.bt, 'supported', return_value=False):
      self.assertFalse(m.supported(sys))

  def test_missing_image_marker_refused(self):
    def runner(args, **kwargs):
      return subprocess.CompletedProcess(args, 0, stdout='/updates/dkms/brcmfmac.ko', stderr='')
    with self.assertRaises(ValueError): m.check_images(self.root, runner)

  def test_missing_apple_firmware_refused(self):
    def runner(args, **kwargs):
      result = self.runner(args, **kwargs)
      result.stdout = '\n'.join(line for line in result.stdout.splitlines() if not line.endswith('formosa.bin'))
      return result
    with self.assertRaisesRegex(ValueError, 'Missing Apple Wi-Fi firmware'):
      m.check_images(self.root, runner)

  def test_hook_aborts_before_modules_when_firmware_missing(self):
    firmware = self.root / 'usr/lib/firmware/brcm'
    firmware.mkdir(parents=True)
    files = [firmware / ('brcmfmac4377b3-pcie.apple,formosa' + s)
             for s in ('.bin', '-SPPR-m.txt', '-SPPR-u.txt', '.clm_blob', '.txcap_blob')]
    for missing in files:
      with self.subTest(missing=missing.name):
        for p in files: p.write_bytes(b'firmware fixture')
        missing.unlink()
        result = subprocess.run(['bash', '-c', '''
source "$1"
KERNELVERSION=$2
_optmoduleroot=$3
error() { echo "$*" >&2; }
modinfo() { echo "UNEXPECTED MODULE LOOKUP" >&2; return 99; }
build
echo "UNEXPECTED BUILD CONTINUED"
''', 'test', str(m.HERE / 'initcpio-install'), RELEASE, str(self.root)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Missing Apple Wi-Fi firmware: ' + str(missing), result.stderr)
        self.assertNotIn('UNEXPECTED', result.stderr + result.stdout)

  def test_bluez_policy_preserves_custom_values(self):
    for data in (b'[Policy]\nResumeDelay = 9\n', b'[Policy]\n[Policy]\n'):
      with self.assertRaises(ValueError): m.bluez_policy(data)
    data = b'[Policy]\nResumeDelay = 5\n'
    self.assertEqual(m.bluez_policy(data), data)

if __name__ == '__main__': unittest.main()
