"""Install Bluetooth boot ordering for the validated T2 model, without starting it."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ASSETS = Path(__file__).resolve().parent
CONFIG = 'etc/modules-load.d/t2.conf'
HELPER = 'usr/local/sbin/bluetooth-after-wifi'
UNIT = 'etc/systemd/system/bluetooth-after-wifi.service'
DROPIN = 'etc/systemd/system/bluetooth.service.d/50-t2-startup.conf'
BLACKLIST = 'etc/modprobe.d/t2-bluetooth-order.conf'
LINK = 'etc/systemd/system/multi-user.target.wants/bluetooth-after-wifi.service'
RECEIPT = 'var/lib/omarchy-t2-bluetooth/receipt.json'
# Earlier packaged helpers that setup replaces in place, by SHA-256.
PREVIOUS_HELPERS = {
  'cf4eb4a6584ce95b73ec0685c04a5ead11a34cb640f41eb63da0978f717e5360',  # fixed PCI address 0000:73:00.0
}

_spec = importlib.util.spec_from_file_location('omarchy_t2_bluetooth_gate', ASSETS/'gate.py')
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def supported(sys=Path('/sys')):
  try:
    if (sys/'class/dmi/id/sys_vendor').read_text().strip() != 'Apple Inc.':
      return False
    if (sys/'class/dmi/id/product_name').read_text().strip() != 'MacBookAir9,1':
      return False
    pci = sys/'bus/pci/devices'
    if not any((p/'vendor').read_text().strip() == '0x106b' and
        (p/'device').read_text().strip() in ('0x1801', '0x1802') for p in pci.iterdir()):
      return False
    return gate.find_wifi(sys) is not None
  except OSError:
    return False


def safe(root, name):
  path = root/name
  for parent in path.parents:
    if parent == root:
      break
    if parent.is_symlink():
      raise ValueError('Symlink parent: ' + str(parent))
  return path


def read(root, name):
  p = safe(root, name)
  if p.is_symlink():
    return {'link': os.readlink(p)}
  if not p.exists():
    return None
  if not p.is_file():
    raise ValueError('Not a regular file: ' + name)
  return {'hex': p.read_bytes().hex(), 'mode': p.stat().st_mode & 0o777}


def file(data, mode=0o644):
  return {'hex': data.hex(), 'mode': mode}


def write(root, name, value):
  p = safe(root, name)
  p.parent.mkdir(parents=True, exist_ok=True)
  if value is None:
    p.unlink(missing_ok=True)
    return
  fd, tmp = tempfile.mkstemp(prefix='.omarchy-bt-', dir=p.parent)
  try:
    with os.fdopen(fd, 'wb') as stream:
      if 'hex' in value:
        stream.write(bytes.fromhex(value['hex']))
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), value['mode'])
    if 'link' in value:
      os.unlink(tmp)
      os.symlink(value['link'], tmp)
    os.replace(tmp, p)
  finally:
    if os.path.lexists(tmp):
      os.unlink(tmp)


def payload():
  return {
    BLACKLIST: file(b'# Diagnostic: explicit service loads Bluetooth after Wi-Fi\nblacklist hci_bcm4377\n'),
    HELPER: file((ASSETS/'gate.py').read_bytes(), 0o755),
    UNIT: file((ASSETS/'bluetooth-after-wifi.service').read_bytes()),
    DROPIN: file((ASSETS/'50-t2-startup.conf').read_bytes()),
    CONFIG: file(b't2bce_vhci\n'),
    LINK: {'link': '/' + UNIT},
  }


def save(root, receipt):
  safe(root, RECEIPT).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  write(root, RECEIPT, file(json.dumps(receipt, indent=2).encode(), 0o600))


def load(root):
  record = read(root, RECEIPT)
  if record is None or 'hex' not in record:
    raise ValueError('Missing or invalid Bluetooth receipt')
  return json.loads(bytes.fromhex(record['hex']))


def verify(root, receipt):
  if receipt['state'] != 'installed':
    raise ValueError('Incomplete transaction; rollback before retry')
  for name, value in receipt['installed'].items():
    if read(root, name) != value:
      raise ValueError('Changed owned Bluetooth file: ' + name)


def restore(root, receipt):
  # Validate all paths before restoring any: never overwrite administrator edits.
  # An interrupted helper upgrade may still hold the previous helper.
  for name, original in receipt['original'].items():
    expected = [original, receipt['installed'][name]]
    if name in receipt.get('previous', {}):
      expected.append(receipt['previous'][name])
    if read(root, name) not in expected:
      raise ValueError('Changed transaction file: ' + name)
  for name, original in reversed(list(receipt['original'].items())):
    write(root, name, original)
  receipt['state'] = 'rolled-back'
  save(root, receipt)


def upgradable(installed, files):
  """An earlier packaged revision that differs only by a known helper."""
  helper = installed.get(HELPER) or {}
  rest = lambda payload: {n: v for n, v in payload.items() if n != HELPER}
  return (rest(installed) == rest(files) and helper.get('mode') == 0o755 and 'hex' in helper and
      hashlib.sha256(bytes.fromhex(helper['hex'])).hexdigest() in PREVIOUS_HELPERS)


def preflight(root, files):
  receipt = None
  if read(root, RECEIPT) is not None:
    receipt = load(root)
    verify(root, receipt)
    if receipt['installed'] != files and not upgradable(receipt['installed'], files):
      raise ValueError('Installed revision differs; review upgrade before replacing it')
  # Known lab revision 2 can be adopted in place, with full rollback to it.
  qualified = ASSETS.parents[3]/'docs/t2-bluetooth-qualified'
  allowed = {name: [None, value] for name, value in files.items()}
  allowed[CONFIG] = [file(b't2bce_vhci\nhci_bcm4377\n'), file(b't2bce_vhci\n')]
  allowed[HELPER].append(file((qualified/'bluetooth-after-wifi.py').read_bytes(), 0o755))
  if receipt is not None:
    allowed[HELPER].append(receipt['installed'][HELPER])
  for name in files:
    if read(root, name) not in allowed[name]:
      raise ValueError('Preserving unrecognized configuration: ' + name)
  for directory in ['etc/systemd/system/bluetooth-after-wifi.service.d',
      'usr/lib/systemd/system/bluetooth-after-wifi.service.d',
      'run/systemd/system/bluetooth-after-wifi.service.d',
      'etc/systemd/system/bluetooth.service.d',
      'run/systemd/system/bluetooth.service.d',
      'usr/lib/systemd/system/bluetooth.service.d']:
    d = safe(root, directory)
    if d.is_symlink():
      raise ValueError('Symlink override directory: ' + directory)
    if d.exists() and any(p != root/DROPIN for p in d.iterdir()):
      raise ValueError('Review existing Bluetooth service overrides: ' + directory)
  for name in ['etc/systemd/system/bluetooth.service', 'run/systemd/system/bluetooth.service',
      'run/systemd/system/bluetooth-after-wifi.service', 'usr/lib/systemd/system/bluetooth-after-wifi.service']:
    if read(root, name) is not None:
      raise ValueError('Review custom or masked Bluetooth unit: ' + name)
  for pattern in ['etc/modules-load.d/*.conf', 'usr/lib/modules-load.d/*.conf',
      'run/modules-load.d/*.conf', 'etc/mkinitcpio.conf', 'etc/mkinitcpio.conf.d/*.conf',
      'etc/modprobe.d/*.conf', 'run/modprobe.d/*.conf']:
    for p in root.glob(pattern):
      if p in (root/CONFIG, root/BLACKLIST):
        continue
      text = '\n'.join(line.split('#', 1)[0] for line in p.read_text().splitlines())
      if 'hci_bcm4377' in text:
        raise ValueError('Conflicting early Bluetooth load: ' + str(p))
  return receipt


def check_images(root, fresh, run=subprocess.run):
  images = list((root/'boot/EFI/Linux').glob('*linux-t2*.efi'))
  images += list((root/'boot').glob('initramfs-linux-t2*.img'))
  if not images and not fresh:
    raise ValueError('No stock T2 boot image found; inspect boot layout before setup')
  for image in images:
    result = run(['/usr/bin/lsinitcpio', '-l', str(image)], check=True,
        capture_output=True, text=True, timeout=60)
    if 'hci_bcm4377' in result.stdout:
      raise ValueError('Early Bluetooth in boot image: ' + str(image))


def upgrade(root, receipt, files, validate):
  # Only the helper changes. 'original' is kept, so rollback still restores the
  # pre-installation state; a failed upgrade leaves the previous revision installed.
  previous = receipt['installed']
  receipt.update(state='preparing', installed=files, previous={HELPER: previous[HELPER]})
  save(root, receipt)
  try:
    write(root, HELPER, files[HELPER])
    validate()
    receipt['state'] = 'installed'
    del receipt['previous']
    save(root, receipt)
    verify(root, receipt)
  except BaseException:
    write(root, HELPER, previous[HELPER])
    receipt.update(state='installed', installed=previous)
    receipt.pop('previous', None)
    save(root, receipt)
    raise


def install(root, validate=lambda: None):
  files = payload()
  receipt = preflight(root, files)
  if receipt is not None:
    if receipt['installed'] != files:
      upgrade(root, receipt, files, validate)
    return
  receipt = {'state': 'preparing', 'original': {n: read(root, n) for n in files}, 'installed': files}
  save(root, receipt)
  try:
    for name, value in files.items():
      write(root, name, value)
    validate()
    receipt['state'] = 'installed'
    save(root, receipt)
    verify(root, receipt)
  except BaseException:
    restore(root, receipt)
    raise


def upgrade_installed(root, validate=lambda: None):
  """Replace a recognized earlier helper; leave absent or rolled-back installs alone."""
  if read(root, RECEIPT) is None or load(root)['state'] != 'installed':
    return False
  install(root, validate)
  return True


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('action', choices=['supported', 'install', 'upgrade', 'verify', 'rollback'])
  parser.add_argument('--fresh', action='store_true', help='Allow a target whose boot image has not been generated yet')
  args = parser.parse_args()
  if args.action == 'supported':
    raise SystemExit(0 if supported() else 1)
  if os.geteuid() != 0:
    raise SystemExit('Root required')
  root = Path('/')
  os.umask(0o077)
  with open('/run/lock/omarchy-t2-bluetooth.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    def validate():
      subprocess.run(['/usr/bin/systemd-analyze', 'verify', '/' + UNIT,
          'bluetooth.service', 'systemd-user-sessions.service'], check=True, timeout=30)
      subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30)
    if args.action in ('install', 'upgrade'):
      if not supported():
        raise SystemExit('Requires validated MacBookAir9,1 with T2 and BCM4377b')
      try:
        if args.action == 'install':
          preflight(root, payload())
          check_images(root, args.fresh)
          install(root, validate)
        elif not upgrade_installed(root, validate):
          print('upgrade: no installed Bluetooth startup gate; nothing changed')
          return
      except BaseException:
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=False, timeout=30)
        raise
    elif args.action == 'rollback':
      restore(root, load(root))
      subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30)
    else:
      verify(root, load(root))
  print(args.action + ': complete; Bluetooth startup changes take effect on the next boot')


if __name__ == '__main__':
  main()
