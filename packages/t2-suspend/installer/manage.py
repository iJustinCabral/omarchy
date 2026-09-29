#!/usr/bin/python3
"""Install the scoped T2 DKMS driver set for the next boot; never change live radios."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
REPO = HERE.parents[2]
NAME, VERSION = 'omarchy-t2-radio', '1.6'

def source_name(version):
  return f'usr/src/{NAME}-{version}'

SOURCE = source_name(VERSION)
STATE = 'var/lib/omarchy-t2-suspend'
RECEIPT = STATE + '/receipt.json'
# Radio only. The BCE family (keyboard, trackpad, audio) is never replaced by this package.
MODULES = ('brcmfmac', 'brcmfmac-wcc', 'brcmfmac-cyw', 'brcmfmac-bca', 'hci_bcm4377')
INITRAMFS_MODULES = ('brcmfmac', 'brcmfmac-wcc', 'brcmfmac-cyw', 'brcmfmac-bca')
# Every one of these must resolve to the stock kernel tree; t2bce_ave is optional.
BCE_FAMILY = ('t2bce_dma', 't2bce_core', 't2bce_vhci', 't2bce_audio', 't2bce_ave')
BCE_STOCK = '/kernel/drivers/staging/t2bce/'
# DKMS build gate and qualified stock fingerprints, shipped in the DKMS source tree.
SOURCE_FILES = ('dkms.conf', 'build-modules.sh', 'check-radio-qualification.sh', 'qualified-radio.conf')

def load_module(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result

bt = load_module('t2_bluetooth_installer', REPO / 'install/hardware/apple/t2-bluetooth/manage.py')
prepare = load_module('t2_prepare', PACKAGE / 'prepare-source.py')
fetcher = load_module('t2_fetch', PACKAGE / 'fetch-source.py')

def supported(sys=Path('/sys')):
  if not bt.supported(sys): return False
  try:
    sibling = sys / 'bus/pci/devices/0000:73:00.1'
    return ((sibling / 'vendor').read_text().strip() == '0x14e4' and
            (sibling / 'device').read_text().strip() == '0x5fa0')
  except OSError:
    return False

def run(args, **kwargs):
  kwargs.setdefault('check', True)
  kwargs.setdefault('text', True)
  kwargs.setdefault('capture_output', True)
  return subprocess.run(args, **kwargs)

def safe(root, name):
  return bt.safe(root, name)

def save(root, receipt):
  bt.write(root, RECEIPT, bt.file((json.dumps(receipt, indent=2) + '\n').encode(), 0o600))

def load(root):
  return json.loads(bytes.fromhex(bt.read(root, RECEIPT)['hex']))

def installed_version(receipt):
  version = receipt.get('version')
  if not isinstance(version, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version):
    raise ValueError('Invalid T2 suspend receipt version')
  return version

def tree_hash(path):
  return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(path.rglob('*')) if p.is_file()}

def kernels(root):
  result = []
  for p in sorted((root / 'usr/lib/modules').glob('*/pkgbase')):
    if p.read_text().strip() == 'linux-t2':
      release = p.parent.name
      if not re.fullmatch(r'[a-zA-Z0-9._+-]+-t2', release):
        raise ValueError('Unexpected T2 kernel release')
      if not (p.parent / 'build/Makefile').is_file():
        raise ValueError('Install matching linux-t2-headers before driver setup')
      result.append(release)
  if not result:
    raise ValueError('No installed linux-t2 kernel with headers')
  return result

def bluez_policy(data):
  text = data.decode()
  section = None
  found = []
  sections = 0
  for i, line in enumerate(text.splitlines()):
    m = re.match(r'\s*\[([^]]+)\]', line)
    if m:
      section = m[1]
      sections += section == 'Policy'
    if section == 'Policy' and re.match(r'\s*ResumeDelay\s*=', line):
      found.append(line.split('=', 1)[1].strip())
  if sections > 1 or len(found) > 1:
    raise ValueError('Ambiguous BlueZ Policy/ResumeDelay configuration')
  if found:
    if found != ['5']:
      raise ValueError('Preserving administrator BlueZ ResumeDelay; expected 5')
    return data
  if sections:
    return re.sub(r'(?m)^(\s*\[Policy\].*)$', r'\1\n# Allow T2 HCI reconstruction before automatic reconnect.\nResumeDelay = 5', text, count=1).encode()
  return (text.rstrip() + '\n\n[Policy]\nResumeDelay = 5\n').encode()

def files(root):
  bluez = bt.read(root, 'etc/bluetooth/main.conf')
  if bluez is not None and 'hex' not in bluez:
    raise ValueError('BlueZ configuration must be a regular file')
  data = bytes.fromhex(bluez['hex']) if bluez else b''
  return {
    'etc/bluetooth/main.conf': bt.file(bluez_policy(data), bluez['mode'] if bluez else 0o644),
    'etc/modprobe.d/omarchy-t2-suspend.conf': bt.file((HERE / 'radio.conf').read_bytes()),
    'etc/NetworkManager/conf.d/99-omarchy-t2-radio.conf': bt.file((HERE / 'network.conf').read_bytes()),
    'etc/mkinitcpio.conf.d/zz-omarchy-t2-suspend.conf': bt.file((HERE / 'mkinitcpio.conf').read_bytes()),
    'usr/lib/initcpio/install/omarchy-t2-suspend': bt.file((HERE / 'initcpio-install').read_bytes(), 0o755),
    # Vendor companion modules can have unchanged srcversions; DKMS must replace the set.
    'usr/share/dkms/modules_to_force_install/omarchy-t2-radio': bt.file(b'omarchy-t2-radio\n'),
  }

def check_dkms_policy(root):
  configs = [root / 'etc/dkms/framework.conf'] + sorted((root / 'etc/dkms/framework.conf.d').glob('*.conf'))
  for path in configs:
    if not path.exists(): continue
    for line in path.read_text().splitlines():
      value = line.split('#', 1)[0].strip()
      if re.match(r'(?:export\s+)?modprobe_on_install\s*=', value) and value.split('=', 1)[1].strip().strip("\"'"):
        raise ValueError('DKMS automatic live loading is enabled in ' + str(path))
  for path in (root / 'etc/dkms').glob(NAME + '*.conf'):
    raise ValueError('Preserving custom DKMS module configuration: ' + str(path))

def qualified(root, release, runner=run):
  """True when the kernel's stock radio srcversions match a qualified row."""
  result = runner(['bash', str(HERE / 'check-radio-qualification.sh'), release, str(root)], check=False)
  if result.returncode not in (0, 1):
    raise ValueError('Cannot evaluate T2 radio qualification for ' + release)
  return result.returncode == 0

def check_bce_family(release, runner=run):
  for name in BCE_FAMILY:
    try:
      selected = runner(['modinfo', '-k', release, '-n', name]).stdout.strip()
    except subprocess.CalledProcessError:
      if name == 't2bce_ave': continue
      raise ValueError('Missing T2 BCE module: ' + name)
    if BCE_STOCK not in selected:
      raise ValueError('Mixed or foreign T2 BCE module family: ' + name + ' resolves to ' +
                       selected + '; every t2bce_* module must come from the stock kernel tree')

def check_selection(releases, runner=run, root=Path('/')):
  for release in releases:
    check_bce_family(release, runner)
    if not qualified(root, release, runner):
      # DKMS skipped the package: the whole radio set must be stock, with no package build.
      build = root / f'var/lib/dkms/{NAME}/{VERSION}/{release}/x86_64/module'
      for name in MODULES:
        selected = runner(['modinfo', '-k', release, '-n', name]).stdout.strip()
        if '/kernel/drivers/' not in selected or any(build.glob(name + '.ko*')):
          raise ValueError('Unqualified kernel ' + release + ' must use stock radio drivers: ' + name)
      print('Warning: T2 radio package skipped for unqualified kernel ' + release +
            '; stock radio drivers stay in use', flush=True)
      continue
    for name in MODULES:
      selected = runner(['modinfo', '-k', release, '-n', name]).stdout.strip()
      if not selected.startswith('/lib/modules/' + release + '/') and not selected.startswith('/usr/lib/modules/' + release + '/'):
        raise ValueError('Unexpected module selection: ' + selected)
      vermagic = runner(['modinfo', '-F', 'vermagic', selected]).stdout.split()
      if not vermagic or vermagic[0] != release:
        raise ValueError('Wrong module ABI: ' + name)
      actual = runner(['modinfo', '-F', 'srcversion', selected]).stdout.strip()
      module = root / f'var/lib/dkms/{NAME}/{VERSION}/{release}/x86_64/module/{name}.ko'
      candidates = [module] + [Path(str(module) + ext) for ext in ('.zst', '.xz', '.gz')]
      built = next((p for p in candidates if p.is_file()), None)
      if built is None:
        raise ValueError('Missing DKMS module: ' + name)
      expected = runner(['modinfo', '-F', 'srcversion', str(built)]).stdout.strip()
      if not expected or actual != expected:
        raise ValueError('Wrong replacement module selected: ' + name)

def check_images(root, runner=run):
  bt.check_images(root, False, runner)
  images = list((root / 'boot/EFI/Linux').glob('*linux-t2*.efi'))
  images += list((root / 'boot').glob('initramfs-linux-t2*.img'))
  for image in images:
    listing = runner(['/usr/bin/lsinitcpio', '-l', str(image)]).stdout
    if 'etc/omarchy-t2-radio-source.json' not in listing:
      raise ValueError('T2 verification hook did not run for ' + str(image))
    for suffix in ('.bin', '-SPPR-m.txt', '-SPPR-u.txt', '.clm_blob', '.txcap_blob'):
      firmware = 'usr/lib/firmware/brcm/brcmfmac4377b3-pcie.apple,formosa' + suffix
      if firmware not in listing.splitlines():
        raise ValueError('Missing Apple Wi-Fi firmware in boot image: ' + firmware)
    for name in INITRAMFS_MODULES:
      if '/' + name + '.ko' not in listing:
        raise ValueError('Missing required module in boot image: ' + name)

def verify(root, runner=run, selection=check_selection):
  receipt = load(root)
  if receipt['state'] != 'installed':
    raise ValueError('Incomplete installation; run rollback before retry')
  if installed_version(receipt) != VERSION:
    raise ValueError('Installed T2 suspend drivers require an upgrade')
  for name, value in receipt['installed'].items():
    if bt.read(root, name) != value:
      raise ValueError('Changed owned configuration: ' + name)
  if tree_hash(safe(root, SOURCE)) != receipt['source_hashes']:
    raise ValueError('Changed DKMS source tree')
  releases = kernels(root)
  selection(releases, runner, root)
  check_images(root, runner)
  return receipt

def backup_boot(root, dest):
  boot = root / 'boot'
  shutil.copytree(boot, dest, symlinks=True)

def restore_boot(root, backup):
  # Installation holds our lock and rejects an active package transaction.
  # Never follow a saved symlink into another filesystem.
  boot = root / 'boot'
  for p in sorted(boot.rglob('*'), key=lambda p: len(p.parts), reverse=True):
    old = backup / p.relative_to(boot)
    if not old.exists() and not old.is_symlink():
      if p.is_symlink() or p.is_file(): p.unlink()
      elif p.is_dir(): p.rmdir()
  shutil.copytree(backup, boot, symlinks=True, dirs_exist_ok=True)

def rollback(root, runner=run, rebuild=True):
  receipt = load(root)
  if receipt['state'] == 'rolled-back':
    return
  version = installed_version(receipt)
  for name, original in receipt['original'].items():
    if bt.read(root, name) not in (original, receipt['installed'][name]):
      raise ValueError('Preserving edited configuration: ' + name)
  source = safe(root, source_name(version))
  if source.exists() and tree_hash(source) != receipt['source_hashes']:
    raise ValueError('Preserving edited DKMS source tree')
  if receipt.get('dkms_added') and (root / f'var/lib/dkms/{NAME}/{version}').exists():
    runner(['dkms', 'remove', '-m', NAME, '-v', version, '--all'])
  for name, original in reversed(list(receipt['original'].items())):
    bt.write(root, name, original)
  if source.exists(): shutil.rmtree(source)
  for release in kernels(root): runner(['depmod', '-a', release])
  if rebuild:
    # A later manual rollback rebuilds for the current kernel, not an old snapshot.
    runner(['limine-mkinitcpio', 'linux-t2'])
  else:
    restore_boot(root, root / receipt['boot_backup'])
  receipt['state'] = 'rolled-back'
  save(root, receipt)

def install(root, runner=run, selection=check_selection, fetch=fetcher.fetch):
  if bt.read(root, RECEIPT) is not None:
    receipt = load(root)
    if receipt['state'] == 'installed':
      if installed_version(receipt) == VERSION:
        safe(root, SOURCE).chmod(0o755)
        verify(root, runner, selection)
        return
      rollback(root, runner)
      receipt = load(root)
    if receipt['state'] != 'rolled-back':
      raise ValueError('Incomplete installation; run rollback before retry')
  check_dkms_policy(root)
  # The gate must already own and verify startup ordering. This also rejects lab overrides.
  bt.verify(root, bt.load(root))
  bt.preflight(root, bt.payload())
  bt.check_images(root, True, runner)
  releases = kernels(root)
  payload = files(root)
  for name, value in payload.items():
    if name != 'etc/bluetooth/main.conf' and bt.read(root, name) not in (None, value):
      raise ValueError('Preserving conflicting configuration: ' + name)
  source = safe(root, SOURCE)
  if source.exists(): raise ValueError('Unowned DKMS source already exists')
  if (root / f'var/lib/dkms/{NAME}/{VERSION}').exists():
    raise ValueError('Unowned DKMS registration already exists')
  # Only kernels whose stock radio drivers match a qualified fingerprint get a build;
  # the rest keep stock drivers. With none qualified there is nothing to install.
  buildable = [release for release in releases if qualified(root, release, runner)]
  if not buildable:
    raise ValueError('No installed linux-t2 kernel has a qualified stock radio fingerprint; keeping stock drivers')
  state = safe(root, STATE)
  state.mkdir(parents=True, exist_ok=True, mode=0o700)
  # Source download/patching finishes before any driver/configuration mutation.
  with tempfile.TemporaryDirectory(prefix='prepare-', dir=state) as temp:
    work = Path(temp)
    # Radio only: no BCE source is fetched, patched, or built.
    fetch(work / 'input', False)
    prepare.prepare(work / 'input/drivers/net/wireless/broadcom/brcm80211',
                    work / 'input/drivers/bluetooth/hci_bcm4377.c',
                    None, work / 'source', 'wifi-reenable', include_bce=False)
    for name in SOURCE_FILES:
      shutil.copy2(HERE / name, work / 'source' / name)
    hashes = tree_hash(work / 'source')
    backup = Path(tempfile.mkdtemp(prefix='boot-', dir=state)) / 'boot'
    backup_boot(root, backup)
    receipt = {'state': 'preparing', 'version': VERSION, 'kernels': releases, 'qualified_kernels': buildable,
               'original': {name: bt.read(root, name) for name in payload},
               'installed': payload, 'source_hashes': hashes,
               'boot_backup': str(backup.relative_to(root)), 'dkms_added': False}
    save(root, receipt)
    try:
      source.parent.mkdir(parents=True, exist_ok=True)
      with tempfile.TemporaryDirectory(prefix='.omarchy-t2-', dir=source.parent) as directory:
        staged = Path(directory) / 'source'
        shutil.copytree(work / 'source', staged)
        staged.rename(source)
        source.chmod(0o755)
      receipt['dkms_added'] = True
      save(root, receipt)
      runner(['dkms', 'add', '-m', NAME, '-v', VERSION])
      # Complete all builds before selecting any replacement modules.
      for release in buildable:
        print('Building T2 suspend drivers for ' + release, flush=True)
        runner(['dkms', 'build', '-m', NAME, '-v', VERSION, '-k', release])
      for name, value in payload.items(): bt.write(root, name, value)
      for release in buildable:
        runner(['dkms', 'install', '--force', '-m', NAME, '-v', VERSION, '-k', release])
      for release in releases:
        runner(['depmod', '-a', release])
      selection(releases, runner, root)
      runner(['limine-mkinitcpio', 'linux-t2'])
      check_images(root, runner)
      receipt['state'] = 'installed'
      save(root, receipt)
      verify(root, runner, selection)
    except BaseException:
      rollback(root, runner, rebuild=False)
      raise

def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('action', choices=['supported', 'install', 'verify', 'rollback'])
  args = parser.parse_args()
  if args.action == 'supported':
    raise SystemExit(0 if supported() else 1)
  if os.geteuid() != 0: raise SystemExit('Root required')
  if not supported(): raise SystemExit('Supports Apple MacBookAir9,1 with BCM4377 only')
  if Path('/var/lib/pacman/db.lck').exists(): raise SystemExit('Wait for the package transaction to finish')
  os.umask(0o022)
  with open('/run/lock/omarchy-t2-suspend.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if args.action == 'install': install(Path('/'))
    elif args.action == 'verify': verify(Path('/'))
    else: rollback(Path('/'))
  print('T2 suspend ' + args.action + ' complete. Driver/configuration changes apply at next boot.')

if __name__ == '__main__': main()
