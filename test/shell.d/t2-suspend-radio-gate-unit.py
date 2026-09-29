"""Radio package 1.1: BCE family coherence guard, qualification gate and DKMS original-module archive."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installer_unit', HERE / 't2-suspend-installer-unit.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
m, RELEASE = base.m, base.RELEASE

QUALIFIED = {'brcmfmac': '9292F32C85527BC13D71BF0', 'brcmfmac-wcc': '48FEB72B5C763DD2CF59B61',
             'brcmfmac-cyw': 'EDC6A59C171B416E52E134B', 'brcmfmac-bca': 'C5AB32DBCEB73D5C1C3B79A',
             'hci_bcm4377': '34947550229A96A34F46E55'}
RADIO_DIRS = {'brcmfmac': 'drivers/net/wireless/broadcom/brcm80211/brcmfmac',
              'brcmfmac-wcc': 'drivers/net/wireless/broadcom/brcm80211/brcmfmac/wcc',
              'brcmfmac-cyw': 'drivers/net/wireless/broadcom/brcm80211/brcmfmac/cyw',
              'brcmfmac-bca': 'drivers/net/wireless/broadcom/brcm80211/brcmfmac/bca',
              'hci_bcm4377': 'drivers/bluetooth'}
BCE = ('t2bce_dma', 't2bce_core', 't2bce_vhci', 't2bce_audio', 't2bce_ave')
FIRMWARE = ('.bin', '-SPPR-m.txt', '-SPPR-u.txt', '.clm_blob', '.txcap_blob')

# A bash stand-in for kmod: depmod precedence is updates/ before extra/ before kernel/, and a
# fixture module file holds "srcversion=..." lines instead of an ELF.
FAKE_MODINFO = r"""
modinfo() {
  local base=/ kernel= mode= name= field=
  while (( $# )); do
    case $1 in
      -b) base=$2; shift 2 ;;
      -k) kernel=$2; shift 2 ;;
      -n) mode=path; shift ;;
      -F) field=$2; shift 2 ;;
      *) name=$1; shift ;;
    esac
  done
  base=${base%/}
  if [[ $mode == path ]]; then
    local dir found
    for dir in updates extra kernel; do
      found=$(find "$base/usr/lib/modules/$kernel/$dir" -name "$name.ko*" 2>/dev/null | head -n 1)
      if [[ -n $found ]]; then echo "$found"; return 0; fi
    done
    return 1
  fi
  [[ -f $name ]] || return 1
  if [[ $field == vermagic ]]; then
    echo "$(sed -n 's/^vermagic=//p' "$name") SMP"
  else
    sed -n "s/^$field=//p" "$name"
  fi
}
export -f modinfo
"""

HOOK_HARNESS = 'source "$1"\nKERNELVERSION=$2\n_optmoduleroot=$3\n_builderrors=0\n' + FAKE_MODINFO + r"""
error() { echo "ERROR: $*" >&2; }
warning() { echo "WARNING: $*" >&2; }
add_file() { :; }
add_module() { echo "add_module $1"; }
build
echo "BUILD COMPLETE"
"""


def module_file(root, release, place, name, srcversion, directory):
  p = root / 'usr/lib/modules' / release / place / directory / (name + '.ko')
  p.parent.mkdir(parents=True, exist_ok=True)
  p.write_text(f'srcversion={srcversion}\nvermagic={release}\n')
  return p


class Fixture:
  """A fake root holding one kernel's stock BCE, stock radio, optional replacements and the package source."""
  def __init__(self, root, release=RELEASE, qualified=True):
    self.root, self.release = root, release
    fw = root / 'usr/lib/firmware/brcm'
    fw.mkdir(parents=True, exist_ok=True)
    for suffix in FIRMWARE:
      (fw / ('brcmfmac4377b3-pcie.apple,formosa' + suffix)).write_bytes(b'fw')
    source = root / m.SOURCE
    source.mkdir(parents=True, exist_ok=True)
    for name in ('check-radio-qualification.sh', 'qualified-radio.conf'):
      shutil.copy2(m.HERE / name, source / name)
    (source / 'provenance.json').write_text('{}')
    for name in BCE:
      self.bce(name)
    for name, sv in QUALIFIED.items():
      self.stock(name, sv if qualified else 'DEADBEEF' + sv[8:])

  def bce(self, name, place='kernel'):
    directory = 'drivers/staging/t2bce/' + name if place == 'kernel' else 'dkms'
    return module_file(self.root, self.release, place, name, 'BCE' + name, directory)

  def stock(self, name, srcversion):
    return module_file(self.root, self.release, 'kernel', name, srcversion, RADIO_DIRS[name])

  def package(self, name, srcversion=None):
    """A DKMS-built radio module installed under updates/."""
    sv = srcversion or QUALIFIED[name] + 'X'
    build = self.root / f'var/lib/dkms/{m.NAME}/{m.VERSION}/{self.release}/x86_64/module' / (name + '.ko')
    build.parent.mkdir(parents=True, exist_ok=True)
    build.write_text(f'srcversion={sv}\nvermagic={self.release}\n')
    module_file(self.root, self.release, 'updates', name, sv, 'dkms')

  def package_all(self):
    for name in QUALIFIED: self.package(name)

  def hook(self):
    return subprocess.run(['bash', '-c', HOOK_HARNESS, 'test', str(m.HERE / 'initcpio-install'), self.release,
                           str(self.root)], text=True, capture_output=True, timeout=60)

  def gate(self, *args, env=None):
    return subprocess.run(['bash', '-c', FAKE_MODINFO + '\nexec "$@"\n', 'gate',
                           str(m.HERE / 'check-radio-qualification.sh'), *args],
                          text=True, capture_output=True, timeout=60, env={**os.environ, **(env or {})})


class HookAndGate(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)

  def refused(self, fixture, text):
    result = fixture.hook()
    self.assertEqual(result.returncode, 1, result.stderr)
    self.assertIn(text, result.stderr)
    self.assertNotIn('BUILD COMPLETE', result.stdout)

  def test_hook_accepts_all_stock_bce_with_package_radio(self):
    f = Fixture(self.root)
    f.package_all()
    result = f.hook()
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn('BUILD COMPLETE', result.stdout)
    self.assertEqual(result.stdout.count('add_module'), 4)
    self.assertNotIn('t2bce', result.stdout)
    self.assertNotIn('WARNING', result.stderr)

  def test_hook_refuses_mixed_bce_family(self):
    f = Fixture(self.root)
    f.package_all()
    (self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/staging/t2bce/t2bce_core/t2bce_core.ko').unlink()
    f.bce('t2bce_core', 'updates')  # core replaced while t2bce_dma stays in-tree
    self.refused(f, 'Mixed or foreign T2 BCE module family: t2bce_core')

  def test_hook_refuses_foreign_bce_in_updates_or_extra(self):
    for name in ('t2bce_audio', 't2bce_dma', 't2bce_vhci', 't2bce_ave'):
      for place in ('updates', 'extra'):
        with self.subTest(name=name, place=place):
          with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            f.package_all()
            f.bce(name, place)
            self.refused(f, 'Mixed or foreign T2 BCE module family: ' + name)

  def test_hook_refuses_missing_required_bce_and_tolerates_missing_ave(self):
    f = Fixture(self.root)
    f.package_all()
    (self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/staging/t2bce/t2bce_ave/t2bce_ave.ko').unlink()
    self.assertEqual(f.hook().returncode, 0)
    (self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/staging/t2bce/t2bce_vhci/t2bce_vhci.ko').unlink()
    self.refused(f, 'Missing T2 BCE module: t2bce_vhci')

  def test_hook_refuses_stale_package_build(self):
    f = Fixture(self.root)
    f.package_all()
    build = self.root / f'var/lib/dkms/{m.NAME}/{m.VERSION}/{RELEASE}/x86_64/module/brcmfmac.ko'
    build.write_text(f'srcversion=STALE\nvermagic={RELEASE}\n')
    self.refused(f, 'Stock/conflicting T2 module selected: brcmfmac')

  def test_hook_refuses_stock_radio_on_qualified_kernel(self):
    self.refused(Fixture(self.root), 'package build is missing for a qualified kernel')

  def test_hook_accepts_fully_stock_radio_on_unqualified_kernel_with_warning(self):
    result = Fixture(self.root, qualified=False).hook()
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn('BUILD COMPLETE', result.stdout)
    self.assertIn('WARNING: T2 radio package skipped for unqualified kernel ' + RELEASE, result.stderr)

  def test_hook_refuses_mixed_radio_on_unqualified_kernel(self):
    f = Fixture(self.root, qualified=False)
    f.package('hci_bcm4377')
    self.refused(f, 'Mixed T2 radio module set')

  def test_hook_refuses_foreign_radio_module(self):
    f = Fixture(self.root, qualified=False)
    module_file(self.root, RELEASE, 'extra', 'brcmfmac', 'FOREIGN', 'other')
    self.refused(f, 'Foreign T2 radio module selected: brcmfmac')

  def test_hook_refuses_bce_mix_even_on_unqualified_kernel(self):
    f = Fixture(self.root, qualified=False)
    f.bce('t2bce_core', 'updates')
    self.refused(f, 'Mixed or foreign T2 BCE module family')

  def test_gate_accepts_both_recorded_kernels(self):
    f = Fixture(self.root)
    for release in ('7.2.6-arch2-Watanare-T2-2-t2', '7.2.7-arch1-Watanare-T2-2-t2'):
      Fixture(self.root, release)
      result = f.gate(release, str(self.root))
      self.assertEqual(result.returncode, 0, result.stderr)

  def test_gate_refuses_unqualified_stock_srcversions(self):
    result = Fixture(self.root, qualified=False).gate(RELEASE, str(self.root))
    self.assertEqual(result.returncode, 1)
    self.assertIn('not qualified for kernel ' + RELEASE, result.stderr)
    self.assertIn('DEADBEEF', result.stderr)

  def test_gate_refuses_one_differing_or_missing_module(self):
    f = Fixture(self.root)
    f.stock('hci_bcm4377', 'SOMETHINGELSE')
    self.assertEqual(f.gate(RELEASE, str(self.root)).returncode, 1)
    f.stock('hci_bcm4377', QUALIFIED['hci_bcm4377'])
    self.assertEqual(f.gate(RELEASE, str(self.root)).returncode, 0)
    (self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/bluetooth/hci_bcm4377.ko').unlink()
    self.assertEqual(f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_gate_ignores_installed_replacements(self):
    f = Fixture(self.root, qualified=False)
    f.package_all()  # updates/ carries qualified-looking modules; only the stock tree counts
    self.assertEqual(f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_gate_reads_release_from_dkms_environment_and_requires_one(self):
    f = Fixture(self.root)
    self.assertEqual(f.gate('', str(self.root), env={'kernelver': RELEASE}).returncode, 0)
    self.assertEqual(f.gate('', str(self.root), env={'kernelver': ''}).returncode, 2)

  def test_dkms_pre_build_runs_from_the_copied_build_tree(self):
    Fixture(self.root)
    build = self.root / 'build-tree'
    build.mkdir()
    for name in m.SOURCE_FILES:
      shutil.copy2(m.HERE / name, build / name)
    result = subprocess.run(['bash', '-c', FAKE_MODINFO + '\ncd "$1" && ./check-radio-qualification.sh "$2" "$3"', 'x',
                             str(build), RELEASE, str(self.root)], text=True, capture_output=True, timeout=60)
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertRegex((m.HERE / 'dkms.conf').read_text(), r'PRE_BUILD="check-radio-qualification\.sh \$\{kernelver\}"')


class Selection(unittest.TestCase):
  """check_selection (the verify path) against emulated modinfo output."""
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.paths = {n: f'/usr/lib/modules/{RELEASE}/kernel/drivers/staging/t2bce/{n}/{n}.ko.zst' for n in BCE}
    self.stock = {n: f'/usr/lib/modules/{RELEASE}/kernel/{RADIO_DIRS[n]}/{n}.ko.zst' for n in m.MODULES}
    self.updates = {n: f'/usr/lib/modules/{RELEASE}/updates/dkms/{n}.ko.zst' for n in m.MODULES}
    self.qualified = True
    self.packaged = False

  def build(self, name):
    p = self.root / f'var/lib/dkms/{m.NAME}/{m.VERSION}/{RELEASE}/x86_64/module/{name}.ko'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('x')

  def runner(self, args, **kwargs):
    if args[0] == 'bash':
      return subprocess.CompletedProcess(args, 0 if self.qualified else 1, '', '')
    if '-n' in args:
      name = args[-1]
      table = {**self.paths, **(self.updates if self.packaged else self.stock)}
      if name not in table: raise subprocess.CalledProcessError(1, args)
      return subprocess.CompletedProcess(args, 0, table[name] + '\n', '')
    field = args[args.index('-F') + 1]
    out = RELEASE + ' SMP' if field == 'vermagic' else 'SV' + Path(args[-1]).name.split('.')[0]
    return subprocess.CompletedProcess(args, 0, out + '\n', '')

  def select(self):
    m.check_selection([RELEASE], self.runner, self.root)

  def test_package_radio_with_stock_bce_passes(self):
    self.packaged = True
    for n in m.MODULES: self.build(n)
    self.select()

  def test_stock_radio_on_qualified_kernel_without_build_refused(self):
    with self.assertRaisesRegex(ValueError, 'Missing DKMS module'): self.select()

  def test_mixed_bce_family_refused(self):
    self.packaged = True
    for n in m.MODULES: self.build(n)
    self.paths['t2bce_core'] = f'/usr/lib/modules/{RELEASE}/updates/dkms/t2bce_core.ko.zst'
    with self.assertRaisesRegex(ValueError, 'Mixed or foreign T2 BCE module family: t2bce_core'): self.select()

  def test_foreign_extra_bce_refused_even_on_unqualified_kernel(self):
    self.qualified = False
    self.paths['t2bce_audio'] = f'/usr/lib/modules/{RELEASE}/extra/t2bce_audio.ko'
    with self.assertRaisesRegex(ValueError, 'Mixed or foreign T2 BCE module family: t2bce_audio'): self.select()

  def test_missing_bce_module_refused_but_ave_optional(self):
    del self.paths['t2bce_ave']
    self.qualified = False
    self.select()
    del self.paths['t2bce_dma']
    with self.assertRaisesRegex(ValueError, 'Missing T2 BCE module: t2bce_dma'): self.select()

  def test_unqualified_kernel_accepts_only_fully_stock_radio(self):
    self.qualified = False
    self.select()
    self.build('brcmfmac')  # a package build exists although the gate should have skipped it
    with self.assertRaisesRegex(ValueError, 'must use stock radio drivers'): self.select()
    (self.root / f'var/lib/dkms/{m.NAME}/{m.VERSION}/{RELEASE}/x86_64/module/brcmfmac.ko').unlink()
    self.packaged = True
    with self.assertRaisesRegex(ValueError, 'must use stock radio drivers'): self.select()


class DkmsArchive(unittest.TestCase):
  """After `dkms install` the stock radio modules live in DKMS's original_module archive."""
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.f = Fixture(self.root)

  def archive_dir(self):
    return self.root / f'var/lib/dkms/{m.NAME}/original_module/{RELEASE}/x86_64'

  def dkms_install(self):
    """Emulate dkms install: move each stock module into the archive with an .origin note, add the replacement."""
    archive = self.archive_dir()
    archive.mkdir(parents=True, exist_ok=True)
    for name in QUALIFIED:
      stock = self.root / f'usr/lib/modules/{RELEASE}/kernel/{RADIO_DIRS[name]}/{name}.ko'
      (archive / stock.name).write_bytes(stock.read_bytes())
      (archive / (stock.name + '.origin')).write_text(f'/usr/lib/modules/{RELEASE}/kernel/{RADIO_DIRS[name]}/{name}.ko\n')
      stock.unlink()
    self.f.package_all()

  def runner(self, args, **kwargs):
    """Real gate, fake kmod over the fixture root; module paths are reported root-relative like the live system."""
    root = str(self.root)
    if args[0] == 'modinfo':
      args = ['modinfo', '-b', root] + args[1:]
      args = [root + a if a.startswith('/usr/') else a for a in args]
    out = subprocess.run(['bash', '-c', FAKE_MODINFO + '\n"$@"\n', 'x', *args], text=True,
                         capture_output=True, timeout=60)
    if out.returncode and args[0] != 'bash':
      raise subprocess.CalledProcessError(out.returncode, args, out.stdout, out.stderr)
    return subprocess.CompletedProcess(args, out.returncode, out.stdout.replace(root, ''), out.stderr)

  def test_gate_qualifies_from_the_archive_after_dkms_install(self):
    self.dkms_install()
    result = self.f.gate(RELEASE, str(self.root))
    self.assertEqual(result.returncode, 0, result.stderr)

  def test_check_selection_and_verify_path_accept_the_package_set(self):
    self.dkms_install()
    m.check_selection([RELEASE], self.runner, self.root, [RELEASE])  # install: recorded decision
    m.check_selection([RELEASE], self.runner, self.root)             # verify: archive-aware gate

  def test_hook_accepts_package_set_after_dkms_install(self):
    self.dkms_install()
    result = self.f.hook()
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn('BUILD COMPLETE', result.stdout)

  def test_missing_stock_and_missing_archive_is_unqualified(self):
    self.dkms_install()
    (self.archive_dir() / 'hci_bcm4377.ko').unlink()
    self.assertEqual(self.f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_archive_srcversion_mismatch_is_unqualified(self):
    self.dkms_install()
    (self.archive_dir() / 'brcmfmac.ko').write_text('srcversion=NOTQUALIFIED\nvermagic=x\n')
    self.assertEqual(self.f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_archive_entry_not_taken_from_the_stock_directory_is_ignored(self):
    self.dkms_install()
    (self.archive_dir() / 'brcmfmac.ko.origin').write_text(f'/usr/lib/modules/{RELEASE}/updates/dkms/brcmfmac.ko\n')
    self.assertEqual(self.f.gate(RELEASE, str(self.root)).returncode, 1)
    (self.archive_dir() / 'brcmfmac.ko.origin').unlink()
    self.assertEqual(self.f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_replacements_in_updates_never_qualify(self):
    Fixture(self.root, qualified=False)
    shutil.rmtree(self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/net')
    shutil.rmtree(self.root / f'usr/lib/modules/{RELEASE}/kernel/drivers/bluetooth')
    self.f.package_all()
    self.assertEqual(self.f.gate(RELEASE, str(self.root)).returncode, 1)

  def test_unqualified_decision_still_demands_stock_radio(self):
    self.dkms_install()
    with self.assertRaisesRegex(ValueError, 'must use stock radio drivers'):
      m.check_selection([RELEASE], self.runner, self.root, [])


class Upgrade(base.Installer):
  """Upgrade from an installed 1.0 (older receipt, no qualified_kernels) by rollback then install."""
  OLD = '1.0'

  def install_old(self):
    self.install()
    (self.root / m.SOURCE).rename(self.root / m.source_name(self.OLD))
    receipt = m.load(self.root)
    receipt['version'] = self.OLD
    del receipt['qualified_kernels']
    m.save(self.root, receipt)
    build = self.root / f'var/lib/dkms/{m.NAME}/{self.OLD}/{RELEASE}/x86_64/module'
    build.mkdir(parents=True)
    (build / 'brcmfmac.ko').write_text('old')
    self.calls.clear()

  def test_upgrade_1_0_is_transactional(self):
    original = (self.root / 'etc/bluetooth/main.conf').read_bytes()
    self.install_old()
    self.install()
    order = [c[:2] for c in self.calls if c[0] in ('dkms', 'limine-mkinitcpio')]
    self.assertEqual(order, [['dkms', 'remove'], ['limine-mkinitcpio', 'linux-t2'], ['dkms', 'add'],
                             ['dkms', 'build'], ['dkms', 'install'], ['limine-mkinitcpio', 'linux-t2']])
    self.assertIn(['dkms', 'remove', '-m', m.NAME, '-v', self.OLD, '--all'], self.calls)
    self.assertIn(['dkms', 'build', '-m', m.NAME, '-v', m.VERSION, '-k', RELEASE], self.calls)
    self.assertFalse((self.root / m.source_name(self.OLD)).exists())
    receipt = m.load(self.root)
    self.assertEqual((receipt['version'], receipt['state']), (m.VERSION, 'installed'))
    m.rollback(self.root, self.runner)
    self.assertEqual((self.root / 'etc/bluetooth/main.conf').read_bytes(), original)
    self.assertFalse((self.root / m.SOURCE).exists())

  def test_upgrade_failure_leaves_stock_and_rolled_back_receipt(self):
    original = (self.root / 'etc/bluetooth/main.conf').read_bytes()
    self.install_old()
    self.fail = ['dkms', 'build']
    with self.assertRaises(subprocess.CalledProcessError): self.install()
    self.assertEqual(m.load(self.root)['state'], 'rolled-back')
    self.assertEqual((self.root / 'etc/bluetooth/main.conf').read_bytes(), original)
    self.assertIsNone(m.bt.read(self.root, 'etc/modprobe.d/omarchy-t2-suspend.conf'))
    # The stock-driver image published by the old package's rollback survives the failed retry.
    self.assertEqual((self.root / 'boot/EFI/Linux/test-linux-t2.efi').read_bytes(), b'generated image')
    self.assertFalse((self.root / m.SOURCE).exists())
    self.assertFalse((self.root / m.source_name(self.OLD)).exists())

  def test_rollback_from_1_0_receipt_cleans_up_1_0(self):
    self.install_old()
    m.rollback(self.root, self.runner)
    self.assertIn(['dkms', 'remove', '-m', m.NAME, '-v', self.OLD, '--all'], self.calls)
    self.assertFalse((self.root / m.source_name(self.OLD)).exists())
    self.assertEqual(m.load(self.root)['state'], 'rolled-back')
    self.assertIsNone(m.bt.read(self.root, 'etc/modprobe.d/omarchy-t2-suspend.conf'))

  def test_verify_reports_version_mismatch_clearly(self):
    self.install_old()
    with self.assertRaisesRegex(ValueError, 'version 1.0, not ' + re.escape(m.VERSION) + '; run omarchy setup t2-suspend to upgrade'):
      m.verify(self.root, self.runner, lambda *_: None)
    self.assertEqual(self.calls, [])


class Qualification(base.Installer):
  """Install-time qualification decisions."""
  def add_kernel(self, release):
    for name, data in ((f'usr/lib/modules/{release}/pkgbase', b'linux-t2\n'),
                       (f'usr/lib/modules/{release}/build/Makefile', b'headers')):
      p = self.root / name
      p.parent.mkdir(parents=True, exist_ok=True)
      p.write_bytes(data)

  def test_only_qualified_kernels_are_built_and_all_get_depmod(self):
    other = '7.2.9-arch1-Watanare-T2-1-t2'
    self.add_kernel(other)
    def runner(args, **kwargs):
      if args[0] == 'bash':
        return subprocess.CompletedProcess(args, 1 if args[2] == other else 0, '', '')
      return self.runner(args, **kwargs)
    m.install(self.root, runner, lambda *_: None, lambda *_: None)
    self.assertEqual([c[-1] for c in self.calls if c[:2] == ['dkms', 'build']], [RELEASE])
    self.assertEqual([c[-1] for c in self.calls if c[:2] == ['dkms', 'install']], [RELEASE])
    self.assertEqual(sorted(c[-1] for c in self.calls if c[0] == 'depmod'), sorted([RELEASE, other]))
    self.assertEqual(m.load(self.root)['qualified_kernels'], [RELEASE])

  def test_no_qualified_kernel_refuses_before_mutating_and_leaves_stock(self):
    def runner(args, **kwargs):
      if args[0] == 'bash':
        return subprocess.CompletedProcess(args, 1, '', '')
      return self.runner(args, **kwargs)
    with self.assertRaisesRegex(ValueError, 'No installed linux-t2 kernel has a qualified'):
      m.install(self.root, runner, lambda *_: None, lambda *_: None)
    self.assertIsNone(m.bt.read(self.root, m.RECEIPT))
    self.assertIsNone(m.bt.read(self.root, 'etc/modprobe.d/omarchy-t2-suspend.conf'))
    self.assertFalse((self.root / m.SOURCE).exists())
    self.assertFalse(any(c[0] != '/usr/bin/lsinitcpio' for c in self.calls))

  def test_install_passes_its_decision_to_selection(self):
    seen = []
    m.install(self.root, self.runner, lambda releases, runner, root, decided=None: seen.append(decided), lambda *_: None)
    # Install trusts its pre-build decision; the closing verify asks the archive-aware gate.
    self.assertEqual(seen, [[RELEASE], None])


if __name__ == '__main__': unittest.main()
