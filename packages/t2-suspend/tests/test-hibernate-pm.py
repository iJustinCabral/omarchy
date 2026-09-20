#!/usr/bin/env python3

from pathlib import Path
import re
import sys

image_rebuild = sys.argv[2:] == ['--image-rebuild']
assert len(sys.argv) == 2 or image_rebuild, 'usage: test-hibernate-pm.py PCIE_C [--image-rebuild]'
source = Path(sys.argv[1]).read_text()
match = re.search(
  r'static const struct dev_pm_ops brcmf_pciedrvr_pm = \{(.*?)\n\};',
  source,
  re.S,
)
assert match, 'missing brcmfmac PCIe PM operations'

operations = dict(re.findall(r'\.(\w+)\s*=\s*(\w+)', match.group(1)))
expected = {
  'suspend': 'brcmf_pcie_pm_enter_D3',
  'resume': 'brcmf_pcie_pm_leave_D3',
  'freeze': 'brcmf_pcie_pm_enter_D3',
  'thaw': 'brcmf_pcie_pm_leave_D3',
  'poweroff': 'brcmf_pcie_pm_enter_D3',
  'restore': 'brcmf_pcie_pm_restore' if image_rebuild else 'brcmf_pcie_pm_leave_D3',
}
assert operations == expected, f'incomplete brcmfmac PM callback pairing: {operations}'

if image_rebuild:
  restore = re.search(
    r'static int brcmf_pcie_pm_restore\(struct device \*dev\)\n\{(.*?)\n\}',
    source,
    re.S,
  )
  assert restore, 'missing brcmfmac image-restore implementation'
  body = restore.group(1)
  guard = body.index('if (!brcmf_t2_recovery_flr)')
  hot_resume = body.index('return brcmf_pcie_pm_leave_D3(dev);')
  rebuild = body.index('return brcmf_pcie_reset(dev);')
  assert guard < hot_resume < rebuild, 'image restore must gate full reconstruction on the scoped FLR option'

print('PASS: brcmfmac hibernation transitions match the selected recovery profile')
