#!/usr/bin/env python3

from pathlib import Path
import re
import sys

assert len(sys.argv) == 2, 'usage: test-hibernate-pm.py PCIE_C'
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
  'restore': 'brcmf_pcie_pm_leave_D3',
}
assert operations == expected, f'incomplete brcmfmac PM callback pairing: {operations}'

print('PASS: brcmfmac hibernation transitions match the selected recovery profile')
