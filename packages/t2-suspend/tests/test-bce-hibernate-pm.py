#!/usr/bin/env python3

from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text()
match = re.search(
  r'struct dev_pm_ops t2bce_pci_driver_pm = \{(.*?)\n\};',
  source,
  re.S,
)
assert match, 'missing t2bce core PM operations'

operations = dict(re.findall(r'\.(\w+)\s*=\s*(\w+)', match.group(1)))
expected = {
  'prepare': 't2bce_prepare',
  'suspend': 't2bce_suspend',
  'resume': 't2bce_resume',
  'freeze': 't2bce_suspend',
  'thaw': 't2bce_resume',
  'restore': 't2bce_resume',
  'complete': 't2bce_complete',
}
assert operations == expected, f'incomplete t2bce image callback pairing: {operations}'
assert 'poweroff' not in operations, 'cold S4 must not claim the stateful image path'

print('PASS: t2bce pairs the in-place hibernation image callbacks')
