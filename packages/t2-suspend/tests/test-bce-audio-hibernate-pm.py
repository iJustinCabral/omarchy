#!/usr/bin/env python3

from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text()
match = re.search(
  r'struct dev_pm_ops t2audio_pci_driver_pm = \{(.*?)\n\};',
  source,
  re.S,
)
assert match, 'missing t2bce audio PM operations'

operations = dict(re.findall(r'\.(\w+)\s*=\s*(\w+)', match.group(1)))
expected = {
  'suspend': 't2audio_suspend',
  'resume': 't2audio_resume',
  'freeze': 't2audio_suspend',
  'thaw': 't2audio_resume',
  'restore': 't2audio_resume',
}
assert operations == expected, f'incomplete t2bce audio image callback pairing: {operations}'
assert 'poweroff' not in operations, 'cold S4 must not claim the stateful audio path'

assert re.search(
  r'static int t2audio_suspend\(.*?'
  r't2audio_quiesce\(t2audio, true\);.*?'
  r'pci_disable_device\(t2audio->pci\);',
  source,
  re.S,
), 'audio freeze must revoke remote access before disabling its PCI function'

assert re.search(
  r'static int t2audio_resume\(.*?'
  r'pci_enable_device\(t2audio->pci\).*?'
  r'pci_set_master\(t2audio->pci\).*?'
  r't2audio->resume_deferred = true;',
  source,
  re.S,
), 'stateful audio restore must defer remote access until BCE reconstruction completes'

print('PASS: t2bce audio pairs the in-place hibernation image callbacks')
