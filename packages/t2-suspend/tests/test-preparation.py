#!/usr/bin/env python3
"""Exercise publication and drift rejection without installed kernel sources."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).resolve().parents[1] / 'prepare-source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def sha(data):
    return hashlib.sha256(data).hexdigest()

class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        module.HERE = self.root / 'package'
        module.HERE.mkdir()
        self.wifi = self.root / 'wifi'
        self.wifi.mkdir()
        (self.wifi / 'a.c').write_bytes(b'old\n')
        self.bt = self.root / 'hci.c'
        self.bt.write_bytes(b'bluetooth\n')
        self.bce_source = self.root / 't2bce.patch'
        self.bce_source.write_text('--- /dev/null\n+++ b/drivers/staging/t2bce/t2bce_core/core.c\n@@ -0,0 +1 @@\n+core\n')
        self.patch = module.HERE / 'change.patch'
        self.patch.write_text('--- a/drivers/net/wireless/broadcom/brcm80211/a.c\n+++ b/drivers/net/wireless/broadcom/brcm80211/a.c\n@@ -1 +1 @@\n-old\n+new\n')
        self.manifest = {'lab_commit': 'fixture', 'kernel_release': 'fixture',
                         'wifi_base': {'a.c': sha(b'old\n')},
                         'bluetooth_base_sha256': sha(b'bluetooth\n'),
                         't2bce_source': {
                           'commit': 'fixture', 'path': 'fixture.patch',
                           'sha256': sha(self.bce_source.read_bytes()),
                           'base': {'drivers/staging/t2bce/t2bce_core/core.c': sha(b'core\n')},
                         },
                         't2bce_patched': {
                           'drivers/staging/t2bce/t2bce_core/core.c': sha(b'core\n'),
                         },
                         'patches': [{'path': 'change.patch', 'sha256': module.digest(self.patch), 'series': 'wifi'}],
                         's3': {'wifi': {'a.c': sha(b'new\n')}, 'bluetooth_sha256': sha(b'bluetooth\n')}}
        self.save()
        self.out = self.root / 'output'

    def save(self):
        (module.HERE / 'manifest.json').write_text(json.dumps(self.manifest))

    def run_prepare(self):
        module.prepare(self.wifi, self.bt, self.bce_source, self.out, 's3')

    def test_success_preserves_input(self):
        self.run_prepare()
        self.assertEqual((self.out / 'drivers/net/wireless/broadcom/brcm80211/a.c').read_bytes(), b'new\n')
        self.assertEqual((self.wifi / 'a.c').read_bytes(), b'old\n')
        self.assertEqual((self.out / 'drivers/staging/t2bce/t2bce_core/core.c').read_bytes(), b'core\n')
        self.assertTrue(json.loads((self.out / 'provenance.json').read_text())['source_parity'])
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o755)

    def test_existing_output_preserved(self):
        self.out.mkdir()
        (self.out / 'owned').write_text('keep')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual((self.out / 'owned').read_text(), 'keep')

    def test_input_drift(self):
        self.bt.write_text('changed')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse(self.out.exists())

    def test_patch_drift(self):
        self.patch.write_text('changed')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse(self.out.exists())

    def test_t2bce_source_drift(self):
        self.bce_source.write_text('changed')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse(self.out.exists())

    def test_output_mismatch_never_published(self):
        self.manifest['s3']['wifi']['a.c'] = sha(b'wrong\n')
        self.save()
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse(self.out.exists())
        self.assertFalse(list(self.root.glob('.t2-source-*')))

if __name__ == '__main__': unittest.main()
