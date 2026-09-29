#!/usr/bin/env python3
"""Exercise the hibernation source profile and its isolation from the radio profiles."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).resolve().parents[1] / 'prepare-source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
REAL = Path(__file__).resolve().parents[1]

def sha(data):
    return hashlib.sha256(data).hexdigest()

class HibernationPreparation(unittest.TestCase):
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
        self.radio = module.HERE / 'radio.patch'
        self.radio.write_text('--- a/drivers/net/wireless/broadcom/brcm80211/a.c\n+++ b/drivers/net/wireless/broadcom/brcm80211/a.c\n@@ -1 +1 @@\n-old\n+new\n')
        self.hibernation = module.HERE / 'hibernation.patch'
        self.hibernation.write_text('--- a/drivers/net/wireless/broadcom/brcm80211/a.c\n+++ b/drivers/net/wireless/broadcom/brcm80211/a.c\n@@ -1 +1 @@\n-new\n+hibernate\n')
        self.manifest = {
            'lab_commit': 'fixture', 'kernel_release': 'fixture',
            'wifi_base': {'a.c': sha(b'old\n')},
            'bluetooth_base_sha256': sha(b'bluetooth\n'),
            'patches': [{'path': 'radio.patch', 'sha256': module.digest(self.radio), 'series': 'wifi'}],
            's3': {'wifi': {'a.c': sha(b'new\n')}, 'bluetooth_sha256': sha(b'bluetooth\n')},
            'wifi-reenable': {'wifi': {'a.c': sha(b'new\n')}, 'bluetooth_sha256': sha(b'bluetooth\n')},
        }
        self.pins = {
            't2bce_source': {'commit': 'fixture', 'path': 'fixture.patch',
                             'sha256': sha(self.bce_source.read_bytes()),
                             'base': {'drivers/staging/t2bce/t2bce_core/core.c': sha(b'core\n')}},
            't2bce_patched': {'drivers/staging/t2bce/t2bce_core/core.c': sha(b'core\n')},
        }
        self.sidecar = {
            'patches': [{'path': 'hibernation.patch', 'sha256': module.digest(self.hibernation), 'series': 'hibernation'}],
            'hibernation': {'wifi': {'a.c': sha(b'hibernate\n')}, 'bluetooth_sha256': sha(b'bluetooth\n')},
        }
        self.save()
        self.out = self.root / 'output'

    def save(self):
        (module.HERE / 'manifest.json').write_text(json.dumps(self.manifest))
        (module.HERE / 'manifest-hibernation.json').write_text(json.dumps(self.sidecar))
        (module.HERE / 't2bce-source.json').write_text(json.dumps(self.pins))

    def run_hibernation(self):
        module.prepare(self.wifi, self.bt, self.out, 'hibernation', self.bce_source)

    def test_hibernation_profile_adds_series_and_bce(self):
        self.run_hibernation()
        self.assertEqual((self.out / 'drivers/net/wireless/broadcom/brcm80211/a.c').read_bytes(), b'hibernate\n')
        self.assertEqual((self.out / 'drivers/staging/t2bce/t2bce_core/core.c').read_bytes(), b'core\n')
        provenance = json.loads((self.out / 'provenance.json').read_text())
        self.assertEqual(provenance['t2bce_source_commit'], 'fixture')
        self.assertEqual(provenance['t2bce_pins_sha256'], module.digest(module.HERE / 't2bce-source.json'))
        self.assertEqual(provenance['profile'], 'hibernation')

    def test_radio_profiles_ignore_the_sidecar_entirely(self):
        for profile in ('s3', 'wifi-reenable'):
            out = self.root / profile
            (module.HERE / 'manifest-hibernation.json').unlink(missing_ok=True)
            (module.HERE / 't2bce-source.json').unlink(missing_ok=True)
            module.prepare(self.wifi, self.bt, out, profile)
            self.assertEqual((out / 'drivers/net/wireless/broadcom/brcm80211/a.c').read_bytes(), b'new\n')
            self.assertFalse((out / 'drivers/staging').exists())
            self.assertEqual(set(json.loads((out / 'provenance.json').read_text())),
                             {'profile', 'lab_commit', 'manifest_sha256', 'kernel_release', 'source_parity'})

    def test_hibernation_requires_the_pinned_bce_patch(self):
        with self.assertRaises(ValueError): module.prepare(self.wifi, self.bt, self.out, 'hibernation')
        self.bce_source.write_text('drifted')
        with self.assertRaises(ValueError): self.run_hibernation()
        self.assertFalse(self.out.exists())

    def test_bce_pins_file_is_authoritative(self):
        self.pins['t2bce_source']['sha256'] = sha(b'stale pin')
        self.save()
        with self.assertRaises(ValueError): self.run_hibernation()
        self.assertFalse(self.out.exists())

    def test_hibernation_patch_drift_never_published(self):
        self.hibernation.write_text('changed')
        with self.assertRaises(ValueError): self.run_hibernation()
        self.assertFalse(self.out.exists())

    def test_hibernation_output_mismatch_never_published(self):
        self.sidecar['hibernation']['wifi']['a.c'] = sha(b'wrong\n')
        self.save()
        with self.assertRaises(ValueError): self.run_hibernation()
        self.assertFalse(self.out.exists())

    def test_shipped_manifest_keeps_hibernation_out_of_radio_series(self):
        manifest = json.loads((REAL / 'manifest.json').read_text())
        sidecar = json.loads((REAL / 'manifest-hibernation.json').read_text())
        pins = json.loads((REAL / 't2bce-source.json').read_text())
        self.assertNotIn('t2bce_patched', sidecar)
        self.assertEqual(set(pins), {'t2bce_source', 't2bce_patched'})
        self.assertNotIn('hibernation', manifest)
        self.assertNotIn('t2bce_source', manifest)
        self.assertEqual({p['series'] for p in manifest['patches']}, {'wifi', 'bluetooth', 'wifi-reenable'})
        self.assertEqual({p['series'] for p in sidecar['patches']}, {'hibernation'})
        for patch in sidecar['patches']:
            self.assertEqual(sha((REAL / patch['path']).read_bytes()), patch['sha256'])

if __name__ == '__main__': unittest.main()
