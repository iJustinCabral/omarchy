#!/usr/bin/env python3
"""Verify pinned input, apply a selected driver series to a new output, verify parity.
No network, installation, module loading, or power transitions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def prepare(wifi, bluetooth, t2bce_source_patch, output, profile):
    manifest = json.loads((HERE / 'manifest.json').read_text())
    if output.exists():
        raise ValueError('Output already exists; choose a new directory')
    for name, expected in manifest['wifi_base'].items():
        if digest(wifi / name) != expected:
            raise ValueError(f'Wi-Fi source mismatch: {name}')
    if digest(bluetooth) != manifest['bluetooth_base_sha256']:
        raise ValueError('Bluetooth source mismatch')
    if digest(t2bce_source_patch) != manifest['t2bce_source']['sha256']:
        raise ValueError('T2 BCE source patch mismatch')
    selected = [p for p in manifest['patches']
                if p['series'] != 'wifi-reenable' or profile == 'wifi-reenable']
    for patch in selected:
        if digest(HERE / patch['path']) != patch['sha256']:
            raise ValueError(f"Patch mismatch: {patch['path']}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.t2-source-', dir=output.parent) as directory:
        root = Path(directory)
        dest = root / 'drivers/net/wireless/broadcom/brcm80211'
        for name in manifest['wifi_base']:
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(wifi / name, target)
        bt = root / 'drivers/bluetooth/hci_bcm4377.c'
        bt.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(bluetooth, bt)
        extracted = root / '.t2bce-extracted'
        extracted.mkdir()
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(t2bce_source_patch)], cwd=extracted, check=True)
        for name, expected in manifest['t2bce_source']['base'].items():
            source = extracted / name
            if digest(source) != expected:
                raise ValueError(f'T2 BCE base source mismatch: {name}')
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        shutil.rmtree(extracted)
        for patch in selected:
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                            str(HERE / patch['path'])], cwd=root, check=True)
        for name, expected in manifest[profile]['wifi'].items():
            if digest(dest / name) != expected:
                raise ValueError(f'Patched source mismatch: {name}')
        if digest(bt) != manifest[profile]['bluetooth_sha256']:
            raise ValueError('Patched Bluetooth mismatch')
        for name, expected in manifest['t2bce_patched'].items():
            if digest(root / name) != expected:
                raise ValueError(f'Patched T2 BCE mismatch: {name}')
        (bt.parent / 'Makefile').write_text('obj-m += hci_bcm4377.o\n')
        (root / 'provenance.json').write_text(json.dumps({
            'profile': profile, 'lab_commit': manifest['lab_commit'],
            'manifest_sha256': digest(HERE / 'manifest.json'),
            'kernel_release': manifest['kernel_release'],
            't2bce_source_commit': manifest['t2bce_source']['commit'],
            'source_parity': True,
        }, indent=2) + '\n')
        # Only a fully verified source tree is published; an existing output is refused.
        if output.exists():
            raise ValueError('Output appeared during preparation')
        root.chmod(0o755)
        root.rename(output)
    print(f'PASS: {profile} source matches pinned manifest: {output}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wifi-source', type=Path, required=True,
                        help='Unpatched brcm80211 source directory')
    parser.add_argument('--bluetooth-source', type=Path, required=True,
                        help='Unpatched hci_bcm4377.c')
    parser.add_argument('--t2bce-source-patch', type=Path, required=True,
                        help='Pinned linux-t2 patch that adds the BCE source tree')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['s3', 'wifi-reenable'], required=True)
    args = parser.parse_args()
    prepare(args.wifi_source.resolve(), args.bluetooth_source.resolve(),
            args.t2bce_source_patch.resolve(), args.output.absolute(), args.profile)
