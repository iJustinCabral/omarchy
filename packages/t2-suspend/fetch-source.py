#!/usr/bin/env python3
"""Fetch only hash-pinned T2 driver source; never execute downloaded code."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request

HERE = Path(__file__).resolve().parent
LINUX_BASE = 'https://raw.githubusercontent.com/gregkh/linux/v7.2.4/'
T2_PATCH_BASE = 'https://raw.githubusercontent.com/t2linux/linux-t2-patches/'

def fetch(output):
  manifest = json.loads((HERE / 'manifest.json').read_text())
  files = {'drivers/net/wireless/broadcom/brcm80211/' + name:
           (LINUX_BASE + 'drivers/net/wireless/broadcom/brcm80211/' + name, digest)
           for name, digest in manifest['wifi_base'].items()}
  files['drivers/bluetooth/hci_bcm4377.c'] = (
    LINUX_BASE + 'drivers/bluetooth/hci_bcm4377.c', manifest['bluetooth_base_sha256'])
  t2bce = manifest['t2bce_source']
  files['t2bce/' + t2bce['path']] = (
    T2_PATCH_BASE + t2bce['commit'] + '/' + t2bce['path'], t2bce['sha256'])
  def one(item):
    name, (url, expected) = item
    path = output / name
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected:
      return
    with urllib.request.urlopen(url, timeout=60) as response:
      data = response.read(4 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected:
      raise ValueError('Upstream source hash mismatch: ' + name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(one, files.items()))

if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('output', type=Path)
  fetch(parser.parse_args().output)
