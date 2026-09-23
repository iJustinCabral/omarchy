#!/usr/bin/env python3
"""Fetch only hash-pinned radio source; never execute downloaded code."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request

HERE = Path(__file__).resolve().parent
BASE = 'https://raw.githubusercontent.com/gregkh/linux/v7.2.4/'

def fetch(output):
  manifest = json.loads((HERE / 'manifest.json').read_text())
  files = {'drivers/net/wireless/broadcom/brcm80211/' + name: digest
           for name, digest in manifest['wifi_base'].items()}
  files['drivers/bluetooth/hci_bcm4377.c'] = manifest['bluetooth_base_sha256']
  def one(item):
    name, expected = item
    path = output / name
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected:
      return
    with urllib.request.urlopen(BASE + name, timeout=60) as response:
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
