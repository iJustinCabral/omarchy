#!/usr/bin/python3
"""BCM4377 boot gate: wait for firmware-backed netdev, never cycle modules."""
from pathlib import Path
import subprocess
import time

PCI = '0000:73:00.0'


def wifi_ready(sys=Path('/sys')):
  dev = sys/'bus/pci/devices'/PCI
  try:
    if (dev/'vendor').read_text().strip() != '0x14e4' or (dev/'device').read_text().strip() != '0x4488':
      return None
    if (dev/'driver').resolve().name != 'brcmfmac':
      return None
    for net in (dev/'net').iterdir():
      # Independent of interface name, carrier, NM, and radio soft block.
      if int((net/'ifindex').read_text()) > 0 and (net/'phy80211').is_dir():
        return net.name
  except (OSError, ValueError):
    return None
  return None


def gate(sys=Path('/sys'), run=subprocess.run, monotonic=time.monotonic, sleep=time.sleep):
  if (sys/'class/dmi/id/product_name').read_text().strip() != 'MacBookAir9,1':
    raise RuntimeError('unsupported model')
  if (sys/'module/hci_bcm4377').exists():
    raise RuntimeError('Bluetooth already loaded before gate')
  print('bt-order-v2: BEGIN waiting for firmware-backed BCM netdev', flush=True)
  deadline = monotonic() + 25
  while monotonic() < deadline:
    interface = wifi_ready(sys)
    if interface:
      if (sys/'module/hci_bcm4377').exists():
        raise RuntimeError('Bluetooth bypassed gate')
      print(f'bt-order-v2: WIFI_READY interface={interface}; loading Bluetooth', flush=True)
      run(['/usr/bin/modprobe', 'hci_bcm4377'], check=True, timeout=8)
      print('bt-order-v2: LOAD_RETURNED; hardware health unverified', flush=True)
      return
    sleep(0.2)
  raise RuntimeError('Wi-Fi netdev not ready; Bluetooth left unloaded')


if __name__ == '__main__':
  gate()
