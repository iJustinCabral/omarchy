"""Recover the observed BCM4377 firmware-command stall without a reboot."""
import argparse
import fcntl
import errno
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time

SYS = Path('/sys')
RUNTIME = Path('/run/omarchy-t2-wifi-recovery')
SLEEP_STATE = Path('/run/omarchy-t2-bcm4377-sleep.state')
SLEEP_LOCK = Path('/run/lock/omarchy-t2-bcm4377.lock')
VALIDATED_MODELS = {'MacBookAir9,1'}
TIMEOUT = re.compile(r'^ieee80211 (phy[0-9]+): brcmf_msgbuf_query_dcmd: Timeout on response for query command$')


def log(event, **fields):
  print(json.dumps({'event': event, 'monotonic': time.monotonic(), **fields}), flush=True)


def hardware():
  if (SYS/'class/dmi/id/sys_vendor').read_text().strip() != 'Apple Inc.':
    raise RuntimeError('Requires an Apple T2 Mac')
  model = (SYS/'class/dmi/id/product_name').read_text().strip()
  if model not in VALIDATED_MODELS and os.environ.get('OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL') != '1':
    raise RuntimeError('Model is unvalidated; explicit opt-in required')
  ids = []
  for dev in (SYS/'bus/pci/devices').glob('*'):
    try:
      ids.append((dev, (dev/'vendor').read_text().strip(), (dev/'device').read_text().strip()))
    except FileNotFoundError:
      continue
  if not any(vendor == '0x106b' and ident in ('0x1801', '0x1802') for _, vendor, ident in ids):
    raise RuntimeError('Apple T2 controller absent')
  wifi = [dev for dev, vendor, ident in ids if vendor == '0x14e4' and ident == '0x4488']
  if len(wifi) != 1:
    raise RuntimeError('Requires exactly one BCM4377b (14e4:4488)')
  return wifi[0]


def guard():
  pci = hardware()
  if (pci/'driver').resolve().name != 'brcmfmac':
    raise RuntimeError('Wi-Fi driver not bound to brcmfmac')


def device():
  nets = list((hardware()/'net').glob('*'))
  if len(nets) != 1:
    raise RuntimeError('Expected one primary Wi-Fi netdev')
  net = nets[0]
  phy = (net/'phy80211').resolve().name
  if not re.fullmatch(r'phy[0-9]+', phy):
    raise RuntimeError('Unexpected phy')
  radios = list((net/'phy80211').glob('rfkill*'))
  if len(radios) != 1:
    raise RuntimeError('Expected one Wi-Fi rfkill device')
  radio = radios[0]
  return {'interface': net.name, 'index': int((net/'ifindex').read_text()),
      'phy': phy, 'enabled': all((radio/n).read_text().strip() == '0' for n in ('soft', 'hard')),
      'connected': (net/'operstate').read_text().strip() == 'up',
      'reset': str(SYS/'kernel/debug/ieee80211'/phy/'reset')}


def eligible(entry, boot, cutoff, now, dev, state):
  # Journal metadata and the exact current PHY tie the trigger to this device.
  if entry.get('_BOOT_ID', '').replace('-', '') != boot.replace('-', '') or entry.get('_TRANSPORT') != 'kernel':
    return False
  msg = entry.get('MESSAGE')
  match = TIMEOUT.fullmatch(msg) if isinstance(msg, str) else None
  if not match or match[1] != dev['phy']:
    return False
  try:
    stamp = int(entry['__MONOTONIC_TIMESTAMP']) / 1e6
  except (KeyError, TypeError, ValueError):
    return False
  return (cutoff <= stamp <= now and now - stamp <= 20 and dev['enabled']
      and not dev['connected'] and state['attempts'] < 3
      and now - state['last_attempt'] >= 120)


def save(state):
  temp = RUNTIME/'state.tmp'
  temp.write_text(json.dumps(state, indent=2))
  temp.replace(RUNTIME/'state.json')


def recover_locked(dev, state):
  # Persist the attempt before scheduling reset; no retry storm after restart.
  state['attempts'] += 1
  state['last_attempt'] = time.monotonic()
  save(state)
  guard()
  current = device()
  if current['index'] != dev['index'] or not current['enabled'] or current['connected']:
    log('CANCELLED_STATE_CHANGED')
    return
  log('RESET_BEGIN', interface=dev['interface'], index=dev['index'], attempt=state['attempts'])
  Path(current['reset']).write_text('1\n')
  deadline = time.monotonic() + 35
  new_index = None
  while time.monotonic() < deadline:
    try:
      after = device()
      if not after['enabled']:
        log('USER_DISABLED_WIFI', index=after['index'])
        return
      if after['index'] != dev['index']:
        new_index = after['index']
        if after['connected']:
          # Confirm NM association too, rather than treating reset return as success.
          nm = subprocess.run(['/usr/bin/nmcli', '-g', 'GENERAL.STATE', 'device', 'show', after['interface']],
                    capture_output=True, text=True, timeout=5,
                    env={**os.environ, 'LC_ALL': 'C'})
          if nm.returncode == 0 and nm.stdout.startswith('100 '):
            log('RECOVERED', old_index=dev['index'], index=after['index'])
            return
    except OSError as exc:
      if exc.errno not in (errno.ENOENT, errno.ENODEV):
        raise
    except (RuntimeError, subprocess.TimeoutExpired):
      pass
    time.sleep(0.5)
  log('RECOVERY_FAILED', old_index=dev['index'], new_index=new_index)


def recover(dev, state):
  # The sleep helper holds this same lock during pre/post. Its state file
  # stays present across sleep, covering the interval between those processes.
  with SLEEP_LOCK.open('a') as lock:
    try:
      fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      log('SKIP_SLEEP_BUSY')
      return
    if SLEEP_STATE.exists():
      log('SKIP_SLEEP_PREPARED')
      return
    recover_locked(dev, state)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--check', action='store_true')
  parser.add_argument('--supported', action='store_true', help='Check hardware eligibility without requiring a loaded driver')
  args = parser.parse_args()
  if args.supported:
    log('SUPPORTED', pci=str(hardware()))
    return
  deadline = time.monotonic() + (0 if args.check else 30)
  while True:
    try:
      guard()
      dev = device()
      break
    except (FileNotFoundError, RuntimeError):
      if time.monotonic() >= deadline:
        raise
      time.sleep(0.5)
  if not Path(dev['reset']).is_file():
    raise RuntimeError('Driver reset entry point absent')
  if args.check:
    log('CHECK_PASS', **dev)
    return
  if os.geteuid() != 0:
    raise RuntimeError('Root required')
  os.umask(0o077)
  RUNTIME.mkdir(mode=0o700, exist_ok=True)
  lock = (RUNTIME/'lock').open('a')
  fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
  boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  state = {'boot': boot, 'attempts': 0, 'last_attempt': -120.0}
  if (RUNTIME/'state.json').exists():
    previous = json.loads((RUNTIME/'state.json').read_text())
    if previous['boot'] == boot:
      if not isinstance(previous['attempts'], int) or not 0 <= previous['attempts'] <= 3:
        raise RuntimeError('Invalid recovery budget')
      if not isinstance(previous['last_attempt'], (int, float)):
        raise RuntimeError('Invalid recovery timestamp')
      state = previous
  save(state)
  cutoff = time.monotonic()
  child = subprocess.Popen(['/usr/bin/journalctl', '-k', '-b', '-f', '--since=-5s', '-o', 'json', '--no-pager'],
              stdout=subprocess.PIPE, text=True)
  def stop(*_):
    raise KeyboardInterrupt()
  for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, stop)
  log('READY', boot=boot, kernel=os.uname().release, attempts=state['attempts'])
  try:
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
      with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
        notify.connect('\0' + address[1:] if address.startswith('@') else address)
        notify.sendall(b'READY=1')
    for line in child.stdout:
      try:
        entry = json.loads(line)
        # Most kernel messages require no sysfs access at all.
        if not isinstance(entry.get('MESSAGE'), str) or not TIMEOUT.fullmatch(entry['MESSAGE']):
          continue
        dev = device()
        if eligible(entry, boot, cutoff, time.monotonic(), dev, state):
          recover(dev, state)
          # Ignore the original burst accumulated while reset was running.
          cutoff = time.monotonic()
      except (ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
        log('SKIPPED', reason=str(exc))
    raise RuntimeError('Journal follower ended')
  except KeyboardInterrupt:
    log('STOPPED')
  finally:
    child.terminate()
    try:
      child.wait(timeout=5)
    except subprocess.TimeoutExpired:
      child.kill()
      child.wait()


if __name__ == '__main__':
  main()
