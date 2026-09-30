#!/usr/bin/python3
"""Transient hibernation preparation for the upstream-model test (stdlib only).

Copied by the runner to /run/omarchy-t2-upstream-model/ (root-owned, hash-pinned) and run
by the /run drop-in of systemd-hibernate.service: `pre` before systemd-sleep, `post` after
it (also after a failed or returned transition). It mirrors the product preparation order
(bolt stop, Bluetooth off, Wi-Fi detach) using the repo Wi-Fi helper, and undoes exactly
what it did. It never enters hibernation.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


DIRECTORY = Path("/run/omarchy-t2-upstream-model")
HELPER_NAME = "omarchy-t2-hibernate-wifi"
STATE_NAME = "prepare-state.json"
PINS_NAME = "pins.json"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}


def run(arguments, check=False, timeout=30):
  return subprocess.run([str(item) for item in arguments], text=True, capture_output=True, check=check, timeout=timeout, env=ENV)


def bluetooth_powered(runner=run):
  result = runner(("timeout", "5s", "bluetoothctl", "show"))
  if result.returncode == 0 and re.search(r"^\s*Powered:\s+yes\s*$", result.stdout, re.M):
    return True
  if result.returncode == 0 and re.search(r"^\s*Powered:\s+no\s*$", result.stdout, re.M):
    return False
  raise RuntimeError("Bluetooth power state is unavailable")


def set_bluetooth(powered, runner=run, sleeper=time.sleep):
  attempts = 3 if powered else 1
  for attempt in range(attempts):
    result = runner(("timeout", "5s", "bluetoothctl", "power", "on" if powered else "off"))
    if result.returncode == 0 and bluetooth_powered(runner) is powered:
      return
    if attempt + 1 < attempts:
      sleeper(1)
  raise RuntimeError("Bluetooth did not power " + ("on" if powered else "off"))


def helper(directory, owner=0):
  """The pinned Wi-Fi helper path, or raise."""
  path = Path(directory) / HELPER_NAME
  pins = json.loads((Path(directory) / PINS_NAME).read_text())
  if path.is_symlink() or not path.is_file():
    raise RuntimeError("Wi-Fi helper is missing or symlinked")
  metadata = path.stat()
  if metadata.st_uid != owner or metadata.st_mode & 0o022:
    raise RuntimeError("Wi-Fi helper must be root-owned and not group/world writable")
  if hashlib.sha256(path.read_bytes()).hexdigest() != pins.get("wifi_helper_sha256"):
    raise RuntimeError("Wi-Fi helper differs from its pinned SHA-256")
  return path


def write_state(directory, state):
  path = Path(directory) / STATE_NAME
  temporary = path.with_name(STATE_NAME + ".tmp")
  descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, "w") as stream:
    stream.write(json.dumps(state, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
  os.replace(temporary, path)


def pre(directory=DIRECTORY, runner=run, owner=0):
  directory = Path(directory)
  if (directory / STATE_NAME).exists():
    raise RuntimeError("A previous upstream-model preparation is still pending")
  wifi = helper(directory, owner)
  bolt_active = runner(("systemctl", "is-active", "--quiet", "bolt.service")).returncode == 0
  powered = bluetooth_powered(runner)
  write_state(directory, {"bolt_was_active": bolt_active, "bluetooth_was_powered": powered, "wifi_prepared": True})
  if bolt_active and runner(("systemctl", "stop", "bolt.service")).returncode != 0:
    raise RuntimeError("bolt.service did not stop")
  if powered:
    set_bluetooth(False, runner)
  if runner((wifi, "prepare")).returncode != 0:
    raise RuntimeError("Wi-Fi detach failed")


def post(directory=DIRECTORY, runner=run, owner=0, sleeper=time.sleep):
  directory = Path(directory)
  errors = []
  state_path = directory / STATE_NAME
  state = json.loads(state_path.read_text()) if state_path.exists() else {}
  try:
    if state.get("wifi_prepared"):
      if runner((helper(directory, owner), "restore")).returncode != 0:
        errors.append("wifi restore failed")
  except Exception as error:
    errors.append("wifi: " + str(error))
  if state.get("bluetooth_was_powered"):
    try:
      set_bluetooth(True, runner, sleeper)
    except Exception as error:
      errors.append("bluetooth: " + str(error))
  if state.get("bolt_was_active"):
    try:
      if runner(("systemctl", "start", "bolt.service")).returncode != 0:
        errors.append("bolt.service did not start")
    except Exception as error:
      errors.append("bolt: " + str(error))
  if not errors and state_path.exists():
    state_path.unlink()
  if errors:
    raise RuntimeError("; ".join(errors))


def main(argv=None):
  arguments = sys.argv[1:] if argv is None else argv
  if len(arguments) != 1 or arguments[0] not in ("pre", "post") or os.geteuid() != 0:
    raise SystemExit("usage (root): prepare.py pre|post")
  try:
    (pre if arguments[0] == "pre" else post)()
  except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
    print("omarchy-t2-upstream-model prepare " + arguments[0] + ": " + str(error), file=sys.stderr)
    raise SystemExit(1) from error


if __name__ == "__main__":
  main()
