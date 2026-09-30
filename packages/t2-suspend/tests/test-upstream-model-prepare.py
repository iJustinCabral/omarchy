#!/usr/bin/python3
"""Check the transient upstream-model hibernation preparation (bolt, Bluetooth, Wi-Fi detach) with fake commands."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile


package = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("upstream_model_prepare", package / "upstream-model/prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
OWNER = os.getuid()


def rejects(action, expected):
  try:
    action()
  except RuntimeError as error:
    assert expected in str(error), error
  else:
    raise AssertionError("Unsafe preparation accepted: " + expected)


class Fake:
  def __init__(self, bolt=True, bluetooth=True, wifi_rc=0, bluetooth_on_rc=0):
    self.bolt, self.bluetooth, self.wifi_rc, self.bluetooth_on_rc = bolt, bluetooth, wifi_rc, bluetooth_on_rc
    self.calls = []

  def __call__(self, arguments, **_options):
    arguments = tuple(str(item) for item in arguments)
    self.calls.append(arguments)
    done = lambda out="", rc=0: subprocess.CompletedProcess(arguments, rc, out, "")
    if arguments[:3] == ("systemctl", "is-active", "--quiet"):
      return done(rc=0 if self.bolt else 3)
    if arguments == ("systemctl", "stop", "bolt.service"):
      self.bolt = False
      return done()
    if arguments == ("systemctl", "start", "bolt.service"):
      self.bolt = True
      return done()
    if arguments[:3] == ("timeout", "5s", "bluetoothctl"):
      if arguments[3] == "show":
        return done("Controller AA\n\tPowered: " + ("yes" if self.bluetooth else "no") + "\n")
      if arguments[4] == "off":
        self.bluetooth = False
        return done()
      if self.bluetooth_on_rc:
        return done(rc=self.bluetooth_on_rc)
      self.bluetooth = True
      return done()
    if arguments[-1] == "prepare":
      return done(rc=self.wifi_rc)
    if arguments[-1] == "restore":
      return done()
    raise AssertionError("Unexpected command: " + repr(arguments))


def directory_fixture(base, helper_data=b"#!/bin/sh\n"):
  directory = base / "run"
  directory.mkdir()
  (directory / prepare.HELPER_NAME).write_bytes(helper_data)
  (directory / prepare.HELPER_NAME).chmod(0o755)
  (directory / prepare.PINS_NAME).write_text(json.dumps({"wifi_helper_sha256": hashlib.sha256(b"#!/bin/sh\n").hexdigest()}))
  return directory


with tempfile.TemporaryDirectory(prefix="t2-upstream-prepare-") as temporary:
  base = Path(temporary)

  # pre isolates bolt, Bluetooth and Wi-Fi in the product order; post undoes exactly that.
  (base / "a").mkdir()
  directory = directory_fixture(base / "a")
  fake = Fake()
  prepare.pre(directory, fake, owner=OWNER)
  order = [call for call in fake.calls if call[0] in ("systemctl", "timeout") or call[-1] == "prepare"]
  stop = next(index for index, call in enumerate(order) if call == ("systemctl", "stop", "bolt.service"))
  off = next(index for index, call in enumerate(order) if call[:5] == ("timeout", "5s", "bluetoothctl", "power", "off"))
  wifi = next(index for index, call in enumerate(order) if call[-1] == "prepare")
  assert stop < off < wifi
  assert fake.bolt is False and fake.bluetooth is False
  state = json.loads((directory / prepare.STATE_NAME).read_text())
  assert state == {"bolt_was_active": True, "bluetooth_was_powered": True, "wifi_prepared": True}
  assert (directory / prepare.STATE_NAME).stat().st_mode & 0o777 == 0o600
  rejects(lambda: prepare.pre(directory, fake, owner=OWNER), "still pending")
  prepare.post(directory, fake, owner=OWNER, sleeper=lambda _seconds: None)
  assert fake.bolt is True and fake.bluetooth is True and not (directory / prepare.STATE_NAME).exists()
  assert any(call[-1] == "restore" for call in fake.calls)
  prepare.post(directory, fake, owner=OWNER, sleeper=lambda _seconds: None)  # idempotent

  # Nothing active: nothing is stopped, powered off or restarted, but Wi-Fi is still detached and restored.
  (base / "b").mkdir()
  directory = directory_fixture(base / "b")
  fake = Fake(bolt=False, bluetooth=False)
  prepare.pre(directory, fake, owner=OWNER)
  assert ("systemctl", "stop", "bolt.service") not in fake.calls
  prepare.post(directory, fake, owner=OWNER)
  assert ("systemctl", "start", "bolt.service") not in fake.calls and fake.bluetooth is False

  # A failed Wi-Fi detach fails the start job; the state stays so post can still restore.
  (base / "c").mkdir()
  directory = directory_fixture(base / "c")
  fake = Fake(wifi_rc=1)
  rejects(lambda: prepare.pre(directory, fake, owner=OWNER), "Wi-Fi detach failed")
  prepare.post(directory, fake, owner=OWNER, sleeper=lambda _seconds: None)
  assert fake.bolt is True and fake.bluetooth is True

  # Restore failures are reported and keep the state for another attempt.
  (base / "d").mkdir()
  directory = directory_fixture(base / "d")
  fake = Fake()
  prepare.pre(directory, fake, owner=OWNER)
  fake.bluetooth_on_rc = 1
  rejects(lambda: prepare.post(directory, fake, owner=OWNER, sleeper=lambda _seconds: None), "bluetooth")
  assert (directory / prepare.STATE_NAME).exists() and fake.bolt is True

  # The helper is hash-pinned, root-owned (here: test-owned), non-symlink and not group/world writable.
  (base / "e").mkdir()
  directory = directory_fixture(base / "e", helper_data=b"#!/bin/sh\nevil\n")
  rejects(lambda: prepare.pre(directory, Fake(), owner=OWNER), "pinned SHA-256")
  assert not (directory / prepare.STATE_NAME).exists()
  (directory / prepare.HELPER_NAME).write_bytes(b"#!/bin/sh\n")
  (directory / prepare.HELPER_NAME).chmod(0o777)
  rejects(lambda: prepare.pre(directory, Fake(), owner=OWNER), "writable")
  (directory / prepare.HELPER_NAME).chmod(0o755)
  rejects(lambda: prepare.pre(directory, Fake(), owner=OWNER + 1), "root-owned")
  (directory / prepare.HELPER_NAME).unlink()
  (directory / prepare.HELPER_NAME).symlink_to("/bin/true")
  rejects(lambda: prepare.pre(directory, Fake(), owner=OWNER), "symlinked")

  # Bluetooth state that cannot be read refuses before anything is changed.
  (base / "f").mkdir()
  directory = directory_fixture(base / "f")
  unreadable = lambda arguments, **_options: subprocess.CompletedProcess(arguments, 1, "", "")
  rejects(lambda: prepare.pre(directory, unreadable, owner=OWNER), "unavailable")

# A raising bolt start and a timed-out command are reported, never propagated out of post unhandled.
with tempfile.TemporaryDirectory(prefix="t2-upstream-prepare-") as temporary:
  base = Path(temporary)
  (base / "g").mkdir()
  directory = directory_fixture(base / "g")
  fake = Fake()
  prepare.pre(directory, fake, owner=OWNER)
  original_call = fake.__class__.__call__

  def raising(self, arguments, **options):
    if tuple(str(item) for item in arguments) == ("systemctl", "start", "bolt.service"):
      raise subprocess.TimeoutExpired(arguments, 30)
    return original_call(self, arguments, **options)

  fake.__class__.__call__ = raising
  try:
    rejects(lambda: prepare.post(directory, fake, owner=OWNER, sleeper=lambda _seconds: None), "bolt")
  finally:
    fake.__class__.__call__ = original_call
  assert fake.bluetooth is True and (directory / prepare.STATE_NAME).exists()
  # The real entry point turns a timeout into a clean failure.
  prepare.os.geteuid = lambda: 0
  prepare.pre = lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("x", 1))
  try:
    prepare.main(["pre"])
  except SystemExit as error:
    assert error.code == 1
  else:
    raise AssertionError("timeout not handled")

# The entry point is root-only and takes exactly pre or post.
for arguments in ([], ["both"], ["pre", "post"]):
  prepare.os.geteuid = lambda: 0
  try:
    prepare.main(arguments)
  except SystemExit as error:
    assert "usage" in str(error) or error.code

print("PASS: upstream-model preparation mirrors the product order, restores exactly what it changed and pins its helper")
