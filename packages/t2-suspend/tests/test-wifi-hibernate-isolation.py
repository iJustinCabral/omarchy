#!/usr/bin/env python3
"""Exercise the Wi-Fi hibernation isolation helper on a synthetic sysfs tree."""

import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "packages/t2-suspend/experiments/0008-wifi-hibernate-isolation/omarchy-t2-hibernate-wifi"
DROP_IN = ROOT / "packages/t2-suspend/experiments/0008-wifi-hibernate-isolation/systemd-hibernate.service.conf"

loader = importlib.machinery.SourceFileLoader("wifi_hibernate_isolation", str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class FakeControl:
  def __init__(self, root):
    self.root = root
    self.calls = []
    self.ignore_unbind = False
    self.ignore_bind = False

  @property
  def device(self):
    return self.root / f"sys/bus/pci/devices/{module.DEVICE}"

  @property
  def driver(self):
    return self.root / f"sys/bus/pci/drivers/{module.DRIVER}"

  def __call__(self, path, value):
    assert value == module.DEVICE
    self.calls.append(path.name)
    link = self.device / "driver"
    if path.name == "unbind" and not self.ignore_unbind:
      link.unlink()
    elif path.name == "bind" and not self.ignore_bind:
      link.symlink_to(self.driver)


def write(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(value + "\n")


def fixture(root, model=module.MODEL, bound=True):
  write(root / "sys/class/dmi/id/product_name", model)
  device = root / f"sys/bus/pci/devices/{module.DEVICE}"
  driver = root / f"sys/bus/pci/drivers/{module.DRIVER}"
  write(device / "vendor", module.VENDOR)
  write(device / "device", module.DEVICE_ID)
  driver.mkdir(parents=True)
  (driver / "bind").touch()
  (driver / "unbind").touch()
  if bound:
    (device / "driver").symlink_to(driver)
  return FakeControl(root)


def expect_failure(callable_):
  try:
    callable_()
  except module.IsolationError:
    return
  raise AssertionError("expected isolation failure")


with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root, model="OtherModel")
  module.prepare(root, control)
  assert control.calls == []

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root, bound=False)
  module.prepare(root, control)
  assert control.calls == []
  assert not (root / module.STATE / module.MARKER).exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root)
  module.prepare(root, control)
  marker = root / module.STATE / module.MARKER
  assert control.calls == ["unbind"] and marker.read_text().strip() == module.DEVICE
  assert not (control.device / "driver").exists()
  module.restore(root, control)
  assert control.calls == ["unbind", "bind"]
  assert (control.device / "driver").resolve() == control.driver.resolve()
  assert not marker.exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root)
  control.ignore_unbind = True
  expect_failure(lambda: module.prepare(root, control))
  marker = root / module.STATE / module.MARKER
  assert marker.exists()
  module.restore(root, control)
  assert not marker.exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root)
  module.prepare(root, control)
  control.ignore_bind = True
  expect_failure(lambda: module.restore(root, control))
  assert (root / module.STATE / module.MARKER).exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root)
  marker = root / module.STATE / module.MARKER
  marker.parent.mkdir(parents=True)
  marker.write_text(module.DEVICE + "\n")
  expect_failure(lambda: module.prepare(root, control))
  module.restore(root, control)
  assert not marker.exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root, bound=False)
  other = root / "sys/bus/pci/drivers/other"
  other.mkdir(parents=True)
  (control.device / "driver").symlink_to(other)
  marker = root / module.STATE / module.MARKER
  marker.parent.mkdir(parents=True)
  marker.write_text(module.DEVICE + "\n")
  expect_failure(lambda: module.restore(root, control))
  assert marker.exists()

with tempfile.TemporaryDirectory() as temporary:
  root = Path(temporary)
  control = fixture(root, bound=False)
  marker = root / module.STATE / module.MARKER
  marker.parent.mkdir(parents=True)
  marker.write_text("0000:00:00.0\n")
  expect_failure(lambda: module.restore(root, control))
  assert marker.exists()

drop_in = DROP_IN.read_text()
assert "ExecStartPre=/usr/lib/omarchy/omarchy-t2-hibernate-wifi prepare" in drop_in
assert "ExecStopPost=/usr/lib/omarchy/omarchy-t2-hibernate-wifi restore" in drop_in
assert not any(line.startswith("-") for line in drop_in.splitlines() if "Exec" in line)

print("PASS: Wi-Fi hibernation isolation is fail-closed and restores only owned detach state")
