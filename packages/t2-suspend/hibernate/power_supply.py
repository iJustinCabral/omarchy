"""Read-only power observations, with no admission policy or host default root.

Linux power_supply charge, current, voltage, energy and power attributes are
reported in microamp-hours, microamps, microvolts, microwatt-hours and microwatts
respectively. Capacity is the firmware-reported percentage, never charge/full
or charge/design. Missing optional fields remain None; no energy, capacity,
runtime or safe reserve is inferred. A successful sample does not qualify S4.
"""

import math
import os
from pathlib import Path
import re
import stat
import time


_METRICS = {
  "capacity": ("capacity_percent", False, 0, 100),
  "charge_now": ("charge_now_uah", False, 0, None),
  "charge_full": ("charge_full_uah", False, 1, None),
  "charge_full_design": ("charge_full_design_uah", False, 1, None),
  "current_now": ("current_now_ua", True, None, None),
  "voltage_now": ("voltage_now_uv", False, 0, None),
  "voltage_min_design": ("voltage_min_design_uv", False, 1, None),
  "energy_now": ("energy_now_uwh", False, 0, None),
  "energy_full": ("energy_full_uwh", False, 1, None),
  "energy_full_design": ("energy_full_design_uwh", False, 1, None),
  "power_now": ("power_now_uw", True, None, None),
}
_STATUSES = {"Unknown", "Charging", "Discharging", "Not charging", "Full"}


def _text(path, *, optional=False):
  try:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
  except FileNotFoundError:
    if optional:
      return None
    raise ValueError("Missing power supply attribute: " + str(path)) from None
  with os.fdopen(fd, "rb") as stream:
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
      raise ValueError("Nonregular power supply attribute: " + str(path))
    raw = stream.read(257)
  if len(raw) > 256:
    raise ValueError("Oversized power supply attribute: " + str(path))
  value = raw.decode("ascii")
  if value.endswith("\n"):
    value = value[:-1]
  if not value or any(ord(char) < 32 or ord(char) > 126 for char in value):
    raise ValueError("Malformed power supply attribute: " + str(path))
  return value


def _number(path, *, signed=False, minimum=None, maximum=None):
  value = _text(path, optional=True)
  if value is None:
    return None
  if re.fullmatch(r"-?[0-9]+" if signed else r"[0-9]+", value) is None:
    raise ValueError("Noninteger power supply attribute: " + str(path))
  result = int(value)
  if (minimum is not None and result < minimum) or (maximum is not None and result > maximum):
    raise ValueError("Out-of-range power supply attribute: " + str(path))
  return result


def _controls(path):
  supply_type = _text(path / "type")
  status = _text(path / "status", optional=True)
  if status is not None and status not in _STATUSES:
    raise ValueError("Unknown power supply status: " + str(path))
  def boolean(attribute):
    value = _text(path / attribute, optional=True)
    if value is not None and value not in ("0", "1"):
      raise ValueError("Invalid power supply boolean: " + str(path / attribute))
    return None if value is None else value == "1"
  present = boolean("present")
  online = boolean("online")
  if supply_type == "Mains" and online is None:
    raise ValueError("Mains supply has no online observation: " + str(path))
  return {"type": supply_type, "present": present, "online": online, "status": status}


def _inventory(directory):
  entries = sorted(directory.iterdir(), key=lambda path: path.name)
  if len(entries) > 64:
    raise ValueError("Power supply inventory exceeds bounded sample")
  result = {}
  for path in entries:
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
      raise ValueError("Non-directory power supply: " + str(path))
    # Real sysfs class entries are symlinks; include both target and inode to
    # detect a changed device under the same class name between reads.
    result[path.name] = (str(path.resolve(strict=True)), info.st_dev, info.st_ino)
  return result


def _capture(directory):
  inventory = _inventory(directory)
  supplies = []
  for name in inventory:
    path = directory / name
    before = _controls(path)
    reading = {"name": name, **before}
    for attribute, (key, signed, minimum, maximum) in _METRICS.items():
      reading[key] = _number(path / attribute, signed=signed, minimum=minimum, maximum=maximum)
    if before != _controls(path):
      raise ValueError("Power supply state changed during sample: " + name)
    supplies.append(reading)
  if inventory != _inventory(directory):
    raise ValueError("Power supply inventory changed during sample")
  return inventory, supplies


def sample_power_supply(root, *, clock=time.monotonic, max_duration_seconds=1.0):
  """Capture fresh telemetry from an explicit absolute host root.

  Two complete passes must agree on supply identity, type, presence, online and
  status; numeric drift is normal and the returned metrics are from the second
  pass. Missing battery presence/status/metrics stay unknown, rather than being
  silently admitted. Mains without an online field is invalid. ac_online is the
  actual strict boolean OR of observed Mains supplies, not battery admission.

  ValueError rejects missing/unreadable/malformed attributes, changed supplies
  or power states, a nonfinite/backward clock or an expired sampling interval.
  max_duration_seconds bounds elapsed sampling, not a sysfs I/O timeout, and
  cannot detect driver-cached/stale measurements. No userspace sampler can
  prove the absence of an unplug/replug between reads. Consumers must evaluate
  reserve separately and sample again at the final image writer after slow
  preparation; retaining this observation is not authority for a later write.
  """
  root = Path(root)
  if not root.is_absolute() or not root.is_dir():
    raise ValueError("Explicit absolute power supply host root required")
  if isinstance(max_duration_seconds, bool) or not isinstance(max_duration_seconds, (int, float)) or not math.isfinite(max_duration_seconds) or max_duration_seconds <= 0:
    raise ValueError("Positive finite sampling duration required")
  try:
    started = clock()
    inventory, first = _capture(root / "sys/class/power_supply")
    middle = clock()
    second_inventory, second = _capture(root / "sys/class/power_supply")
    finished = clock()
    times = (started, middle, finished)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in times):
      raise ValueError("Invalid power supply monotonic clock")
    if not started <= middle <= finished or finished - started > max_duration_seconds:
      raise ValueError("Power supply sample expired or clock moved backwards")
    controls = lambda supplies: [{key: supply[key] for key in ("name", "type", "present", "online", "status")} for supply in supplies]
    if inventory != second_inventory or controls(first) != controls(second):
      raise ValueError("Power supply identity or state changed between samples")
    return {"started_monotonic": started, "finished_monotonic": finished,
            "ac_online": any(supply["type"] == "Mains" and supply["online"] is True for supply in second),
            "supplies": second}
  except (OSError, UnicodeError) as error:
    raise ValueError("Unreadable power supply sample: " + str(error)) from error
