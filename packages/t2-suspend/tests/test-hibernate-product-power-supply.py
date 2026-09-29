#!/usr/bin/python3
"""Temporary synthetic sysfs only; never samples or mutates live power state."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("power_supply", Path(__file__).parents[1] / "hibernate/power_supply.py")
power = importlib.util.module_from_spec(spec)
spec.loader.exec_module(power)


class PowerSupply(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.supplies = self.root / "sys/class/power_supply"
    self.supplies.mkdir(parents=True)
    self.supply("AC", type="Mains", online="1")
    self.supply("BAT0", type="Battery", present="1", status="Full", capacity="79",
                charge_now="3440000", charge_full="3518000", charge_full_design="4381000",
                current_now="0", voltage_now="12507000", voltage_min_design="11000000")

  def supply(self, name, **attributes):
    directory = self.supplies / name
    directory.mkdir(exist_ok=True)
    for attribute, value in attributes.items():
      (directory / attribute).write_text(value + "\n")

  def sample(self, mutation=None, times=(10.0, 10.1, 10.2), **kwargs):
    ticks = iter(times)
    calls = 0
    def clock():
      nonlocal calls
      calls += 1
      if calls == 2 and mutation is not None:
        mutation()
      return next(ticks)
    return power.sample_power_supply(self.root, clock=clock, **kwargs)

  def battery(self, snapshot):
    return next(supply for supply in snapshot["supplies"] if supply["name"] == "BAT0")

  def test_mba_charge_telemetry_preserves_firmware_capacity_without_inference(self):
    result = self.sample()
    battery = self.battery(result)
    self.assertIs(result["ac_online"], True)
    self.assertIs(battery["present"], True)
    self.assertEqual(battery["capacity_percent"], 79)
    self.assertEqual(battery["charge_now_uah"], 3440000)
    self.assertEqual(battery["charge_full_uah"], 3518000)
    self.assertEqual(battery["charge_full_design_uah"], 4381000)
    self.assertEqual(battery["voltage_now_uv"], 12507000)
    self.assertIsNone(battery["energy_now_uwh"])
    self.assertIsNone(battery["power_now_uw"])
    self.assertNotIn("reserve", result)

  def test_unplugged_battery_is_truthfully_observed(self):
    self.supply("AC", online="0")
    self.supply("BAT0", status="Discharging", current_now="-12345")
    result = self.sample()
    self.assertIs(result["ac_online"], False)
    self.assertEqual(self.battery(result)["current_now_ua"], -12345)

  def test_energy_fields_are_independent_measurements(self):
    for field in ("charge_now", "charge_full", "charge_full_design"):
      (self.supplies / "BAT0" / field).unlink()
    self.supply("BAT0", energy_now="38000000", energy_full="40000000", energy_full_design="50000000", power_now="5000000")
    battery = self.battery(self.sample())
    self.assertIsNone(battery["charge_now_uah"])
    self.assertEqual(battery["energy_now_uwh"], 38000000)
    self.assertEqual(battery["power_now_uw"], 5000000)

  def test_missing_battery_metrics_presence_and_status_are_unknown(self):
    shutil.rmtree(self.supplies / "BAT0")
    self.supply("BAT0", type="Battery")
    battery = self.battery(self.sample())
    for key in ("present", "status", "capacity_percent", "charge_now_uah", "energy_now_uwh"):
      self.assertIsNone(battery[key])

  def test_no_supplies_or_no_battery_are_observations_not_admission(self):
    shutil.rmtree(self.supplies / "BAT0")
    self.assertTrue(self.sample()["ac_online"])
    shutil.rmtree(self.supplies / "AC")
    self.assertEqual(self.sample()["supplies"], [])
    self.assertFalse(self.sample()["ac_online"])

  def test_normal_numeric_drift_returns_later_values(self):
    result = self.sample(lambda: self.supply("BAT0", charge_now="3439999", current_now="17", voltage_now="12506999", capacity="80"))
    battery = self.battery(result)
    self.assertEqual(battery["charge_now_uah"], 3439999)
    self.assertEqual(battery["current_now_ua"], 17)
    self.assertEqual(battery["capacity_percent"], 80)
    self.assertEqual(result["finished_monotonic"], 10.2)

  def test_strict_malformed_metrics_are_not_treated_as_missing(self):
    for field, values in {"capacity": ("101", "-1", "79%", "79.0", " 79", "79 "),
                          "charge_now": ("-1", "NaN", "3440000 uAh", "", "1\n2", "9" * 257),
                          "charge_full": ("0",), "voltage_min_design": ("0",),
                          "current_now": ("+1", "1.5")}.items():
      path = self.supplies / "BAT0" / field
      original = path.read_bytes()
      for value in values:
        with self.subTest(field=field, value=value):
          path.write_text(value + "\n")
          with self.assertRaises(ValueError):
            self.sample()
      path.write_bytes(original)

  def test_invalid_boolean_unknown_status_and_missing_mains_online_reject(self):
    for supply, field, value in (("AC", "online", "2"), ("AC", "online", "01"),
                                 ("BAT0", "present", "true"), ("BAT0", "status", "Almost Full")):
      path = self.supplies / supply / field
      original = path.read_bytes()
      path.write_text(value + "\n")
      with self.assertRaises(ValueError):
        self.sample()
      path.write_bytes(original)
    (self.supplies / "AC/online").unlink()
    with self.assertRaises(ValueError):
      self.sample()

  def test_control_changes_between_passes_reject(self):
    for supply, field, value in (("AC", "online", "0"), ("BAT0", "present", "0"),
                                 ("BAT0", "status", "Discharging"), ("AC", "type", "USB")):
      path = self.supplies / supply / field
      original = path.read_bytes()
      with self.subTest(field=field):
        with self.assertRaises(ValueError):
          self.sample(lambda: path.write_text(value + "\n"))
      path.write_bytes(original)

  def test_supply_disappearance_addition_and_replacement_reject(self):
    def replace():
      previous = self.supplies / "old-battery"
      (self.supplies / "BAT0").rename(previous)
      self.supply("BAT0", type="Battery", present="1", status="Full")
      shutil.rmtree(previous)
    for mutation in (lambda: shutil.rmtree(self.supplies / "BAT0"),
                     lambda: self.supply("AC2", type="Mains", online="1"), replace):
      with self.subTest(mutation=mutation):
        with self.assertRaises(ValueError):
          self.sample(mutation)
        if not (self.supplies / "BAT0").exists():
          self.supply("BAT0", type="Battery", present="1", status="Full")
        if (self.supplies / "AC2").exists():
          shutil.rmtree(self.supplies / "AC2")

  def test_control_change_inside_capture_rejects(self):
    original = power._number
    changed = False
    def number(path, **kwargs):
      nonlocal changed
      result = original(path, **kwargs)
      if path.name == "charge_now" and not changed:
        changed = True
        self.supply("AC", online="0")
        self.supply("BAT0", status="Discharging")
      return result
    with mock.patch.object(power, "_number", side_effect=number):
      with self.assertRaises(ValueError):
        self.sample()

  def test_real_sysfs_style_class_symlink_allowed_attribute_symlink_rejected(self):
    battery = self.supplies / "BAT0"
    target = self.root / "devices/BAT0"
    target.parent.mkdir()
    battery.rename(target)
    battery.symlink_to(target, target_is_directory=True)
    self.assertEqual(self.battery(self.sample())["charge_now_uah"], 3440000)
    (target / "capacity").unlink()
    (target / "capacity").symlink_to(target / "charge_now")
    with self.assertRaises(ValueError):
      self.sample()

  def test_time_bound_nonfinite_backwards_and_expired_samples_reject(self):
    for times in ((10, 10.1, 12), (10, 9, 10.2), (10, 10.1, 9),
                  (10, float("nan"), 10.2), (True, 10.1, 10.2)):
      with self.subTest(times=times):
        with self.assertRaises(ValueError):
          self.sample(times=times)
    for duration in (0, -1, True, float("inf"), "1"):
      with self.assertRaises(ValueError):
        self.sample(max_duration_seconds=duration)

  def test_missing_class_relative_root_and_nonascii_reject(self):
    with self.assertRaises(ValueError):
      power.sample_power_supply(Path("relative"))
    (self.supplies / "BAT0/capacity").write_bytes(b"\xff\n")
    with self.assertRaises(ValueError):
      self.sample()
    shutil.rmtree(self.supplies)
    with self.assertRaises(ValueError):
      self.sample()


if __name__ == "__main__":
  unittest.main()
