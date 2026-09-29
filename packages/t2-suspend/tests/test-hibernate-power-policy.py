#!/usr/bin/python3
"""Pure provisional power decisions; no host power operation."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("tested_power_policy", Path(__file__).parents[1] / "hibernate/power_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PowerPolicy(unittest.TestCase):
  def setUp(self):
    self.policy = {"schema": policy.SCHEMA, "min_charge_percent": 30}
    self.battery = {"name": "BAT0", "type": "Battery", "present": True, "online": None, "status": "Discharging",
                    **{key: None for key, *_ in policy.SUPPLY._METRICS.values()}}
    self.battery.update(charge_now_uah=30, charge_full_uah=100)
    self.sample = {"started_monotonic": 1.0, "finished_monotonic": 1.1, "ac_online": False, "supplies": [self.battery]}

  def test_exact_threshold_native_charge_and_energy(self):
    self.assertEqual(policy.decide(self.sample, self.policy)["reserve_unit"], "charge_uah")
    self.battery.update(charge_now_uah=None, charge_full_uah=None, energy_now_uwh=30, energy_full_uwh=100)
    self.assertEqual(policy.decide(self.sample, self.policy)["reserve_unit"], "energy_uwh")

  def test_no_percentage_fallback_or_charge_energy_conversion(self):
    for change in ({"charge_now_uah": 29}, {"charge_now_uah": 101},
                   {"charge_now_uah": None, "capacity_percent": 99}, {"charge_full_uah": None, "energy_now_uwh": 90, "energy_full_uwh": 100},
                   {"status": "Unknown"}, {"present": False}):
      with self.subTest(change=change):
        battery = self.battery.copy()
        battery.update(change)
        with self.assertRaises(ValueError): policy.decide({**self.sample, "supplies": [battery]}, self.policy)

  def test_mains_valid_snapshot_admits_even_with_missing_battery_reserve(self):
    mains = {"name": "AC", "type": "Mains", "present": None, "online": True, "status": None,
             **{key: None for key, *_ in policy.SUPPLY._METRICS.values()}}
    battery = {**self.battery, "charge_now_uah": None, "charge_full_uah": None}
    sample = {**self.sample, "ac_online": True, "supplies": [mains, battery]}
    self.assertEqual(policy.decide(sample, self.policy)["source"], "mains")
    with self.assertRaises(ValueError): policy.decide(self.sample, None)

  def test_policy_requires_explicit_strict_threshold(self):
    for value in (None, True, 29, 101, 30.0, "30"):
      with self.subTest(value=value), self.assertRaises(ValueError):
        policy.validate({"schema": policy.SCHEMA, "min_charge_percent": value})
    with self.assertRaises(ValueError): policy.validate({**self.policy, "extra": True})

  def test_observe_retains_the_single_exact_native_sample_used_for_decision(self):
    with patch.object(policy.SUPPLY, "sample_power_supply", return_value=self.sample) as sample:
      observed = policy.observe(Path("/synthetic"), self.policy)
    sample.assert_called_once_with(Path("/synthetic"))
    self.assertIs(observed["snapshot"], self.sample)
    self.assertEqual(observed["decision"], policy.decide(self.sample, self.policy))


if __name__ == "__main__": unittest.main()
