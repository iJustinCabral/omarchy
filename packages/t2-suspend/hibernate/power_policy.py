"""Provisional attended battery admission, not measured endurance assurance.

The explicit 30..100 charge/full threshold is an engineering guard for attended
qualification. It is not a final automatic low-battery hibernation policy.
No power writes, unit conversion or percentage-only reserve fallback exists.
None selects the historical AC-only admission contract.
"""
import copy
import importlib.util
import math
from pathlib import Path

spec = importlib.util.spec_from_file_location("policy_power_supply", Path(__file__).with_name("power_supply.py"))
SUPPLY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SUPPLY)
SCHEMA = "omarchy-t2-attended-battery-policy-v1"


def validate(policy):
  if policy is None: return None
  if type(policy) is not dict or set(policy) != {"schema", "min_charge_percent"} or policy["schema"] != SCHEMA:
    raise ValueError("Explicit attended battery policy fields required")
  minimum = policy["min_charge_percent"]
  if type(minimum) is not int or not 30 <= minimum <= 100:
    raise ValueError("Provisional attended charge threshold must be integer 30..100")
  return copy.deepcopy(policy)


def decide(snapshot, policy=None):
  policy = validate(policy)
  if type(snapshot) is not dict or set(snapshot) != {"started_monotonic", "finished_monotonic", "ac_online", "supplies"} or type(snapshot["ac_online"]) is not bool or type(snapshot["supplies"]) is not list:
    raise ValueError("Valid power-supply snapshot required")
  start, finish = snapshot["started_monotonic"], snapshot["finished_monotonic"]
  if any(type(value) not in (int, float) or not math.isfinite(value) for value in (start, finish)) or not 0 <= finish - start <= 1:
    raise ValueError("Bounded monotonic power observation required")
  keys = {"name", "type", "present", "online", "status"} | {item[0] for item in SUPPLY._METRICS.values()}
  names = []
  for supply in snapshot["supplies"]:
    if type(supply) is not dict or set(supply) != keys or any(type(supply[key]) is not str or not supply[key] for key in ("name", "type")):
      raise ValueError("Exact power supply fields required")
    names.append(supply["name"])
    if any(supply[key] is not None and type(supply[key]) is not bool for key in ("present", "online")) or supply["status"] not in SUPPLY._STATUSES | {None}:
      raise ValueError("Strict power supply controls required")
    if supply["type"] == "Mains" and type(supply["online"]) is not bool:
      raise ValueError("Known mains observation required")
    for key, signed, minimum, maximum in SUPPLY._METRICS.values():
      value = supply[key]
      if value is not None and (type(value) is not int or (minimum is not None and value < minimum) or (maximum is not None and value > maximum)):
        raise ValueError("Malformed native power metric")
  if len(names) > 64 or names != sorted(set(names)) or snapshot["ac_online"] != any(supply["type"] == "Mains" and supply["online"] is True for supply in snapshot["supplies"]):
    raise ValueError("Inconsistent power supply inventory")
  if snapshot["ac_online"]:
    return {"source": "mains", "policy": "legacy-ac-only" if policy is None else SCHEMA}
  if policy is None: raise ValueError("Live AC required by legacy policy")
  batteries = [supply for supply in snapshot["supplies"] if supply["type"] == "Battery" and supply["present"] is True]
  if len(batteries) != 1: raise ValueError("Exactly one present battery required")
  battery = batteries[0]
  if battery["status"] not in ("Discharging", "Not charging", "Full"):
    raise ValueError("Known noncharging battery status required off mains")
  charge = (battery["charge_now_uah"], battery["charge_full_uah"])
  energy = (battery["energy_now_uwh"], battery["energy_full_uwh"])
  unit, values = ("charge_uah", charge) if any(value is not None for value in charge) else ("energy_uwh", energy)
  now, full = values
  if type(now) is not int or type(full) is not int or not 0 < now <= full:
    raise ValueError("Positive sane native charge/full or energy/full reserve required")
  minimum = policy["min_charge_percent"]
  if now * 100 < full * minimum: raise ValueError("Battery reserve below provisional attended threshold")
  return {"source": "battery", "policy": SCHEMA, "reserve_unit": unit,
          "reserve_now": now, "reserve_full": full, "min_charge_percent": minimum}


def observe(root, policy=None):
  """Retain the exact native-unit sample used for one admission decision."""
  snapshot = SUPPLY.sample_power_supply(root)
  return {"snapshot": snapshot, "decision": decide(snapshot, policy)}


def check(root, policy=None):
  return observe(root, policy)["decision"]
