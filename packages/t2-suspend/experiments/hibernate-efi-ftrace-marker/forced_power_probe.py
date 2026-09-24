#!/usr/bin/python3
"""One-use EFI persistence probe intended for an operator-forced power cut.

The software cannot prove how power was removed. The return record establishes
only exact-value persistence across a different stock boot; journal and operator
evidence must separately establish the forced-power recovery path.
"""

import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("t2_forced_power_persistence_core", HERE / "persistence_probe.py")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)

# A new GUID and state directory are essential: the earlier disposable
# persistence vector has been consumed and must never be reused.
CORE.VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2ForcedPowerProbe-6d9b1274-1196-4b45-94ee-04ab5331c92d")
CORE.STATE = Path("var/lib/omarchy-t2-forced-power-probe")
CORE.MAGIC = b"MBFP"
INTENT = CORE.STATE / "forced-power-intent.json"


def arm(root, *, allow_live=False, operator_attended=False):
  root = Path(root)
  if not operator_attended:
    raise ValueError("Forced-power probe requires an attending operator")
  result = CORE.arm(root, allow_live=allow_live)
  CORE.atomic_new_json(root / INTENT, {
    "kind": "forced-power-efi-probe-intent-v1",
    "source_boot_id": result["source_boot_id"],
    "value_sha256": result["value_sha256"],
    "requested_method": "physical-power-button-long-press",
    "operator_attended": True,
    "software_cannot_verify_power_cut": True,
  })
  return result


def require_intent(root):
  root = Path(root)
  intent = CORE.load_json(root / INTENT, root)
  armed = CORE.load_json(root / CORE.STATE / "armed.json", root)
  if (intent.get("kind") != "forced-power-efi-probe-intent-v1" or
      intent.get("source_boot_id") != armed.get("source_boot_id") or
      intent.get("value_sha256") != armed.get("value_sha256") or
      intent.get("requested_method") != "physical-power-button-long-press" or
      intent.get("operator_attended") is not True or
      intent.get("software_cannot_verify_power_cut") is not True):
    raise ValueError("Forced-power intent differs from exact armed EFI value")
  return intent


def verify(root, *, allow_live=False):
  require_intent(root)
  result = CORE.verify(Path(root), allow_live=allow_live)
  return {**result, "power_cut_proven_by_software": False}


def clear(root, *, allow_live=False):
  require_intent(root)
  return CORE.clear(Path(root), allow_live=allow_live)
