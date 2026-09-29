"""Shared contract for the retired pair's receipt custody (stdlib only, no I/O).

The stager's retirement leaves two root-private files in the product state directory so the maintenance chain
(update guard, assess, rebind) keeps validating once the receipt file itself is gone: the exact retired receipt bytes and
a strict record chaining to their SHA-256. Both the stager and boot_policy_transition import these names and this one
validator; nothing else defines them.
"""
import hashlib
import json

RETIREMENT_SCHEMA = "omarchy-t2-pair-retirement-v1"
RETIREMENT_KEYS = {"protocol", "retired_receipt_sha256", "source_sha256", "restore_sha256"}
RETIREMENT_NAME = "pair-retirement.json"
RETIRED_RECEIPT_NAME = "pair-retired-receipt.json"
ROLES = ("source", "restore")


def digest(raw): return hashlib.sha256(raw).hexdigest()


def record(receipt_raw, receipt):
  """The exact custody record for a retired receipt (its image identities come from the receipt itself)."""
  return {"protocol": RETIREMENT_SCHEMA, "retired_receipt_sha256": digest(receipt_raw),
          **{role + "_sha256": receipt["images"][role]["sha256"] for role in ROLES}}


def record_bytes(receipt_raw, receipt):
  return (json.dumps(record(receipt_raw, receipt), indent=2, sort_keys=True) + "\n").encode()


def check(record_value, retained_raw):
  """Validate a parsed record against the retained receipt bytes, including the image identities the receipt names."""
  if type(record_value) is not dict or set(record_value) != RETIREMENT_KEYS or record_value["protocol"] != RETIREMENT_SCHEMA:
    raise ValueError("Exact pair retirement record required")
  for name in RETIREMENT_KEYS - {"protocol"}:
    if type(record_value[name]) is not str or len(record_value[name]) != 64 or any(c not in "0123456789abcdef" for c in record_value[name]):
      raise ValueError("Invalid pair retirement hash")
  if record_value["retired_receipt_sha256"] != digest(retained_raw): raise ValueError("Retained retired receipt differs from the maintenance receipt")
  try: receipt = json.loads(retained_raw)
  except ValueError as error: raise ValueError("Retained retired receipt is not JSON") from error
  images = receipt.get("images") if type(receipt) is dict else None
  if type(images) is not dict: raise ValueError("Retained retired receipt names no images")
  for role in ROLES:
    if type(images.get(role)) is not dict or images[role].get("sha256") != record_value[role + "_sha256"]:
      raise ValueError("Pair retirement record does not name the retired " + role + " image of the retained receipt")
