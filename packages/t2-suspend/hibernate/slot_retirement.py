"""Injected retirement of exactly two archived PRODUCT-cycle reusable slots.

No CLI, EFI backend, host sampler or power operation exists. All destructive
behavior is explicitly supplied by a trusted compare-and-delete callback. Only
the fixed V3 source and V2 restore slots can reach that callback. Vector-bound
witnesses, consumed guards/attempts and historical experiment evidence remain
outside its scope. This adapter establishes neither qualification nor authority
to clear the historical v16 slots on this machine.

A genuine process crash may resume an archived/released cycle using exact durable
journals. A missing slot is accepted only after its confirmed-absent journal was
durable. Uncertain deletion and preterminal failures block further cycles; no
automatic reconciliation of ambiguous deletion is available. Removing the owned
unresolved sentinel happens only after durable reconciliation. A subsequent
sentinel-cleanup fsync error is reported separately: a surviving sentinel blocks,
while its absence permits allocation only with the validated terminal chain.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


ARCHIVE = _module("retirement_archive", "evidence_archive.py")
CONTINUITY = _module("retirement_continuity", "continuity.py")
TX = ARCHIVE.TX
PROTOCOL = "omarchy-t2-product-slot-retirement-v1"
HEALTH_SCHEMA = "omarchy-t2-product-slot-retirement-health-v1"
SLOTS = {"source": CONTINUITY.SOURCE_VARIABLE, "restore": CONTINUITY.RESTORE_VARIABLE}


def _decode(raw):
  return json.loads(raw, object_pairs_hook=TX.no_duplicates,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite retirement JSON")))


def _exists(ledger, name):
  path = ledger.directory / name
  return path.exists() or path.is_symlink()


def _exact_journal(ledger, name, expected):
  if _exists(ledger, name):
    CONTINUITY.exact(ledger._read(name), expected, "Durable retirement journal")
    _sync_existing_journal(ledger, name)
  else:
    ledger._write(name, expected, exclusive=True)
  return TX.digest(expected)


def _sync_existing_journal(ledger, name):
  # A process can crash after complete bytes became visible but before their
  # fsync finished. Re-establish durability before relying on a resumed journal.
  fd = os.open(ledger.directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
      raise ValueError("Unsafe existing retirement journal")
    os.fsync(fd)
  finally:
    os.close(fd)
  ledger._sync()


def _archived_evidence(directory, cycle):
  receipt = ARCHIVE.verify_archive(directory, cycle, cycle["archive_evidence_sha256"])
  parent = ARCHIVE._open_parent(directory)
  child = None
  evidence = {}
  try:
    child = ARCHIVE._open_child(parent, cycle["cycle_id"])
    for name in ARCHIVE.REQUIRED_NAMES:
      raw = ARCHIVE._read_private(child, name)
      CONTINUITY.exact(CONTINUITY.raw_digest(raw), receipt["files"][name]["sha256"], "Verified archived bytes")
      evidence[name] = raw
  finally:
    if child is not None:
      ARCHIVE.os.close(child)
    ARCHIVE.os.close(parent)
  CONTINUITY.exact(ARCHIVE.verify_archive(directory, cycle, cycle["archive_evidence_sha256"]), receipt,
                   "Archive changed while reading retirement evidence")
  witness = _decode(evidence["source-return-witness.bin"])
  CONTINUITY.fields(witness, ("proof", "capture", "cleanup_health"), "Archived source witness")
  proof = witness["proof"]
  for key, expected in (("schema", CONTINUITY.SCHEMA), ("classification", "conditional-original-process-cycle-return"),
                        ("post_cleanup_health_valid", True), ("hardware_qualified", False),
                        ("physical_input_confirmed", False), ("usable_hibernation_qualified", False)):
    CONTINUITY.exact(proof[key], expected, "Archived proof " + key)
  binding = ARCHIVE.cycle_binding(cycle)
  original_binding = proof["binding"]
  for key in CONTINUITY.BINDING_KEYS:
    CONTINUITY.exact(original_binding[key], cycle[key], "Archived original-cycle binding")
  CONTINUITY.exact(witness["capture"]["binding"], original_binding, "Archived capture binding")
  CONTINUITY.exact(witness["cleanup_health"], _decode(evidence["cleanup-health.bin"]), "Archived cleanup health bytes")
  CONTINUITY.exact(witness["cleanup_health"]["binding"], original_binding, "Archived health binding")
  CONTINUITY.consumed_records(cycle, evidence["consumed-guard.bin"], evidence["consumed-attempt.bin"])
  for name, field in (("consumed-guard.bin", "consumed_guard"), ("consumed-attempt.bin", "consumed_attempt")):
    CONTINUITY.exact(witness["capture"][field], {"raw_hex": evidence[name].hex()}, "Archived consumed raw bytes")
  prefix = cycle["prefix"]
  expected = {"source-stage.bin": b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04",
              "restore-stage.bin": b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07",
              "restore-hook-entered.bin": b"\x07\0\0\0MBRH" + prefix.encode() + b"\x01",
              "restore-hook-armed.bin": b"\x07\0\0\0MBRH" + prefix.encode() + b"\x02"}
  marker_names = {"source-stage.bin": SLOTS["source"], "restore-stage.bin": SLOTS["restore"],
                  "restore-hook-entered.bin": "OmarchyT2RestoreHookEntered" + prefix + "-" + CONTINUITY.GUID,
                  "restore-hook-armed.bin": "OmarchyT2RestoreHookArmed" + prefix + "-" + CONTINUITY.GUID}
  CONTINUITY.fields(witness["capture"]["markers"], marker_names.values(), "Archived exact marker names")
  for name, raw in expected.items():
    CONTINUITY.exact(evidence[name], raw, "Archived product marker raw bytes")
    CONTINUITY.exact(witness["capture"]["markers"][marker_names[name]], {"raw_hex": raw.hex()}, "Witness marker raw bytes")
  baseline = CONTINUITY.pm_value(witness["cleanup_health"]["pm"])
  return binding, expected, baseline


def _health_expected(binding, baseline):
  return {"schema": HEALTH_SCHEMA, "binding": binding, "boot_id": binding["original_boot_id"],
          "after_slot_retirement": True,
          "devices": {"primary_encrypted_root": True, "internal_keyboard": True, "internal_trackpad": True,
                      "wifi": True, "bluetooth": True, "ac_online": True},
          "services": {"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"},
          "failed_units": [], "pm": baseline}


def retire(ledger, cycle, archive_directory, *, read_slot, compare_delete_slot, health):
  """Retire an archived product cycle under the existing ledger lock.

  ``read_slot(name)`` returns exact raw bytes or None. ``compare_delete_slot``
  receives (fixed_name, expected_raw_bytes) and must atomically compare/delete,
  returning literal True only after deletion. Health receives copied binding.
  The ledger release/reconciliation hashes are computed here from verified
  archive, absence journals and health, never supplied by the caller.
  """
  cycle = copy.deepcopy(TX.cycle_value(cycle))
  if cycle["state"] not in ("archived", "released"):
    raise ValueError("Retirement requires archived product cycle or journaled release")
  cycle_id = cycle["cycle_id"]
  stem = "slot-retirement-" + cycle_id
  def execute(advance):
    phase = "verify-archive"
    try:
      binding, expected, baseline = _archived_evidence(archive_directory, cycle)
      intent = {"schema": PROTOCOL, "state": "intent", "binding": binding,
                "archive_sha256": cycle["archive_evidence_sha256"],
                "slots": {SLOTS[role]: CONTINUITY.raw_digest(expected[role + "-stage.bin"]) for role in SLOTS}}
      intent_name = stem + "-intent.json"
      if cycle["state"] == "released" and not _exists(ledger, intent_name):
        raise ValueError("Released cycle lacks durable retirement intent")
      phase = "intent"
      intent_hash = _exact_journal(ledger, intent_name, intent)
      sentinel_name = stem + "-unresolved.json"
      sentinel = {"schema": PROTOCOL, "state": "unresolved", "binding": binding, "intent_sha256": intent_hash}
      phase = "unresolved-sentinel"
      _exact_journal(ledger, sentinel_name, sentinel)
      # Inspect both slots before the first destructive callback. A foreign
      # second slot must not cause a partial retirement of the first one.
      phase = "preflight-both-slots"
      for role, name in SLOTS.items():
        confirmed_name = stem + "-" + role + "-confirmed.json"
        clear_intent = {"schema": PROTOCOL, "state": "clear-intent", "intent_sha256": intent_hash,
                        "slot": name, "expected_sha256": CONTINUITY.raw_digest(expected[role + "-stage.bin"])}
        clear_name = stem + "-" + role + "-clear-intent.json"
        if _exists(ledger, clear_name):
          _exact_journal(ledger, clear_name, clear_intent)
        if _exists(ledger, confirmed_name):
          confirmed = {"schema": PROTOCOL, "state": "confirmed-absent", "intent_sha256": intent_hash,
                       "clear_intent_sha256": TX.digest(clear_intent), "slot": name,
                       "expected_sha256": CONTINUITY.raw_digest(expected[role + "-stage.bin"])}
          CONTINUITY.exact(ledger._read(stem + "-" + role + "-clear-intent.json"), clear_intent,
                           "Preflight preceding clear intent")
          _exact_journal(ledger, confirmed_name, confirmed)
          CONTINUITY.exact(read_slot(name), None, "Journaled slot absent at preflight")
        else:
          CONTINUITY.exact(read_slot(name), expected[role + "-stage.bin"], "Both exact product slots at preflight")
      confirmations = {}
      for role, name in SLOTS.items():
        raw = expected[role + "-stage.bin"]
        clear_intent = {"schema": PROTOCOL, "state": "clear-intent", "intent_sha256": intent_hash,
                        "slot": name, "expected_sha256": CONTINUITY.raw_digest(raw)}
        clear_name = stem + "-" + role + "-clear-intent.json"
        confirmed_name = stem + "-" + role + "-confirmed.json"
        confirmed = {"schema": PROTOCOL, "state": "confirmed-absent", "intent_sha256": intent_hash,
                     "clear_intent_sha256": TX.digest(clear_intent), "slot": name,
                     "expected_sha256": CONTINUITY.raw_digest(raw)}
        phase = "inspect-" + role
        if _exists(ledger, confirmed_name):
          if not _exists(ledger, clear_name):
            raise ValueError("Confirmed absence lacks preceding clear intent")
          _exact_journal(ledger, clear_name, clear_intent)
          _exact_journal(ledger, confirmed_name, confirmed)
          CONTINUITY.exact(read_slot(name), None, "Previously confirmed slot remains absent")
        else:
          if cycle["state"] == "released":
            raise ValueError("Released cycle lacks confirmed slot retirement")
          # Verify raw bytes before writing intent and again immediately before
          # the injected atomic compare/delete. Missing without confirmation is
          # an ambiguous interrupted deletion, never permission to continue.
          CONTINUITY.exact(read_slot(name), raw, "Exact reusable product slot")
          _exact_journal(ledger, clear_name, clear_intent)
          CONTINUITY.exact(read_slot(name), raw, "Slot bytes immediately before deletion")
          phase = "delete-" + role
          CONTINUITY.exact(compare_delete_slot(name, raw), True, "Atomic exact slot deletion")
          CONTINUITY.exact(read_slot(name), None, "Deleted slot readback")
          phase = "confirm-" + role
          ledger._write(confirmed_name, confirmed, exclusive=True)
        confirmations[name] = TX.digest(confirmed)
      phase = "health-before-release"
      for name in SLOTS.values():
        CONTINUITY.exact(read_slot(name), None, "Both reusable slots absent")
      sampled_health = health(copy.deepcopy(binding))
      CONTINUITY.exact(sampled_health, _health_expected(binding, baseline), "Healthy post-retirement source")
      completion = {"schema": PROTOCOL, "state": "complete", "binding": binding,
                    "intent_sha256": intent_hash, "confirmed_slots": confirmations,
                    "health": copy.deepcopy(sampled_health)}
      completion_name = stem + "-complete.json"
      if cycle["state"] == "released" and not _exists(ledger, completion_name):
        raise ValueError("Released cycle lacks durable retirement completion")
      phase = "completion"
      completion_hash = _exact_journal(ledger, completion_name, completion)
      ARCHIVE.verify_archive(archive_directory, cycle, cycle["archive_evidence_sha256"])
      if cycle["state"] == "released":
        CONTINUITY.exact(cycle["release_evidence_sha256"], completion_hash, "Journaled ledger release")
      else:
        phase = "release"
        advance("release", completion_hash)
      phase = "health-before-reconcile"
      for name in SLOTS.values():
        CONTINUITY.exact(read_slot(name), None, "Slots remain absent before reconciliation")
      final_health = health(copy.deepcopy(binding))
      CONTINUITY.exact(final_health, _health_expected(binding, baseline), "Healthy source before reconciliation")
      reconciliation = {"schema": PROTOCOL, "state": "reconciled", "binding": binding,
                        "completion_sha256": completion_hash, "health": copy.deepcopy(final_health)}
      phase = "reconciliation"
      reconciliation_hash = _exact_journal(ledger, stem + "-reconcile.json", reconciliation)
      ARCHIVE.verify_archive(archive_directory, cycle, cycle["archive_evidence_sha256"])
      reconciled = advance("reconcile", reconciliation_hash)
      # The successful advance has fsynced the reconciliation record and its
      # directory. Never remove the durable blocker before that return.
      CONTINUITY.exact(ledger._read(sentinel_name), sentinel, "Owned unresolved retirement sentinel")
      sentinel_cleanup_error = None
      try:
        (ledger.directory / sentinel_name).unlink()
        ledger._sync()
      except OSError as cleanup_error:
        # Terminal reconciliation is already durable. A surviving/reappearing
        # blocker refuses allocation; if absent, Ledger.begin verifies the full
        # terminal receipt chain rather than treating cleanup failure as proof.
        sentinel_cleanup_error = type(cleanup_error).__name__
      return {"cycle": reconciled, "completion_sha256": completion_hash,
              "reconciliation_sha256": reconciliation_hash, "cleared_slots": list(SLOTS.values()),
              "sentinel_cleanup_error": sentinel_cleanup_error,
              "hardware_qualified": False, "usable_hibernation_qualified": False}
    except BaseException as error:
      failure = {"schema": PROTOCOL, "state": "ambiguous", "cycle_id": cycle_id,
                 "phase": phase, "error_type": type(error).__name__}
      try:
        ledger._write(stem + "-failure.json", failure, exclusive=True)
      except BaseException as persistence_error:
        error.add_note("Retirement failure journal could not persist: " + type(persistence_error).__name__)
      try:
        advance("ambiguous", TX.digest(failure))
      except BaseException as latch_error:
        error.add_note("Retirement latch could not persist; cycle remains incomplete: " + type(latch_error).__name__)
        # A failed fsync after publishing reconciliation can leave a new record
        # visible while the compare-and-run closure retains its older snapshot.
        # Independently invalidate qualification under the same held lock, so
        # that stale advancement or an immutable terminal record cannot permit
        # another cycle after this failed transaction.
        try:
          state = ledger._state()
          state["blocked"] = True
          state["qualification"] = None
          ledger._write("state.json", state)
        except BaseException as block_error:
          error.add_note("Retirement qualification block also failed: " + type(block_error).__name__)
      raise
  return ledger.compare_and_run(cycle, execute)
