"""One separately authorized archival completion for the known returned trial.

No CLI, power, preparation, allocation or slot deletion exists here. The caller
holds the fixed global physical-cycle lock. Original failed bytes and guards are
preserved. A durable .pending-* sentinel blocks every normal ledger API until
the same cycle is archived with its original qualified=false trial authority.
Any interrupted recovery refuses repetition; it requires independent review.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


TX = _module("post_return_transaction", "transaction.py")
RETIREMENT = _module("post_return_retirement", "slot_retirement.py")
CT = RETIREMENT.CONTINUITY
ARCHIVE = RETIREMENT.ARCHIVE
HOST = _module("post_return_observation", "host_observation.py")
SCHEMA = "omarchy-t2-known-post-return-archive-recovery-v1"
CYCLE = "d8923d12-7794-483f-8746-91face7e2ab9"
BOOT = "b795a460-bf57-4ff6-84b7-4ebc415a9350"
VECTOR = "8946b182fa68d358ce5efc50091c3f17189e276ef847bab054f1d0278241a67e"
STATE = Path("/var/lib/omarchy/t2-hibernate-trial")
STEM = "post-return-recovery-" + CYCLE
SENTINEL = ".pending-" + STEM
CODE = ("post_return_reconcile.py", "transaction.py", "evidence_archive.py", "slot_retirement.py")
KNOWN_PINS = {
  "failed_cycle": "d1cb311793ef0cd94b642a8bbaa7f525357a355ee46ba32249141649c288c3e2",
  "failed_state": "49b739a210eb495c2cf43d16a356812026457bc0ccc12f08c12d11844bec7618",
  "authorization": "d7c033bf6cc954eb21ae270129e18fed9d2d567680e8efce75666f2c83538428",
  "consumed_trial_guard": "fb529b27e9c8507d05270c4b0414c8bd4cbcdbaa42676de4a24370ac502cf2a4",
  "failure_journal": "dd517a3ea170856946d0f3406082ff4a0e6f65e94f52d0563ac4771c4fe53194",
  "preparation_receipt": "d5fa70f99eb199f2bfd4fb112360bbe9eff0b1d6a0aad072a144f12f933e97a3",
  "archive_completion": "c08fd4c135441016f4558abe2a8f9a29c21882d96f5ada55e27c8e7e529ca87a",
}


def _hash(raw):
  return hashlib.sha256(raw).hexdigest()


def _json(raw):
  return json.loads(raw, object_pairs_hook=TX.no_duplicates)


def _code_hash(name):
  return _hash(Path(__file__).with_name(name).read_bytes())


def _preserve(ledger, name, raw):
  fd = os.open(ledger.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  ledger._sync()
  CT.exact(HOST._raw(ledger.directory / name, private=True), raw, "Preserved original bytes")


def reconcile_archive(ledger, *, root, recovery_receipt, authorization_file, guard_file,
                      preparation_file, archive_directory):
  """Finish only verified archival; existing retirement remains a separate step.

  All paths are explicit. Live root requires the fixed private deployment paths
  and root identity. Synthetic roots are solely for offline regression tests.
  No bypass of ledger locks, .pending blockers or failure guards is provided.
  """
  root = Path(root)
  paths = {"receipt": Path(recovery_receipt), "authorization": Path(authorization_file),
           "guard": Path(guard_file), "preparation": Path(preparation_file), "archive": Path(archive_directory)}
  if not root.is_absolute() or any(not path.is_absolute() for path in paths.values()):
    raise ValueError("Explicit absolute recovery paths required")
  if root == Path("/"):
    if os.geteuid() != 0: raise ValueError("Explicit root invocation required")
    expected = {"receipt": STATE / "post-return-recovery-authorization.json", "authorization": STATE / "authorization.json",
                "guard": STATE / "guards/trial-consumed.json",
                "preparation": STATE / ("ledger/preparation-" + CYCLE + "-complete.json"), "archive": STATE / "archives"}
    CT.exact(paths, expected, "Fixed live recovery paths")
    CT.exact(ledger.directory, STATE / "ledger", "Fixed live ledger")
  with ledger._lock():
    if any(item.name.startswith(STEM) for item in ledger.directory.iterdir()):
      raise ValueError("Post-return recovery already started")
    CT.exact(HOST._raw(root / "proc/sys/kernel/random/boot_id").decode().strip(), BOOT, "Known original source boot")
    receipt_raw = HOST._raw(paths["receipt"], private=True)
    receipt = _json(receipt_raw)
    CT.fields(receipt, ("schema", "accepted", "cycle_id", "original_boot_id", "vector", "pins", "implementation_sha256"), "Recovery authority")
    for name, value in (("schema", SCHEMA), ("accepted", True), ("cycle_id", CYCLE), ("original_boot_id", BOOT), ("vector", VECTOR)):
      CT.exact(receipt[name], value, "Known recovery authority " + name)
    CT.exact(receipt["pins"], KNOWN_PINS, "Independently reviewed known evidence pins")
    CT.fields(receipt["implementation_sha256"], CODE, "Reviewed recovery code")
    for name in CODE:
      CT.exact(_code_hash(name), TX.hash_value(receipt["implementation_sha256"][name]), "Reviewed exact implementation")
    raw = {
      "failed_cycle": HOST._raw(ledger.directory / ("cycle-" + CYCLE + ".json"), private=True),
      "failed_state": HOST._raw(ledger.directory / "state.json", private=True),
      "authorization": HOST._raw(paths["authorization"], private=True),
      "consumed_trial_guard": HOST._raw(paths["guard"], private=True),
      "failure_journal": HOST._raw(ledger.directory / ("workflow-failure-" + CYCLE + ".json"), private=True),
      "preparation_receipt": HOST._raw(paths["preparation"], private=True),
      "archive_completion": HOST._raw(paths["archive"] / ("cycle-" + CYCLE) / ARCHIVE.COMPLETION, private=True),
    }
    for name, data in raw.items():
      CT.exact(_hash(data), receipt["pins"][name], "Pinned recovery evidence " + name)
    failed = TX.cycle_value(_json(raw["failed_cycle"]))
    state = ledger._state()
    for name, value in (("cycle_id", CYCLE), ("original_boot_id", BOOT), ("vector", VECTOR), ("state", "failed")):
      CT.exact(failed[name], value, "Known failed cycle " + name)
    CT.exact(state["blocked"], True, "Existing failure latch")
    CT.exact(state["qualification"], None, "Existing revoked authority")
    CT.exact(state["manifest"], failed["manifest"], "Retained artifact manifest")
    CT.exact(ledger._allocation_head(ledger._cycles()), failed, "Exact latest allocated cycle")
    authority = TX.trial_value(_json(raw["authorization"]), failed["manifest"])
    CT.exact(TX.digest(authority), failed["qualification_sha256"], "Original false trial authority")
    guard = _json(raw["consumed_trial_guard"])
    CT.fields(guard, ("protocol", "authorization_sha256", "cycle"), "Retained consumed trial guard")
    CT.exact(guard["protocol"], TX.TRIAL_PROTOCOL, "Original trial protocol")
    CT.exact(guard["authorization_sha256"], TX.digest(authority), "Consumed authority")
    reserved = TX.cycle_value(guard["cycle"])
    CT.exact(reserved["state"], "reserved", "Original consumed reservation")
    for name in CT.BINDING_KEYS: CT.exact(reserved[name], failed[name], "Original guard cycle")
    failure = _json(raw["failure_journal"])
    CT.exact(TX.digest(failure), failed["failed_evidence_sha256"], "Original failure receipt")
    for name, value in (("schema", "omarchy-t2-product-workflow-failure-v1"), ("cycle_id", CYCLE),
                        ("phase", "creating-archive"), ("error_type", "ValueError")):
      CT.exact(failure[name], value, "Known post-return failure")
    CT.exact(failure["snapshot"]["cleanup_errors"], [], "Recorded successful cleanup")
    prep = _json(raw["preparation_receipt"])
    CT.exact(TX.digest(prep), failed["prepared_evidence_sha256"], "Completed preparation receipt")
    returned = copy.deepcopy(failed)
    returned["state"] = "returned"
    TX.cycle_value(returned)
    archive_hash = receipt["pins"]["archive_completion"]
    archived = {**returned, "state": "archived", "archive_evidence_sha256": archive_hash}
    archive_record = {**returned, "archive_evidence_sha256": archive_hash}
    archived["archive_sha256"] = TX.digest(archive_record)
    TX.cycle_value(archived)
    RETIREMENT._archived_evidence(paths["archive"], archived)
    archive_health = _json(HOST._raw(paths["archive"] / ("cycle-" + CYCLE) / "cleanup-health.bin", private=True))
    CT.exact(archive_health, failure["snapshot"]["cleanup_health"], "Failure snapshot agrees with archived health")
    for name in ("archive-" + CYCLE + ".json", SENTINEL):
      path = ledger.directory / name
      if path.exists() or path.is_symlink(): raise ValueError("Recovery destination already exists")
    intent = {"schema": SCHEMA, "recovery_authorization_sha256": _hash(receipt_raw), "pins": receipt["pins"],
              "implementation_sha256": receipt["implementation_sha256"], "archived_cycle_sha256": TX.digest(archived)}
    # Publish the blocker BEFORE preservation or changing either authoritative
    # record. Any caught error/crash thereafter leaves normal APIs blocked.
    ledger._write(SENTINEL, intent, exclusive=True)
    for name in ("failed_cycle", "failed_state"):
      _preserve(ledger, STEM + "-" + name + ".bin", raw[name])
    ledger._write(STEM + "-intent.json", intent, exclusive=True)
    ARCHIVE.verify_archive(paths["archive"], returned, archive_hash)
    ledger._write("archive-" + CYCLE + ".json", archive_record, exclusive=True)
    ledger._write("cycle-" + CYCLE + ".json", archived)
    restored_state = {**state, "qualification": authority, "blocked": False}
    ledger._write("state.json", restored_state)
    completion = {"schema": SCHEMA, "intent_sha256": TX.digest(intent), "archived_cycle_sha256": TX.digest(archived),
                  "restored_state_sha256": TX.digest(restored_state), "qualified": False, "slot_clear_authorized": False}
    ledger._write(STEM + "-complete.json", completion, exclusive=True)
    ARCHIVE.verify_archive(paths["archive"], archived, archive_hash)
    CT.exact(ledger._read("cycle-" + CYCLE + ".json"), archived, "Durable archived cycle")
    CT.exact(ledger._state(), restored_state, "Durable original trial authority")
    # A failed final directory fsync can resurrect the sentinel on crash, which
    # blocks. If absent, all terminal records above already completed fsync.
    os.unlink(ledger.directory / SENTINEL)
    ledger._sync()
    return {"cycle": archived, "recovery_receipt_sha256": _hash(receipt_raw), "qualified": False,
            "slot_clear_authorized": False, "power_write": False}
