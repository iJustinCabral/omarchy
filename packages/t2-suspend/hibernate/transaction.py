"""Offline product-cycle ledger; never performs EFI, module or PM operations.

An external reviewer supplies qualification receipts. This module validates their
binding, not hardware evidence. Existing experimental guards are never imported.
Outcome hashes are caller-supplied attestations, not authenticated return proof.
The local archive stores metadata and binds an external archive receipt hash; it
does not collect or verify the raw EFI/PM originals behind that receipt.
The caller must give a synthetic/dedicated ledger directory, never the host root.
Ordinary boot verification remains separate: restored EFI selection is restore ID.
"""

import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


PROTOCOL = "omarchy-t2-product-cycle-v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
PINS = ("source_sha256", "restore_sha256", "runtime_sha256", "linux_sha256", "cmdline_sha256")


def digest(value):
  return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hash_value(value):
  if not isinstance(value, str) or not HASH.fullmatch(value):
    raise ValueError("Invalid SHA-256 identity")
  return value


def uuid_value(value):
  if not isinstance(value, str) or str(uuid.UUID(value)) != value:
    raise ValueError("Invalid canonical UUID")
  return value


def manifest_value(value):
  if not isinstance(value, dict) or set(value) != {"protocol", "model", *PINS}:
    raise ValueError("Manifest fields differ")
  if value["protocol"] != PROTOCOL or value["model"] != "MacBookAir9,1":
    raise ValueError("Unsupported product protocol/model")
  for key in PINS:
    hash_value(value[key])
  if value["source_sha256"] == value["restore_sha256"]:
    raise ValueError("Source and restore must differ")
  return dict(value)


def qualification_vector(manifest):
  value = manifest_value(manifest)
  return hashlib.sha256(":".join(value[key] for key in PINS[:3]).encode()).hexdigest()


def receipt_value(value, manifest):
  if not isinstance(value, dict) or set(value) != {"protocol", "manifest_sha256", "evidence_sha256", "qualified"}:
    raise ValueError("Qualification receipt fields differ")
  if value["protocol"] != PROTOCOL or value["qualified"] is not True or value["manifest_sha256"] != digest(manifest):
    raise ValueError("Qualification is not bound to this product manifest")
  hash_value(value["evidence_sha256"])
  return dict(value)


def no_duplicates(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ValueError("Duplicate JSON key")
    result[key] = value
  return result


def cycle_value(record):
  required = {"protocol", "cycle_id", "original_boot_id", "manifest", "qualification_sha256",
              "qualification_vector", "vector", "prefix", "state"}
  actions = ("prepared", "returned", "archive", "release", "reconcile", "failed", "ambiguous")
  allowed = required | {action + "_evidence_sha256" for action in actions} | {"archive_sha256"}
  if not isinstance(record, dict) or not required <= set(record) <= allowed:
    raise ValueError("Malformed cycle record")
  if record["protocol"] != PROTOCOL:
    raise ValueError("Foreign cycle protocol")
  uuid_value(record["cycle_id"])
  uuid_value(record["original_boot_id"])
  manifest_value(record["manifest"])
  hash_value(record["qualification_sha256"])
  identity = {key: record[key] for key in ("protocol", "cycle_id", "original_boot_id", "manifest", "qualification_sha256")}
  if (record["vector"] != digest(identity) or record["prefix"] != record["vector"][:24] or
      record["qualification_vector"] != qualification_vector(record["manifest"])):
    raise ValueError("Cycle identity differs")
  order = ("reserved", "prepared", "returned", "archived", "released", "reconciled")
  if record["state"] not in (*order, "failed", "ambiguous"):
    raise ValueError("Unknown cycle state")
  for key in set(record) - required:
    hash_value(record[key])
  if record["state"] in order:
    needed = ("prepared", "returned", "archive", "release", "reconcile")[:order.index(record["state"])]
    if any(action + "_evidence_sha256" not in record for action in needed):
      raise ValueError("Cycle lacks completion receipts")
    if record["state"] in ("archived", "released", "reconciled") and "archive_sha256" not in record:
      raise ValueError("Cycle lacks archive binding")
  return record


class Ledger:
  def __init__(self, directory):
    self.directory = Path(directory).absolute()
    if self.directory == Path("/") or self.directory.is_symlink():
      raise ValueError("Dedicated ledger directory required")
    self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for component in (self.directory, *self.directory.parents):
      if component.is_symlink():
        raise ValueError("Symlinked ledger ancestor")
    self._private(self.directory, directory=True)

  def _private(self, path, directory=False):
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
      raise ValueError("Unsafe ledger owner/mode")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
      raise ValueError("Unexpected ledger file type")

  @contextlib.contextmanager
  def _lock(self):
    path = self.directory / "lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
      self._private(path)
      fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      if any(item.name.startswith(".pending-") for item in self.directory.iterdir()):
        raise ValueError("Incomplete durable write requires reconciliation")
      yield
    finally:
      os.close(fd)

  def _sync(self):
    fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
      os.fsync(fd)
    finally:
      os.close(fd)

  def _read(self, name):
    path = self.directory / name
    self._private(path)
    return json.loads(path.read_text(), object_pairs_hook=no_duplicates)

  def _write(self, name, value, exclusive=False):
    path = self.directory / name
    if exclusive:
      fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
      with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    else:
      temporary = self.directory / (".pending-" + str(uuid.uuid4()))
      self._write(temporary.name, value, exclusive=True)
      if path.exists() or path.is_symlink():
        self._private(path)
      os.replace(temporary, path)
    self._sync()

  def _state(self):
    value = self._read("state.json")
    if not isinstance(value, dict) or set(value) != {"manifest", "qualification", "blocked"} or type(value["blocked"]) is not bool:
      raise ValueError("Malformed ledger state")
    manifest_value(value["manifest"])
    if value["qualification"] is not None:
      receipt_value(value["qualification"], value["manifest"])
    return value

  def configure(self, manifest):
    manifest = manifest_value(manifest)
    with self._lock():
      state_path = self.directory / "state.json"
      if state_path.exists() or state_path.is_symlink():
        state = self._state()
        if state["manifest"] != manifest:
          state["manifest"] = manifest
          state["qualification"] = None
      else:
        state = {"manifest": manifest, "qualification": None, "blocked": False}
      self._write("state.json", state)

  def qualify(self, receipt):
    """Record externally reviewed evidence; this does not qualify hardware itself."""
    with self._lock():
      state = self._state()
      if state["blocked"]:
        raise ValueError("Failure blocks qualification; external reconciliation required")
      state["qualification"] = receipt_value(receipt, state["manifest"])
      self._write("state.json", state)

  def _cycles(self):
    if any(path.name.startswith(".pending-") for path in self.directory.iterdir()):
      raise ValueError("Incomplete durable write requires reconciliation")
    result = []
    for path in self.directory.glob("cycle-*.json"):
      record = cycle_value(self._read(path.name))
      if path.name != "cycle-" + record["cycle_id"] + ".json":
        raise ValueError("Cycle filename differs")
      result.append(record)
    return result

  def begin(self, original_boot_id, cycle_id=None):
    original_boot_id = uuid_value(original_boot_id)
    cycle_id = uuid_value(cycle_id or str(uuid.uuid4()))
    with self._lock():
      state = self._state()
      if state["blocked"] or state["qualification"] is None:
        raise ValueError("Product is not qualified or is failure-blocked")
      if any(self.directory.glob("slot-retirement-*-unresolved.json")):
        raise ValueError("Unresolved retirement blocks new cycle allocation")
      cycles = self._cycles()
      if any(record.get("state") != "reconciled" for record in cycles):
        raise ValueError("A previous cycle is active, failed or unreconciled")
      self._retirement_completions(cycles)
      identity = {"protocol": PROTOCOL, "cycle_id": cycle_id, "original_boot_id": original_boot_id,
                  "manifest": state["manifest"], "qualification_sha256": digest(state["qualification"])}
      vector = digest(identity)
      if any(record.get("prefix") == vector[:24] for record in cycles):
        raise ValueError("Cycle prefix is already reserved")
      record = {**identity, "qualification_vector": qualification_vector(state["manifest"]),
                "vector": vector, "prefix": vector[:24], "state": "reserved"}
      self._write("cycle-" + cycle_id + ".json", record, exclusive=True)
      return record

  def _retirement_completions(self, cycles):
    """Verify the terminal journal chain after an owned blocker was removed.

    The retirement adapter removes its unresolved sentinel only after successful
    reconciliation file/directory fsync. If removal's directory fsync fails,
    either the sentinel survives/reappears and blocks, or these already durable
    terminal receipts prove reconciliation. This does not authenticate hardware.
    """
    records = {cycle["cycle_id"]: cycle for cycle in cycles}
    protocol = "omarchy-t2-product-slot-retirement-v1"
    for path in self.directory.glob("slot-retirement-*-intent.json"):
      # Per-slot clear intents do not describe the transaction as a whole.
      identity = path.name[len("slot-retirement-"):-len("-intent.json")]
      if identity.endswith(("-source-clear", "-restore-clear")):
        continue
      uuid_value(identity)
      cycle = records.get(identity)
      if cycle is None or cycle["state"] != "reconciled":
        raise ValueError("Retirement intent lacks reconciled cycle")
      stem = "slot-retirement-" + identity
      intent = self._read(stem + "-intent.json")
      completion = self._read(stem + "-complete.json")
      reconciliation = self._read(stem + "-reconcile.json")
      binding = {key: cycle[key] for key in ("protocol", "cycle_id", "original_boot_id", "manifest", "qualification_sha256",
                                           "qualification_vector", "vector", "prefix", "returned_evidence_sha256")}
      if any(type(item) is not dict or item.get("schema") != protocol or item.get("binding") != binding
             for item in (intent, completion, reconciliation)):
        raise ValueError("Retirement terminal binding differs")
      if intent.get("state") != "intent" or completion.get("state") != "complete" or reconciliation.get("state") != "reconciled":
        raise ValueError("Retirement terminal state differs")
      if (intent.get("archive_sha256") != cycle["archive_evidence_sha256"] or
          completion.get("intent_sha256") != digest(intent) or reconciliation.get("completion_sha256") != digest(completion) or
          cycle["release_evidence_sha256"] != digest(completion) or cycle["reconcile_evidence_sha256"] != digest(reconciliation)):
        raise ValueError("Retirement terminal receipt chain differs")

  def advance(self, cycle_id, action, evidence_sha256):
    """Record abstract outcomes; slot-release only records permission, never writes EFI."""
    cycle_id = uuid_value(cycle_id)
    hash_value(evidence_sha256)
    with self._lock():
      return self._advance_locked(cycle_id, action, evidence_sha256)

  def compare_and_run(self, expected, callback):
    """Run a bounded adapter under one lock with exact compare-and-advance.

    Callbacks are trusted code, not serialized proposals. A process crash leaves
    its current incomplete cycle blocking future allocation. No PM is supplied.
    """
    expected = copy.deepcopy(cycle_value(expected))
    with self._lock():
      current = self._read("cycle-" + expected["cycle_id"] + ".json")
      if digest(current) != digest(expected):
        raise ValueError("Adapter cycle snapshot is stale")
      state = self._state()
      if state["blocked"] or state["qualification"] is None or state["manifest"] != expected["manifest"] or digest(state["qualification"]) != expected["qualification_sha256"]:
        raise ValueError("Adapter qualification changed")
      active = True
      def advance(action, evidence_sha256):
        nonlocal current
        if not active or digest(self._read("cycle-" + current["cycle_id"] + ".json")) != digest(current):
          raise ValueError("Adapter lock scope ended or cycle changed")
        current = self._advance_locked(current["cycle_id"], action, evidence_sha256)
        return copy.deepcopy(current)
      try:
        return callback(advance)
      finally:
        active = False

  def _advance_locked(self, cycle_id, action, evidence_sha256):
    uuid_value(cycle_id)
    hash_value(evidence_sha256)
    transitions = {"prepared": "reserved", "returned": "prepared", "archive": "returned",
                   "release": "archived", "reconcile": "released"}
    state = self._state()
    name = "cycle-" + cycle_id + ".json"
    record = cycle_value(self._read(name))
    if record["cycle_id"] != cycle_id:
      raise ValueError("Cycle filename differs")
    if record.get("manifest") != state["manifest"] or record.get("qualification_sha256") != digest(state["qualification"]):
      raise ValueError("Cycle qualification changed")
    if action in ("failed", "ambiguous"):
      if record.get("state") == "reconciled":
        raise ValueError("Reconciled cycle is immutable")
      state["blocked"] = True
      state["qualification"] = None
      self._write("state.json", state)
      record["state"] = action
    else:
      if state["blocked"] or action not in transitions or record.get("state") != transitions[action]:
        raise ValueError("Invalid cycle transition")
      if action == "archive":
        record["archive_evidence_sha256"] = evidence_sha256
        self._write("archive-" + cycle_id + ".json", record, exclusive=True)
        record["archive_sha256"] = digest(record)
      if action in ("release", "reconcile"):
        archived = cycle_value(self._read("archive-" + cycle_id + ".json"))
        if archived["state"] != "returned" or archived["cycle_id"] != cycle_id or digest(archived) != record.get("archive_sha256"):
          raise ValueError("Archive changed; reusable slots remain blocked")
      record["state"] = {"archive": "archived", "release": "released", "reconcile": "reconciled"}.get(action, action)
    record[action + "_evidence_sha256"] = evidence_sha256
    self._write(name, record)
    return record
