"""Source-default transition core; public API remains fixture-only.

Public transition() unconditionally refuses live `/` and aliases. Its injected
fixture precheck cannot establish real admission. The separate installed native
adapter supplies fixed host verification and real logind power exclusion to the
internal core, after reviewed snapshot verification. No kernel, EFI, modules,
power, qualification issuance or phase replay occurs here. Retained fixture
recovery retries only settlement/veto repair under the original exclusions.
Source tests and
installation alone do not approve or execute any native policy transition.
The maintenance action leaves a durable sleep/update veto but grants no
package admission. Its public fixture form refuses `/`. The live form exists only
inside the internal core and requires the private native capability plus the
native adapter's own verified gate; it has no runner, client or broker.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  value = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(value)
  return value


P = _module("transition_policy", "boot_policy.py")
D = _module("transition_snapshot", "runtime_deployment.py")
G = _module("transition_update_guard", "update_guard.py")
PRODUCT = _module("transition_product", "product.py")
CUSTODY = _module("transition_pair_custody", "pair_custody.py")
DB_LOCK = Path("var/lib/pacman/db.lck")
PHYSICAL_LOCK = Path("var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock")
REVIEW = P.STATE / "boot-policy-review.json"
OPT_IN = Path("etc/omarchy/t2-hibernate-product.enabled")
HOOK = Path("etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook")
HISTORY = P.STATE / "boot-policy-transitions"
PENDINGS = {action: P.STATE / ("source-default-" + action + ".pending") for action in ("activation", "deactivation")}
MAINTENANCE = P.STATE / "package-maintenance.pending"
MAINTENANCE_SCHEMA = "omarchy-t2-package-maintenance-intent-v1"
BASELINE_NAME = "generation-baseline.json"
BASELINE_SCHEMA = "omarchy-t2-generation-baseline-v1"
# Items the native provider must return; the engine adds "limine" itself from the
# exact stock bytes it retains, so the provider never sees or guesses them.
BASELINE_ITEMS = ("kernel", "production_uki", "source_uki", "restore_uki", "module_stack", "manifest", "config",
                  "qualification", "driver_modules", "firmware", "control_inventory", "bootloader")
RUNTIME_PENDINGS = (P.STATE / D.UPGRADE_PENDING, P.STATE / D.PENDING)
PRODUCTION = Path("boot/EFI/Linux/omarchy_linux-t2.efi")
MAX_UKI = 256 * 1024 * 1024
# Internal capability for the reviewed native adapter only. It is not security
# against hostile root; it keeps the public fixture API from naming live roots.
_NATIVE_MAINTENANCE = object()
GATE_PHASES = ("before", "after", "final", "retained")
# Reactivation reuses the runtime upgrade's barrier FILENAME (the installed guard and sleep entry veto it by
# presence) but a distinct protocol. Neither side may adopt the other's bytes: each recovery compares exact
# canonical bytes and its own protocol string, and each start refuses when the name exists.
REACTIVATION_SCHEMA = "omarchy-t2-package-reactivation-intent-v1"
REACTIVATION_COMPARISON = "omarchy-t2-package-reactivation-comparison-v1"
REACTIVATION_COMPLETE = "omarchy-t2-package-reactivation-complete-v1"
REACTIVATION_ROLLBACK = "omarchy-t2-package-reactivation-rollback-v1"
ROLLBACK_NAME = "rollback.json"
# New-generation rebind (docs/t2-suspend/REBIND-DESIGN.md). It reuses the activation-pending filename under its own
# protocol string, exactly as reactivation does; each recovery authenticates its own canonical bytes and never adopts another's.
REBIND_SCHEMA = "omarchy-t2-package-rebind-intent-v1"
REBIND_COMPARISON = "omarchy-t2-package-rebind-comparison-v1"
REBIND_COMPLETE = "omarchy-t2-package-rebind-complete-v1"
REBIND_ROLLBACK = "omarchy-t2-package-rebind-rollback-v1"
REBIND_BASELINE = "omarchy-t2-package-rebind-baseline-v1"
# Written by the pair stager's retire mode (the names and the validator live in pair_custody.py, shared with it).
RETIREMENT_SCHEMA = CUSTODY.RETIREMENT_SCHEMA
RETIREMENT_KEYS = CUSTODY.RETIREMENT_KEYS
RETIREMENT = P.STATE / CUSTODY.RETIREMENT_NAME
RETIRED_RECEIPT = P.STATE / CUSTODY.RETIRED_RECEIPT_NAME
PAIR_BACKUP = Path("var/lib/omarchy-t2-hibernation-pair/limine.conf.before")
CONFIG = P.STATE / "config.json"
QUALIFICATION = P.STATE / "qualification.json"
# Externally issued replacement authority, staged under distinct names; only `rebind` installs it.
STAGED = {"config": P.STATE / "rebind-config.json", "qualification": P.STATE / "rebind-qualification.json",
          "review": P.STATE / "rebind-boot-policy-review.json"}
AUTHORITY = (("config", CONFIG), ("qualification", QUALIFICATION), ("review", REVIEW), ("backup", P.BACKUP))
REBIND_KEYS = {"protocol", "transition_id", "action", "maintenance_transition_id", "marker_sha256", "baseline_sha256", "retirement_sha256",
               "retired_receipt_sha256", "new_receipt_sha256", "new_baseline_sha256", "trial_evidence_sha256", "old", "new", "limine"}
# The generation trial's durable terminal record: state root per generation, named by 12 hex of the manifest digest.
TRIAL_GENERATIONS = Path("var/lib/omarchy/t2-hibernate-trial/generations")
REBIND_ARCHIVE = {"old": {"config": "old-config.json", "qualification": "old-qualification.json", "review": "old-policy.json", "backup": "old-backup"},
                  "new": {"config": "new-config.json", "qualification": "new-qualification.json", "review": "policy.json", "backup": "new-backup"}}
REACTIVATION_KEYS = {"protocol", "transition_id", "action", "maintenance_transition_id", "marker_sha256", "baseline_sha256", "policy_sha256", "limine"}
REACTIVATION_LIMINE = {"from_sha256", "to_sha256", "from_canonical_sha256", "to_canonical_sha256"}


def _sync(directory):
  fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try: os.fsync(fd)
  finally: os.close(fd)


def _new(path, raw, mode=0o600):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fchmod(stream.fileno(), mode)
    os.fsync(stream.fileno())
  _sync(path.parent)


def _encoded(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _present(path):
  try: path.lstat()
  except FileNotFoundError: return False
  return True


def _retained(operation, recover):
  """Fixture retained retry: notification is not permission to drop exclusion.

  No deadline/interrupt converts an unresolved condition into safe exit. The
  reviewed native owner is still unavailable; old fixtures without this seam
  do NOT establish retained native failure behavior.
  """
  attempt = 0
  while True:
    try: return operation()
    except BaseException as error:
      attempt += 1
      try: recover(error, attempt)
      except BaseException: pass
      try: time.sleep(0.01)
      except BaseException: pass


def _veto(root, intent, *, durable=False):
  G._ancestors(root, root / MAINTENANCE, os.geteuid())
  if not _present(root / MAINTENANCE):
    _new(root / MAINTENANCE, intent)
    if _read(root, MAINTENANCE) != intent: raise ValueError("Rearmed maintenance veto readback differs")
  if not durable: return  # legacy fixture presence-only behavior, NOT native
  fd = os.open(root / MAINTENANCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    opened, named = os.fstat(fd), (root / MAINTENANCE).lstat()
    def metadata(info):
      return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or opened.st_size != len(intent) or metadata(opened) != metadata(named) or os.read(fd, len(intent) + 1) != intent:
      raise ValueError("Foreign maintenance veto preserved; exact private repair required")
    os.fsync(fd)
    _sync((root / MAINTENANCE).parent)
    os.lseek(fd, 0, os.SEEK_SET)
    if os.read(fd, len(intent) + 1) != intent or metadata(os.fstat(fd)) != metadata(opened) or metadata((root / MAINTENANCE).lstat()) != metadata(opened):
      raise ValueError("Maintenance veto changed after durability check")
  finally: os.close(fd)


def _owner(root): return 0 if root == Path("/") else os.geteuid()


def _artifact_ancestors(root, path, owner):
  """Qualified private-artifact ancestry: the artifacts' own account (the directory owner) may own the chain.

  Same trust the product artifact audit extends to the configured source/restore
  directories. Every component must be a real directory (no symlink) that no
  group/other can write, owned by root, the runtime or the artifact owner.
  Returns the artifact owner uid. Root-owned strictness stays in _stable_bytes.
  """
  allowed = {0, os.geteuid(), owner}
  for directory in path.parents:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in allowed or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink qualified artifact ancestors required")
    if directory == root: break


def _stable_bytes(root, relative, limit, *, keep=False, artifact=False):
  """Bounded owned regular bytes with SHA-256/BLAKE2b and unchanged identity.

  `artifact=True` is only for the configured qualified source/restore artifact
  directories, which the product audit reads without a root-ownership rule and
  which live under the operator's account; callers pin the bytes to the manifest.
  """
  path, owner = root / relative, _owner(root)
  if artifact:
    owner = path.parent.lstat().st_uid
    _artifact_ancestors(root, path, owner)
  else: G._ancestors(root, path, owner)
  named = path.lstat()
  if not stat.S_ISREG(named.st_mode) or named.st_uid != owner or named.st_mode & 0o022 or named.st_nlink != 1 or not 0 < named.st_size <= limit:
    raise ValueError("Bounded owned regular fallback bytes required")
  def identity(info): return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    opened = os.fstat(fd)
    if identity(opened) != identity(named): raise ValueError("Fallback changed before read")
    sha, blake, count, chunks = hashlib.sha256(), hashlib.blake2b(), 0, []
    while True:
      raw = os.read(fd, min(1024 * 1024, limit + 1 - count))
      if not raw: break
      count += len(raw)
      if count > limit: raise ValueError("Fallback exceeded byte bound")
      sha.update(raw)
      blake.update(raw)
      if keep: chunks.append(raw)
    if count != opened.st_size or identity(os.fstat(fd)) != identity(opened) or identity(path.lstat()) != identity(opened):
      raise ValueError("Short or changed fallback read")
    return {"sha256": sha.hexdigest(), "blake2b": blake.hexdigest(), "size": count}, b"".join(chunks)
  finally: os.close(fd)


def verify_fallback(root, raw=None):
  """Prove canonical stock default 2 whose entry hash is the actual production UKI.

  raw=None reads and rereads the live boot configuration; otherwise raw is a
  retained candidate (for example the pre-transition backup). Matching bytes do
  not prove ordinary bootability beyond the reviewed Limine BLAKE2b binding.
  """
  root = Path(root)
  live = raw is None
  if live: config, raw = _stable_bytes(root, P.LIMINE, P.MAX_BYTES, keep=True)
  else: config = {"sha256": P.digest(raw), "size": len(raw)}
  G._stock(raw)
  lines = raw.decode().splitlines()
  entries = [index for index, line in enumerate(lines) if line.strip().startswith("/")]
  block = lines[entries[1] + 1:entries[2] if len(entries) > 2 else len(lines)]
  paths = [line.strip().split(":", 1)[1].strip() for line in block if line.strip().split(":", 1)[0].strip().lower() == "path"]
  if len(paths) != 1 or "#" not in paths[0]: raise ValueError("Exact production boot entry hash required")
  expected = paths[0].rsplit("#", 1)[1]
  image, _ = _stable_bytes(root, PRODUCTION, MAX_UKI)
  if image["blake2b"] != expected: raise ValueError("Stock entry does not bind actual production UKI bytes")
  if live:  # nothing may have changed while the UKI was hashed
    repeated, repeated_raw = _stable_bytes(root, P.LIMINE, P.MAX_BYTES, keep=True)
    if repeated_raw != raw or repeated != config: raise ValueError("Stock configuration changed while reading UKI")
  return {"classification": "fallback-bytes-verified", "limine": config, "production": image}


_read = P._read


def _owned_lock(path, fd):
  current, held = path.lstat(), os.fstat(fd)
  if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
    raise ValueError("Foreign pacman lock replacement must remain preserved")


@contextmanager
def _locks(root):
  db = root / DB_LOCK
  G._ancestors(root, db, os.geteuid())
  fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  released = False
  scoped = True
  physical = None
  try:
    os.fchmod(fd, 0o600)
    os.fsync(fd)
    _sync(db.parent)
    _read(root, PHYSICAL_LOCK)
    expected = (root / PHYSICAL_LOCK).lstat()
    physical = os.open(root / PHYSICAL_LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    held = os.fstat(physical)
    if not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1 or (held.st_dev, held.st_ino) != (expected.st_dev, expected.st_ino):
      raise ValueError("Fixed private physical lock descriptor required")
    fcntl.flock(physical, fcntl.LOCK_EX | fcntl.LOCK_NB)
    def release_db(*, verify_only=False):
      nonlocal released
      _owned_lock(db, fd)
      if verify_only: return
      db.unlink()
      released = True
      _sync(db.parent)
    def check_physical():
      if not scoped: raise ValueError("Physical exclusion scope ended")
      current, held = (root / PHYSICAL_LOCK).lstat(), os.fstat(physical)
      if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
        raise ValueError("Physical exclusion inode changed")
      if not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1:
        raise ValueError("Owned physical exclusion changed")
    release_db.check_physical = check_physical
    yield release_db
  finally:
    scoped = False
    try:
      if not released:
        _owned_lock(db, fd)
        db.unlink()
        _sync(db.parent)
    finally:
      if physical is not None: os.close(physical)
      os.close(fd)


def _idle(root):
  efi = root / G.EFI
  G._ancestors(root, efi / "view", os.geteuid())
  if not stat.S_ISDIR(efi.lstat().st_mode): raise ValueError("Visible EFI view required")
  names = ["LoaderEntryOneShot-" + G.LOADER_GUID, "LoaderEntryDefault-" + G.LOADER_GUID,
           PRODUCT.HOST.CT.SOURCE_VARIABLE, PRODUCT.HOST.CT.RESTORE_VARIABLE]
  if any(_present(efi / name) for name in names): raise ValueError("EFI overrides or reusable stages prevent policy transition")
  directory = root / P.STATE / "ledger"
  if not directory.is_dir() or directory.is_symlink(): raise ValueError("Existing idle ledger required")
  _read(root, P.STATE / "ledger/lock")
  ledger = PRODUCT.TX.Ledger(directory)
  with ledger._lock(): PRODUCT._head(ledger)


def _runtime(root):
  runtime = root / P.STATE / "runtime"
  review_raw = _read(root, P.STATE / "runtime-deployment-review.json")
  review = P._json(review_raw)
  snapshot = P._json(_read(root, P.STATE / "runtime/snapshot.json"))
  if set(review) != {"protocol", "approved", "reviewed_commit", "files"} or review["protocol"] != D.SCHEMA or review["approved"] is not True:
    raise ValueError("Reviewed runtime required")
  if snapshot.get("protocol") != D.SCHEMA or snapshot.get("review_sha256") != P.digest(review_raw) or snapshot.get("reviewed_commit") != review["reviewed_commit"] or snapshot.get("files") != review["files"]:
    raise ValueError("Runtime receipt differs from private review")
  if any(not (stat.S_ISDIR(path.lstat().st_mode) or stat.S_ISREG(path.lstat().st_mode)) for path in runtime.rglob("*")):
    raise ValueError("Regular reviewed runtime files required")
  D._verify_tree(runtime, review["files"])
  installed = _read(root, HOOK, private=False)
  if installed != _read(root, P.STATE / "runtime" / D.UPDATE_GUARD_HOOK):
    raise ValueError("Installed update guard differs from reviewed template")
  return P.digest(review_raw)


def _opt_in(root):
  raw = _read(root, OPT_IN, private=False)
  if raw or stat.S_IMODE((root / OPT_IN).lstat().st_mode) != 0o644:
    raise ValueError("Existing valid routine opt-in required")
  return raw


def _replace(root, expected, replacement, transition_id, *, guard=lambda: None):
  target = root / P.LIMINE
  if _read(root, P.LIMINE, private=False) != expected: raise ValueError("Configuration changed before replacement")
  temporary = target.with_name("limine.conf.source-default-" + transition_id)
  _new(temporary, replacement, stat.S_IMODE(target.lstat().st_mode))
  # The exclusion covers cooperating boot/package writers, not hostile root.
  if _read(root, P.LIMINE, private=False) != expected: raise ValueError("Configuration changed immediately before replacement")
  guard()
  os.replace(temporary, target)
  _sync(target.parent)
  # This readback may come from the page cache; durability rests on the file
  # fsync in _new plus this directory fsync, not on the readback itself.
  if _read(root, P.LIMINE, private=False) != replacement: raise ValueError("Configuration replacement readback failed")


def stock_projection(raw):
  """Canonical stock-boot identity the guard cares about, blind to snapshot churn.

  Reuses the guard's exact stock validator, then keeps only default_entry 2, the
  two leading entry names and the //linux-t2 properties with the production UKI
  hash masked (the UKI itself is compared by its own bytes). limine-snapper-sync
  rewrites its //Snapshots region after the //linux-t2 block, so it never enters
  this value; theme or other unrelated configuration is not part of it either.
  """
  G._stock(raw)
  lines = raw.decode().splitlines()
  entries = [(index, line.strip()) for index, line in enumerate(lines) if line.strip().startswith("/")]
  end = entries[2][0] if len(entries) > 2 else len(lines)
  properties = {}
  for line in lines[entries[1][0] + 1:end]:
    if not line.strip() or line.lstrip().startswith("#"): continue
    key, value = line.strip().split(":", 1)
    key = key.strip().lower()
    if key != "comment": properties[key] = value.strip()
  properties["path"] = properties["path"].rsplit("#", 1)[0] + "#<production-uki-blake2b>"
  return {"default_entry": 2, "entries": [entries[0][1], entries[1][1]], "linux_t2": properties}


def stock_identity(raw):
  """Exact bytes and snapshot-blind stock projection digests of one Limine configuration."""
  return {"exact_sha256": P.digest(raw), "projection_sha256": P.digest(_encoded(stock_projection(raw)))}


def _plain(value, depth=0):
  """JSON-plain data only: no floats, non-string keys or excessive nesting."""
  if depth > 12: raise ValueError("Generation baseline nests too deeply")
  if value is None or type(value) in (bool, int, str): return
  if type(value) is list:
    for item in value: _plain(item, depth + 1)
  elif type(value) is dict:
    for key, item in value.items():
      if type(key) is not str: raise ValueError("Generation baseline keys must be strings")
      _plain(item, depth + 1)
  else: raise ValueError("Generation baseline holds a non-JSON value")


def _baseline_value(value):
  """Exact provider shape: one JSON-plain dict per required item, nothing else."""
  if type(value) is not dict or set(value) != set(BASELINE_ITEMS) or any(type(item) is not dict for item in value.values()):
    raise ValueError("Exact generation baseline item set required")
  _plain(value)
  raw = _encoded(value)
  # Refused before any write; the document adds only fixed-size bindings and the limine identity.
  if len(raw) > P.MAX_BYTES // 2: raise ValueError("Generation baseline exceeds the bounded evidence size")
  return json.loads(raw)


def _baseline_document(identifier, items, intent, intent_raw):
  """Canonical archived baseline, bound to the transition and the maintenance intent digest.

  Written after maintenance-resume.json and before maintenance-intent.json and the
  marker, so no marker ever exists without it. The marker/intent field set is
  unchanged; only new reviewed code reads this object (the guard ignores it).
  """
  document = {"protocol": BASELINE_SCHEMA, "transition_id": identifier, "maintenance_intent_sha256": P.digest(intent_raw), "items": items}
  for name in ("old_policy_sha256", "staged_receipt_sha256", "deactivation_completion_sha256"):
    document[name] = intent[name]
  raw = _encoded(document)
  if len(raw) > P.MAX_BYTES: raise ValueError("Generation baseline exceeds the bounded evidence size")
  return raw


def read_baseline(root, marker_raw=None):
  """Validated archived baseline items for the published maintenance transition.

  Read-only. Raises FileNotFoundError when the sidecar is absent (an older or
  fixture publication) and ValueError when it is not exactly the canonical
  document bound to this marker; callers turn both into "compatibility unknown".
  """
  root = Path(root)
  marker = _read(root, MAINTENANCE) if marker_raw is None else marker_raw
  intent = P._json(marker)
  if type(intent) is not dict or _encoded(intent) != marker: raise ValueError("Exact canonical maintenance intent required")
  identifier = PRODUCT.TX.uuid_value(intent.get("transition_id"))
  raw = _read(root, HISTORY / identifier / BASELINE_NAME)
  document = P._json(raw)
  if type(document) is not dict or document.get("protocol") != BASELINE_SCHEMA or type(document.get("items")) is not dict:
    raise ValueError("Exact generation baseline document required")
  items = document["items"]
  if set(items) != {*BASELINE_ITEMS, "limine"} or any(type(item) is not dict for item in items.values()):
    raise ValueError("Exact generation baseline item set required")
  _plain(document)
  if _baseline_document(identifier, items, intent, marker) != raw: raise ValueError("Generation baseline is not bound to the maintenance intent")
  return items


def transition(root, action, *, precheck, maintenance_continuation=None, guard=None, recover=None, maintenance_resume=None, maintenance_baseline=None):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root.resolve() == Path("/"):
    raise ValueError("Fixture-only transition refuses live root and aliases")
  if action not in (*PENDINGS, "maintenance") or not callable(precheck): raise ValueError("Explicit fixture action/precheck required")
  if guard is not None and not callable(guard): raise ValueError("Explicit fixture exclusion guard required")
  if recover is not None and (action != "maintenance" or not callable(recover)):
    raise ValueError("Explicit fixture maintenance recovery required")
  return _transition(root, action, precheck=precheck, guard=(lambda: None) if guard is None else guard, maintenance_continuation=maintenance_continuation, recover=recover,
                     maintenance_resume=maintenance_resume, maintenance_baseline=maintenance_baseline)


def _runtime_pending(root, action):
  """Maintenance never starts over an interrupted runtime deployment or upgrade."""
  if action != "maintenance": return
  for path in RUNTIME_PENDINGS:
    G._ancestors(root, root / path, _owner(root))
    if _present(root / path): raise ValueError("Runtime deployment/upgrade pending refuses maintenance")


def _live_maintenance(root, gate, native):
  """Only the reviewed native adapter may name `/`; it must bring its own gate."""
  if not Path(root).is_absolute(): raise ValueError("Absolute maintenance root required")
  if Path(root).resolve() == Path("/") and (native is not _NATIVE_MAINTENANCE or not callable(gate)):
    raise ValueError("Live maintenance entry requires a separately reviewed native coordinator")


def _transition(root, action, *, precheck, guard, maintenance_continuation=None, recover=None, maintenance_gate=None, native=None, maintenance_resume=None, maintenance_baseline=None):
  """Internal core; maintenance is a durable veto, not update permission.

  maintenance_gate(root, phase) supplies additional read-only prerequisites at
  "before" (before any policy write), "after" (stock fallback restored) and
  "final" (marker durable, deactivation pending still retained). Any failure
  leaves the deactivation pending and, once published, the maintenance marker.

  maintenance_resume() returns the audited qualified {device, devnum, offset}
  resume target the publisher's no-image proofs used. It is archived (before the
  archived intent and marker exist) in maintenance-resume.json so the update
  guard can prove image absence later without re-deriving qualified artifacts,
  which a kernel/UKI update legitimately invalidates. The live root requires it.

  maintenance_baseline() returns the qualified generation's identity items
  (exactly BASELINE_ITEMS), called in the pre-write "before" phase while that
  generation is still active. The engine adds the stock Limine identity it
  retains and archives the canonical document in generation-baseline.json after
  the resume evidence and before maintenance-intent.json and the marker. The
  live root requires it; fixtures may omit it, and an absent sidecar later means
  compatibility unknown.
  """
  root = Path(root)
  if maintenance_resume is not None and (action != "maintenance" or not callable(maintenance_resume)):
    raise ValueError("Maintenance resume provider is only valid for the maintenance action")
  if maintenance_baseline is not None and (action != "maintenance" or not callable(maintenance_baseline)):
    raise ValueError("Maintenance baseline provider is only valid for the maintenance action")
  if maintenance_continuation is not None and (root.resolve() == Path("/") or action != "maintenance" or not callable(maintenance_continuation)):
    raise ValueError("Explicit fixture-only maintenance continuation required")
  if maintenance_gate is not None and (action != "maintenance" or not callable(maintenance_gate)):
    raise ValueError("Maintenance gate is only valid for the maintenance action")
  if action == "maintenance": _live_maintenance(root, maintenance_gate, native)
  if action == "maintenance" and root.resolve() == Path("/") and maintenance_resume is None:
    raise ValueError("Live maintenance requires the audited resume target for durable evidence")
  if action == "maintenance" and root.resolve() == Path("/") and maintenance_baseline is None:
    raise ValueError("Live maintenance requires the qualified generation baseline for durable evidence")
  if recover is not None and (root.resolve() == Path("/") or action != "maintenance" or not callable(recover)):
    raise ValueError("Explicit fixture-only retained recovery required")
  if action not in (*PENDINGS, "maintenance"):
    raise ValueError("Explicit reviewed transition action required")
  mechanics = "deactivation" if action == "maintenance" else action
  guard()
  G._ancestors(root, root / MAINTENANCE, os.geteuid())
  if _present(root / MAINTENANCE): raise ValueError("Existing package maintenance intent refuses new transition")
  _runtime_pending(root, action)
  for path in PENDINGS.values():
    G._ancestors(root, root / path, os.geteuid())
    if _present(root / path): raise ValueError("Incomplete transition preserved; no automatic retry")
  with _locks(root) as release_db:
    if _present(root / MAINTENANCE) or any(_present(root / path) for path in PENDINGS.values()):
      raise ValueError("Incomplete transition or maintenance intent preserved")
    _runtime_pending(root, action)
    runtime_review = _runtime(root)
    _idle(root)
    opt_in = _opt_in(root)
    receipt_raw = _read(root, P.RECEIPT)
    policy_raw = _read(root, REVIEW if mechanics == "activation" else P.POLICY)
    policy = P._json(policy_raw)
    actual = _read(root, P.LIMINE, private=False)
    if mechanics == "activation":
      if _present(root / P.POLICY): raise ValueError("Active policy cannot be overwritten")
      before = actual
      proposal = P.prepare(before, receipt_raw)
      after = proposal["after"]
      P.validate(policy, before, after, receipt_raw)
      G._stock(before)
    else:
      before = _read(root, P.BACKUP)
      P.validate(policy, before, actual, receipt_raw)
      after = before
    precheck(root, mechanics, "before")
    # Validated before any write: a bad tuple must not strand a half-finished deactivation.
    resume = None if maintenance_resume is None else G._resume_target(maintenance_resume())
    if maintenance_gate is not None: maintenance_gate(root, "before")
    # Captured while the qualified generation is still active and before any write.
    baseline = None if maintenance_baseline is None else _baseline_value(maintenance_baseline())
    # The stock projection is derived here too, so the only late step is a pure document build.
    stock_limine = None if baseline is None else stock_identity(after)
    guard()
    transition_id = str(uuid.uuid4())
    # A deactivation leaves the APPROVED source-default bytes (P.validate above proved the actual bytes equal them apart
    # from the snapper snapshot region). The guard's maintenance validator pins exactly that approved hash, so recording
    # digest(actual) would make every marker published after snapshot churn unverifiable and block all updates.
    intent = _encoded({"protocol": "omarchy-t2-source-default-transition-v1", "transition_id": transition_id,
      "action": mechanics, "policy_sha256": P.digest(policy_raw),
      "from_sha256": P.digest(actual) if mechanics == "activation" else policy["after_limine_sha256"], "to_sha256": P.digest(after)})
    pending = root / PENDINGS[mechanics]
    _new(pending, intent)
    guard()
    history = root / HISTORY
    if not _present(history):
      guard()
      history.mkdir(mode=0o700)
      _sync(history.parent)
    G._ancestors(root, history / "member", os.geteuid())
    archive = history / transition_id
    guard()
    archive.mkdir(mode=0o700)
    _sync(history)
    guard()
    _new(archive / "policy.json", policy_raw)
    guard()
    _new(archive / "opt-in", opt_in, 0o644)
    guard()
    _new(archive / "intent.json", intent)
    guard()
    if mechanics == "activation":
      if _present(root / P.BACKUP):
        if _read(root, P.BACKUP) != before: raise ValueError("Retained source-default backup differs")
      else:
        guard()
        _new(root / P.BACKUP, before)
      guard()
      _new(root / P.POLICY, policy_raw)
      guard()
      _replace(root, actual, after, transition_id, guard=guard)
      P.verify(root, P.digest(receipt_raw))
    else:
      if _opt_in(root) != opt_in: raise ValueError("Opt-in changed before disable")
      guard()
      (root / OPT_IN).unlink()
      _sync((root / OPT_IN).parent)
      guard()
      _replace(root, actual, after, transition_id, guard=guard)
      if _read(root, P.POLICY) != policy_raw: raise ValueError("Active policy changed before retirement")
      guard()
      (root / P.POLICY).unlink()
      _sync((root / P.POLICY).parent)
    _idle(root)
    precheck(root, mechanics, "after")
    _idle(root)
    if _runtime(root) != runtime_review: raise ValueError("Reviewed runtime changed during transition")
    if _read(root, P.LIMINE, private=False) != after: raise ValueError("Final configuration differs from exact authorized bytes")
    if mechanics == "deactivation":
      G._stock(after)
      if _present(root / OPT_IN) or _present(root / P.POLICY): raise ValueError("Deactivation remains active")
      if maintenance_gate is not None: maintenance_gate(root, "after")
    else:
      if _read(root, P.POLICY) != policy_raw: raise ValueError("Final active policy differs")
      P.verify(root, P.digest(receipt_raw))
      if _opt_in(root) != opt_in: raise ValueError("Activation did not preserve opt-in")
    completion = {"protocol": "omarchy-t2-source-default-transition-complete-v1", "transition_id": transition_id,
                  "action": mechanics, "intent_sha256": P.digest(intent), "configuration_sha256": P.digest(after)}
    guard()
    _new(archive / "completion.json", _encoded(completion))
    maintenance_intent = None
    if action == "maintenance":
      if _read(root, (archive / "completion.json").relative_to(root)) != _encoded(completion):
        raise ValueError("Deactivation completion readback differs before maintenance handoff")
      fields = {"protocol": MAINTENANCE_SCHEMA, "transition_id": transition_id,
        "old_policy_sha256": P.digest(policy_raw), "runtime_review_sha256": runtime_review,
        "staged_receipt_sha256": P.digest(receipt_raw), "fallback_limine_sha256": P.digest(after),
        "deactivation_completion_sha256": P.digest(_encoded(completion))}
      maintenance_intent = _encoded(fields)
      if resume is not None:
        resume_raw = G._resume_document(transition_id, resume, fields)
        guard()
        _new(archive / G.RESUME_NAME, resume_raw)
        if _read(root, (archive / G.RESUME_NAME).relative_to(root)) != resume_raw:
          raise ValueError("Archived maintenance resume target readback differs")
      if baseline is not None:
        baseline_raw = _baseline_document(transition_id, {**baseline, "limine": stock_limine}, fields, maintenance_intent)
        guard()
        _new(archive / BASELINE_NAME, baseline_raw)
        if _read(root, (archive / BASELINE_NAME).relative_to(root)) != baseline_raw:
          raise ValueError("Archived generation baseline readback differs")
      guard()
      _new(archive / "maintenance-intent.json", maintenance_intent)
      if _read(root, (archive / "maintenance-intent.json").relative_to(root)) != maintenance_intent:
        raise ValueError("Archived maintenance intent readback differs")
      guard()
      _new(root / MAINTENANCE, maintenance_intent)
      if _read(root, MAINTENANCE) != maintenance_intent:
        raise ValueError("Package maintenance marker readback differs")
      if maintenance_gate is not None:
        # The marker is already a durable veto; the compatible deactivation
        # pending is retired only after these final prerequisites hold again.
        guard()
        maintenance_gate(root, "final")
        if _runtime(root) != runtime_review: raise ValueError("Reviewed runtime changed before pending retirement")
    # Both exclusions remain owned through durable pending cleanup. A failure
    # releasing our package lock reinstates pending and never deletes a foreign
    # replacement; only cooperating writers are within this lock contract.
    release_db(verify_only=True)
    try:
      guard()
      pending.unlink()
      _sync(pending.parent)
      guard()
      release_db()
    except BaseException:
      if not _present(pending): _new(pending, intent)
      raise
    result = {**completion, "live_execution": False, "qualification_issued": False}
    if maintenance_intent is not None: result["maintenance_intent_sha256"] = P.digest(maintenance_intent)
    if maintenance_continuation is not None:
      # Deactivation is already complete. Pipeline errors retain maintenance's
      # durable veto, not a fabricated incomplete deactivation. Keep physical
      # exclusion continuously held while actual package callbacks own db.lck.
      release_db.check_physical()
      try:
        result["maintenance"] = maintenance_continuation(archive, maintenance_intent, release_db.check_physical)
      finally:
        # A failed pipeline may have removed its veto. Rearm only an absent
        # marker under retained physical exclusion; never replace foreign data.
        try:
          def confirm_veto():
            release_db.check_physical()
            if recover is not None and _read(root, (archive / "maintenance-intent.json").relative_to(root)) != maintenance_intent:
              raise ValueError("Original archived maintenance intent changed")
            _veto(root, maintenance_intent, durable=recover is not None)
          if recover is None: confirm_veto()
          else: _retained(confirm_veto, recover)
        except BaseException as error:
          raise RuntimeError("Maintenance veto durability unconfirmed") from error
    return result


def _pinned_resume(root):
  """The archived publish-time resume tuple, via the guard's exact validator."""
  return G._maintenance(Path(root))["resume"]


def _verify_existing_maintenance(root, *, guard, gate, native=None):
  """Read-only idempotent re-entry accepting exactly what the update guard accepts.

  Reuses the guard's exact inactive-maintenance validator (which reuses
  package_maintenance's fallback check, so coherent NEW stock bytes after an OS
  or kernel update are accepted and incoherent ones refused), under the same DB
  and physical locks, then the caller's retained gate. Never writes, repairs or
  removes the marker; any deviation raises with the marker untouched.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir(): raise ValueError("Canonical root required")
  _live_maintenance(root, gate, native)
  if not callable(guard) or not callable(gate): raise ValueError("Explicit guard and gate required")
  validator = getattr(G, "_maintenance", None)
  if not callable(validator): raise ValueError("Reviewed update guard lacks the exact maintenance validator")
  guard()
  G._ancestors(root, root / MAINTENANCE, _owner(root))
  with _locks(root) as release_db:
    guard()
    marker = _read(root, MAINTENANCE)
    result = validator(root)
    gate(root, "retained")
    guard()
    release_db(verify_only=True)
    if _read(root, MAINTENANCE) != marker: raise ValueError("Maintenance marker changed during verification")
  return {"protocol": "omarchy-t2-package-maintenance-verified-v1", "transition_id": result["transition_id"],
          "maintenance_intent_sha256": P.digest(marker), "already_inactive": True,
          "live_execution": False, "qualification_issued": False}


def _complete_interrupted_maintenance(root, *, guard, gate, native=None, pinned=None):
  """Finish exactly the state a crash left between marker publication and pending retirement.

  Only the step the interrupted publisher would have done next: marker and
  deactivation pending both present, nothing else active, and the pending
  byte-identical to the archived intent the marker chains to. Runs the guard's
  exact maintenance validator (its only relaxation is its explicit ignore of that one
  proven pending), the caller's "final" gate with the archived resume tuple pinned,
  retires the pending as _transition does, then re-verifies as inactive
  maintenance ("retained"). Any mismatch raises with every file untouched; the
  marker is never written or removed. A failure after retirement reinstates the
  identical pending.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir(): raise ValueError("Canonical root required")
  _live_maintenance(root, gate, native)
  if not callable(guard) or not callable(gate): raise ValueError("Explicit guard and gate required")
  if pinned is not None and type(pinned) is not dict: raise ValueError("Pinned evidence dictionary required")
  validator = getattr(G, "_maintenance", None)
  if not callable(validator): raise ValueError("Reviewed update guard lacks the exact maintenance validator")
  pending_path = PENDINGS["deactivation"]
  pending = root / pending_path
  guard()
  for path in (MAINTENANCE, pending_path): G._ancestors(root, root / path, _owner(root))
  def expected_state():
    """Prove the pending is exactly the archived intent the marker chains to; return marker bytes."""
    marker, raw = _read(root, MAINTENANCE), _read(root, pending_path)
    intent = P._json(marker)
    if type(intent) is not dict or _encoded(intent) != marker: raise ValueError("Exact canonical maintenance intent required")
    identifier = PRODUCT.TX.uuid_value(intent.get("transition_id"))
    archived = _read(root, HISTORY / identifier / "intent.json")
    pinned_intent = P._json(raw)
    if (raw != archived or type(pinned_intent) is not dict or _encoded(pinned_intent) != raw or pinned_intent.get("transition_id") != identifier or
        pinned_intent.get("action") != "deactivation" or pinned_intent.get("policy_sha256") != intent.get("old_policy_sha256")):
      raise ValueError("Deactivation pending is not the archived intent of the maintenance transition")
    completion = _read(root, HISTORY / identifier / "completion.json")
    completed = P._json(completion)
    if (P.digest(completion) != intent.get("deactivation_completion_sha256") or type(completed) is not dict or
        completed.get("intent_sha256") != P.digest(raw) or completed.get("transition_id") != identifier):
      raise ValueError("Deactivation pending does not chain to the completed deactivation")
    return marker
  def evaluate():
    """The guard's exact validator, relaxed only for the one proven pending."""
    return validator(root, ignore=(pending_path,))
  with _locks(root) as release_db:
    guard()
    marker = expected_state()
    result = evaluate()
    if _read(root, MAINTENANCE) != marker or expected_state() != marker: raise ValueError("Maintenance evidence changed during verification")
    resume = result["resume"]
    if pinned is not None: pinned["resume"] = resume
    guard()
    gate(root, "final")
    guard()
    release_db(verify_only=True)
    if expected_state() != marker: raise ValueError("Maintenance evidence changed before pending retirement")
    raw = _read(root, pending_path)
    try:
      guard()
      pending.unlink()
      _sync(pending.parent)
      guard()
      verified = validator(root)
      gate(root, "retained")
      guard()
      if _read(root, MAINTENANCE) != marker or verified["transition_id"] != result["transition_id"]:
        raise ValueError("Maintenance marker changed during completion")
      release_db()
    except BaseException:
      if not _present(pending): _new(pending, raw)
      raise
  return {"protocol": "omarchy-t2-package-maintenance-verified-v1", "transition_id": result["transition_id"],
          "maintenance_intent_sha256": P.digest(marker), "completed_interrupted_maintenance": True,
          "live_execution": False, "qualification_issued": False}


# --- reactivation --------------------------------------------------------------------------------
#
# Class (a) only: the qualified generation is provably unchanged (assess-core `unchanged`), so the
# retained policy, backup and staged receipt are re-applied WITHOUT requalification. Everything else
# refuses with zero writes. The boot-config write is one line: the current bytes (snapshot region and
# all) with default_entry 2 replaced by the source entry, verified canonically against P.prepare(BACKUP).
# Never restore `after` or BACKUP bytes: that would drop snapshot entries.
#
# Write order (each preceded by guard()):
#   W1 activation pending   W2 archive intent/policy/comparison/opt-in   W3 boot-policy.json
#   W4 boot-config line (point of no return)   W5 opt-in   W6 postchecks   W7 completion.json
#   W8 unlink marker   W9 unlink pending   W10 release the package lock
# Recovery of any interruption is a re-run, which authenticates the pending and rolls back (never forward
# past W4); only a durable completion allows it to finish W8/W9. Do NOT reboot while it is mid-run: sleep is
# vetoed through W9 but a reboot is not.


def reactivation_pending(root):
  """True when the activation-pending name holds THIS engine's reactivation intent (never the runtime barrier)."""
  root = Path(root)
  G._ancestors(root, root / PENDINGS["activation"], _owner(root))
  try: value = P._json(_read(root, PENDINGS["activation"]))
  except (OSError, ValueError): return False
  return type(value) is dict and value.get("protocol") == REACTIVATION_SCHEMA


def _default_line(entry): return ("default_entry: " + entry + "\n").encode()


def _one_line_change(before, after):
  old, new = before.splitlines(True), after.splitlines(True)
  if len(old) != len(new) or sum(1 for left, right in zip(old, new) if left != right) != 1:
    raise ValueError("Source-default change must differ from the current bytes in exactly one line")


def _to_source_default(current, entry):
  """prepare()'s exact one-line substitution, applied to the CURRENT bytes."""
  P._line(current, b"default_entry: 2\n")
  result, count = re.subn(rb"^default_entry: 2\n", lambda match: _default_line(entry), current, count=1, flags=re.M)
  if count != 1: raise ValueError("Exactly one stock default_entry substitution required")
  _one_line_change(current, result)
  return result


def _to_stock_default(current, entry):
  """The reverse one-line transform; the result must be stock."""
  P._line(current, _default_line(entry))
  result, count = re.subn(b"^" + re.escape(_default_line(entry)), lambda match: b"default_entry: 2\n", current, count=1, flags=re.M)
  if count != 1: raise ValueError("Exactly one source default_entry substitution required")
  _one_line_change(current, result)
  G._stock(result)
  return result


def _reactivation_state_refusals(root):
  """Read-only refusals shared by every entry; nothing here writes."""
  for relative in RUNTIME_PENDINGS:
    G._ancestors(root, root / relative, _owner(root))
    if _present(root / relative): raise ValueError("Runtime deployment/upgrade pending refuses reactivation; finish or recover it first")
  G._ancestors(root, root / PENDINGS["deactivation"], _owner(root))
  if _present(root / PENDINGS["deactivation"]):
    raise ValueError("Interrupted deactivation/maintenance publication preserved; re-enter `maintenance` to finish it before reactivating")


def _reactivation_refuse_assessment(assessment):
  if type(assessment) is not dict or assessment.get("class") not in ("unchanged", "requalification-required", "unknown"):
    raise ValueError("compatibility unknown: malformed assessment; nothing was changed")
  if assessment["class"] == "requalification-required":
    raise ValueError("requalification required: " + ", ".join(assessment.get("changed_items", [])) + "; nothing was changed and updates stay allowed")
  if assessment["class"] == "unknown":
    detail = assessment.get("reason") or "unknown items: " + ", ".join(assessment.get("unknown_items", []))
    raise ValueError("compatibility unknown: " + detail + "; nothing was changed")
  if assessment.get("limine", {}).get("stock_projection_equal") is not True:
    raise ValueError("compatibility unknown: stock Limine projection is not equal; nothing was changed")


def _canonical_digest(raw): return P.digest(P.limine_canonical(raw))


def _retire(root, guard, release_db, pending, raw, marker):
  """W8 then W9: marker first (the pending keeps the veto), then the pending; W10 releases the package lock."""
  if _read(root, MAINTENANCE) != marker: raise ValueError("Maintenance marker changed before retirement")
  guard()
  (root / MAINTENANCE).unlink()
  _sync((root / MAINTENANCE).parent)
  _retire_pending(root, guard, release_db, pending, raw)


def _retire_pending(root, guard, release_db, pending, raw):
  release_db(verify_only=True)
  try:
    guard()
    pending.unlink()
    _sync(pending.parent)
    guard()
    release_db()
  except BaseException:
    if not _present(pending): _new(pending, raw)
    raise


def _reactivation_completion(transition_id, pending_intent, configuration):
  return _encoded({"protocol": REACTIVATION_COMPLETE, "transition_id": transition_id, "action": "reactivation",
                   "intent_sha256": P.digest(pending_intent), "configuration_canonical_sha256": _canonical_digest(configuration)})


def _reactivate(root, *, guard, gate, assess, inspect, postchecks, native=None, pinned=None):
  """Internal reactivation core; the live form needs the native capability and its own callbacks.

  gate(root, "retained")      maintenance read-only prerequisites (route, vetoes, fallback, no image)
  assess(evidence, marker)    lock-free assessment core; only `unchanged` may proceed
  inspect(evidence)           {"config", "manifest"}: qualified config and freshly derived manifest,
                              after product.validate and the derived-resume equality
  postchecks(root, baseline)  native ACTIVE-state checks (deployment, product, generation == baseline, no image)
  pinned                      dict the gate reads the archived resume tuple from (the activation pending
                              makes the guard's own re-derivation refuse)
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir(): raise ValueError("Canonical root required")
  _live_maintenance(root, gate, native)
  if not all(callable(item) for item in (guard, gate, assess, inspect, postchecks)): raise ValueError("Explicit callbacks required")
  context = {"guard": guard, "gate": gate, "assess": assess, "inspect": inspect, "postchecks": postchecks, "pinned": {} if pinned is None else pinned}
  guard()
  _reactivation_state_refusals(root)
  for relative in (PENDINGS["activation"], MAINTENANCE): G._ancestors(root, root / relative, _owner(root))
  if not _present(root / PENDINGS["activation"]) and not _present(root / MAINTENANCE):
    raise ValueError("Inactive package maintenance marker required; nothing to reactivate")
  with _locks(root) as release_db:
    guard()
    _reactivation_state_refusals(root)
    if _present(root / PENDINGS["activation"]): return _reactivation_recover(root, context, release_db)
    return _reactivation_forward(root, context, release_db)


def _reactivation_forward(root, context, release_db):
  guard, gate, pinned = context["guard"], context["gate"], context["pinned"]
  # R0: nothing of the source state may exist.
  for relative in (P.POLICY, OPT_IN, PENDINGS["activation"], PENDINGS["deactivation"]):
    G._ancestors(root, root / relative, _owner(root))
    if _present(root / relative): raise ValueError("Existing source-default policy, opt-in or pending refuses reactivation: " + relative.name)
  evidence = G._maintenance(root)
  pinned["resume"] = evidence["resume"]
  marker = _read(root, MAINTENANCE)
  intent = P._json(marker)
  identifier = evidence["transition_id"]
  if _runtime(root) != intent["runtime_review_sha256"]: raise ValueError("Reviewed runtime differs from the maintenance intent")
  gate(root, "retained")
  # The assessment precedes derive_artifacts so a real kernel/UKI update reports requalification, not a derivation failure.
  assessment = context["assess"](evidence, marker)
  _reactivation_refuse_assessment(assessment)
  if _read(root, MAINTENANCE) != marker: raise ValueError("Maintenance marker changed during assessment")
  info = context["inspect"](evidence)
  config, manifest = info["config"], info["manifest"]
  baseline_raw = _read(root, HISTORY / identifier / BASELINE_NAME)
  baseline_document, baseline = P._json(baseline_raw), read_baseline(root, marker)
  receipt_raw = _read(root, P.RECEIPT)
  digests = {P.digest(receipt_raw), config["staged_receipt_sha256"], intent["staged_receipt_sha256"], baseline_document["staged_receipt_sha256"]}
  if len(digests) != 1: raise ValueError("Staged receipt digests differ between the file, configuration, marker and baseline")
  review_raw = _read(root, REVIEW)
  if P.digest(review_raw) != intent["old_policy_sha256"] or review_raw != _read(root, HISTORY / identifier / "policy.json"):
    raise ValueError("Reviewed policy differs from the archived old policy")
  if not manifest == config["manifest"] == baseline["manifest"]["fields"]: raise ValueError("Qualified manifest differs between derivation, configuration and baseline")
  policy = P._json(review_raw)
  backup = _read(root, P.BACKUP)
  proposal = P.prepare(backup, receipt_raw)
  P.validate(policy, backup, proposal["after"], receipt_raw)
  current = _read(root, P.LIMINE, private=False)
  G._stock(current)
  if P.limine_canonical(current) != P.limine_canonical(backup):
    raise ValueError("Unrelated Limine drift: the current configuration is not the retained backup apart from the snapshot region")
  replacement = _to_source_default(current, policy["source_entry_id"])
  if P.limine_canonical(replacement) != P.limine_canonical(proposal["after"]): raise ValueError("Source-default bytes differ from the approved proposal")
  _idle(root)
  # --- writes ---------------------------------------------------------------------------------
  transition_id = str(uuid.uuid4())
  limine = {"from_sha256": P.digest(current), "to_sha256": P.digest(replacement),
            "from_canonical_sha256": _canonical_digest(current), "to_canonical_sha256": _canonical_digest(replacement)}
  pending_intent = _encoded({"protocol": REACTIVATION_SCHEMA, "transition_id": transition_id, "action": "reactivation",
    "maintenance_transition_id": identifier, "marker_sha256": P.digest(marker), "baseline_sha256": P.digest(baseline_raw),
    "policy_sha256": P.digest(review_raw), "limine": limine})
  comparison = _encoded({"protocol": REACTIVATION_COMPARISON, "transition_id": transition_id, "intent_sha256": P.digest(pending_intent),
    "assessment": assessment, "limine": limine})
  pending = root / PENDINGS["activation"]
  guard()
  _new(pending, pending_intent)  # W1: sleep and updates are vetoed from here on
  archive = root / HISTORY / transition_id
  guard()
  archive.mkdir(mode=0o700)
  _sync(archive.parent)
  for name, raw, mode in (("intent.json", pending_intent, 0o600), ("policy.json", review_raw, 0o600), ("comparison.json", comparison, 0o600), ("opt-in", b"", 0o644)):
    guard()
    _new(archive / name, raw, mode)  # W2
  guard()
  _new(root / P.POLICY, review_raw)  # W3
  guard()
  _replace(root, current, replacement, transition_id, guard=guard)  # W4: point of no return; recovery only rolls back
  guard()
  _new(root / OPT_IN, b"", 0o644)  # W5
  _reactivation_active(root, context, intent, baseline)  # W6
  completion = _reactivation_completion(transition_id, pending_intent, replacement)
  guard()
  _new(archive / "completion.json", completion)  # W7
  if _read(root, (archive / "completion.json").relative_to(root)) != completion: raise ValueError("Reactivation completion readback differs")
  _retire(root, guard, release_db, pending, pending_intent, marker)  # W8, W9, W10
  return {**json.loads(completion), "reactivated": True, "requalification_required": False, "maintenance_transition_id": identifier,
          "live_execution": False, "qualification_issued": False}


def _reactivation_active(root, context, marker_intent, baseline):
  """The ACTIVE-state postchecks shared by W6, post-W7 recovery and post-W8 verification."""
  receipt_raw = _read(root, P.RECEIPT)
  if P.digest(receipt_raw) != marker_intent["staged_receipt_sha256"] or P.verify(root, marker_intent["staged_receipt_sha256"]) is not True:
    raise ValueError("Source default is not active")
  _opt_in(root)
  _idle(root)
  if _runtime(root) != marker_intent["runtime_review_sha256"]: raise ValueError("Reviewed runtime changed during reactivation")
  context["postchecks"](root, baseline)


def _reactivation_recover(root, context, release_db):
  """Re-run after a crash or failure: authenticate our own pending, then roll back or finish retirement."""
  guard, pinned = context["guard"], context["pinned"]
  pending_path = PENDINGS["activation"]
  raw = _read(root, pending_path)
  pending = P._json(raw)
  if type(pending) is not dict or pending.get("protocol") != REACTIVATION_SCHEMA or _encoded(pending) != raw:
    raise ValueError("Activation pending is not a reactivation intent; a foreign or runtime-upgrade barrier is preserved untouched")
  if set(pending) != REACTIVATION_KEYS or pending["action"] != "reactivation" or type(pending["limine"]) is not dict or set(pending["limine"]) != REACTIVATION_LIMINE:
    raise ValueError("Exact reactivation intent required")
  identifier, maintenance_id = PRODUCT.TX.uuid_value(pending["transition_id"]), PRODUCT.TX.uuid_value(pending["maintenance_transition_id"])
  for name in ("marker_sha256", "baseline_sha256", "policy_sha256"): P._hash(pending[name])
  limine = pending["limine"]
  for name in REACTIVATION_LIMINE: P._hash(limine[name])
  archive = root / HISTORY / identifier
  G._ancestors(root, archive / "member", _owner(root))
  marker_present = _present(root / MAINTENANCE)
  marker = _read(root, MAINTENANCE) if marker_present else _read(root, HISTORY / maintenance_id / "maintenance-intent.json")
  if P.digest(marker) != pending["marker_sha256"]: raise ValueError("Maintenance marker is not the one this reactivation bound")
  marker_intent = P._json(marker)
  if type(marker_intent) is not dict or marker_intent.get("transition_id") != maintenance_id: raise ValueError("Maintenance transition differs from the reactivation intent")
  baseline_raw = _read(root, HISTORY / maintenance_id / BASELINE_NAME)
  if P.digest(baseline_raw) != pending["baseline_sha256"]: raise ValueError("Generation baseline is not the one this reactivation bound")
  baseline = read_baseline(root, marker)
  review_raw = _read(root, REVIEW)
  if P.digest(review_raw) != pending["policy_sha256"] or pending["policy_sha256"] != marker_intent["old_policy_sha256"]:
    raise ValueError("Reviewed policy is not the one this reactivation bound")
  receipt_raw, backup = _read(root, P.RECEIPT), _read(root, P.BACKUP)
  proposal = P.prepare(backup, receipt_raw)
  if _canonical_digest(backup) != limine["from_canonical_sha256"] or _canonical_digest(proposal["after"]) != limine["to_canonical_sha256"]:
    raise ValueError("Retained backup or approved proposal differs from the reactivation intent")
  current = _read(root, P.LIMINE, private=False)
  digest = _canonical_digest(current)
  if digest not in (limine["from_canonical_sha256"], limine["to_canonical_sha256"]): raise ValueError("Unrelated Limine drift; nothing was touched")
  switched = digest == limine["to_canonical_sha256"]
  present = {name: _present(archive / name) for name in ("intent.json", "comparison.json", "completion.json", ROLLBACK_NAME)}
  if switched or _present(root / P.POLICY) or _present(root / OPT_IN):
    # Boot state was changed: the archive written before it must be complete and exact (before that, a torn archive is only noise).
    if not (present["intent.json"] and present["comparison.json"]) or _read(root, (archive / "intent.json").relative_to(root)) != raw:
      raise ValueError("Reactivation archive does not match the pending while boot state is changed; nothing was touched")
    comparison = P._json(_read(root, (archive / "comparison.json").relative_to(root)))
    if type(comparison) is not dict or comparison.get("protocol") != REACTIVATION_COMPARISON or comparison.get("transition_id") != identifier or comparison.get("intent_sha256") != P.digest(raw):
      raise ValueError("Archived comparison does not match the reactivation pending")
    if _present(archive / "policy.json") and _read(root, (archive / "policy.json").relative_to(root)) != review_raw:
      raise ValueError("Archived policy differs from the reviewed policy")
  completion = _reactivation_completion(identifier, raw, proposal["after"])
  # A torn or foreign completion is never trusted: it cannot lead forward.
  complete = present["completion.json"] and _read(root, (archive / "completion.json").relative_to(root)) == completion
  guard()
  if not marker_present:
    # Only W9 remains: the marker is gone and the completion is durable.
    if not complete or present[ROLLBACK_NAME]: raise ValueError("Marker missing without a valid completion; state preserved")
    _reactivation_active(root, context, marker_intent, baseline)
    _retire_pending(root, guard, release_db, root / pending_path, raw)
    return {**json.loads(completion), "reactivated": True, "recovered": "retired-pending", "requalification_required": False,
            "maintenance_transition_id": maintenance_id, "live_execution": False, "qualification_issued": False}
  if complete and not present[ROLLBACK_NAME]:
    try: _reactivation_active(root, context, marker_intent, baseline)
    except Exception: pass  # checks failed after W7: never proceed forward, roll back below
    else:
      _retire(root, guard, release_db, root / pending_path, raw, marker)
      return {**json.loads(completion), "reactivated": True, "recovered": "finished-retirement", "requalification_required": False,
              "maintenance_transition_id": maintenance_id, "live_execution": False, "qualification_issued": False}
  return _reactivation_rollback(root, context, release_db, raw=raw, identifier=identifier, archive=archive, rolled=present[ROLLBACK_NAME],
                                entry=P.source_entry(P._json(receipt_raw)), review_raw=review_raw, backup=backup, current=current,
                                switched=switched, maintenance_id=maintenance_id)


def _reactivation_rollback(root, context, release_db, *, raw, identifier, archive, rolled, entry, review_raw, backup, current, switched, maintenance_id):
  """Reverse only what this reactivation wrote, in reverse order; every step is idempotent and resumable."""
  guard, gate, pinned = context["guard"], context["gate"], context["pinned"]
  pending_path = PENDINGS["activation"]
  touched = switched or _present(root / P.POLICY) or _present(root / OPT_IN)
  for name in ("limine.conf.source-default-" + identifier, "limine.conf.source-default-" + identifier + "-rollback"):
    stray = (root / P.LIMINE).with_name(name)
    if _present(stray):
      if not stat.S_ISREG(stray.lstat().st_mode): raise ValueError("Stray staged configuration is not a regular file")
      guard()
      stray.unlink()
      _sync(stray.parent)
  if switched:
    reverse = _to_stock_default(current, entry)
    if P.limine_canonical(reverse) != P.limine_canonical(backup): raise ValueError("Rolled-back configuration is not the retained backup apart from the snapshot region")
    guard()
    _replace(root, current, reverse, identifier + "-rollback", guard=guard)
  if _present(root / OPT_IN):
    _opt_in(root)
    guard()
    (root / OPT_IN).unlink()
    _sync((root / OPT_IN).parent)
  if _present(root / P.POLICY):
    if _read(root, P.POLICY) != review_raw: raise ValueError("Active policy is not the reviewed policy; preserved")
    guard()
    (root / P.POLICY).unlink()
    _sync((root / P.POLICY).parent)
  evidence = G._maintenance(root, ignore=(pending_path,))
  pinned["resume"] = evidence["resume"]
  if touched: gate(root, "retained")
  if not rolled:
    guard()
    if not _present(archive):
      archive.mkdir(mode=0o700)
      _sync(archive.parent)
    _new(archive / ROLLBACK_NAME, _encoded({"protocol": REACTIVATION_ROLLBACK, "transition_id": identifier, "intent_sha256": P.digest(raw),
                                            "maintenance_transition_id": maintenance_id}))
  _retire_pending(root, guard, release_db, root / pending_path, raw)
  return {"protocol": REACTIVATION_ROLLBACK, "transition_id": identifier, "reactivated": False, "rolled_back": True,
          "maintenance_transition_id": maintenance_id, "live_execution": False, "qualification_issued": False}


# --- pair retirement evidence and new-generation rebind -------------------------------------------
#
# A kernel update makes the qualified generation obsolete (assess: requalification-required). The old pair is
# retired by the stager (its receipt file and images are deleted), a NEW pair is built, audited, staged and
# qualified, and `rebind` then installs the new authority and returns maintenance to ACTIVE source-default
# hibernation. It is modelled on reactivation: same locks, the activation-pending name under its own protocol,
# archive-before-write, one point of no return (the default_entry line), rollback to the exact prior maintenance
# state before completion, forward-only finish after it. It issues nothing: the config, qualification and boot
# policy review are external inputs, and no hardware evidence is produced or implied.
#
# Custody of the old receipt: the maintenance chain (update guard, assess) reads the receipt bytes the marker pins.
# Retiring the old pair deletes them, so the stager leaves RETIRED_RECEIPT plus a strict RETIREMENT record
# chaining to the marker's staged_receipt_sha256. marker_receipt() resolves either source; a receipt whose
# digest is neither is refused, so a NEW receipt at the fixed path never satisfies the OLD marker.
#
# Write order (each preceded by guard()):
#   W1 rebind pending   W2 archive (intent, comparison, old and new authority copies, fresh baseline, retirement)
#   W3 install config, qualification, boot-policy-review, backup (atomic replaces)   W4 boot-policy.json
#   W5 boot-config line (point of no return)   W6 opt-in   W7 ACTIVE postchecks   W8 completion.json
#   W9 unlink marker   W10 unlink pending, release the package lock
# Recovery of any interruption is a re-run: it rolls back to the exact prior maintenance state (never forward
# past W5) or, once a valid completion is durable, finishes W9/W10.


def rebind_pending(root):
  """True when the activation-pending name holds THIS engine's rebind intent (never a reactivation or runtime barrier)."""
  root = Path(root)
  G._ancestors(root, root / PENDINGS["activation"], _owner(root))
  try: value = P._json(_read(root, PENDINGS["activation"]))
  except (OSError, ValueError): return False
  return type(value) is dict and value.get("protocol") == REBIND_SCHEMA


def retirement(root, receipt_sha256):
  """(record, record bytes, retained receipt bytes) proving the stager retired the pair whose receipt has this digest."""
  raw = _required(root, RETIREMENT, "Pair retirement record")
  record = P._json(raw)
  if type(record) is dict and record.get("retired_receipt_sha256") != P._hash(receipt_sha256) and set(record) == RETIREMENT_KEYS:
    raise ValueError("Pair retirement record does not chain to the maintenance receipt")
  retained = _required(root, RETIRED_RECEIPT, "Retained retired receipt")
  if P.digest(retained) != receipt_sha256: raise ValueError("Retained retired receipt differs from the maintenance receipt")
  CUSTODY.check(record, retained)  # exact keys, hashes, and the record's images equal the retained receipt's own
  return record, raw, retained


def _file_sha256(path):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    sha = hashlib.sha256()
    while True:
      chunk = os.read(fd, 1024 * 1024)
      if not chunk: return sha.hexdigest()
      sha.update(chunk)
  finally: os.close(fd)


def _retired_images_gone(root, record):
  """Retirement really happened: no ESP image still has a retired image's hash (absent, or different bytes of the new pair)."""
  for role, relative in CUSTODY.IMAGE_PATHS.items():
    path = root / relative
    if not _present(path): continue
    if not stat.S_ISREG(path.lstat().st_mode) or _file_sha256(path) == record[role + "_sha256"]:
      raise ValueError("A retired " + role + " image is still on the ESP; the pair is not retired")


def marker_receipt(root, intent):
  """The receipt bytes a maintenance intent pins: the live receipt while it is the old one, else the retained copy of a retired pair."""
  wanted = intent["staged_receipt_sha256"]
  try: live = _read(root, P.RECEIPT)
  except FileNotFoundError: live = None
  if live is not None and P.digest(live) == wanted: return live
  record, _raw, retained = retirement(root, wanted)
  _retired_images_gone(root, record)
  return retained


def _required(root, relative, what):
  try: return _read(root, relative)
  except FileNotFoundError: raise ValueError(what + " required: " + relative.name + "; nothing was changed") from None


def _swap(root, relative, expected, replacement, tag, guard):
  """Atomically replace one private authority file whose current bytes must be exactly `expected`."""
  path = root / relative
  if _read(root, relative) != expected: raise ValueError("Authority file changed before replacement: " + relative.name)
  temporary = path.with_name(relative.name + ".rebind-" + tag)
  _new(temporary, replacement, stat.S_IMODE(path.lstat().st_mode))
  guard()
  if _read(root, relative) != expected: raise ValueError("Authority file changed immediately before replacement: " + relative.name)
  os.replace(temporary, path)
  _sync(path.parent)
  if _read(root, relative) != replacement: raise ValueError("Authority replacement readback failed: " + relative.name)


def _publish(path, raw, mode, tag):
  """Torn-write-safe publication of a new name: a complete temporary is renamed into place, so the name never holds partial bytes.

  The exclusions held by the caller cover cooperating writers; the existence check is the exclusive-create intent.
  """
  if _present(path): raise FileExistsError(str(path))
  temporary = path.with_name(path.name + ".rebind-tmp-" + tag)
  _new(temporary, raw, mode)
  os.replace(temporary, path)
  _sync(path.parent)


def trial_evidence(root, manifest):
  """The generation trial's terminal record for this manifest, read and validated before rebind writes anything.

  Authoritative record: the ledger's reconciled cycle file `generations/<manifest12>/ledger/cycle-<id>.json` (the state
  `trial.execute` makes durable when the trial retires its slots and reconciles). The qualification's evidence_sha256 must be the
  SHA-256 of its exact bytes. The generation's consumed guard must name the same reserved cycle, and the ledger must be unblocked
  and hold exactly this one cycle. Every directory is a real 0700 owner directory and every file a private single-link regular file.
  """
  identity = PRODUCT.TX.digest(manifest)[:12]
  base = TRIAL_GENERATIONS / identity
  for relative in (TRIAL_GENERATIONS, base, base / "guards", base / "ledger"):
    G._ancestors(root, root / relative / "member", _owner(root))
    try: info = (root / relative).lstat()
    except FileNotFoundError: raise ValueError("Generation trial state required: " + str(relative)) from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != _owner(root) or stat.S_IMODE(info.st_mode) != 0o700:
      raise ValueError("Private real generation trial directory required: " + str(relative))
  def load(relative, what):
    try: return _read(root, relative)
    except FileNotFoundError: raise ValueError(what + " required: " + str(relative)) from None
  cycles = sorted(path.name for path in (root / base / "ledger").iterdir() if path.name.startswith("cycle-") and path.name.endswith(".json"))
  if len(cycles) != 1: raise ValueError("Exactly one generation trial cycle required")
  cycle_raw = load(base / "ledger" / cycles[0], "Generation trial cycle")
  cycle = PRODUCT.TX.cycle_value(P._json(cycle_raw))
  if cycles[0] != "cycle-" + cycle["cycle_id"] + ".json" or cycle["manifest"] != manifest:
    raise ValueError("Generation trial cycle does not belong to the staged manifest")
  if cycle["state"] != "reconciled": raise ValueError("Generation trial cycle is not reconciled: " + cycle["state"])
  ledger_state = P._json(load(base / "ledger" / "state.json", "Generation trial ledger state"))
  if type(ledger_state) is not dict or ledger_state.get("blocked") is not False or ledger_state.get("manifest") != manifest:
    raise ValueError("Generation trial ledger is blocked or for another manifest")
  guard_raw = load(base / "guards" / "trial-consumed.json", "Consumed generation trial guard")
  guard = P._json(guard_raw)
  reserved = guard.get("cycle") if type(guard) is dict else None
  if (type(reserved) is not dict or guard.get("protocol") != PRODUCT.TX.TRIAL_PROTOCOL or reserved.get("cycle_id") != cycle["cycle_id"] or
      reserved.get("vector") != cycle["vector"] or reserved.get("manifest") != manifest):
    raise ValueError("Consumed generation trial guard does not name this cycle")
  return {"cycle_sha256": P.digest(cycle_raw), "cycle_raw": cycle_raw, "guard_raw": guard_raw}


def _rebind_refuse_assessment(assessment):
  if type(assessment) is not dict or assessment.get("class") not in ("unchanged", "requalification-required", "unknown"):
    raise ValueError("compatibility unknown: malformed assessment; nothing was changed")
  if assessment["class"] == "unchanged":
    raise ValueError("generation unchanged: use `reactivate`, not `rebind`; nothing was changed")
  if assessment["class"] == "unknown":
    detail = assessment.get("reason") or "unknown items: " + ", ".join(assessment.get("unknown_items", []))
    raise ValueError("compatibility unknown: " + detail + "; rebind needs a definite requalification-required assessment; nothing was changed")


def _rebind_completion(transition_id, pending_intent, canonical_sha256):
  return _encoded({"protocol": REBIND_COMPLETE, "transition_id": transition_id, "action": "rebind",
                   "intent_sha256": P.digest(pending_intent), "configuration_canonical_sha256": canonical_sha256})


def _rebind(root, *, guard, gate, assess, inspect, postchecks, native=None, pinned=None):
  """Internal rebind core; the live form needs the native capability and its own callbacks.

  gate(root, "retained")          maintenance read-only prerequisites (route, vetoes, fallback, no image)
  assess(evidence, marker)        lock-free assessment core; only `requalification-required` may proceed
  inspect(evidence, staged)       product-level validation of the staged {config, qualification} (parsed): must return
                                  {"manifest": derived manifest, "baseline": freshly captured generation items}
  postchecks(root, baseline)      native ACTIVE-state checks (deployment, product, generation == fresh baseline, no image)
  pinned                          dict the gate reads the archived resume tuple from
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir(): raise ValueError("Canonical root required")
  _live_maintenance(root, gate, native)
  if not all(callable(item) for item in (guard, gate, assess, inspect, postchecks)): raise ValueError("Explicit callbacks required")
  context = {"guard": guard, "gate": gate, "assess": assess, "inspect": inspect, "postchecks": postchecks, "pinned": {} if pinned is None else pinned}
  guard()
  _reactivation_state_refusals(root)
  for relative in (PENDINGS["activation"], MAINTENANCE): G._ancestors(root, root / relative, _owner(root))
  if not _present(root / PENDINGS["activation"]) and not _present(root / MAINTENANCE):
    raise ValueError("Inactive package maintenance marker required; nothing to rebind")
  with _locks(root) as release_db:
    guard()
    _reactivation_state_refusals(root)
    if _present(root / PENDINGS["activation"]): return _rebind_recover(root, context, release_db)
    return _rebind_forward(root, context, release_db)


def _rebind_forward(root, context, release_db):
  guard, gate, pinned = context["guard"], context["gate"], context["pinned"]
  for relative in (P.POLICY, OPT_IN, PENDINGS["activation"], PENDINGS["deactivation"]):
    G._ancestors(root, root / relative, _owner(root))
    if _present(root / relative): raise ValueError("Existing source-default policy, opt-in or pending refuses rebind: " + relative.name)
  evidence = G._maintenance(root)
  pinned["resume"] = evidence["resume"]
  marker = _read(root, MAINTENANCE)
  intent = P._json(marker)
  identifier = evidence["transition_id"]
  if _runtime(root) != intent["runtime_review_sha256"]: raise ValueError("Reviewed runtime differs from the maintenance intent; upgrade the runtime under maintenance first")
  gate(root, "retained")
  assessment = context["assess"](evidence, marker)
  _rebind_refuse_assessment(assessment)
  if _read(root, MAINTENANCE) != marker: raise ValueError("Maintenance marker changed during assessment")
  baseline_raw = _read(root, HISTORY / identifier / BASELINE_NAME)
  baseline = read_baseline(root, marker)
  # The old pair must be gone and provably the one the marker pinned; a NEW pair must be staged in its place.
  new_receipt_raw = _required(root, P.RECEIPT, "Staged replacement pair receipt")
  new_receipt_sha = P.digest(new_receipt_raw)
  if new_receipt_sha == intent["staged_receipt_sha256"]: raise ValueError("The old pair is still staged; retire it and stage the new pair first")
  record, record_raw, old_receipt_raw = retirement(root, intent["staged_receipt_sha256"])
  new_receipt = P._json(new_receipt_raw)
  old_manifest = baseline["manifest"]["fields"]
  for role in ("source", "restore"):
    if record[role + "_sha256"] != old_manifest.get(role + "_sha256"): raise ValueError("Pair retirement record does not name the retired " + role + " image")
    if P._hash(new_receipt["images"][role]["sha256"]) == record[role + "_sha256"]: raise ValueError("The staged " + role + " image is the retired one; a new pair is required")
  raws = {name: _required(root, relative, "Staged replacement authority") for name, relative in STAGED.items()}
  new_config, new_qualification = P._json(raws["config"]), P._json(raws["qualification"])
  if type(new_config) is not dict or type(new_config.get("manifest")) is not dict: raise ValueError("Staged configuration lacks a manifest")
  if new_config.get("staged_receipt_sha256") != new_receipt_sha: raise ValueError("Staged configuration does not bind the staged pair receipt")
  PRODUCT.TX.receipt_value(new_qualification, new_config["manifest"])
  if new_config["manifest"] == old_manifest: raise ValueError("Staged manifest equals the retired generation's; nothing was requalified")
  for role in ("source", "restore"):
    if new_config["manifest"].get(role + "_sha256") != new_receipt["images"][role]["sha256"]: raise ValueError("Staged manifest does not pin the staged " + role + " image")
  trial = trial_evidence(root, new_config["manifest"])
  if new_qualification["evidence_sha256"] != trial["cycle_sha256"]:
    raise ValueError("Qualification evidence does not bind the generation trial's reconciled cycle; nothing was changed")
  info = context["inspect"](evidence, {"config": new_config, "qualification": new_qualification})
  if type(info) is not dict or info.get("manifest") != new_config["manifest"]: raise ValueError("Derived manifest differs from the staged configuration")
  fresh = _baseline_value(info["baseline"])
  for name in ("config", "qualification"):  # the fresh capture must have read exactly the bytes this run will install
    if fresh[name].get("sha256") != P.digest(raws[name]): raise ValueError("Fresh generation capture read different " + name + " bytes than the staged file")
  old_raws = {"config": _read(root, CONFIG), "qualification": _read(root, QUALIFICATION), "review": _read(root, REVIEW), "backup": _read(root, P.BACKUP)}
  if P.digest(old_raws["review"]) != intent["old_policy_sha256"] or old_raws["review"] != _read(root, HISTORY / identifier / "policy.json"):
    raise ValueError("Reviewed policy differs from the archived old policy")
  if P._json(old_raws["config"]).get("staged_receipt_sha256") != intent["staged_receipt_sha256"]: raise ValueError("Current configuration does not bind the maintenance receipt")
  # New boot policy: the staged pair bytes (the retained pair backup with the current snapshot region spliced in) must match the receipt.
  policy = P._json(raws["review"])
  donor = _required(root, PAIR_BACKUP, "Staged pair Limine backup")
  if P.digest(donor) != new_receipt["original_limine_sha256"]: raise ValueError("Pair Limine backup differs from the staged receipt")
  current = _read(root, P.LIMINE, private=False)
  G._stock(current)
  staged = P.with_region(current, donor)
  if P.digest(staged) != P._hash(new_receipt["staged_limine_sha256"]):
    raise ValueError("Unrelated Limine drift: the current configuration is not the staged pair bytes apart from the snapshot region")
  proposal = P.prepare(staged, new_receipt_raw)
  P.validate(policy, staged, proposal["after"], new_receipt_raw)
  replacement = _to_source_default(current, policy["source_entry_id"])
  if P.limine_canonical(replacement) != P.limine_canonical(proposal["after"]): raise ValueError("Source-default bytes differ from the approved proposal")
  new_raws = {"config": raws["config"], "qualification": raws["qualification"], "review": raws["review"], "backup": staged}
  same = [name for name in old_raws if old_raws[name] == new_raws[name]]
  if same: raise ValueError("Replacement authority equals the current authority: " + ", ".join(same))
  _idle(root)
  # --- writes ---------------------------------------------------------------------------------
  transition_id = str(uuid.uuid4())
  limine = {"from_sha256": P.digest(current), "to_sha256": P.digest(replacement),
            "from_canonical_sha256": _canonical_digest(current), "to_canonical_sha256": _canonical_digest(replacement)}
  baseline_new = _encoded({"protocol": REBIND_BASELINE, "transition_id": transition_id, "items": {**fresh, "limine": stock_identity(current)}})
  if len(baseline_new) > P.MAX_BYTES: raise ValueError("Fresh generation baseline exceeds the bounded evidence size")
  pending_intent = _encoded({"protocol": REBIND_SCHEMA, "transition_id": transition_id, "action": "rebind", "maintenance_transition_id": identifier,
    "marker_sha256": P.digest(marker), "baseline_sha256": P.digest(baseline_raw), "retirement_sha256": P.digest(record_raw),
    "retired_receipt_sha256": P.digest(old_receipt_raw), "new_receipt_sha256": new_receipt_sha, "new_baseline_sha256": P.digest(baseline_new),
    "trial_evidence_sha256": trial["cycle_sha256"],
    "old": {name: P.digest(raw) for name, raw in old_raws.items()}, "new": {name: P.digest(raw) for name, raw in new_raws.items()}, "limine": limine})
  comparison = _encoded({"protocol": REBIND_COMPARISON, "transition_id": transition_id, "intent_sha256": P.digest(pending_intent),
                         "assessment": assessment, "limine": limine})
  pending = root / PENDINGS["activation"]
  # A torn W1 temporary from an earlier dead run holds no authority (it never became the pending): clear it, never adopt it.
  for stray in sorted(pending.parent.glob(pending.name + ".rebind-tmp-*")):
    if not stat.S_ISREG(stray.lstat().st_mode): raise ValueError("Stray staged pending is not a regular file")
    guard()
    stray.unlink()
    _sync(stray.parent)
  guard()
  _publish(pending, pending_intent, 0o600, transition_id)  # W1: sleep and updates are vetoed from here on
  archive = root / HISTORY / transition_id
  guard()
  archive.mkdir(mode=0o700)
  _sync(archive.parent)
  files = [("intent.json", pending_intent, 0o600), ("comparison.json", comparison, 0o600), ("new-baseline.json", baseline_new, 0o600),
           ("retirement.json", record_raw, 0o600), ("retired-receipt.json", old_receipt_raw, 0o600), ("new-receipt.json", new_receipt_raw, 0o600), ("opt-in", b"", 0o644),
           ("trial-cycle.json", trial["cycle_raw"], 0o600), ("trial-guard.json", trial["guard_raw"], 0o600)]
  files += [(REBIND_ARCHIVE[side][name], raw, 0o600) for side, values in (("old", old_raws), ("new", new_raws)) for name, raw in values.items()]
  for name, raw, mode in files:
    guard()
    _new(archive / name, raw, mode)  # W2
  for name, relative in AUTHORITY:
    guard()
    _swap(root, relative, old_raws[name], new_raws[name], transition_id, guard)  # W3
  guard()
  _publish(root / P.POLICY, raws["review"], 0o600, transition_id)  # W4
  guard()
  _replace(root, current, replacement, transition_id, guard=guard)  # W5: point of no return; recovery only rolls back
  guard()
  _new(root / OPT_IN, b"", 0o644)  # W6
  _rebind_active(root, context, intent, new_receipt_sha, fresh)  # W7
  completion = _rebind_completion(transition_id, pending_intent, limine["to_canonical_sha256"])
  guard()
  _new(archive / "completion.json", completion)  # W8
  if _read(root, (archive / "completion.json").relative_to(root)) != completion: raise ValueError("Rebind completion readback differs")
  _retire(root, guard, release_db, pending, pending_intent, marker)  # W9, W10
  return {**json.loads(completion), "rebound": True, "requalification_required": False, "maintenance_transition_id": identifier,
          "live_execution": False, "qualification_issued": False}


def _rebind_active(root, context, marker_intent, new_receipt_sha, fresh):
  """The ACTIVE-state postchecks shared by W7, post-W8 recovery and post-W9 verification."""
  if P.digest(_read(root, P.RECEIPT)) != new_receipt_sha or P.verify(root, new_receipt_sha) is not True:
    raise ValueError("Source default is not active for the new generation")
  _opt_in(root)
  _idle(root)
  if _runtime(root) != marker_intent["runtime_review_sha256"]: raise ValueError("Reviewed runtime changed during rebind")
  context["postchecks"](root, fresh)


def _rebind_pending_value(raw):
  """Exact canonical rebind intent, or a refusal that preserves whatever else uses the shared filename."""
  pending = P._json(raw)
  if type(pending) is not dict or pending.get("protocol") != REBIND_SCHEMA or _encoded(pending) != raw:
    raise ValueError("Activation pending is not a rebind intent; a foreign, reactivation or runtime-upgrade barrier is preserved untouched")
  if set(pending) != REBIND_KEYS or pending["action"] != "rebind" or type(pending["limine"]) is not dict or set(pending["limine"]) != REACTIVATION_LIMINE:
    raise ValueError("Exact rebind intent required")
  names = {name for name, _ in AUTHORITY}
  if any(type(pending[side]) is not dict or set(pending[side]) != names for side in ("old", "new")): raise ValueError("Exact rebind authority digests required")
  PRODUCT.TX.uuid_value(pending["transition_id"])
  PRODUCT.TX.uuid_value(pending["maintenance_transition_id"])
  for name in ("marker_sha256", "baseline_sha256", "retirement_sha256", "retired_receipt_sha256", "new_receipt_sha256", "new_baseline_sha256", "trial_evidence_sha256"): P._hash(pending[name])
  for side in ("old", "new"):
    for name in names: P._hash(pending[side][name])
  for name in REACTIVATION_LIMINE: P._hash(pending["limine"][name])
  return pending


def _rebind_recover(root, context, release_db):
  """Re-run after a crash or failure: authenticate our own pending, then roll back or finish retirement."""
  guard = context["guard"]
  pending_path = PENDINGS["activation"]
  raw = _read(root, pending_path)
  pending = _rebind_pending_value(raw)
  identifier, maintenance_id = pending["transition_id"], pending["maintenance_transition_id"]
  archive = root / HISTORY / identifier
  G._ancestors(root, archive / "member", _owner(root))
  marker_present = _present(root / MAINTENANCE)
  marker = _read(root, MAINTENANCE) if marker_present else _read(root, HISTORY / maintenance_id / "maintenance-intent.json")
  if P.digest(marker) != pending["marker_sha256"]: raise ValueError("Maintenance marker is not the one this rebind bound")
  marker_intent = P._json(marker)
  if type(marker_intent) is not dict or marker_intent.get("transition_id") != maintenance_id: raise ValueError("Maintenance transition differs from the rebind intent")
  if P.digest(_read(root, HISTORY / maintenance_id / BASELINE_NAME)) != pending["baseline_sha256"]: raise ValueError("Generation baseline is not the one this rebind bound")
  if P.digest(_read(root, HISTORY / maintenance_id / "policy.json")) != marker_intent["old_policy_sha256"]: raise ValueError("Archived old policy is not the one the marker pins")
  # Where each authority file is: exactly the old bytes or exactly the new bytes, nothing else.
  where = {}
  for name, relative in AUTHORITY:
    digest = P.digest(_required(root, relative, "Authority file"))
    if digest == pending["old"][name]: where[name] = "old"
    elif digest == pending["new"][name]: where[name] = "new"
    else: raise ValueError("Authority file is neither the old nor the new bytes; nothing was touched: " + relative.name)
  if _present(root / P.POLICY) and P.digest(_read(root, P.POLICY)) != pending["new"]["review"]:
    raise ValueError("Active policy is not the new reviewed policy; preserved")
  limine = pending["limine"]
  current = _read(root, P.LIMINE, private=False)
  digest = _canonical_digest(current)
  if digest not in (limine["from_canonical_sha256"], limine["to_canonical_sha256"]): raise ValueError("Unrelated Limine drift; nothing was touched")
  switched = digest == limine["to_canonical_sha256"]
  touched = switched or "new" in where.values() or _present(root / P.POLICY) or _present(root / OPT_IN)
  present = {name: _present(archive / name) for name in ("intent.json", "comparison.json", "completion.json", ROLLBACK_NAME, "new-baseline.json", "new-receipt.json")}
  if touched:
    # Boot state or authority was changed: the archive written before it must be complete and exact.
    if not (present["intent.json"] and present["comparison.json"]) or _read(root, (archive / "intent.json").relative_to(root)) != raw:
      raise ValueError("Rebind archive does not match the pending while state is changed; nothing was touched")
    comparison = P._json(_read(root, (archive / "comparison.json").relative_to(root)))
    if type(comparison) is not dict or comparison.get("protocol") != REBIND_COMPARISON or comparison.get("transition_id") != identifier or comparison.get("intent_sha256") != P.digest(raw):
      raise ValueError("Archived comparison does not match the rebind pending")
    for side in ("old", "new"):
      for name, archived in REBIND_ARCHIVE[side].items():
        if not _present(archive / archived) or P.digest(_read(root, (archive / archived).relative_to(root))) != pending[side][name]:
          raise ValueError("Archived " + side + " " + name + " is missing or differs from the rebind pending; nothing was touched")
    if not present["new-baseline.json"] or P.digest(_read(root, (archive / "new-baseline.json").relative_to(root))) != pending["new_baseline_sha256"]:
      raise ValueError("Archived fresh baseline differs from the rebind pending; nothing was touched")
    for name, digest_ in (("new-receipt.json", pending["new_receipt_sha256"]), ("retirement.json", pending["retirement_sha256"]), ("retired-receipt.json", pending["retired_receipt_sha256"]), ("trial-cycle.json", pending["trial_evidence_sha256"])):
      if not _present(archive / name) or P.digest(_read(root, (archive / name).relative_to(root))) != digest_:
        raise ValueError("Archived " + name + " differs from the rebind pending; nothing was touched")
  completion = _rebind_completion(identifier, raw, limine["to_canonical_sha256"])
  # A torn or foreign completion is never trusted: it cannot lead forward.
  complete = present["completion.json"] and _read(root, (archive / "completion.json").relative_to(root)) == completion
  fresh = P._json(_read(root, (archive / "new-baseline.json").relative_to(root)))["items"] if touched else None
  guard()
  if not marker_present:
    # Only W10 remains: the marker is gone and the completion is durable.
    if not complete or present[ROLLBACK_NAME] or "old" in where.values(): raise ValueError("Marker missing without a valid completion; state preserved")
    _rebind_active(root, context, marker_intent, pending["new_receipt_sha256"], fresh)
    _retire_pending(root, guard, release_db, root / pending_path, raw)
    return {**json.loads(completion), "rebound": True, "recovered": "retired-pending", "requalification_required": False,
            "maintenance_transition_id": maintenance_id, "live_execution": False, "qualification_issued": False}
  if complete and not present[ROLLBACK_NAME] and "old" not in where.values():
    try: _rebind_active(root, context, marker_intent, pending["new_receipt_sha256"], fresh)
    except Exception: pass  # checks failed after W8: never proceed forward, roll back below
    else:
      _retire(root, guard, release_db, root / pending_path, raw, marker)
      return {**json.loads(completion), "rebound": True, "recovered": "finished-retirement", "requalification_required": False,
              "maintenance_transition_id": maintenance_id, "live_execution": False, "qualification_issued": False}
  return _rebind_rollback(root, context, release_db, raw=raw, pending=pending, archive=archive, rolled=present[ROLLBACK_NAME], where=where,
                          current=current, switched=switched, touched=touched)


def _rebind_rollback(root, context, release_db, *, raw, pending, archive, rolled, where, current, switched, touched):
  """Reverse only what this rebind wrote, in reverse order; every step is idempotent and resumable."""
  guard, gate, pinned = context["guard"], context["gate"], context["pinned"]
  pending_path = PENDINGS["activation"]
  identifier = pending["transition_id"]
  strays = [(root / relative).with_name(relative.name + ".rebind-" + identifier + suffix) for _, relative in AUTHORITY for suffix in ("", "-rollback")]
  strays += [(root / P.LIMINE).with_name("limine.conf.source-default-" + identifier + suffix) for suffix in ("", "-rollback")]
  strays += [(root / relative).with_name(relative.name + ".rebind-tmp-" + identifier) for relative in (P.POLICY, PENDINGS["activation"])]
  for stray in strays:
    if _present(stray):
      if not stat.S_ISREG(stray.lstat().st_mode): raise ValueError("Stray staged file is not a regular file")
      guard()
      stray.unlink()
      _sync(stray.parent)
  if switched:
    entry = P.source_entry(P._json(_read(root, (archive / "new-receipt.json").relative_to(root))))
    reverse = _to_stock_default(current, entry)
    if _canonical_digest(reverse) != pending["limine"]["from_canonical_sha256"]: raise ValueError("Rolled-back configuration is not the prior maintenance configuration")
    guard()
    _replace(root, current, reverse, identifier + "-rollback", guard=guard)
  if _present(root / OPT_IN):
    _opt_in(root)
    guard()
    (root / OPT_IN).unlink()
    _sync((root / OPT_IN).parent)
  if _present(root / P.POLICY):
    if P.digest(_read(root, P.POLICY)) != pending["new"]["review"]: raise ValueError("Active policy is not the new reviewed policy; preserved")
    guard()
    (root / P.POLICY).unlink()
    _sync((root / P.POLICY).parent)
  for name, relative in reversed(AUTHORITY):
    if where[name] == "new":
      guard()
      _swap(root, relative, _read(root, relative), _read(root, (archive / REBIND_ARCHIVE["old"][name]).relative_to(root)), identifier + "-rollback", guard)
      if P.digest(_read(root, relative)) != pending["old"][name]: raise ValueError("Rolled-back authority differs from the recorded old bytes: " + relative.name)
  evidence = G._maintenance(root, ignore=(pending_path,))
  pinned["resume"] = evidence["resume"]
  if touched: gate(root, "retained")
  if not rolled:
    guard()
    if not _present(archive):
      archive.mkdir(mode=0o700)
      _sync(archive.parent)
    _new(archive / ROLLBACK_NAME, _encoded({"protocol": REBIND_ROLLBACK, "transition_id": identifier, "intent_sha256": P.digest(raw),
                                            "maintenance_transition_id": pending["maintenance_transition_id"]}))
  _retire_pending(root, guard, release_db, root / pending_path, raw)
  return {"protocol": REBIND_ROLLBACK, "transition_id": identifier, "rebound": False, "rolled_back": True,
          "maintenance_transition_id": pending["maintenance_transition_id"], "live_execution": False, "qualification_issued": False}
