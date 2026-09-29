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


def _stable_bytes(root, relative, limit, *, keep=False):
  """Bounded owned regular bytes with SHA-256/BLAKE2b and unchanged identity."""
  path, owner = root / relative, _owner(root)
  G._ancestors(root, path, owner)
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
    intent = _encoded({"protocol": "omarchy-t2-source-default-transition-v1", "transition_id": transition_id,
      "action": mechanics, "policy_sha256": P.digest(policy_raw), "from_sha256": P.digest(actual), "to_sha256": P.digest(after)})
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
