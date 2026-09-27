"""Source-default transition core; public API remains fixture-only.

Public transition() unconditionally refuses live `/` and aliases. Its injected
fixture precheck cannot establish real admission. The separate installed native
adapter supplies fixed host verification and real logind power exclusion to the
internal core, after reviewed snapshot verification. No kernel, EFI, modules,
power, qualification issuance or automatic retry occurs here. Source tests and
installation alone do not approve or execute any native policy transition.
The explicit maintenance action is fixture-only groundwork: it leaves a durable
sleep/update veto but grants no package admission or live maintenance route.
"""
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
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
  if _read(root, P.LIMINE, private=False) != replacement: raise ValueError("Configuration replacement readback failed")


def transition(root, action, *, precheck, maintenance_continuation=None):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root.resolve() == Path("/"):
    raise ValueError("Fixture-only transition refuses live root and aliases")
  if action not in (*PENDINGS, "maintenance") or not callable(precheck): raise ValueError("Explicit fixture action/precheck required")
  return _transition(root, action, precheck=precheck, guard=lambda: None, maintenance_continuation=maintenance_continuation)


def _transition(root, action, *, precheck, guard, maintenance_continuation=None):
  """Internal core; maintenance is fixture-only groundwork, not update permission."""
  root = Path(root)
  if maintenance_continuation is not None and (root.resolve() == Path("/") or action != "maintenance" or not callable(maintenance_continuation)):
    raise ValueError("Explicit fixture-only maintenance continuation required")
  if action == "maintenance" and root.resolve() == Path("/"):
    raise ValueError("Live maintenance entry requires a separately reviewed native coordinator")
  if action not in (*PENDINGS, "maintenance"):
    raise ValueError("Explicit reviewed transition action required")
  mechanics = "deactivation" if action == "maintenance" else action
  guard()
  G._ancestors(root, root / MAINTENANCE, os.geteuid())
  if _present(root / MAINTENANCE): raise ValueError("Existing package maintenance intent refuses new transition")
  for path in PENDINGS.values():
    G._ancestors(root, root / path, os.geteuid())
    if _present(root / path): raise ValueError("Incomplete transition preserved; no automatic retry")
  with _locks(root) as release_db:
    if _present(root / MAINTENANCE) or any(_present(root / path) for path in PENDINGS.values()):
      raise ValueError("Incomplete transition or maintenance intent preserved")
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
      maintenance_intent = _encoded({"protocol": MAINTENANCE_SCHEMA, "transition_id": transition_id,
        "old_policy_sha256": P.digest(policy_raw), "runtime_review_sha256": runtime_review,
        "staged_receipt_sha256": P.digest(receipt_raw), "fallback_limine_sha256": P.digest(after),
        "deactivation_completion_sha256": P.digest(_encoded(completion))})
      guard()
      _new(archive / "maintenance-intent.json", maintenance_intent)
      if _read(root, (archive / "maintenance-intent.json").relative_to(root)) != maintenance_intent:
        raise ValueError("Archived maintenance intent readback differs")
      guard()
      _new(root / MAINTENANCE, maintenance_intent)
      if _read(root, MAINTENANCE) != maintenance_intent:
        raise ValueError("Package maintenance marker readback differs")
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
          G._ancestors(root, root / MAINTENANCE, os.geteuid())
          if not _present(root / MAINTENANCE):
            _new(root / MAINTENANCE, maintenance_intent)
            if _read(root, MAINTENANCE) != maintenance_intent:
              raise ValueError("Rearmed maintenance veto readback differs")
        except BaseException as error:
          raise RuntimeError("Maintenance veto durability unconfirmed") from error
    return result
