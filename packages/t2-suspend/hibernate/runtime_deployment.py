"""Copy an externally reviewed source inventory to the fixed private runtime.

This module never imports or executes the source tree, installs a service, issues
qualification, copies UKIs/unlock assets or performs host power operations.
Source may be user-owned: externally reviewed exact byte hashes are the boundary.
Only the root-owned, verified snapshot is suitable for privileged execution.
Fresh deployment refuses overwrite. A separate bounded fixture upgrade retains
old runtime/authority/config and requires a compatible admission barrier.
Live upgrades require a separately reviewed adapter; interrupted upgrades never
replay automatically. Runtime-only v2 upgrades preserve exact config bytes.

The ordinary upgrade refuses while package-maintenance.pending exists: the marker pins the runtime review it
was published under. `maintenance=True` is the only path that may upgrade under a marker. It requires the
runtime-only v2 pins, and rewrites the marker's runtime binding under the same barrier: the archived
maintenance intent, generation baseline (which binds the intent digest) and the marker are replaced together,
after the old bytes are retained beside them (see _maintenance_binding and settle_maintenance_binding).
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid


STATE = Path("/var/lib/omarchy/t2-hibernate-product")
RUNTIME = STATE / "runtime"
REVIEW = STATE / "runtime-deployment-review.json"
SCHEMA = "omarchy-t2-product-runtime-snapshot-v1"
TREES = ("packages/t2-suspend/hibernate", "packages/t2-suspend/experiments")
ENTRYPOINT = TREES[0] + "/product.py"
UPDATE_GUARD_HOOK = TREES[0] + "/00-omarchy-t2-hibernate-guard.hook"
MANIFEST = "snapshot.json"
PENDING = ".runtime-pending"
UPGRADE_PENDING = "runtime-upgrade.pending"
COMPATIBLE_BARRIER = "source-default-activation.pending"
CONFIG = "config.json"
BOOTSTRAP = "runtime-deployment-bootstrap.py"
CANDIDATE_REVIEW = "runtime-upgrade-review.json"
CANDIDATE_CONFIG = "runtime-upgrade-config.json"
CANDIDATE_BOOTSTRAP = "runtime-upgrade-bootstrap.py"
HOOK = Path("etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook")
DEACTIVATION_PENDING = "source-default-deactivation.pending"
MAINTENANCE_PENDING = "package-maintenance.pending"
HISTORY = "boot-policy-transitions"
MAINTENANCE_SCHEMA = "omarchy-t2-package-maintenance-intent-v1"
MAINTENANCE_FIELDS = {"protocol", "transition_id", "old_policy_sha256", "runtime_review_sha256", "staged_receipt_sha256",
                      "fallback_limine_sha256", "deactivation_completion_sha256"}
BASELINE_NAME = "generation-baseline.json"
BASELINE_SCHEMA = "omarchy-t2-generation-baseline-v1"
REBIND_RECORD_SCHEMA = "omarchy-t2-runtime-marker-rebind-v1"
INTENT_MAINTENANCE = "omarchy-t2-runtime-upgrade-maintenance-intent-v1"
COMPLETED_MAINTENANCE = "omarchy-t2-runtime-upgrade-maintenance-completed-v1"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
CHUNK = 1024 * 1024


def _encoded(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _source_name(name):
  path = PurePosixPath(name)
  if path.is_absolute() or ".." in path.parts or str(path) != name or not any(name.startswith(tree + "/") for tree in TREES):
    raise ValueError("Runtime source path outside fixed code trees")
  if any(part.startswith(".") for part in path.parts): raise ValueError("Hidden runtime source path")
  allowed = path.suffix in (".py", ".md", ".c", ".conf", ".patch", ".service", ".sh")
  # This reviewed pacman hook template is code, not a general asset extension.
  allowed |= name == UPDATE_GUARD_HOOK
  allowed |= path.name in ("Makefile", "Kbuild", "functions")
  allowed |= not path.suffix and (path.parent.name in ("hooks", "install") or path.name.startswith(("run-", "omarchy-")))
  if not allowed: raise ValueError("Non-source asset cannot enter runtime snapshot")


def _open_directory(path):
  path = Path(path)
  if not path.is_absolute() or ".." in path.parts: raise ValueError("Explicit absolute deployment path required")
  fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try:
    for part in path.parts[1:]:
      child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
      os.close(fd)
      fd = child
    return fd
  except BaseException:
    os.close(fd)
    raise


def _private(fd, directory=False):
  info = os.fstat(fd)
  expected = stat.S_ISDIR if directory else stat.S_ISREG
  if not expected(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
    raise ValueError("Runtime destination/review must be current-owner private")
  if not directory and info.st_nlink != 1: raise ValueError("Runtime file has multiple links")


def _source_fd(source, name):
  _source_name(name)
  fd = _open_directory(Path(source) / Path(name).parent)
  try:
    child = os.open(Path(name).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
  finally:
    os.close(fd)
  info = os.fstat(child)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_FILE:
    os.close(child)
    raise ValueError("Runtime source must be bounded regular non-linked bytes")
  return child


def _identity(fd):
  size, digest = 0, hashlib.sha256()
  while True:
    raw = os.read(fd, CHUNK)
    if not raw: break
    size += len(raw)
    if size > MAX_FILE: raise ValueError("Runtime source exceeds byte limit")
    digest.update(raw)
  return {"size": size, "sha256": digest.hexdigest()}


def inventory(source_directory):
  """Read-only exact source inventory; this is NOT approval or qualification."""
  source = Path(source_directory)
  descriptor = _open_directory(source)
  os.close(descriptor)
  files = {}
  for tree in TREES:
    start = source / tree
    descriptor = _open_directory(start)
    os.close(descriptor)
    for directory, folders, names in os.walk(start, followlinks=False):
      for name in folders:
        if (Path(directory) / name).is_symlink(): raise ValueError("Symlinked runtime source directory")
      folders[:] = [name for name in folders if name != "__pycache__"]
      for name in sorted(names):
        if name == ".gitattributes": continue
        relative = (Path(directory) / name).relative_to(source).as_posix()
        fd = _source_fd(source, relative)
        try: files[relative] = _identity(fd)
        finally: os.close(fd)
  if ENTRYPOINT not in files: raise ValueError("Missing routine dispatcher")
  if sum(value["size"] for value in files.values()) > MAX_TOTAL: raise ValueError("Runtime source inventory exceeds limit")
  return dict(sorted(files.items()))


def _verify_tree(directory, expected):
  actual = inventory(directory)
  if actual != expected: raise ValueError("Runtime snapshot byte inventory differs")
  for current, folders, names in os.walk(directory, followlinks=False):
    fd = _open_directory(current)
    try: _private(fd, directory=True)
    finally: os.close(fd)
    for name in names:
      fd = os.open(Path(current) / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
      try: _private(fd)
      finally: os.close(fd)


def deploy_snapshot(source_directory, *, root):
  """Copy reviewed bytes exclusively; explicit root maps only fixed destinations.

  Live root `/` requires root identity. Other roots are synthetic test fixtures.
  The fixed root-private REVIEW is authored externally, never by this helper.
  Publication is after file/directory fsync and exact private readback only.
  """
  root = Path(root)
  if not root.is_absolute(): raise ValueError("Explicit absolute deployment root required")
  if root == Path("/") and os.geteuid() != 0: raise ValueError("Explicit root deployment required")
  state = root / STATE.relative_to("/")
  parent = _open_directory(state)
  lock = None
  try:
    _private(parent, directory=True)
    lock = os.open("runtime-deployment.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    _private(lock)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return _deploy_locked(source_directory, state, parent)
  finally:
    if lock is not None: os.close(lock)
    os.close(parent)


def _pairs(items):
  value = {}
  for key, item in items:
    if key in value: raise ValueError("Duplicate runtime review field")
    value[key] = item
  return value


def _private_read(parent, name):
  fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
  try:
    _private(fd)
    raw = os.read(fd, MAX_FILE + 1)
    if len(raw) > MAX_FILE: raise ValueError("Private deployment input exceeds limit")
    return raw
  finally: os.close(fd)


def _review(raw):
  review = json.loads(raw, object_pairs_hook=_pairs)
  if type(review) is not dict or set(review) != {"protocol", "approved", "reviewed_commit", "files"}:
    raise ValueError("Runtime review fields differ")
  if review["protocol"] != SCHEMA or review["approved"] is not True or type(review["reviewed_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", review["reviewed_commit"]):
    raise ValueError("Explicit reviewed source approval required")
  return review


def _deploy_locked(source_directory, state, parent):
  """Caller owns runtime-deployment.lock throughout the complete publication."""
  if any(name in os.listdir(parent) for name in ("runtime", PENDING)):
    raise ValueError("Existing or partial runtime snapshot refuses overwrite")
  raw = _private_read(parent, REVIEW.name)
  review = _review(raw)
  expected = inventory(source_directory)
  if review["files"] != expected: raise ValueError("Source bytes differ from independently reviewed inventory")
  os.mkdir(PENDING, mode=0o700, dir_fd=parent)
  os.fsync(parent)
  staging = state / PENDING
  for name, identity in expected.items():
    target = staging / name
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Normalize every new directory under this exclusive private staging tree.
    for directory in (target.parent, *target.parent.parents):
      if directory == state: break
      directory.chmod(0o700)
    src = _source_fd(source_directory, name)
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
      size, digest = 0, hashlib.sha256()
      while True:
        chunk = os.read(src, CHUNK)
        if not chunk: break
        size += len(chunk)
        if size > MAX_FILE: raise ValueError("Source changed beyond bounded size")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
          written = os.write(out, view)
          if written <= 0: raise OSError("Short runtime snapshot write")
          view = view[written:]
      if {"size": size, "sha256": digest.hexdigest()} != identity: raise ValueError("Source changed while copying approved bytes")
      os.fchmod(out, 0o600)
      os.fsync(out)
    finally:
      os.close(src)
      os.close(out)
  _verify_tree(staging, expected)
  completion = {"protocol": SCHEMA, "reviewed_commit": review["reviewed_commit"], "review_sha256": hashlib.sha256(raw).hexdigest(),
                "files": expected, "entrypoint": ENTRYPOINT}
  fd = os.open(staging / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(fd, "wb") as stream:
    stream.write(_encoded(completion))
    stream.flush()
    os.fchmod(stream.fileno(), 0o600)
    os.fsync(stream.fileno())
  if (staging / MANIFEST).read_bytes() != _encoded(completion):
    raise ValueError("Runtime completion readback differs")
  for directory, folders, names in os.walk(staging, topdown=False):
    fd = _open_directory(directory)
    try: os.fsync(fd)
    finally: os.close(fd)
  os.rename(PENDING, "runtime", src_dir_fd=parent, dst_dir_fd=parent)
  os.fsync(parent)
  _verify_tree(state / "runtime", expected)
  return completion


def _new_private(parent, name, raw):
  fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fchmod(stream.fileno(), 0o600)
    os.fsync(stream.fileno())
  os.fsync(parent)


def _match_reviewed(raw, review, name):
  if review["files"].get(name) != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
    raise ValueError("Authority bytes differ from reviewed runtime: " + name)


def _installed_hook(root):
  path = root / HOOK
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1 or info.st_size > MAX_FILE:
      raise ValueError("Exact installed regular update guard required")
    raw = os.read(fd, MAX_FILE + 1)
    if len(raw) > MAX_FILE: raise ValueError("Oversized installed update guard")
    return raw
  finally: os.close(fd)


def _approval_identity(value):
  if type(value) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) or uuid.UUID(value).version != 4:
    raise ValueError("Fresh canonical UUID4 runtime upgrade approval required")
  return value


def _canonical_uuid(value):
  if type(value) is not str or str(uuid.UUID(value)) != value: raise ValueError("Canonical UUID required")
  return value


def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _private_file(path):
  """Bounded owner-private regular bytes at a named path (no symlink, single link)."""
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    _private(fd)
    raw = os.read(fd, MAX_FILE + 1)
    if len(raw) > MAX_FILE: raise ValueError("Private maintenance evidence exceeds limit")
    return raw
  finally: os.close(fd)


def _private_directory(path):
  info = os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
    raise ValueError("Owner-private maintenance evidence directory required")


def _fsync_directory(path):
  fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try: os.fsync(fd)
  finally: os.close(fd)


def _write_private(path, raw, *, replace):
  """Durable owner-private file: exclusive create, or atomic replace of an existing one via a same-directory temporary."""
  target = Path(path)
  temporary = target.with_name(target.name + ".runtime-rebind-tmp") if replace else target
  if replace and os.path.lexists(temporary):
    if not stat.S_ISREG(os.lstat(temporary).st_mode): raise ValueError("Stray rebind temporary is not a regular file")
    os.unlink(temporary)
  fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fchmod(stream.fileno(), 0o600)
    os.fsync(stream.fileno())
  if replace: os.replace(temporary, target)
  _fsync_directory(target.parent)


def _maintenance_binding(old_marker, old_baseline, old_review, new_review):
  """Pure: the marker and generation baseline bytes for a marker moved from one runtime review to another.

  The marker's only runtime-dependent field is runtime_review_sha256. The archived baseline binds the marker's
  digest, so it moves with it; nothing else in either document changes.
  """
  marker = json.loads(old_marker, object_pairs_hook=_pairs)
  if type(marker) is not dict or set(marker) != MAINTENANCE_FIELDS or marker["protocol"] != MAINTENANCE_SCHEMA or _encoded(marker) != old_marker:
    raise ValueError("Exact canonical maintenance intent required")
  _canonical_uuid(marker["transition_id"])
  if marker["runtime_review_sha256"] != old_review: raise ValueError("Maintenance marker is not bound to the old runtime review")
  baseline = json.loads(old_baseline, object_pairs_hook=_pairs)
  if (type(baseline) is not dict or baseline.get("protocol") != BASELINE_SCHEMA or baseline.get("transition_id") != marker["transition_id"] or
      baseline.get("maintenance_intent_sha256") != _sha(old_marker) or _encoded(baseline) != old_baseline):
    raise ValueError("Exact generation baseline bound to the maintenance intent required")
  new_marker = _encoded({**marker, "runtime_review_sha256": new_review})
  return new_marker, _encoded({**baseline, "maintenance_intent_sha256": _sha(new_marker)})


def _binding_names(new_review):
  tag = new_review[:12]
  return ("maintenance-intent.before-runtime-" + tag + ".json", "generation-baseline.before-runtime-" + tag + ".json", "runtime-rebind-" + tag + ".json")


def _maintenance_plan(state, parent, old_review, new_review):
  """Read-only validation of the marker, its archive and baseline before any write; refuses any prior rebind evidence."""
  try: marker = _private_read(parent, MAINTENANCE_PENDING)
  except FileNotFoundError: raise ValueError("Maintenance runtime upgrade requires the package maintenance marker") from None
  identifier = _canonical_uuid(json.loads(marker, object_pairs_hook=_pairs).get("transition_id"))
  archive = state / HISTORY / identifier
  for directory in (state / HISTORY, archive): _private_directory(directory)
  if _private_file(archive / "maintenance-intent.json") != marker: raise ValueError("Maintenance marker differs from its archived intent")
  baseline = _private_file(archive / BASELINE_NAME)
  new_marker, new_baseline = _maintenance_binding(marker, baseline, old_review, new_review)
  if any(os.path.lexists(archive / name) for name in _binding_names(new_review)) or os.path.lexists(state / (MAINTENANCE_PENDING + ".runtime-rebind-tmp")):
    raise ValueError("Existing runtime marker rebind evidence refuses automatic retry")
  return {"archive": archive, "marker": marker, "baseline": baseline, "new_marker": new_marker, "new_baseline": new_baseline}


def _converge_binding(state, archive, forms, target):
  """Bring baseline, archived intent and marker to exactly the old or the new form; any other bytes are foreign."""
  documents = ((archive / BASELINE_NAME, forms["baseline"]), (archive / "maintenance-intent.json", forms["marker"]), (state / MAINTENANCE_PENDING, forms["marker"]))
  current = [_private_file(path) for path, _ in documents]
  # Every file is proven to be one of the two known forms before any is written: foreign bytes leave all three untouched.
  for (path, (old, new)), raw in zip(documents, current):
    if raw not in (old, new): raise ValueError("Maintenance evidence is neither the old nor the new bytes; preserved: " + path.name)
  for (path, (old, new)), raw in zip(documents, current):
    wanted = new if target == "new" else old
    if raw != wanted: _write_private(path, wanted, replace=True)


def _retain_binding(archive, expected, approval_id, old_marker, old_baseline, new_marker, new_baseline):
  """Create-if-missing the retained old evidence and the rebind record; an existing file must already be exactly the expected bytes."""
  old_marker_name, old_baseline_name, record_name = _binding_names(expected["new_review"])
  record = _encoded({"protocol": REBIND_RECORD_SCHEMA, "approval_id": approval_id,
    "old_review_sha256": expected["old_review"], "new_review_sha256": expected["new_review"],
    "old_marker_sha256": _sha(old_marker), "new_marker_sha256": _sha(new_marker),
    "old_baseline_sha256": _sha(old_baseline), "new_baseline_sha256": _sha(new_baseline)})
  for name, raw in ((old_marker_name, old_marker), (old_baseline_name, old_baseline), (record_name, record)):
    if os.path.lexists(archive / name):
      if _private_file(archive / name) != raw: raise ValueError("Retained runtime rebind evidence differs; preserved: " + name)
    else: _write_private(archive / name, raw, replace=False)


def _apply_maintenance_binding(state, plan, expected, approval_id):
  """Retain the old evidence, record the rebind, then move baseline, archived intent and marker to the new runtime binding."""
  _retain_binding(plan["archive"], expected, approval_id, plan["marker"], plan["baseline"], plan["new_marker"], plan["new_baseline"])
  _converge_binding(state, plan["archive"], {"marker": (plan["marker"], plan["new_marker"]), "baseline": (plan["baseline"], plan["new_baseline"])}, "new")


def settle_maintenance_binding(state, record, installed_review):
  """Idempotent recovery: make marker, archived intent and baseline agree with the runtime review actually installed.

  `record` is the upgrade's maintenance intent (review digests, approval and the old marker digest); `installed_review`
  is the SHA-256 of the installed runtime-deployment-review.json. The old bytes come from the retained copies or, when a
  crash preceded them, from the still-old current files (which are then retained first). Anything foreign, or a new
  binding whose old evidence was never retained, raises and is preserved untouched.
  """
  state = Path(state)
  old_review, new_review = record["old_review_sha256"], record["new_review_sha256"]
  if installed_review == new_review: target = "new"
  elif installed_review == old_review: target = "old"
  else: raise ValueError("Installed runtime review is neither the old nor the new one; marker binding preserved")
  marker = _private_file(state / MAINTENANCE_PENDING)
  identifier = _canonical_uuid(json.loads(marker, object_pairs_hook=_pairs).get("transition_id"))
  archive = state / HISTORY / identifier
  old_marker_name, old_baseline_name, _ = _binding_names(new_review)
  # The retained copies are written before any replacement, so a missing copy means that document is still the old one.
  old_marker = _private_file(archive / old_marker_name) if os.path.lexists(archive / old_marker_name) else marker
  old_baseline = _private_file(archive / old_baseline_name) if os.path.lexists(archive / old_baseline_name) else _private_file(archive / BASELINE_NAME)
  if _sha(old_marker) != record["marker_sha256"]: raise ValueError("Old maintenance marker is not the one the upgrade pinned; preserved")
  new_marker, new_baseline = _maintenance_binding(old_marker, old_baseline, old_review, new_review)
  _retain_binding(archive, {"old_review": old_review, "new_review": new_review}, record["approval_id"], old_marker, old_baseline, new_marker, new_baseline)
  _converge_binding(state, archive, {"marker": (old_marker, new_marker), "baseline": (old_baseline, new_baseline)}, target)
  return target


def _upgrade_snapshot(source_directory, *, root, expected, guard, precheck, postcheck, approval_id=None, maintenance=False):
  """Internal core; live caller must be a separately reviewed fixed native adapter.

  The adapter must own a real sleep:shutdown block inhibitor, pacman db.lck and
  the physical-cycle flock, verify idle power/current boot at every guard(),
  pin all expected old/new hashes, and supply fixed old admission precheck().
  postcheck() must verify the *new* installed runtime/config under the still-
  present compatibility barrier, not call product.check() which vetoes it.
  `maintenance=True` upgrades under package-maintenance.pending and additionally rewrites the marker's
  runtime binding (see the module docstring); the ordinary call refuses when the marker exists.
  Callbacks are fixture injections only in the public API below. No live CLI.
  Incomplete publication retains the compatible admission veto and available
  evidence; no automatic retry API exists.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical absolute upgrade root required")
  if type(expected) is not dict or set(expected) != {"old_review", "old_bootstrap", "old_config", "new_review", "new_bootstrap", "new_config"}:
    raise ValueError("Exact old/new externally reviewed pins required")
  if any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) for value in expected.values()):
    raise ValueError("Invalid exact upgrade pin")
  if any(not callable(callback) for callback in (guard, precheck, postcheck)):
    raise ValueError("Fixed guard, precheck and barrier-aware postcheck required")
  if type(maintenance) is not bool: raise ValueError("Explicit boolean maintenance mode required")
  # The ordinary path treats the marker as a blocker; only the maintenance path may run under it.
  blockers = (UPGRADE_PENDING, COMPATIBLE_BARRIER, DEACTIVATION_PENDING, PENDING) + (() if maintenance else (MAINTENANCE_PENDING,))
  state = root / STATE.relative_to("/")
  parent = _open_directory(state)
  lock = None
  try:
    _private(parent, directory=True)
    lock = os.open("runtime-deployment.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    _private(lock)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    guard()
    if any(os.path.lexists(state / name) for name in blockers):
      raise ValueError("Existing or partial runtime upgrade refuses automatic retry")
    old_raw = _private_read(parent, REVIEW.name)
    bootstrap = _private_read(parent, BOOTSTRAP)
    config = _private_read(parent, CONFIG)
    incoming_raw = _private_read(parent, CANDIDATE_REVIEW)
    incoming_bootstrap = _private_read(parent, CANDIDATE_BOOTSTRAP)
    incoming_config = _private_read(parent, CANDIDATE_CONFIG)
    for name, raw in (("old_review", old_raw), ("old_bootstrap", bootstrap), ("old_config", config),
                      ("new_review", incoming_raw), ("new_bootstrap", incoming_bootstrap), ("new_config", incoming_config)):
      if hashlib.sha256(raw).hexdigest() != expected[name]: raise ValueError("Exact upgrade pin differs: " + name)
    old_review, incoming = _review(old_raw), _review(incoming_raw)
    for raw, review in ((bootstrap, old_review), (incoming_bootstrap, incoming)):
      _match_reviewed(raw, review, TREES[0] + "/runtime_deployment.py")
    hook_raw = _installed_hook(root)
    for review in (old_review, incoming):
      _match_reviewed(hook_raw, review, UPDATE_GUARD_HOOK)
    if old_review["reviewed_commit"] == incoming["reviewed_commit"]:
      raise ValueError("Upgrade requires a distinct reviewed source commit")
    runtime_fd = _open_directory(state / "runtime")
    try:
      _private(runtime_fd, directory=True)
      old_snapshot = json.loads(_private_read(runtime_fd, MANIFEST), object_pairs_hook=_pairs)
    finally: os.close(runtime_fd)
    if old_snapshot.get("review_sha256") != expected["old_review"] or old_snapshot.get("files") != old_review["files"] or old_snapshot.get("reviewed_commit") != old_review["reviewed_commit"]:
      raise ValueError("Current runtime receipt differs from approved old review")
    _verify_tree(state / "runtime", old_review["files"])
    if inventory(source_directory) != incoming["files"]:
      raise ValueError("New source differs from exact approved inventory")
    old_config = json.loads(config, object_pairs_hook=_pairs)
    new_config = json.loads(incoming_config, object_pairs_hook=_pairs)
    if type(old_config) is not dict or type(new_config) is not dict or new_config.get("schema") != "omarchy-t2-qualified-product-config-v2":
      raise ValueError("Expected v1 to v2 or exact v2 runtime configuration upgrade")
    runtime_only = old_config.get("schema") == "omarchy-t2-qualified-product-config-v2"
    consumed = None
    if runtime_only:
      _approval_identity(approval_id)
      if config != incoming_config:
        raise ValueError("Runtime-only v2 upgrade must preserve exact configuration bytes")
      consumed = "runtime-upgrade-approval-consumed-" + approval_id + ".json"
    elif old_config.get("schema") == "omarchy-t2-qualified-product-config-v1" and approval_id is None:
      if set(new_config) != set(old_config) | {"power_policy"} or any(new_config[key] != old_config[key] for key in old_config if key != "schema"):
        raise ValueError("Config upgrade changed non-policy artifact or qualification fields")
    else:
      raise ValueError("Historical v1 upgrade cannot use runtime-only approval")
    if type(new_config["power_policy"]) is not dict or set(new_config["power_policy"]) != {"schema", "min_charge_percent"} or new_config["power_policy"]["schema"] != "omarchy-t2-attended-battery-policy-v1" or type(new_config["power_policy"]["min_charge_percent"]) is not int or not 30 <= new_config["power_policy"]["min_charge_percent"] <= 100:
      raise ValueError("Explicit bounded battery policy required")
    if maintenance and not runtime_only: raise ValueError("Maintenance runtime upgrade requires the exact runtime-only v2 configuration")
    plan = _maintenance_plan(state, parent, expected["old_review"], expected["new_review"]) if maintenance else None
    old_prefix, new_prefix = old_review["reviewed_commit"][:12], incoming["reviewed_commit"][:12]
    retained = (("runtime", "runtime-retained-" + old_prefix + "-before-" + new_prefix),
                (REVIEW.name, "runtime-review-retained-" + old_prefix + "-before-" + new_prefix + ".json"),
                (BOOTSTRAP, "runtime-bootstrap-retained-" + old_prefix + "-before-" + new_prefix + ".py"),
                (CONFIG, "config-retained-" + old_prefix + "-before-" + new_prefix + ".json"))
    completed = "runtime-upgrade-completed-" + new_prefix + ".json"
    if any(os.path.lexists(state / name) for name in (*blockers, completed,
                                                       *(target for source, target in retained), *((consumed,) if consumed else ()))):
      raise ValueError("Existing or partial runtime upgrade refuses automatic retry")
    guard()
    precheck()
    intent_record = {"protocol": INTENT_MAINTENANCE if maintenance else ("omarchy-t2-runtime-upgrade-intent-v2" if runtime_only else "omarchy-t2-runtime-upgrade-intent-v1"), "transaction_id": str(uuid.uuid4()),
                       "old_review_sha256": expected["old_review"], "new_review_sha256": expected["new_review"],
                       "old_config_sha256": expected["old_config"], "new_config_sha256": expected["new_config"]}
    if runtime_only: intent_record["approval_id"] = approval_id
    if maintenance: intent_record["marker_sha256"] = _sha(plan["marker"])
    intent = _encoded(intent_record)
    # Installed 608464dd sleep_entry and product both veto this existing name
    # by presence. The distinct payload must never be fed to boot-policy code.
    guard()
    _new_private(parent, COMPATIBLE_BARRIER, intent)
    guard()
    _new_private(parent, UPGRADE_PENDING, intent)
    if consumed:
      guard()
      _new_private(parent, consumed, intent)
    for source, target in retained:
      guard()
      if os.path.lexists(state / target): raise ValueError("Retained target appeared")
      os.rename(source, target, src_dir_fd=parent, dst_dir_fd=parent)
      os.fsync(parent)
    for name, raw in ((REVIEW.name, incoming_raw), (BOOTSTRAP, incoming_bootstrap)):
      guard()
      _new_private(parent, name, raw)
    guard()
    completion = _deploy_locked(source_directory, state, parent)
    guard()
    _new_private(parent, CONFIG, incoming_config)
    if (_private_read(parent, CONFIG) != incoming_config or _private_read(parent, REVIEW.name) != incoming_raw or
        _private_read(parent, BOOTSTRAP) != incoming_bootstrap):
      raise ValueError("Published configuration or authority differs")
    _verify_tree(state / "runtime", incoming["files"])
    if completion["review_sha256"] != expected["new_review"]:
      raise ValueError("Published runtime receipt differs")
    if maintenance:
      guard()
      _apply_maintenance_binding(state, plan, expected, approval_id)
    guard()
    postcheck()
    guard()
    completed_raw = _encoded({"protocol": COMPLETED_MAINTENANCE if maintenance else ("omarchy-t2-runtime-upgrade-completed-v2" if runtime_only else "omarchy-t2-runtime-upgrade-completed-v1"),
      "intent": json.loads(intent, object_pairs_hook=_pairs), "review_sha256": expected["new_review"],
      "config_sha256": expected["new_config"]})
    _new_private(parent, completed, completed_raw)
    if _private_read(parent, completed) != completed_raw:
      raise ValueError("Upgrade completion readback differs")
    guard()
    if _private_read(parent, UPGRADE_PENDING) != intent:
      raise ValueError("Upgrade intent changed before retirement")
    os.unlink(UPGRADE_PENDING, dir_fd=parent)
    os.fsync(parent)
    guard()
    if _private_read(parent, COMPATIBLE_BARRIER) != intent:
      raise ValueError("Compatible admission barrier changed")
    os.unlink(COMPATIBLE_BARRIER, dir_fd=parent)
    os.fsync(parent)
    return completion
  finally:
    if lock is not None: os.close(lock)
    os.close(parent)


def upgrade_snapshot(source_directory, *, root, expected, guard, precheck, postcheck, approval_id=None, maintenance=False):
  """Fixture-only transaction; live upgrade needs a separately reviewed adapter."""
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root == Path("/"):
    raise ValueError("Fixture-only runtime upgrade refuses live root and aliases")
  return _upgrade_snapshot(source_directory, root=root, expected=expected, guard=guard,
                           precheck=precheck, postcheck=postcheck, approval_id=approval_id, maintenance=maintenance)
