"""Read-only ALPM admission while the qualified source boot policy is inactive.

The blanket check() (no maintenance marker) admits only when boot-policy.json,
source-default-activation.pending, source-default-deactivation.pending,
package-maintenance.pending and runtime upgrade markers are all absent; their
presence blocks it regardless of contents. A present maintenance marker instead
routes the fixed CLI to the native inactive-maintenance path described below. Routine opt-in and EFI
loader overrides must also be absent, with efivarfs visible. Future
activation/deactivation must retain evidence elsewhere and exclusively own both
pacman's actual db.lck and the shared physical lock throughout their transition;
this one-shot guard cannot close an independently privileged activation race.

No deactivation, boot writes, automatic rebuild or qualification occurs here.
The fixed root CLI accepts no arguments or environment-based bypass. Explicit
canonical fixture roots are available only to imported offline tests.

Native inactive maintenance: when package-maintenance.pending exists the fixed
root CLI does not fall back to the blanket refusal. It first authenticates the
installed, root-isolated, reviewed-inventory runtime using only stdlib code in
this file (no sibling import precedes the byte pins), then holds the physical
cycle lock non-blockingly while the existing exact inactive-maintenance chain is
validated. Success admits an ordinary transaction; the marker is retained (it is
not a single-use grant), no qualification is issued and hibernation stays vetoed.
Pacman already owns db.lck during a hook, so that lock is never required absent.
Every unknown, partial, foreign or contended condition raises and blocks.

Under the same lock the reviewed image_state.require_no_image proves that the
pinned resume page holds no hibernation image. Its resume target is the exact
tuple the native publisher archived in maintenance-resume.json, validated by the
inactive validator; no qualified artifact derivation happens here, so an update
that rewrites the kernel/UKI never blocks later transactions. A stale swap
location fails closed via image_state's live /sys and btrfs topology checks.

Installation prerequisite and scope: this guard is meaningful only in a runtime
generation whose sleep_entry.py and product.py reject the maintenance marker.
Residual kernel-level routes the marker does not veto (suspend-then-hibernate,
hybrid-sleep, direct /sys/power/state writes) are out of this module's scope; the
saved-image check above is the backstop. Runtime modules are executed from the
byte-pinned reads and bytecode caches are ignored; nested imports inside those
modules rely on the whole-tree verification instead.
"""
import hashlib
import json
import os
import importlib.util
from pathlib import Path
import re
import stat
import sys
import fcntl
import types


STATE = Path("var/lib/omarchy/t2-hibernate-product")
EFI = Path("sys/firmware/efi/efivars")
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
ACTIVE = (STATE / "boot-policy.json", STATE / "source-default-activation.pending",
          STATE / "source-default-deactivation.pending", STATE / "package-maintenance.pending",
          STATE / "runtime-upgrade.pending", STATE / ".runtime-pending",
          Path("etc/omarchy/t2-hibernate-product.enabled"),
          EFI / ("LoaderEntryOneShot-" + LOADER_GUID), EFI / ("LoaderEntryDefault-" + LOADER_GUID))
LIMINE = Path("boot/limine.conf")
PRODUCTION = "boot():/EFI/Linux/omarchy_linux-t2.efi"
MAX_BYTES = 1024 * 1024
MAINTENANCE = STATE / "package-maintenance.pending"
PHYSICAL_LOCK = Path("var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock")
RUNTIME = STATE / "runtime"
REVIEW = STATE / "runtime-deployment-review.json"
SCRIPT = Path("/") / RUNTIME / "packages/t2-suspend/hibernate/update_guard.py"
MAX_REVIEW = 2 * 1024 * 1024
RESUME_NAME = "maintenance-resume.json"
RESUME_SCHEMA = "omarchy-t2-package-maintenance-resume-v1"
PAGE = 4096


def _stock(raw):
  """Bind index 2 to the ordinary production child, permitting updated hashes."""
  if len(raw) > MAX_BYTES: raise ValueError("Oversized Limine configuration")
  text = raw.decode("utf-8", errors="strict")
  lines = text.splitlines()
  defaults = [line for line in lines if re.match(r"^[ \t]*default_entry[ \t]*:", line, re.I)]
  if defaults != ["default_entry: 2"]:
    raise ValueError("Inactive updates require canonical stock default 2")
  if any(re.match(r"^[ \t]*remember_last_entry[ \t]*:", line, re.I) for line in lines):
    raise ValueError("Remembered boot selection is outside inactive stock policy")
  entries = [(index, line.strip()) for index, line in enumerate(lines) if line.strip().startswith("/")]
  if len(entries) < 2 or entries[0][1] != "/+Omarchy" or entries[1][1] != "//linux-t2":
    raise ValueError("Stock index 2 must select Omarchy's production linux-t2 child")
  start, end = entries[1][0] + 1, entries[2][0] if len(entries) > 2 else len(lines)
  properties = {}
  for line in lines[start:end]:
    if not line.strip() or line.lstrip().startswith("#"): continue
    if ":" not in line: raise ValueError("Malformed production boot entry")
    key, value = line.strip().split(":", 1)
    key = key.strip().lower()
    if key == "comment": continue
    if key in properties: raise ValueError("Ambiguous production boot entry")
    properties[key] = value.strip()
  if properties.get("protocol") != "efi" or not re.fullmatch(re.escape(PRODUCTION) + r"#[0-9a-f]{128}", properties.get("path", "")):
    raise ValueError("Stock index 2 must use the fixed production UKI path")
  if any(key in properties for key in ("image_path", "kernel_path", "module_path", "chainload_next")):
    raise ValueError("Alternate boot targets are outside inactive stock policy")


def _ancestors(root, path, owner):
  for parent in path.parents:
    try: info = parent.lstat()
    except FileNotFoundError:
      # Ordinary absent state directories are inactive. Existing ancestors
      # must still be checked, including a dangling intermediate symlink.
      continue
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner) or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink update admission ancestors required")
    if parent == root: break


def check(root):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Explicit canonical update-guard root required")
  owner = 0 if root == Path("/") else os.geteuid()
  if root == Path("/") and os.geteuid() != 0: raise ValueError("Root update admission required")
  for relative in ACTIVE:
    _ancestors(root, root / relative, owner)
    try: (root / relative).lstat()
    except FileNotFoundError: continue
    raise ValueError("T2 source policy or routine hibernation remains active/incomplete: " + str(relative))
  if not stat.S_ISDIR((root / EFI).lstat().st_mode):
    raise ValueError("Visible EFI variable directory required for inactive admission")
  path = root / LIMINE
  _ancestors(root, path, owner)
  initial = path.lstat()
  if not stat.S_ISREG(initial.st_mode): raise ValueError("Regular stock boot configuration required")
  descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or info.st_nlink != 1:
      raise ValueError("Owned regular stock boot configuration required")
    if info.st_size > MAX_BYTES: raise ValueError("Oversized Limine configuration")
    with os.fdopen(descriptor, "rb", closefd=False) as source: raw = source.read(MAX_BYTES + 1)
    _stock(raw)
  finally: os.close(descriptor)
  return {"classification": "inactive-stock-update-admitted", "default_entry": 2}


def check_inactive_maintenance(root):
  """Read-only fixture evidence for a future inactive-maintenance ALPM path.

  No live root/alias, Session, bypass flag, package grant or reactivation. The
  future reviewed publisher must prove no image BEFORE durable publication;
  neither this historical chain nor matching UKI bytes proves that condition
  or ordinary bootability. Its caller must hold the required exclusion: repeated
  reads detect observed drift, not an atomic snapshot. check/main stay unchanged.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root == Path("/"):
    raise ValueError("Fixture-only inactive maintenance refuses live roots and aliases")
  return _maintenance(root)


def _resume_target(resume):
  """Exact qualified resume shape, identical to image_state.require_no_image's."""
  if (type(resume) is not dict or set(resume) != {"device", "devnum", "offset"} or resume["device"] != "/dev/mapper/root" or
      type(resume["devnum"]) is not str or not re.fullmatch(r"[0-9]+:[0-9]+", resume["devnum"]) or
      type(resume["offset"]) is not int or not 0 < resume["offset"] <= (2**63 - 1 - PAGE) // PAGE):
    raise ValueError("Exact qualified resume target required")
  return {"device": resume["device"], "devnum": resume["devnum"], "offset": resume["offset"]}


def _resume_document(identifier, resume, intent):
  """Canonical archived resume evidence, bound to the maintenance intent's pinned chain.

  The audited resume tuple is pinned at publish time because the guard must not
  re-derive qualified artifacts: an OS/kernel update rewrites the production UKI,
  so derivation would block every later transaction. The live topology check in
  image_state still fails closed if the swap location has since moved.
  No pre-fix markers exist in the field (the installed runtime predates all of
  this), so a marker lacking this document is simply refused; there is no migration.
  """
  document = {"protocol": RESUME_SCHEMA, "transition_id": identifier, "resume": _resume_target(resume)}
  for name in ("old_policy_sha256", "staged_receipt_sha256", "deactivation_completion_sha256"):
    document[name] = intent[name]
  return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _load(name, path, expected=None):
  """Execute exactly the bytes read (never a cached .pyc or a re-opened path).

  `expected` is a reviewed inventory entry; when given, the bytes read must match
  it. Fixture callers pass None. Sibling imports made by the loaded module itself
  are covered by the whole-tree verification, not by this pin.
  """
  path = Path(path)
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_REVIEW: raise ValueError("Bounded regular runtime module required")
    raw = os.read(fd, MAX_REVIEW + 1)
  finally: os.close(fd)
  if len(raw) != info.st_size: raise ValueError("Short runtime module read")
  if expected is not None and expected != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
    raise ValueError("Runtime module bytes differ from reviewed inventory")
  return _execute(name, path, raw)


def _execute(name, path, raw):
  module = types.ModuleType(name)
  module.__file__ = str(path)
  exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
  return module


def _maintenance(root, inventory=None, *, ignore=()):
  """Exact inactive-maintenance validation; callers authenticate and lock first.

  `ignore` names known ACTIVE paths (never the marker) skipped by both source-state
  scans. Only the reviewed interrupted-publication completion passes it, after
  proving the exact bytes; every admission path uses the empty default.
  """
  if type(ignore) is not tuple or any(not isinstance(path, Path) or path not in ACTIVE or path == MAINTENANCE for path in ignore):
    raise ValueError("Ignore must name known active source paths other than the maintenance marker")
  # Lazy reuse avoids import-time cycles (the transition itself imports us).
  sibling = Path(__file__).with_name("package_maintenance.py")
  maintenance = _load("guard_maintenance_evidence", sibling, None if inventory is None else inventory["packages/t2-suspend/hibernate/package_maintenance.py"])
  transition, policy = maintenance.T, maintenance.T.P
  for relative in ACTIVE:
    if relative == transition.MAINTENANCE or relative in ignore: continue
    _ancestors(root, root / relative, os.geteuid())
    if transition._present(root / relative):
      raise ValueError("Active or incomplete source state prevents maintenance evidence")
  raw = transition._read(root, transition.MAINTENANCE)
  intent = policy._json(raw)
  fields = {"protocol", "transition_id", "old_policy_sha256", "runtime_review_sha256", "staged_receipt_sha256", "fallback_limine_sha256", "deactivation_completion_sha256"}
  if type(intent) is not dict or set(intent) != fields or intent["protocol"] != transition.MAINTENANCE_SCHEMA or transition._encoded(intent) != raw:
    raise ValueError("Exact canonical maintenance intent required")
  identifier = transition.PRODUCT.TX.uuid_value(intent["transition_id"])
  for name in fields - {"protocol", "transition_id"}: policy._hash(intent[name])
  archive = transition.HISTORY / identifier
  def private_directories():
    for relative in (STATE, transition.HISTORY, archive, STATE / "ledger"):
      info = (root / relative).lstat()
      if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Owned private maintenance evidence directories required")
  private_directories()
  paths = (transition.MAINTENANCE, archive / "maintenance-intent.json", archive / "policy.json",
           archive / "intent.json", archive / "completion.json", policy.BACKUP, archive / RESUME_NAME)
  evidence = {path: transition._read(root, path) for path in paths}
  # The receipt bytes the marker pins: the live staged receipt, or (after the stager retired that pair to stage a
  # replacement) the retained copy under a retirement record chained to the same digest. Anything else refuses.
  receipt = transition.marker_receipt(root, intent)
  if evidence[transition.MAINTENANCE] != raw or evidence[archive / "maintenance-intent.json"] != raw:
    raise ValueError("Maintenance marker/archive bytes differ")
  old_raw = evidence[archive / "policy.json"]
  if policy.digest(old_raw) != intent["old_policy_sha256"] or policy.digest(receipt) != intent["staged_receipt_sha256"]:
    raise ValueError("Retained policy or staged receipt pin differs")
  old = policy._json(old_raw)
  before = evidence[policy.BACKUP]
  proposal = policy.prepare(before, receipt)
  policy.validate(old, before, proposal["after"], receipt)
  expected_transition = {"protocol": "omarchy-t2-source-default-transition-v1", "transition_id": identifier,
    "action": "deactivation", "policy_sha256": policy.digest(old_raw),
    "from_sha256": old["after_limine_sha256"], "to_sha256": old["before_limine_sha256"]}
  if evidence[archive / "intent.json"] != transition._encoded(expected_transition):
    raise ValueError("Exact historical deactivation intent required")
  expected_completion = {"protocol": "omarchy-t2-source-default-transition-complete-v1", "transition_id": identifier,
    "action": "deactivation", "intent_sha256": policy.digest(evidence[archive / "intent.json"]),
    "configuration_sha256": old["before_limine_sha256"]}
  completion = evidence[archive / "completion.json"]
  if (completion != transition._encoded(expected_completion) or policy.digest(completion) != intent["deactivation_completion_sha256"] or
      intent["fallback_limine_sha256"] != old["before_limine_sha256"]):
    raise ValueError("Exact completed stock deactivation chain required")
  resume_raw = evidence[archive / RESUME_NAME]
  resume_doc = policy._json(resume_raw)
  if type(resume_doc) is not dict or _resume_document(identifier, resume_doc.get("resume"), intent) != resume_raw:
    raise ValueError("Exact archived resume target evidence required")
  resume = _resume_target(resume_doc["resume"])
  opt_in = transition._read(root, archive / "opt-in", private=False)
  if opt_in != b"" or stat.S_IMODE((root / archive / "opt-in").lstat().st_mode) != 0o644:
    raise ValueError("Historical routine opt-in differs")
  if transition._runtime(root) != intent["runtime_review_sha256"]:
    raise ValueError("Reviewed runtime differs from maintenance intent")
  transition._idle(root)
  fallback = maintenance._fallback(root)  # current coherent bytes may legitimately be NEW
  transition._idle(root)
  if any(transition._read(root, path) != value for path, value in evidence.items()) or transition.marker_receipt(root, intent) != receipt:
    raise ValueError("Maintenance evidence changed during verification")
  if transition._read(root, archive / "opt-in", private=False) != opt_in or transition._runtime(root) != intent["runtime_review_sha256"]:
    raise ValueError("Maintenance authority changed during verification")
  private_directories()
  if stat.S_IMODE((root / archive / "opt-in").lstat().st_mode) != 0o644:
    raise ValueError("Historical routine opt-in metadata changed")
  for relative in ACTIVE:
    if relative != transition.MAINTENANCE and relative not in ignore and transition._present(root / relative):
      raise ValueError("Source state appeared during maintenance verification")
  return {"classification": "fixture-inactive-maintenance-verified", "transition_id": identifier,
    "maintenance_intent_sha256": policy.digest(raw), "fallback": fallback, "resume": resume,
    "qualification_issued": False, "reactivation_evaluated": False}



def _private_bytes(path, owner):
  named = path.lstat()
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
        not 0 < info.st_size <= MAX_REVIEW or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)):
      raise ValueError("Stable bounded owner-private reviewed bytes required")
    raw = os.read(fd, MAX_REVIEW + 1)
    if len(raw) != info.st_size or (os.fstat(fd).st_mtime_ns, os.fstat(fd).st_size) != (info.st_mtime_ns, info.st_size):
      raise ValueError("Reviewed bytes changed or were short")
    return raw
  finally: os.close(fd)


def _pairs(items):
  value = {}
  for key, item in items:
    if key in value: raise ValueError("Duplicate reviewed inventory field")
    value[key] = item
  return value


def _authenticate(prefix, owner, isolated, script):
  """Installed, isolated, reviewed-inventory proof using ONLY this stdlib prelude.

  No sibling module is loaded before this file and the pinned stdlib-only
  runtime_deployment verifier match the externally reviewed inventory. A
  writable-workspace copy, a non-isolated interpreter or an unreviewed tree is
  refused. Hostile root is out of scope; this is not a defence against it.
  """
  prefix, script = Path(prefix), Path(script)
  state, runtime = prefix / STATE, prefix / RUNTIME
  if os.getresuid() != (owner,) * 3 or not isolated or script != runtime / "packages/t2-suspend/hibernate/update_guard.py":
    raise ValueError("Fixed root-private isolated installed update guard required")
  for path in (script, *script.parents):
    info = path.lstat()
    if info.st_uid != owner or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode) or (path != script and not stat.S_ISDIR(info.st_mode)):
      raise ValueError("Owned nonsymlink installed-guard ancestry required")
    if path == prefix: break
  for path in (state, runtime, *runtime.rglob("*")):
    info = path.lstat()
    directory = stat.S_ISDIR(info.st_mode)
    if (info.st_uid != owner or stat.S_ISLNK(info.st_mode) or not (directory or stat.S_ISREG(info.st_mode)) or
        stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) or (not directory and info.st_nlink != 1)):
      raise ValueError("Whole runtime must be owner-private before imports")
  review = json.loads(_private_bytes(state / REVIEW.name, owner), object_pairs_hook=_pairs)
  if (type(review) is not dict or set(review) != {"protocol", "approved", "reviewed_commit", "files"} or review["approved"] is not True or
      review["protocol"] != "omarchy-t2-product-runtime-snapshot-v1" or type(review["files"]) is not dict or
      type(review["reviewed_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", review["reviewed_commit"])):
    raise ValueError("External exact approved runtime inventory required")
  def pin(path):
    raw = _private_bytes(path, owner)
    if review["files"].get(path.relative_to(runtime).as_posix()) != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
      raise ValueError("Installed guard bytes differ from reviewed inventory")
    return raw
  bootstrap = script.with_name("runtime_deployment.py")
  pin(script)
  # First sibling code: the very bytes just pinned, stdlib-only, executed without re-opening.
  deployment = _execute("guard_reviewed_bootstrap", bootstrap, pin(bootstrap))
  deployment._verify_tree(runtime, review["files"])
  pin(script)
  return review["files"]


def _physical(root, owner):
  """Non-blocking exclusive hold of the fixed cycle lock; contention blocks the update."""
  path = root / PHYSICAL_LOCK
  _ancestors(root, path, owner)
  named = path.lstat()
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
        (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
      raise ValueError("Fixed private physical cycle lock required")
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise ValueError("A hibernation cycle holds the physical lock; update refused") from None
    return fd, (info.st_dev, info.st_ino)
  except BaseException:
    os.close(fd)
    raise


def _live_image(root, inventory, resume, **fixture):
  """Prove the pinned resume page holds no image; no qualified artifact is consulted.

  `resume` is the tuple `_maintenance` authenticated from the archived publish-time
  evidence. `fixture` (query, fixture_identity) is honored only by image_state for
  synthetic roots; `inventory` None means a synthetic fixture runtime.
  """
  base = "packages/t2-suspend/hibernate/"
  image_state = _load("guard_reviewed_image_state", root / RUNTIME / base / "image_state.py", None if inventory is None else inventory[base + "image_state.py"])
  return image_state.require_no_image(root, resume, **fixture)


def _admit(root, owner, isolated, script, *, image=None):
  """Authenticate, hold the physical lock, validate the chain and image absence, admit.

  Never mutates. `image` is a synthetic-root test seam, callable(root, inventory, resume):
  forbidden for the live root, required for any other root.
  """
  root = Path(root)
  if (root == Path("/")) != (image is None): raise ValueError("Live root uses the fixed image check; synthetic roots must supply one")
  saved = sys.dont_write_bytecode, sys.pycache_prefix
  sys.dont_write_bytecode, sys.pycache_prefix = True, "/nonexistent/omarchy-t2-guard-pycache"  # no stale .pyc for any import
  try:
    inventory = _authenticate(root, owner, isolated, script)
    fd, identity = _physical(root, owner)
    try:
      result = _maintenance(root, inventory if image is None else None)  # synthetic fixture runtimes carry no full inventory
      checked = _live_image(root, inventory, result["resume"]) if image is None else image(root, None, result["resume"])
      if type(checked) is not dict or checked.get("classification") != "no-image-at-qualified-resume-page":
        raise ValueError("Verified absence of a saved hibernation image required")
      current = (root / PHYSICAL_LOCK).lstat()
      if (current.st_dev, current.st_ino) != identity or not os.fstat(fd).st_nlink == 1:
        raise ValueError("Physical cycle lock changed during admission")
    finally: os.close(fd)  # closing releases the flock
  finally: sys.dont_write_bytecode, sys.pycache_prefix = saved
  return {**result, "classification": "inactive-maintenance-update-admitted", "image": checked["classification"]}


def native():
  """Fixed live entry: no parameters, environment, files or arguments select authority."""
  if os.geteuid() != 0: raise ValueError("Root update admission required")
  if Path(__file__).absolute() != SCRIPT: raise ValueError("Fixed installed update guard path required")
  return _admit(Path("/"), 0, sys.flags.isolated, SCRIPT)


def _marker_present(root):
  try: (Path(root) / MAINTENANCE).lstat()
  except FileNotFoundError: return False
  return True



def main(argv=None):
  arguments = sys.argv[1:] if argv is None else argv
  if arguments: raise ValueError("No update-guard arguments or bypasses permitted")
  if os.geteuid() != 0: raise ValueError("Explicit root update-guard invocation required")
  if _marker_present(Path("/")): native()
  else: check(Path("/"))
  return 0


if __name__ == "__main__":
  try: raise SystemExit(main())
  except (OSError, ValueError) as error:
    print("T2 hibernation update guard: " + str(error), file=sys.stderr)
    raise SystemExit(1)
