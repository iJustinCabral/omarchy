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


def _maintenance(root):
  """Exact inactive-maintenance validation; callers authenticate and lock first."""
  # Lazy reuse avoids import-time cycles (the transition itself imports us).
  spec = importlib.util.spec_from_file_location("guard_maintenance_evidence", Path(__file__).with_name("package_maintenance.py"))
  maintenance = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(maintenance)
  transition, policy = maintenance.T, maintenance.T.P
  for relative in ACTIVE:
    if relative == transition.MAINTENANCE: continue
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
           archive / "intent.json", archive / "completion.json", policy.RECEIPT, policy.BACKUP)
  evidence = {path: transition._read(root, path) for path in paths}
  if evidence[transition.MAINTENANCE] != raw or evidence[archive / "maintenance-intent.json"] != raw:
    raise ValueError("Maintenance marker/archive bytes differ")
  old_raw, receipt = evidence[archive / "policy.json"], evidence[policy.RECEIPT]
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
  opt_in = transition._read(root, archive / "opt-in", private=False)
  if opt_in != b"" or stat.S_IMODE((root / archive / "opt-in").lstat().st_mode) != 0o644:
    raise ValueError("Historical routine opt-in differs")
  if transition._runtime(root) != intent["runtime_review_sha256"]:
    raise ValueError("Reviewed runtime differs from maintenance intent")
  transition._idle(root)
  fallback = maintenance._fallback(root)  # current coherent bytes may legitimately be NEW
  transition._idle(root)
  if any(transition._read(root, path) != value for path, value in evidence.items()):
    raise ValueError("Maintenance evidence changed during verification")
  if transition._read(root, archive / "opt-in", private=False) != opt_in or transition._runtime(root) != intent["runtime_review_sha256"]:
    raise ValueError("Maintenance authority changed during verification")
  private_directories()
  if stat.S_IMODE((root / archive / "opt-in").lstat().st_mode) != 0o644:
    raise ValueError("Historical routine opt-in metadata changed")
  for relative in ACTIVE:
    if relative != transition.MAINTENANCE and transition._present(root / relative):
      raise ValueError("Source state appeared during maintenance verification")
  return {"classification": "fixture-inactive-maintenance-verified", "transition_id": identifier,
    "maintenance_intent_sha256": policy.digest(raw), "fallback": fallback,
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
  bootstrap = script.with_name("runtime_deployment.py")
  pin(script)
  pin(bootstrap)
  spec = importlib.util.spec_from_file_location("guard_reviewed_bootstrap", bootstrap)
  deployment = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(deployment)  # first sibling import: byte-pinned, stdlib-only
  deployment._verify_tree(runtime, review["files"])
  pin(script)


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


def _admit(root, owner, isolated, script):
  """Authenticate, hold the physical lock, validate the exact chain, admit. Never mutates."""
  root = Path(root)
  _authenticate(root, owner, isolated, script)
  fd, identity = _physical(root, owner)
  try:
    result = _maintenance(root)
    current = (root / PHYSICAL_LOCK).lstat()
    if (current.st_dev, current.st_ino) != identity or not os.fstat(fd).st_nlink == 1:
      raise ValueError("Physical cycle lock changed during admission")
  finally: os.close(fd)  # closing releases the flock
  return {**result, "classification": "inactive-maintenance-update-admitted"}


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
