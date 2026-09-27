"""Read-only, separately approved source-default overlay for an existing pair.

prepare() returns proposed bytes and an UNAPPROVED policy, never publishes it.
verify() requires fixed private retained policy/backup bytes; it grants no boot
or power permission. Historical receipts and image identities remain immutable.
Limine 12.8.0 CONFIG.md supports entry paths and one-shot precedence.
This feature is limited to attended evaluation: an update may leave a stale
source entry as default before userland rejects hibernation. Deactivate the
source default before production/kernel/initramfs/Limine updates; no update
guard, automatic restaging or requalification is provided here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

STATE = Path("var/lib/omarchy/t2-hibernate-product")
POLICY = STATE / "boot-policy.json"
BACKUP = STATE / "limine.conf.before-source-default"
RECEIPT = Path("var/lib/omarchy-t2-hibernation-pair/receipt.json")
LIMINE = Path("boot/limine.conf")
SCHEMA = "omarchy-t2-source-default-policy-v1"
MAX_BYTES = 1024 * 1024
KEYS = {"protocol", "approved", "staged_receipt_sha256", "before_limine_sha256", "after_limine_sha256", "source_entry_id"}


def digest(raw): return hashlib.sha256(raw).hexdigest()


def _pairs(items):
  value = {}
  for key, item in items:
    if key in value: raise ValueError("Duplicate boot policy/receipt field")
    value[key] = item
  return value


def _json(raw):
  if type(raw) is not bytes or len(raw) > MAX_BYTES: raise ValueError("Bounded receipt bytes required")
  return json.loads(raw, object_pairs_hook=_pairs)


def _hash(value):
  if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value): raise ValueError("Invalid boot policy hash")
  return value


def source_entry(receipt):
  metadata = receipt["images"]["source"]
  expected = "MBA-T2-hibernation-source-" + _hash(metadata["sha256"])[:16]
  if metadata["entry_id"] != expected: raise ValueError("Source entry is not bound to the existing image")
  return expected


def _line(raw, expected):
  if type(raw) is not bytes or len(raw) > MAX_BYTES: raise ValueError("Bounded Limine bytes required")
  lines = re.findall(rb"^[ \t]*default_entry[ \t]*:[^\n]*(?:\n|$)", raw, re.M | re.I)
  if lines != [expected]: raise ValueError("Exactly one canonical authorized default_entry line required")
  if re.search(rb"^[ \t]*remember_last_entry[ \t]*:", raw, re.M | re.I):
    raise ValueError("Remembered selection is outside source-default policy")


def prepare(before, receipt_raw):
  """Pure proposal only; root must separately review, preserve and approve it."""
  receipt = _json(receipt_raw)
  entry = source_entry(receipt)
  if digest(before) != _hash(receipt["staged_limine_sha256"]): raise ValueError("Before bytes differ from historical staged configuration")
  _line(before, b"default_entry: 2\n")
  if len(re.findall(("^/" + entry + "\n").encode(), before, re.M)) != 1: raise ValueError("Source entry is missing or duplicated")
  after = re.sub(rb"^default_entry: 2\n", lambda match: ("default_entry: " + entry + "\n").encode(), before, count=1, flags=re.M)
  policy = {"protocol": SCHEMA, "approved": False, "staged_receipt_sha256": digest(receipt_raw),
            "before_limine_sha256": digest(before), "after_limine_sha256": digest(after), "source_entry_id": entry}
  return {"policy": policy, "before": before, "after": after, "physical_permission": False}


def normalize_source_default(actual, receipt):
  """Accept only source default; normalize for the existing full pair checks."""
  entry = source_entry(receipt)
  line = ("default_entry: " + entry + "\n").encode()
  _line(actual, line)
  normalized = re.sub(b"^" + re.escape(line), b"default_entry: 2\n", actual, count=1, flags=re.M)
  if digest(normalized) != _hash(receipt["staged_limine_sha256"]):
    raise ValueError("Source-default policy changed unrelated Limine bytes")
  return normalized


def validate(policy, before, actual, receipt_raw):
  if type(policy) is not dict or set(policy) != KEYS or policy["protocol"] != SCHEMA or policy["approved"] is not True:
    raise ValueError("Separately approved source-default policy required")
  proposal = prepare(before, receipt_raw)
  expected = {**proposal["policy"], "approved": True}
  if policy != expected: raise ValueError("Boot policy does not bind the retained configuration/receipt/source")
  if actual != proposal["after"]: raise ValueError("Actual Limine bytes differ from approved source default")
  return normalize_source_default(actual, _json(receipt_raw))


def _read(root, relative, *, private=True):
  path = root / relative
  expected_uid = 0 if root == Path("/") else os.geteuid()
  for parent in path.parents:
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, expected_uid) or info.st_mode & 0o022:
      raise ValueError("Root-owned nonsymlink policy ancestors required")
    if parent == root / STATE and stat.S_IMODE(info.st_mode) != 0o700:
      raise ValueError("Root-private product policy state required")
    if parent == root: break
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_nlink != 1:
      raise ValueError("Owned regular non-linked boot policy evidence required")
    if (private and stat.S_IMODE(info.st_mode) != 0o600) or info.st_mode & 0o022:
      raise ValueError("Private boot policy evidence required")
    if info.st_size > MAX_BYTES: raise ValueError("Oversized boot policy evidence")
    raw = os.read(fd, MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise ValueError("Oversized boot policy evidence")
    return raw
  finally: os.close(fd)


def verify(root, staged_receipt_sha256):
  """Read fixed evidence only; absent policy retains strict stock verification."""
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir(): raise ValueError("Canonical boot policy root required")
  policy_path = root / POLICY
  if not policy_path.exists() and not policy_path.is_symlink(): return False
  policy = _json(_read(root, POLICY))
  receipt_raw = _read(root, RECEIPT)
  if digest(receipt_raw) != _hash(staged_receipt_sha256): raise ValueError("Boot policy receipt differs from product configuration")
  validate(policy, _read(root, BACKUP), _read(root, LIMINE, private=False), receipt_raw)
  return True
