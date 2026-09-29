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


# Snapshot-blind Limine comparison.
#
# POLICY (reviewed change, 2026-09-29): limine-snapper-sync rewrites the snapshot
# region inside the /+Omarchy entry on every snapshot. Snapshot entries are NOT
# part of the qualified boot policy: they never become default and boot an
# unrelated read-only snapshot. Every ACTIVE-hibernation comparison of Limine
# bytes therefore compares limine_canonical() forms, which are the file with exactly that
# region removed. Everything else stays byte-exact: global options, the
# default_entry rules, the /+Omarchy entry and its //linux-t2 path, BLAKE2b and
# cmdline, the EFI fallback, diagnostic entries and the hibernation pair block.
# Recorded/staged evidence bytes are never rewritten; callers compare
# limine_canonical(current) with limine_canonical(recorded), or, when only the recorded hash is
# known, splice the recorded region into the current bytes with with_region().
# Recognition is strict and fails closed: anything unexpected raises ValueError.
_INDENT = b"     "
_ENTRY = rb"[A-Za-z0-9._+-]+"
_MACHINE = re.compile(rb"machine-id=([0-9a-f]{32})(?![0-9a-f])")


def _split(raw):
  if type(raw) is not bytes or len(raw) > MAX_BYTES: raise ValueError("Bounded Limine bytes required")
  lines = raw.split(b"\n")
  if lines[-1] == b"": lines.pop()
  starts = [0]
  for line in lines: starts.append(min(starts[-1] + len(line) + 1, len(raw)))
  return lines, starts


def _locate(lines):
  """Indexes of the /+Omarchy entry, its //linux-t2 child and the entry end."""
  entries = [index for index, line in enumerate(lines) if line == b"/+Omarchy"]
  if len(entries) != 1: raise ValueError("Exactly one /+Omarchy entry required")
  entry = entries[0]
  # The entry ends at the next top-level entry or column-0 comment; the entry
  # tool's own column-0 "###" lines belong to the entry.
  end = next((index for index in range(entry + 1, len(lines)) if lines[index][:1] == b"/" or (lines[index][:1] == b"#" and not lines[index].startswith(b"###"))), len(lines))
  kernels = [index for index in range(entry + 1, end) if lines[index] == b"  //linux-t2"]
  if len(kernels) != 1: raise ValueError("Exactly one //linux-t2 kernel entry inside /+Omarchy required")
  return entry, kernels[0], end


def _refuse(message, lineno, line):
  """ValueError naming the 1-based file line and at most 80 characters of it."""
  shown = repr(line.decode("utf-8", "replace"))
  if len(shown) > 80: shown = shown[:77] + "..."
  return ValueError(message + " (line " + str(lineno) + ": " + shown + ")")


def _snapshot_line(line, state, identifier, taken):
  try: text = line[len(_INDENT):].decode("utf-8")
  except UnicodeDecodeError: raise ValueError("Snapshot region is not UTF-8") from None
  if "\r" in text or "\0" in text: raise ValueError("Snapshot region contains control characters")
  key = text.split(":", 1)[0].strip().lower()
  if key in ("default_entry", "remember_last_entry"): raise ValueError("Snapshot region may not set the default or remembered entry")
  if text.startswith("comment: "): return
  if re.fullmatch(r"///[0-9]+ \u2502 \S.*", text): state["sub"] = False; return
  if re.fullmatch(r"////linux[A-Za-z0-9._+-]*", text):
    # Default selection is by entry name: a sub-entry may never reuse a top-level name.
    if text[4:] in taken: raise ValueError("Snapshot sub-entry reuses a top-level entry name")
    state["sub"] = True; return
  if not state["sub"]: raise ValueError("Unexpected line inside snapshot region")
  if text == "protocol: efi": return
  if re.fullmatch(r"cmdline: \S.*", text): return
  match = re.fullmatch(r"path: boot\(\):/" + re.escape(identifier.decode()) + r"/limine_history/(" + _ENTRY.decode() + r")(#[0-9a-f]+)?", text)
  if match and match.group(1) not in (".", ".."): return
  raise ValueError("Unexpected line inside snapshot region")


def snapshot_region(raw):
  """(start, end) byte offsets of the limine-snapper-sync region, or None when absent."""
  lines, starts = _split(raw)
  markers = [index for index, line in enumerate(lines) if line.strip() == b"//Snapshots"]
  synced = [index for index, line in enumerate(lines) if b"limine-snapper-sync" in line]
  if not markers:
    if synced: raise ValueError("limine-snapper-sync text outside a recognised snapshot region")
    return None
  if len(markers) != 1: raise ValueError("More than one snapshot region")
  first = markers[0]
  if lines[first] != _INDENT + b"//Snapshots" or first + 1 >= len(lines) or lines[first + 1] != _INDENT + b"### Auto-generated by limine-snapper-sync":
    raise ValueError("Malformed snapshot region header")
  if synced != [first + 1]: raise ValueError("limine-snapper-sync text outside a recognised snapshot region")
  entry, kernel, end = _locate(lines)
  if not kernel < first < end: raise ValueError("Snapshot region is not inside the /+Omarchy entry after its kernel entry")
  identifiers = {match for index in range(entry, end) if not first <= index for match in _MACHINE.findall(lines[index])}
  if len(identifiers) != 1: raise ValueError("Exactly one machine-id required for the snapshot region")
  identifier = next(iter(identifiers))
  taken = set()
  for line in lines:
    if line[:1] == b"/": taken.add(line[1:].lstrip(b"+").decode("utf-8", "replace"))
  state = {"sub": False}
  stop = first + 2
  while stop < len(lines):
    line = lines[stop]
    if line == b"": stop += 1; continue
    if stop >= end or line[:1] in (b"/", b"#"): break
    if not line.startswith(_INDENT): raise _refuse("Unexpected line inside snapshot region", stop + 1, line)
    try: _snapshot_line(line, state, identifier, taken)
    except ValueError as error:
      if "(line " in str(error): raise
      raise _refuse(str(error), stop + 1, line) from None
    stop += 1
  return starts[first], starts[stop]


def limine_canonical(raw):
  """The Limine bytes with exactly the limine-snapper-sync snapshot region removed."""
  region = snapshot_region(raw)
  return raw if region is None else raw[:region[0]] + raw[region[1]:]


def with_region(raw, donor):
  """raw with its snapshot region replaced by donor's (inserted at the entry end or removed)."""
  region, other = snapshot_region(raw), snapshot_region(donor)
  replacement = b"" if other is None else donor[other[0]:other[1]]
  if region is not None: return raw[:region[0]] + replacement + raw[region[1]:]
  if other is None: return raw
  lines, starts = _split(raw)
  return raw[:starts[_locate(lines)[2]]] + replacement + raw[starts[_locate(lines)[2]]:]


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


def normalize_source_default(actual, receipt, donor=None):
  """Accept only source default; normalize for the existing full pair checks.

  With donor (retained bytes carrying the staged snapshot region) snapshot churn
  is tolerated: the recorded region is spliced back before the exact staged hash.
  """
  entry = source_entry(receipt)
  line = ("default_entry: " + entry + "\n").encode()
  _line(actual if donor is None else limine_canonical(actual), line)
  normalized = re.sub(b"^" + re.escape(line), b"default_entry: 2\n", actual, count=1, flags=re.M)
  if donor is not None: normalized = with_region(normalized, donor)
  if digest(normalized) != _hash(receipt["staged_limine_sha256"]):
    raise ValueError("Source-default policy changed unrelated Limine bytes")
  return normalized


def validate(policy, before, actual, receipt_raw):
  if type(policy) is not dict or set(policy) != KEYS or policy["protocol"] != SCHEMA or policy["approved"] is not True:
    raise ValueError("Separately approved source-default policy required")
  proposal = prepare(before, receipt_raw)
  expected = {**proposal["policy"], "approved": True}
  if policy != expected: raise ValueError("Boot policy does not bind the retained configuration/receipt/source")
  if limine_canonical(actual) != limine_canonical(proposal["after"]): raise ValueError("Actual Limine bytes differ from approved source default")
  return normalize_source_default(actual, _json(receipt_raw), donor=before)


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
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
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
