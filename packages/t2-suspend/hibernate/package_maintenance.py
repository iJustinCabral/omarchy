"""Fixture-only coherent update dispatcher; no native package admission.

Reuses exact stock deactivation and continuously held physical exclusion. The
durable maintenance marker remains an unconditional sleep veto after success or
failure. Command callbacks are trusted synthetic fixtures, never live runners.
Matching actual stock UKI bytes is not proof of ordinary bootability, complete
dependencies or hibernation compatibility. No reactivation/qualification exists.
The future native owner must verify real inhibitor and user-pipeline identity;
files, environment flags or these fixture capabilities cannot grant live access.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import uuid


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  value = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(value)
  return value


T = _module("maintenance_transition", "boot_policy_transition.py")
DRIVER = _module("maintenance_stable_bytes", "root_driver_inventory.py")
PHASES = ("pkg-prune", "snapshot", "dev", "keyring", "system-pkgs", "migrate", "post-update", "aur-pkgs", "mise", "orphan-pkgs")
PRODUCTION = Path("boot/EFI/Linux/omarchy_linux-t2.efi")
BOOT = Path("proc/sys/kernel/random/boot_id")
MAX_UKI = 256 * 1024 * 1024
_TOKEN = object()


def _fixture(root):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root == Path("/"):
    raise ValueError("Fixture-only maintenance refuses live root and aliases")
  return root


def _bytes(root, relative, limit, *, keep=False):
  path = root / relative
  DRIVER._ancestors(root, path, os.geteuid())
  named = path.lstat()
  if not stat.S_ISREG(named.st_mode) or named.st_uid != os.geteuid() or named.st_mode & 0o022 or named.st_nlink != 1 or not 0 < named.st_size <= limit:
    raise ValueError("Bounded owned regular fallback bytes required")
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    opened = os.fstat(fd)
    if DRIVER._identity(opened) != DRIVER._identity(named): raise ValueError("Fallback changed before read")
    sha, blake, count, chunks = hashlib.sha256(), hashlib.blake2b(), 0, []
    while True:
      raw = os.read(fd, min(1024 * 1024, limit + 1 - count))
      if not raw: break
      count += len(raw)
      if count > limit: raise ValueError("Fallback exceeded byte bound")
      sha.update(raw)
      blake.update(raw)
      if keep: chunks.append(raw)
    if count != opened.st_size or DRIVER._identity(os.fstat(fd)) != DRIVER._identity(opened) or DRIVER._identity(path.lstat()) != DRIVER._identity(opened):
      raise ValueError("Short or changed fallback read")
    return {"sha256": sha.hexdigest(), "blake2b": blake.hexdigest(), "size": count}, b"".join(chunks)
  finally: os.close(fd)


def _fallback(root):
  config, raw = _bytes(root, T.P.LIMINE, T.P.MAX_BYTES, keep=True)
  T.G._stock(raw)
  lines = raw.decode().splitlines()
  entries = [index for index, line in enumerate(lines) if line.strip().startswith("/")]
  block = lines[entries[1] + 1:entries[2] if len(entries) > 2 else len(lines)]
  expected = next(line.strip().split(":", 1)[1].strip().rsplit("#", 1)[1] for line in block if line.strip().split(":", 1)[0].strip().lower() == "path")
  image, _ = _bytes(root, PRODUCTION, MAX_UKI)
  if image["blake2b"] != expected: raise ValueError("Stock entry does not bind actual production UKI bytes")
  repeated, repeated_raw = _bytes(root, T.P.LIMINE, T.P.MAX_BYTES, keep=True)
  T.G._stock(repeated_raw)
  if repeated != config or repeated_raw != raw: raise ValueError("Stock configuration changed while reading UKI")
  return {"classification": "fallback-bytes-verified", "limine": config, "production": image}


class Session:
  def __init__(self, token, root, archive, intent, start, physical):
    if token is not _TOKEN: raise ValueError("Internally created maintenance session required")
    self.root, self.archive, self.intent, self.start, self.physical = root, archive, intent, start, physical
    self.pid, self.active, self.phase = os.getpid(), True, None

  def _check(self):
    if not self.active or self.pid != os.getpid() or self.phase is None: raise ValueError("Maintenance session is closed or outside pipeline scope")
    self.physical()
    if T._read(self.root, T.MAINTENANCE) != self.intent or T._read(self.root, (self.archive / "maintenance-intent.json").relative_to(self.root)) != self.intent:
      raise ValueError("Maintenance marker/archive identity changed")
    if T._read(self.root, (self.archive / "package-maintenance-start.json").relative_to(self.root)) != T._encoded(self.start):
      raise ValueError("Maintenance start identity changed")
    intent = T.P._json(self.intent)
    for name, expected in (("policy.json", intent["old_policy_sha256"]), ("completion.json", intent["deactivation_completion_sha256"])):
      if T.P.digest(T._read(self.root, (self.archive / name).relative_to(self.root))) != expected:
        raise ValueError("Retained maintenance authority changed")
    completion = T.P._json(T._read(self.root, (self.archive / "completion.json").relative_to(self.root)))
    transition = T._read(self.root, (self.archive / "intent.json").relative_to(self.root))
    if (completion["action"] != "deactivation" or completion["transition_id"] != intent["transition_id"] or
        completion["configuration_sha256"] != intent["fallback_limine_sha256"] or completion["intent_sha256"] != T.P.digest(transition)):
      raise ValueError("Maintenance deactivation completion chain differs")
    if T._read(self.root, (self.archive / "opt-in").relative_to(self.root), private=False) != b"":
      raise ValueError("Retained maintenance opt-in changed")
    if T.P.digest(T._read(self.root, T.P.RECEIPT)) != intent["staged_receipt_sha256"] or T._runtime(self.root) != intent["runtime_review_sha256"]:
      raise ValueError("Maintenance receipt/runtime review changed")
    if T.PRODUCT.TX.uuid_value(T._read(self.root, BOOT, private=False).decode().strip()) != self.start["original_boot_id"]:
      raise ValueError("Maintenance original boot changed")
    for name in (*T.PENDINGS.values(), T.P.POLICY, T.OPT_IN):
      if T._present(self.root / name): raise ValueError("Maintenance retains active/incomplete source state")
    T._idle(self.root)


def check_maintenance(root, session):
  """Fixture ALPM seam: actual scoped Session, not file presence or a boolean.

  A simulated pacman may already own db.lck here. Boundary checks, not this
  pretransaction seam, require it absent. Live public update_guard is unchanged.
  """
  root = _fixture(root)
  if type(session) is not Session or session.root != root: raise ValueError("Exact maintenance session/root required")
  session._check()
  return _fallback(root)


def coordinate(root, *, precheck, run_phase, guard=None):
  """Run the fixed mutation phases once under a retained sleep veto, fixtures only.

  run_phase(name, session) must return the actual strict integer command status.
  Snapshot 127/other failures remain nonfatal as in omarchy-update, but are
  recorded distinctly. Logging/stay-awake/reboot UI are not modeled here.
  """
  root = _fixture(root)
  if not callable(precheck) or not callable(run_phase): raise ValueError("Explicit fixture precheck/phase dispatcher required")
  if guard is not None and not callable(guard): raise ValueError("Explicit fixture exclusion guard required")
  def continuation(archive, raw_intent, physical):
    intent = T.P._json(raw_intent)
    if set(intent) != {"protocol", "transition_id", "old_policy_sha256", "runtime_review_sha256", "staged_receipt_sha256", "fallback_limine_sha256", "deactivation_completion_sha256"} or intent["protocol"] != T.MAINTENANCE_SCHEMA:
      raise ValueError("Exact maintenance intent required")
    T.PRODUCT.TX.uuid_value(intent["transition_id"])
    if archive.name != intent["transition_id"]: raise ValueError("Maintenance archive transition differs")
    fallback = _fallback(root)
    if fallback["limine"]["sha256"] != intent["fallback_limine_sha256"]: raise ValueError("Initial fallback differs from maintenance intent")
    start = {"protocol": "omarchy-t2-package-maintenance-start-v1", "session_id": str(uuid.uuid4()),
             "maintenance_intent_sha256": T.P.digest(raw_intent), "transition_id": intent["transition_id"],
             "original_boot_id": T.PRODUCT.TX.uuid_value(T._read(root, BOOT, private=False).decode().strip()), "fallback": fallback}
    session = Session(_TOKEN, root, archive, raw_intent, start, physical)
    current = "start"
    def publish(name, value):
      raw = T._encoded(value)
      T._new(archive / name, raw)
      if T._read(root, (archive / name).relative_to(root)) != raw: raise ValueError("Maintenance evidence readback differs")
    try:
      publish("package-maintenance-start.json", start)
      for index, phase in enumerate(PHASES):
        current = phase
        if T._present(root / T.DB_LOCK): raise ValueError("Outstanding pacman lock preserved at phase boundary")
        physical()
        session.phase = phase
        before = check_maintenance(root, session)
        stem = "package-phase-" + str(index).zfill(2) + "-" + phase
        publish(stem + "-start.json", {"session_id": start["session_id"], "phase": phase, "fallback": before})
        try: code = run_phase(phase, session)
        finally: session.phase = None
        if type(code) is not int or not 0 <= code <= 255: raise ValueError("Actual strict integer command status required")
        outcome = "success" if code == 0 else ("snapshot-absent" if code == 127 else "snapshot-failed-nonfatal") if phase == "snapshot" else "failure"
        publish(stem + "-result.json", {"session_id": start["session_id"], "phase": phase, "returncode": code, "outcome": outcome})
        if T._present(root / T.DB_LOCK): raise ValueError("Outstanding pacman lock preserved after phase")
        physical()
        if code and phase != "snapshot": raise RuntimeError("Package phase failed: " + phase)
        session.phase = phase
        try: after = check_maintenance(root, session)
        finally: session.phase = None
        publish(stem + "-postcheck.json", {"session_id": start["session_id"], "phase": phase, "fallback": after})
      result = {"protocol": "omarchy-t2-package-maintenance-complete-v1", "session_id": start["session_id"],
                "maintenance_intent_sha256": T.P.digest(raw_intent), "hibernation": "maintenance-disabled",
                "qualification_issued": False, "reactivation_evaluated": False, "fallback": after}
      publish("package-maintenance-complete.json", result)
      return result
    except BaseException as error:
      try: publish("package-maintenance-failure.json", {"session_id": start["session_id"], "phase": current, "error_type": type(error).__name__})
      except BaseException as persistence_error: error.add_note("Maintenance failure persistence unavailable: " + type(persistence_error).__name__)
      raise
    finally:
      session.active, session.phase = False, None
  return T.transition(root, "maintenance", precheck=precheck, maintenance_continuation=continuation, guard=guard)
