"""Fixed, externally approved live adapter for one exact v2 runtime upgrade.

Install this file root-private outside the replaceable runtime. The only public
entrypoint has no flags or alternate roots. It never changes EFI, modules,
qualification, boot policy or power state. Interrupted publications are not
replayed; the compatible pending marker vetoes routine hibernation.

Maintenance mode (approval protocol omarchy-t2-runtime-upgrade-maintenance-approval-v1) is the only way to
upgrade the runtime while package-maintenance.pending exists. It uses the same seven pins, adapter pin, boot
pin and locks, but its unchanged-host pins are the qualification, the update-guard hook and the exact marker
bytes (Limine legitimately churns; the boot policy and the opt-in must be ABSENT). Its checks are the update
guard's: the old reviewed guard validates the maintenance chain and the pinned resume page before the barrier,
the NEW reviewed guard validates it (barrier ignored) after the runtime and the marker's runtime binding were
replaced, and again with the barrier retired. The ordinary v2 protocol still refuses under a marker.
"""
import hashlib
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time
import types
import uuid

sys.dont_write_bytecode = True
ROOT = Path("/")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
SCRIPT = STATE / "runtime-upgrade-native.py"
APPROVAL = STATE / "runtime-upgrade-approval.json"
BOOTSTRAP = STATE / "runtime-upgrade-bootstrap.py"
IMAGE_STATE = STATE / "runtime-upgrade-image-state.py"
WHO = "omarchy-t2-runtime-upgrade"
WHY = "reviewed-v2-runtime-upgrade"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
RUNTIME_REL = "packages/t2-suspend/hibernate/runtime_deployment.py"
IMAGE_STATE_REL = "packages/t2-suspend/hibernate/image_state.py"
PARSER_REL = "packages/t2-suspend/experiments/audit-hibernation-swap-header.py"
# The runtime-deployment core pins exactly these six hashes. The seventh pin,
# new_image_state, belongs to this adapter alone and is never passed to the core.
# The v2 approval protocol was never issued live, so it is extended in place:
# the installed e489bab7 generation has no image_state.py, so the pre-barrier
# no-image check runs a root-staged, externally pinned helper instead.
CORE_HASHES = {"old_review", "old_bootstrap", "old_config", "new_review", "new_bootstrap", "new_config"}
HASHES = CORE_HASHES | {"new_image_state"}
DB_LOCK = Path("var/lib/pacman/db.lck")
PHYSICAL_LOCK = Path("var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock")
MAINTENANCE_PROTOCOL = "omarchy-t2-runtime-upgrade-maintenance-approval-v1"
ORDINARY_PROTOCOL = "omarchy-t2-runtime-upgrade-approval-v2"
MARKER = STATE / "package-maintenance.pending"
UNCHANGED_MAINTENANCE = {
  "qualification": (STATE / "qualification.json", 0o600),
  "hook": (Path("/etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook"), 0o644),
  "marker": (MARKER, 0o600),
}
# Present only in ACTIVE source-default state; their presence during maintenance is not this upgrade's business.
ABSENT_IN_MAINTENANCE = (STATE / "boot-policy.json", Path("/etc/omarchy/t2-hibernate-product.enabled"),
                         STATE / "source-default-activation.pending", STATE / "source-default-deactivation.pending")
UNCHANGED = {
  "qualification": (STATE / "qualification.json", 0o600),
  "boot_policy": (STATE / "boot-policy.json", 0o600),
  "limine": (Path("/boot/limine.conf"), None),
  "opt_in": (Path("/etc/omarchy/t2-hibernate-product.enabled"), 0o644),
  "hook": (Path("/etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook"), 0o644),
}


def _digest(raw): return hashlib.sha256(raw).hexdigest()


def _pairs(items):
  result = {}
  for key, value in items:
    if key in result: raise ValueError("Duplicate upgrade approval field")
    result[key] = value
  return result


def _private_bytes(path, mode=0o600):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or
        (mode is not None and stat.S_IMODE(info.st_mode) != mode) or info.st_size > 2 * 1024 * 1024):
      raise ValueError("Bounded regular owned upgrade input required: " + str(path))
    raw = os.read(fd, 2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024: raise ValueError("Oversized upgrade input")
    return raw
  finally: os.close(fd)


def _pin(value):
  if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
    raise ValueError("Exact SHA-256 approval pin required")
  return value


def _parse_approval(raw, adapter_raw):
  approval = json.loads(raw, object_pairs_hook=_pairs)
  if (type(approval) is not dict or set(approval) != {"protocol", "approved", "current_boot_id", "source_directory",
      "reviewed_commit", "adapter_sha256", "expected", "unchanged", "approval_id"} or
      approval["protocol"] not in (ORDINARY_PROTOCOL, MAINTENANCE_PROTOCOL) or approval["approved"] is not True):
    raise ValueError("Exact external runtime upgrade approval required")
  maintenance = approval["protocol"] == MAINTENANCE_PROTOCOL
  identity = approval["approval_id"]
  if type(identity) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identity) or uuid.UUID(identity).version != 4:
    raise ValueError("Fresh canonical UUID4 runtime upgrade approval required")
  if type(approval["expected"]) is not dict or set(approval["expected"]) != HASHES:
    raise ValueError("Seven exact old/new authority pins required")
  for value in approval["expected"].values(): _pin(value)
  if approval["expected"]["old_config"] != approval["expected"]["new_config"]:
    raise ValueError("Runtime-only approval must preserve exact configuration pin")
  if type(approval["unchanged"]) is not dict or set(approval["unchanged"]) != set(UNCHANGED_MAINTENANCE if maintenance else UNCHANGED):
    raise ValueError("Exact unchanged host pins required")
  for value in approval["unchanged"].values(): _pin(value)
  _pin(approval["adapter_sha256"])
  if _digest(adapter_raw) != approval["adapter_sha256"]:
    raise ValueError("Installed adapter differs from external approval")
  source = approval["source_directory"]
  if type(source) is not str or not source.startswith("/") or Path(source).resolve() != Path(source) or source == "/":
    raise ValueError("Canonical exact source directory required")
  if type(approval["reviewed_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", approval["reviewed_commit"]):
    raise ValueError("Exact reviewed source commit required")
  if type(approval["current_boot_id"]) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", approval["current_boot_id"]):
    raise ValueError("Exact current boot required")
  return {**approval, "maintenance": maintenance}


def _installed_approval():
  if os.geteuid() != 0 or not sys.flags.isolated or Path(__file__).absolute() != SCRIPT:
    raise ValueError("Only fixed root-private isolated installed adapter may run")
  for path in (SCRIPT, *SCRIPT.parents):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
      raise ValueError("Root-owned nonsymlink adapter ancestry required")
    if path == SCRIPT:
      if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Private installed adapter required")
    elif not stat.S_ISDIR(info.st_mode): raise ValueError("Installed adapter directory required")
  return _parse_approval(_private_bytes(APPROVAL), _private_bytes(SCRIPT))


def _unchanged(approval):
  if _private_bytes(Path("/proc/sys/kernel/random/boot_id"), mode=None).decode().strip() != approval["current_boot_id"]:
    raise ValueError("Current boot changed during upgrade")
  maintenance = approval.get("maintenance", False)
  if maintenance:
    for path in ABSENT_IN_MAINTENANCE:
      if os.path.lexists(path): raise ValueError("Active source-default state is present under a maintenance upgrade: " + path.name)
  for name, (path, mode) in (UNCHANGED_MAINTENANCE if maintenance else UNCHANGED).items():
    for ancestor in path.parents:
      info = ancestor.lstat()
      if not stat.S_ISDIR(info.st_mode) or ancestor.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Owned nonsymlink host artifact ancestry required: " + name)
    raw = _private_bytes(path, mode)
    if name == "opt_in" and raw: raise ValueError("Source-default opt-in is not empty")
    if _digest(raw) != approval["unchanged"][name]:
      raise ValueError("Unchanged host artifact differs: " + name)


def _review(raw, expected_sha, commit=None):
  if _digest(raw) != expected_sha: raise ValueError("Runtime review differs from approval")
  review = json.loads(raw, object_pairs_hook=_pairs)
  if (type(review) is not dict or set(review) != {"protocol", "approved", "reviewed_commit", "files"} or
      review["protocol"] != "omarchy-t2-product-runtime-snapshot-v1" or review["approved"] is not True or
      type(review["files"]) is not dict or (commit is not None and review["reviewed_commit"] != commit)):
    raise ValueError("Approved exact runtime inventory required")
  return review


def _reviewed_code(raw, review, name):
  if review["files"].get(name) != {"size": len(raw), "sha256": _digest(raw)}:
    raise ValueError("Bootstrap differs from reviewed runtime source")


def _load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def _pinned_module(name, raw, path):
  """Execute exactly the bytes already verified; the path is only the module identity."""
  module = types.ModuleType(name)
  module.__file__ = str(path)
  exec(compile(raw, str(path), "exec"), module.__dict__)
  return module


def _helper_image_state(approval, new_review):
  """Load the root-staged, doubly pinned image_state helper for the pre-barrier check.

  The installed old runtime may lack image_state.py, so its bytes are never
  imported here. The staged file must match both the external approval pin and
  the new reviewed inventory. The old review must pin the installed parser bytes
  that the helper will read from the fixed runtime path.
  """
  raw = _private_bytes(IMAGE_STATE)
  entry = {"size": len(raw), "sha256": _digest(raw)}
  if entry["sha256"] != approval["expected"]["new_image_state"]:
    raise ValueError("Staged image-state helper differs from external approval")
  if new_review["files"].get(IMAGE_STATE_REL) != entry:
    raise ValueError("Staged image-state helper differs from reviewed new runtime")
  old_review = _review(_private_bytes(STATE / "runtime-deployment-review.json"), approval["expected"]["old_review"])
  parser = old_review["files"].get(PARSER_REL)
  if type(parser) is not dict or type(parser.get("sha256")) is not str: raise ValueError("Old review lacks the swap-header parser")
  module = _pinned_module("reviewed_upgrade_image_state_helper", raw, IMAGE_STATE)
  module.PARSER_PIN = _pin(parser["sha256"])
  return module


def _verified_engines(approval):
  expected = approval["expected"]
  old_review_raw = _private_bytes(STATE / "runtime-deployment-review.json")
  new_review_raw = _private_bytes(STATE / "runtime-upgrade-review.json")
  old_review = _review(old_review_raw, expected["old_review"])
  new_review = _review(new_review_raw, expected["new_review"], approval["reviewed_commit"])
  _reviewed_code(_private_bytes(SCRIPT), new_review, "packages/t2-suspend/hibernate/runtime_upgrade_native.py")
  old_bootstrap = _private_bytes(STATE / "runtime-deployment-bootstrap.py")
  new_bootstrap = _private_bytes(BOOTSTRAP)
  if _digest(old_bootstrap) != expected["old_bootstrap"] or _digest(new_bootstrap) != expected["new_bootstrap"]:
    raise ValueError("Pinned old/new bootstrap differs")
  _reviewed_code(old_bootstrap, old_review, RUNTIME_REL)
  _reviewed_code(new_bootstrap, new_review, RUNTIME_REL)
  # Imported code is root-private and externally pinned; user workspace bytes
  # are only inventory/copy input and are never imported by this adapter.
  core = _load("reviewed_upgrade_core", BOOTSTRAP)
  core._verify_tree(STATE / "runtime", old_review["files"])
  old_native_path = STATE / "runtime/packages/t2-suspend/hibernate/boot_policy_native.py"
  old_native_raw = _private_bytes(old_native_path)
  _reviewed_code(old_native_raw, old_review, "packages/t2-suspend/hibernate/boot_policy_native.py")
  old_native = _load("reviewed_old_native_guard", old_native_path)
  if old_native.WHO != "omarchy-t2-source-default" or old_native.WHY != "reviewed-boot-policy-transition":
    raise ValueError("Unexpected reviewed old native guard identity")
  old_native.WHO, old_native.WHY = WHO, WHY
  engine = _load("reviewed_old_transition", old_native_path.with_name("boot_policy_transition.py"))
  engine._runtime(ROOT)
  if core.inventory(approval["source_directory"]) != new_review["files"]:
    raise ValueError("Workspace source differs from reviewed inventory")
  return core, old_native, engine


def _inhibit_command():
  return ("/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block", "--who=" + WHO,
          "--why=" + WHY, "--no-ask-password", "/usr/bin/python3", "-I", "-B", str(SCRIPT))


def _parent_identity(pid):
  proc = Path("/proc") / str(pid)
  if os.getppid() != pid or (proc / "exe").readlink() != Path("/usr/bin/systemd-inhibit"):
    raise ValueError("Exact inhibitor parent required")
  binary = Path("/usr/bin/systemd-inhibit").stat()
  if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
    raise ValueError("Root-owned inhibitor executable required")
  uids = [line.split()[1:] for line in (proc / "status").read_text().splitlines() if line.startswith("Uid:")]
  if uids != [["0", "0", "0", "0"]]: raise ValueError("Root inhibitor parent required")
  if (proc / "cmdline").read_bytes() != b"\0".join(item.encode() for item in _inhibit_command()) + b"\0":
    raise ValueError("Exact fixed inhibitor command required")
  return (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]


def _guard(old_native, approval):
  pid = os.getppid()
  identity = _parent_identity(pid)
  fd = os.pidfd_open(pid)
  def check():
    if select.select([fd], [], [], 0)[0] or _parent_identity(pid) != identity:
      raise ValueError("Original inhibitor parent exited or changed")
    old_native._power_idle(pid)
    _unchanged(approval)
    if select.select([fd], [], [], 0)[0] or _parent_identity(pid) != identity:
      raise ValueError("Original inhibitor parent changed during exclusion")
  return fd, check


def _product_check(product, *, barrier, image_state=None):
  config = product.TRIAL._private_json(STATE / "config.json")
  qualification = product.TRIAL._private_json(STATE / "qualification.json")
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  # Every caller holds both native exclusions. Never load a helper from the
  # incoming workspace. Ledger reconciliation alone cannot establish that the
  # resume page has no image. The pre-barrier caller supplies the pinned staged
  # helper; later callers have verified the new installed runtime tree instead.
  if image_state is None:
    image_state = _load("reviewed_upgrade_image_state", STATE / "runtime/packages/t2-suspend/hibernate/image_state.py")
  image_state.require_no_image(ROOT, report["audited_details"]["restore_protocol"]["resume"])
  arguments = {"ledger": product.TX.Ledger(STATE / "ledger"), "archive_directory": STATE / "archives", "root": ROOT}
  if not barrier: return product.check(config, qualification, report, **arguments)
  receipt = product.validate(config, qualification, report)
  if product.BOOT_POLICY.verify(ROOT, config["staged_receipt_sha256"]) is not True:
    raise ValueError("Source-default policy changed during runtime upgrade")
  product.TRIAL._verify_deployment(ROOT, config, report, source_default=True)
  return product._admission_state(config, receipt, report, **arguments)


def _postcheck(core, approval):
  raw = _private_bytes(STATE / "runtime-deployment-review.json")
  review = _review(raw, approval["expected"]["new_review"], approval["reviewed_commit"])
  core._verify_tree(STATE / "runtime", review["files"])
  if approval.get("maintenance", False): return _maintenance_check(_load_new_guard(), barrier=True)
  product = _load("reviewed_new_product", STATE / "runtime/packages/t2-suspend/hibernate/product.py")
  return _product_check(product, barrier=True)


def _load_new_guard():
  """The NEW reviewed update guard, from the tree the caller has just verified whole."""
  return _load("reviewed_new_update_guard", STATE / "runtime/packages/t2-suspend/hibernate/update_guard.py")


def _maintenance_check(guard, *, barrier, image_state=None):
  """Inactive-maintenance admission by the update guard's own exact validator, then image absence at the archived resume tuple.

  `barrier` ignores exactly this upgrade's two compatible veto files (never the marker). The resume tuple is the one the
  publisher archived: no qualified artifact is derived, so a kernel/UKI update never blocks it. `image_state` is the
  pinned staged helper before the barrier (the installed old runtime may lack the module); later callers use the installed one.
  """
  ignore = (guard.STATE / "source-default-activation.pending", guard.STATE / "runtime-upgrade.pending") if barrier else ()
  evidence = guard._maintenance(ROOT, ignore=ignore)
  if image_state is None: image_state = _load("reviewed_upgrade_image_state", STATE / "runtime/packages/t2-suspend/hibernate/image_state.py")
  checked = image_state.require_no_image(ROOT, evidence["resume"])
  if type(checked) is not dict or checked.get("classification") != "no-image-at-qualified-resume-page":
    raise ValueError("Verified absence of a saved hibernation image required")
  return evidence


def _intent(core, approval, raw):
  record = json.loads(raw, object_pairs_hook=_pairs)
  expected = approval["expected"]
  maintenance = approval.get("maintenance", False)
  fields = {"protocol", "transaction_id", "approval_id", "old_review_sha256", "new_review_sha256", "old_config_sha256", "new_config_sha256"}
  if (type(record) is not dict or set(record) != (fields | {"marker_sha256"} if maintenance else fields) or
      record["protocol"] != (core.INTENT_MAINTENANCE if maintenance else "omarchy-t2-runtime-upgrade-intent-v2") or record["approval_id"] != approval["approval_id"] or
      any(record[field + "_sha256"] != expected[pin] for field, pin in
          (("old_review", "old_review"), ("new_review", "new_review"), ("old_config", "old_config"), ("new_config", "new_config")))):
    raise ValueError("Cannot restore veto from invalid intent")
  core._approval_identity(record["transaction_id"])
  if core._encoded(record) != raw: raise ValueError("Canonical exact recovery intent required")
  return raw


def _durable_veto(core, state_fd, intent):
  name = core.COMPATIBLE_BARRIER
  try: current = core._private_read(state_fd, name)
  except FileNotFoundError: core._new_private(state_fd, name, intent)
  else:
    if current != intent: raise ValueError("Foreign compatible veto must remain untouched")
  fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=state_fd)
  try:
    core._private(fd)
    def identity(info):
      return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    opened = identity(os.fstat(fd))
    if os.read(fd, len(intent) + 1) != intent or identity(os.stat(name, dir_fd=state_fd, follow_symlinks=False)) != opened:
      raise ValueError("Compatible veto changed before durability check")
    os.fsync(fd)
    os.fsync(state_fd)
    os.lseek(fd, 0, os.SEEK_SET)
    if (os.read(fd, len(intent) + 1) != intent or core._private_read(state_fd, name) != intent or
        identity(os.fstat(fd)) != opened or identity(os.stat(name, dir_fd=state_fd, follow_symlinks=False)) != opened):
      raise ValueError("Compatible veto changed after durability check")
  finally: os.close(fd)


def _restore_veto(core, approval):
  """Prove exact old state or a durable owned veto; never replay publication."""
  state_fd = core._open_directory(STATE)
  try:
    core._private(state_fd, directory=True)
    prefix = approval["reviewed_commit"][:12]
    completed = "runtime-upgrade-completed-" + prefix + ".json"
    consumed = "runtime-upgrade-approval-consumed-" + approval["approval_id"] + ".json"
    evidence = {}
    for name in (completed, consumed, core.UPGRADE_PENDING, core.COMPATIBLE_BARRIER):
      try: evidence[name] = core._private_read(state_fd, name)
      except FileNotFoundError: pass
    intents = []
    if completed in evidence:
      record = json.loads(evidence[completed], object_pairs_hook=_pairs)
      if (type(record) is not dict or set(record) != {"protocol", "intent", "review_sha256", "config_sha256"} or
          record["protocol"] != (core.COMPLETED_MAINTENANCE if approval.get("maintenance", False) else "omarchy-t2-runtime-upgrade-completed-v2") or
          record["review_sha256"] != approval["expected"]["new_review"] or
          record["config_sha256"] != approval["expected"]["new_config"] or consumed not in evidence):
        raise ValueError("Cannot restore veto from foreign completion")
      intents.append(_intent(core, approval, core._encoded(record["intent"])))
    for name in (consumed, core.UPGRADE_PENDING, core.COMPATIBLE_BARRIER):
      if name in evidence: intents.append(_intent(core, approval, evidence[name]))
    if intents:
      if any(raw != intents[0] for raw in intents): raise ValueError("Recovery intents differ; foreign evidence preserved")
      _durable_veto(core, state_fd, intents[0])
      if approval.get("maintenance", False):
        # Marker, archived intent and baseline must agree with the runtime actually installed: forward when the new
        # review is installed, back to the old bytes when it is not. Foreign bytes raise and stay preserved.
        core.settle_maintenance_binding(STATE, json.loads(intents[0], object_pairs_hook=_pairs), _digest(_private_bytes(STATE / "runtime-deployment-review.json")))
    else:
      # No completion is not proof of safety. Require all old authority bytes
      # and the entire tree, with no partial staging or retained publication.
      for name, pin in ((core.REVIEW.name, "old_review"), (core.BOOTSTRAP, "old_bootstrap"), (core.CONFIG, "old_config")):
        if _digest(core._private_read(state_fd, name)) != approval["expected"][pin]:
          raise ValueError("Prepublication old authority changed")
      review = _review(core._private_read(state_fd, core.REVIEW.name), approval["expected"]["old_review"])
      suffix = "-before-" + prefix
      if any(name == core.PENDING or name.startswith(("runtime-retained-", "runtime-review-retained-", "runtime-bootstrap-retained-", "config-retained-")) and suffix in name for name in os.listdir(state_fd)):
        raise ValueError("Partial publication cannot release without durable veto")
      core._verify_tree(STATE / "runtime", review["files"])
  finally: os.close(state_fd)


class _Preserved(ValueError):
  """A foreign pacman lock is preserved; no retry can ever change that."""


RECOVERY_BOUND = 300.0  # seconds of paced retries allowed once the veto is durable


def _retain_recovery(operation, durable=lambda: False):
  """Keep the entered physical scope on repair faults, with paced retries.

  Recovery policy. Until `durable()` reports the veto (or proven old state)
  established, every fault retries without bound: giving up earlier could leave
  a published upgrade unvetoed. Afterwards, deterministic faults (a renamed or
  group-writable lock parent, a replaced physical lock) can never clear, so
  retries are bounded to RECOVERY_BOUND seconds and then the last error
  propagates: the process exits non-zero with the veto retained (fail closed,
  not hung; the flock is released only by that exit). A _Preserved refusal
  cannot change at all and propagates immediately, foreign file untouched.
  This does not own the parent inhibitor or survive SIGTERM/SIGKILL or parent
  loss. Those remain deployment limitations.
  """
  start = None
  while True:
    try:
      operation()
      return
    except _Preserved: raise
    except BaseException:
      if not durable(): start = None  # the bound only runs while the veto is verified in the current attempt
      elif start is None: start = time.monotonic()
      elif time.monotonic() - start >= RECOVERY_BOUND: raise
      while True:
        try:
          time.sleep(1)
          break
        except BaseException: pass


def _lock_parent(root, relative):
  """Owned nonsymlink ancestry, rooted in the fixed host or disposable fixture."""
  fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    for part in (None, *relative.parent.parts):
      if part is not None:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        os.close(fd)
        fd = child
      info = os.fstat(fd)
      if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("Owned nonsymlink lock ancestry required")
    return fd
  except BaseException:
    os.close(fd)
    raise


def _lock_identity(info):
  if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise ValueError("Private regular single-link lock required")
  return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


@contextmanager
def _locks(root):
  """Adapter-owned fixed locks; reviewed old engines need no lock API.

  Acquisition failures precede publication. After physical acquisition, DB
  cleanup retries under the flock; before it, cleanup is retried a bounded
  number of times. Cleanup and close errors never mask a primary exception.
  Remaining limits: parent-inhibitor death, default SIGKILL and power-loss
  durability; no process-lifetime claim follows here. Unlinking by name cannot
  itself be identity-checked, so a replacement between check and unlink stays
  a residual race.
  """
  root = Path(root)
  if root == Path("/") and (os.geteuid() != 0 or not sys.flags.isolated or Path(__file__).absolute() != SCRIPT):
    raise ValueError("Only fixed installed isolated adapter may acquire live locks")
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical explicit lock root required")
  db_parent = physical_parent = db_fd = physical_fd = None
  acquired = released = settled = False
  active = True
  abandoned = []
  primary = None
  try:
    db_parent = _lock_parent(root, DB_LOCK)
    db_fd = os.open(DB_LOCK.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=db_parent)
    def parent_check(parent, relative):
      current = _lock_parent(root, relative)
      try:
        if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (os.fstat(parent).st_dev, os.fstat(parent).st_ino):
          raise ValueError("Lock parent directory changed")
      finally: os.close(current)
    def release_db(*, verify_only=False):
      nonlocal released, settled
      if not active: raise ValueError("Adapter lock scope ended")
      parent_check(db_parent, DB_LOCK)
      was_settled = settled
      if released:
        try: os.stat(DB_LOCK.name, dir_fd=db_parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else:
          # Mid-settlement retry: our unlink is proven done, so a present name
          # is a legitimate foreign owner. Only later calls or verification
          # treat it as a refusal.
          if was_settled or verify_only: raise _Preserved("Foreign pacman lock replacement must remain preserved")
      else:
        try: current = os.stat(DB_LOCK.name, dir_fd=db_parent, follow_symlinks=False)
        except FileNotFoundError: released = True  # our unlink landed before the flag; absence cannot be foreign
        else:
          # Before our unlink, anything on the name that is not exactly our
          # held inode in exact form is foreign or altered: preserve it, never
          # unlink or modify it. Only the held fd check is strict (plain error).
          ours = os.fstat(db_fd)
          if (current.st_dev, current.st_ino) != (ours.st_dev, ours.st_ino):
            raise _Preserved("Foreign pacman lock replacement must remain preserved")
          try: named = _lock_identity(current)
          except ValueError as error: raise _Preserved("Altered pacman lock must remain preserved: " + str(error)) from error
          if named != _lock_identity(ours):
            raise _Preserved("Foreign pacman lock replacement must remain preserved")
      if verify_only: return
      settled = False
      if not released:
        os.unlink(DB_LOCK.name, dir_fd=db_parent)
        released = True  # an ensuing fsync failure must retry absence, not unlink
      os.fsync(db_parent)
      try: os.stat(DB_LOCK.name, dir_fd=db_parent, follow_symlinks=False)
      except FileNotFoundError: pass
      # Decision: once our identity-verified unlink is durable, a name that
      # reappears (real pacman) is a foreign owner. Release is settled, never
      # deleted or modified, and a completed upgrade is not turned into a
      # veto-restoring recovery by it. Physical exclusion still ends with the
      # scope; the foreign lock protects the database from then on.
      settled = True
    def check_physical():
      if not active or not acquired: raise ValueError("Physical exclusion scope ended")
      parent_check(physical_parent, PHYSICAL_LOCK)
      named = os.stat(PHYSICAL_LOCK.name, dir_fd=physical_parent, follow_symlinks=False)
      if _lock_identity(named) != _lock_identity(os.fstat(physical_fd)):
        raise ValueError("Physical exclusion inode changed")
    release_db.check_physical = check_physical
    release_db.abandon = lambda: abandoned.append(True)
    os.fchmod(db_fd, 0o600)
    _lock_identity(os.fstat(db_fd))
    release_db(verify_only=True)
    os.fsync(db_fd)
    os.fsync(db_parent)
    physical_parent = _lock_parent(root, PHYSICAL_LOCK)
    physical_fd = os.open(PHYSICAL_LOCK.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=physical_parent)
    _lock_identity(os.fstat(physical_fd))
    fcntl.flock(physical_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    acquired = True
    check_physical()
    yield release_db
  except BaseException as error:
    primary = error
    raise
  finally:
    problem = None
    try:
      if db_fd is not None and not settled:
        if abandoned:
          try: release_db()  # recovery gave up: one best-effort attempt, no retention
          except Exception as error: problem = error
        elif acquired: _retain_recovery(release_db, lambda: True)
        else: _cleanup_release(release_db)
    except BaseException as error: problem = error
    active = False
    for descriptor in (physical_fd, physical_parent, db_fd, db_parent):
      if descriptor is None: continue
      try: os.close(descriptor)
      except BaseException as error:
        if problem is None: problem = error
    if problem is not None:
      if primary is not None:
        primary.add_note("lock cleanup failed for " + str(root / DB_LOCK) + " (our db.lck may remain and block pacman; remove it only after confirming no pacman process is running, e.g. `pgrep -x pacman` shows none): " + repr(problem))
      if primary is None or not isinstance(problem, Exception): raise problem


def _cleanup_release(release):
  """Bounded pre-acquisition release: 3 paced attempts; an interrupt still gets one more attempt, then re-raises."""
  interrupt, attempts = None, 0
  while True:
    try:
      release()
      break
    except _Preserved: raise
    except Exception:
      attempts += 1
      if attempts >= 3: raise
      try: time.sleep(0.2)
      except BaseException as error: interrupt = interrupt or error
    except BaseException as error:
      if interrupt is not None: raise
      interrupt = error
  if interrupt is not None: raise interrupt


def native():
  approval = _installed_approval()
  _unchanged(approval)
  if (Path("/proc") / str(os.getppid()) / "exe").readlink() != Path("/usr/bin/systemd-inhibit"):
    command = _inhibit_command()
    os.execve(command[0], command, ENV)
    raise RuntimeError("Inhibitor exec unexpectedly returned")
  core, old_native, engine = _verified_engines(approval)
  fd, guard = _guard(old_native, approval)
  try:
    with _locks(ROOT) as release_db:
      release_db.check_physical()
      try:
        guard()
        old_product = engine.PRODUCT
        maintenance = approval.get("maintenance", False)
        def before():
          new_review = _review(_private_bytes(STATE / "runtime-upgrade-review.json"),
                               approval["expected"]["new_review"], approval["reviewed_commit"])
          if maintenance: _maintenance_check(engine.G, barrier=False, image_state=_helper_image_state(approval, new_review))
          else: _product_check(old_product, barrier=False, image_state=_helper_image_state(approval, new_review))
        def after(): _postcheck(core, approval)
        result = core._upgrade_snapshot(approval["source_directory"], root=ROOT,
                                        expected={name: approval["expected"][name] for name in CORE_HASHES},
                                        guard=guard, precheck=before, postcheck=after, approval_id=approval["approval_id"],
                                        **({"maintenance": True} if maintenance else {}))
        guard()
        # After barrier retirement, ordinary admission and db release must
        # pass while the physical lock remains held. Failure rearms the veto.
        core._verify_tree(STATE / "runtime", _review(_private_bytes(STATE / "runtime-deployment-review.json"),
          approval["expected"]["new_review"], approval["reviewed_commit"])["files"])
        if maintenance: _maintenance_check(_load("reviewed_final_update_guard", STATE / "runtime/packages/t2-suspend/hibernate/update_guard.py"), barrier=False)
        else:
          new_product = _load("reviewed_final_product", STATE / "runtime/packages/t2-suspend/hibernate/product.py")
          _product_check(new_product, barrier=False)
        guard()
        release_db(verify_only=True)
        release_db()
      except BaseException as error:
        veto = []
        def recover():
          veto.clear()  # durability is per attempt: never inherited from an earlier one
          _restore_veto(core, approval)
          veto.append(True)  # durable veto (or proven old state) established in this attempt
          release_db.check_physical()
          release_db()
        try: _retain_recovery(recover, lambda: bool(veto))
        except BaseException as stopped:
          release_db.abandon()
          raise error from stopped
        raise
  finally: os.close(fd)
  return {"review_sha256": result["review_sha256"], "live_execution": True, "power_operation": False}


def main(argv=None):
  if (sys.argv[1:] if argv is None else argv): raise ValueError("Fixed adapter takes no arguments")
  print(json.dumps(native(), sort_keys=True))
  return 0


if __name__ == "__main__": raise SystemExit(main())
