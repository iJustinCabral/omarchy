"""Fixed, externally approved live adapter for one exact v2 runtime upgrade.

Install this file root-private outside the replaceable runtime. The only public
entrypoint has no flags or alternate roots. It never changes EFI, modules,
qualification, boot policy or power state. Interrupted publications are not
replayed; the compatible pending marker vetoes routine hibernation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path("/")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
SCRIPT = STATE / "runtime-upgrade-native.py"
APPROVAL = STATE / "runtime-upgrade-approval.json"
BOOTSTRAP = STATE / "runtime-upgrade-bootstrap.py"
WHO = "omarchy-t2-runtime-upgrade"
WHY = "reviewed-v2-runtime-upgrade"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
RUNTIME_REL = "packages/t2-suspend/hibernate/runtime_deployment.py"
HASHES = {"old_review", "old_bootstrap", "old_config", "new_review", "new_bootstrap", "new_config"}
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
      approval["protocol"] != "omarchy-t2-runtime-upgrade-approval-v2" or approval["approved"] is not True):
    raise ValueError("Exact external runtime upgrade approval required")
  identity = approval["approval_id"]
  if type(identity) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identity) or uuid.UUID(identity).version != 4:
    raise ValueError("Fresh canonical UUID4 runtime upgrade approval required")
  if type(approval["expected"]) is not dict or set(approval["expected"]) != HASHES:
    raise ValueError("Six exact old/new authority pins required")
  for value in approval["expected"].values(): _pin(value)
  if approval["expected"]["old_config"] != approval["expected"]["new_config"]:
    raise ValueError("Runtime-only approval must preserve exact configuration pin")
  if type(approval["unchanged"]) is not dict or set(approval["unchanged"]) != set(UNCHANGED):
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
  return approval


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
  for name, (path, mode) in UNCHANGED.items():
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


def _product_check(product, *, barrier):
  config = product.TRIAL._private_json(STATE / "config.json")
  qualification = product.TRIAL._private_json(STATE / "qualification.json")
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  # Every caller holds both native exclusions and has verified this installed
  # runtime tree. Never load a helper from the incoming workspace. Ledger
  # reconciliation alone cannot establish that the resume page has no image.
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
  product = _load("reviewed_new_product", STATE / "runtime/packages/t2-suspend/hibernate/product.py")
  return _product_check(product, barrier=True)


def _restore_veto(core, approval):
  """Emergency fail-closed repair only after a durable completion was written."""
  state_fd = core._open_directory(STATE)
  try:
    core._private(state_fd, directory=True)
    prefix = approval["reviewed_commit"][:12]
    completed = "runtime-upgrade-completed-" + prefix + ".json"
    try: raw = core._private_read(state_fd, completed)
    except FileNotFoundError: return
    record = json.loads(raw, object_pairs_hook=_pairs)
    if (type(record) is not dict or set(record) != {"protocol", "intent", "review_sha256", "config_sha256"} or
        record.get("protocol") != "omarchy-t2-runtime-upgrade-completed-v2" or
        record.get("review_sha256") != approval["expected"]["new_review"] or
        record.get("config_sha256") != approval["expected"]["new_config"]):
      raise ValueError("Cannot restore veto from foreign completion")
    expected = approval["expected"]
    if (type(record["intent"]) is not dict or set(record["intent"]) != {"protocol", "transaction_id",
        "approval_id", "old_review_sha256", "new_review_sha256", "old_config_sha256", "new_config_sha256"} or
        record["intent"].get("protocol") != "omarchy-t2-runtime-upgrade-intent-v2" or
        record["intent"]["approval_id"] != approval["approval_id"] or
        record["intent"]["old_review_sha256"] != expected["old_review"] or
        record["intent"]["new_review_sha256"] != expected["new_review"] or
        record["intent"]["old_config_sha256"] != expected["old_config"] or
        record["intent"]["new_config_sha256"] != expected["new_config"]):
      raise ValueError("Cannot restore veto from invalid intent")
    core._approval_identity(record["intent"]["transaction_id"])
    intent = core._encoded(record["intent"])
    if core._private_read(state_fd, "runtime-upgrade-approval-consumed-" + approval["approval_id"] + ".json") != intent:
      raise ValueError("Cannot restore veto from foreign consumed approval")
    name = core.COMPATIBLE_BARRIER
    try: current = core._private_read(state_fd, name)
    except FileNotFoundError: core._new_private(state_fd, name, intent)
    else:
      if current != intent: raise ValueError("Foreign compatible veto must remain untouched")
  finally: os.close(state_fd)


def native():
  approval = _installed_approval()
  _unchanged(approval)
  if (Path("/proc") / str(os.getppid()) / "exe").readlink() != Path("/usr/bin/systemd-inhibit"):
    command = _inhibit_command()
    os.execve(command[0], command, ENV)
    raise RuntimeError("Inhibitor exec unexpectedly returned")
  core, old_native, engine = _verified_engines(approval)
  fd, guard = _guard(old_native, approval)
  restored = False
  try:
    try:
      with engine._locks(ROOT) as release_db:
        try:
          guard()
          old_product = engine.PRODUCT
          def before(): _product_check(old_product, barrier=False)
          def after(): _postcheck(core, approval)
          result = core._upgrade_snapshot(approval["source_directory"], root=ROOT, expected=approval["expected"],
                                          guard=guard, precheck=before, postcheck=after, approval_id=approval["approval_id"])
          guard()
          # After barrier retirement, ordinary admission and db release must
          # pass while the physical lock remains held. Failure rearms the veto.
          core._verify_tree(STATE / "runtime", _review(_private_bytes(STATE / "runtime-deployment-review.json"),
            approval["expected"]["new_review"], approval["reviewed_commit"])["files"])
          new_product = _load("reviewed_final_product", STATE / "runtime/packages/t2-suspend/hibernate/product.py")
          _product_check(new_product, barrier=False)
          guard()
          release_db(verify_only=True)
          release_db()
        except BaseException:
          _restore_veto(core, approval)
          restored = True
          raise
    except BaseException:
      if not restored: _restore_veto(core, approval)
      raise
  finally: os.close(fd)
  return {"review_sha256": result["review_sha256"], "live_execution": True, "power_operation": False}


def main(argv=None):
  if (sys.argv[1:] if argv is None else argv): raise ValueError("Fixed adapter takes no arguments")
  print(json.dumps(native(), sort_keys=True))
  return 0


if __name__ == "__main__": raise SystemExit(main())
