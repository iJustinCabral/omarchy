"""Fixed installed source-default transition, with no power or authority issuance.

Run only the externally reviewed root-private snapshot with isolated Python.
systemd-inhibit owns the block FD in the parent (systemd v261.2 inhibit.c,
lines 289-307); its child closes inherited FDs and has a parent-death SIGTERM.
The worker verifies that parent and its real logind record at every write
boundary. Direct privileged systemctl operations can bypass logind inhibitors;
the pending router veto, physical lock and power-state checks cover cooperating
callers, not a hostile root. Policy transitions and exclusion startup refuse
all queued jobs. The explicit ongoing-power mode permits ordinary nonpower
jobs only after validating the complete typed inventory; no live entry uses it.

The maintenance action reuses the exact deactivation mechanics, then durably
retains package-maintenance.pending. It adds fixed read-only prerequisites (see
_maintenance_gate) and is source-only: the installed runtime predates the marker
and must first be upgraded by a reviewed runtime upgrade. No package runner,
client or broker exists here, and no qualification or reactivation is issued.

The maintenance publisher also archives generation-baseline.json (the qualified
generation's kernel, UKIs, module stack, driver/control inventories and stock
Limine identity) before the marker. The read-only `assess` action recomputes the
same items and classifies the current generation against it; it takes no
inhibitor, writes nothing and leaves no lock behind, and never authorizes
reactivation or an update (see assess()).

The `reactivate` action (class (a) only: the assessment core reports `unchanged`)
re-applies the retained source default without requalification: it changes one
`default_entry` line of the current Limine bytes, then retires the marker. It
runs under the same inhibitor, db.lck and physical lock as the other actions and
its recovery is a re-run (see boot_policy_transition._reactivate). It is not
requalification, qualification or power permission.

The `rebind` action is the new-generation counterpart for a kernel update whose assessment is
`requalification-required`: after the stager retired the old pair and a NEW pair was staged and qualified
(externally issued config, qualification and boot-policy review, staged under distinct names), it installs that
authority, activates the source default and retires the marker (see boot_policy_transition._rebind and
docs/t2-suspend/REBIND-DESIGN.md). It issues no qualification and performs no power operation.
"""
import argparse
from contextlib import contextmanager
import signal
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path("/")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
SCRIPT = STATE / "runtime/packages/t2-suspend/hibernate/boot_policy_native.py"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
RUNTIME_HIBERNATE = STATE / "runtime/packages/t2-suspend/hibernate"
SLEEP_ENTRY = RUNTIME_HIBERNATE / "sleep_entry.py"
REVIEWED_DROPIN = RUNTIME_HIBERNATE / "systemd-hibernate.conf"
DROPIN = Path("/etc/systemd/system/systemd-hibernate.service.d/omarchy-t2.conf")
VENDOR_UNIT = "/usr/lib/systemd/system/systemd-hibernate.service"
MAINTENANCE_NAME = "package-maintenance.pending"
PROBE_BASE = Path("/run/omarchy-t2-maintenance-probe")
EXEC_EXTRAS = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition")
ACTIONS = ("activation", "deactivation", "maintenance", "reactivate", "rebind")
READ_ONLY = ("assess",)
ASSESSMENT_SCHEMA = "omarchy-t2-generation-assessment-v1"
BOOTLOADERS = ("boot/EFI/BOOT/BOOTX64.EFI", "boot/EFI/limine/limine_x64.efi")
MAX_IMAGE = 256 * 1024 * 1024
MAX_SMALL = 2 * 1024 * 1024
# Items whose change means the qualified generation may no longer match: never
# snapshot churn, which lives only in the Limine //Snapshots region.
CRITICAL_ITEMS = ("kernel", "production_uki", "source_uki", "restore_uki", "module_stack", "manifest", "config", "qualification")
TOLERATED_ITEMS = ("driver_modules", "firmware", "control_inventory", "bootloader")
CONTROL_EXCLUDED = ("boot/limine.conf",)
WHO = "omarchy-t2-source-default"
WHY = "reviewed-boot-policy-transition"
LOGIN = ("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager")
MANAGER = ("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager")
POWER_UNITS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target",
               "suspend-then-hibernate.target", "systemd-suspend.service", "systemd-hibernate.service",
               "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service", "shutdown.target",
               "poweroff.target", "reboot.target", "halt.target", "kexec.target", "soft-reboot.target",
               "systemd-poweroff.service", "systemd-reboot.service", "systemd-halt.service",
               "systemd-kexec.service", "systemd-soft-reboot.service")


def _inhibit_command(action):
  return ("/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block", "--who=" + WHO,
          "--why=" + WHY, "--no-ask-password", "/usr/bin/python3", "-I", "-B", str(SCRIPT), action)


def _installed():
  if os.geteuid() != 0 or not sys.flags.isolated:
    raise ValueError("Explicit root isolated-Python invocation required")
  if Path(__file__).absolute() != SCRIPT:
    raise ValueError("Only the fixed installed reviewed snapshot may execute")
  for path in (SCRIPT, *SCRIPT.parents):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or path.is_symlink():
      raise ValueError("Owned nonsymlink installed runtime required")
    if path == SCRIPT:
      if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Private regular installed adapter required")
    elif not stat.S_ISDIR(info.st_mode):
      raise ValueError("Installed runtime directory required")
  _reviewed_tree()
  spec = importlib.util.spec_from_file_location("native_transition", SCRIPT.with_name("boot_policy_transition.py"))
  engine = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(engine)
  engine._runtime(ROOT)
  # Only the reviewed root-private tree may supply the read-only image check.
  spec = importlib.util.spec_from_file_location("native_reviewed_image_state", SCRIPT.with_name("image_state.py"))
  image_state = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(image_state)
  engine.IMAGE_STATE = image_state
  return engine


def _private_bytes(path):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024:
      raise ValueError("Bounded root-private reviewed code/evidence required")
    raw = os.read(fd, 2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024: raise ValueError("Oversized reviewed code/evidence")
    return raw
  finally: os.close(fd)


def _reviewed_tree():
  """Validate metadata and reviewed bootstrap bytes before importing any code."""
  runtime = STATE / "runtime"
  for path in (STATE, runtime, *runtime.rglob("*")):
    info = path.lstat()
    expected = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
    if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != expected or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
      raise ValueError("Entire installed runtime must be root-private before imports")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
      raise ValueError("Non-linked reviewed code required")
  def pairs(items):
    result = {}
    for key, value in items:
      if key in result: raise ValueError("Duplicate runtime review field")
      result[key] = value
    return result
  review = json.loads(_private_bytes(STATE / "runtime-deployment-review.json"), object_pairs_hook=pairs)
  if set(review) != {"protocol", "approved", "reviewed_commit", "files"} or review["protocol"] != "omarchy-t2-product-runtime-snapshot-v1" or review["approved"] is not True:
    raise ValueError("Externally approved runtime inventory required")
  for path in (SCRIPT, SCRIPT.with_name("runtime_deployment.py")):
    raw = _private_bytes(path)
    if review["files"].get(path.relative_to(runtime).as_posix()) != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
      raise ValueError("Initial adapter/bootstrap bytes differ from reviewed inventory")
  spec = importlib.util.spec_from_file_location("native_reviewed_inventory", SCRIPT.with_name("runtime_deployment.py"))
  deployment = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(deployment)
  deployment._verify_tree(runtime, review["files"])


def _command(argv):
  result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=20, env=ENV)
  if result.returncode != 0 or type(result.stdout) is not str or len(result.stdout.encode()) > 2 * 1024 * 1024:
    raise ValueError("Unavailable bounded native power-exclusion query")
  return result.stdout.strip()


def _bus(method, service, member):
  return shlex.split(_command(("/usr/bin/busctl", "--system", "--no-pager", "--full", method, *service, member)))


def _parent_identity(pid, action):
  proc = Path("/proc") / str(pid)
  if os.getppid() != pid or (proc / "exe").readlink() != Path("/usr/bin/systemd-inhibit"):
    raise ValueError("Exact systemd-inhibit parent required")
  binary = Path("/usr/bin/systemd-inhibit").stat()
  if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
    raise ValueError("Root-owned inhibitor executable required")
  status = (proc / "status").read_text()
  uids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
  if uids != [["0", "0", "0", "0"]]: raise ValueError("Root inhibitor parent required")
  if (proc / "cmdline").read_bytes() != b"\0".join(item.encode() for item in _inhibit_command(action)) + b"\0":
    raise ValueError("Exact fixed inhibitor command required")
  return (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]


def _uint32(value):
  if not (value.isascii() and value.isdecimal() and len(value) <= 10 and str(int(value)) == value and int(value) <= 4294967295):
    raise ValueError("Canonical unsigned 32-bit job inventory field required")
  return int(value)


def _ongoing_jobs(records):
  # systemd v261 man/org.freedesktop.systemd1.xml and
  # src/core/dbus-manager.c method_list_jobs: a(usssoo) is the job ID,
  # primary unit name, type, state, job object path and unit object path.
  # src/core/job.c defines types/states and job_dbus_path; unit paths use
  # src/basic/bus-label.c bus_label_escape (including initial digits).
  if len(records) < 2 or records[0] != "a(usssoo)":
    raise ValueError("Malformed typed system job inventory")
  count = _uint32(records[1])
  if len(records) != 2 + count * 6:
    raise ValueError("Incomplete system job inventory")
  ids = set()
  types = ("start", "verify-active", "stop", "reload", "reload-or-start", "restart", "try-restart", "try-reload", "nop")
  for index in range(2, len(records), 6):
    job_id, unit, job_type, job_state, job_path, unit_path = records[index:index + 6]
    number = _uint32(job_id)
    if number == 0 or number in ids:
      raise ValueError("Zero or duplicate system job ID")
    ids.add(number)
    if not unit or not unit.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in unit):
      raise ValueError("Malformed system job unit name")
    label = "".join(char if char.isalpha() or (offset > 0 and char.isdecimal()) else "_" + format(ord(char), "02x") for offset, char in enumerate(unit))
    if job_type not in types or job_state not in ("waiting", "running") or job_path != "/org/freedesktop/systemd1/job/" + job_id or unit_path != "/org/freedesktop/systemd1/unit/" + label:
      raise ValueError("Malformed or inconsistent system job tuple")
    if unit in POWER_UNITS:
      raise ValueError("Queued power jobs prevent ongoing exclusion")


def _power_idle(pid):
  """Strict startup/transition check: no queued system jobs at all."""
  _power_state(pid, ongoing_power=False)


def _power_ongoing(pid):
  """Read-only ongoing check; parent identity/lifetime belongs to _exclusion."""
  _power_state(pid, ongoing_power=True)


def _power_state(pid, *, ongoing_power):
  records = _bus("call", LOGIN, "ListInhibitors")
  if len(records) < 2 or records[0] != "a(ssssuu)" or not records[1].isdigit():
    raise ValueError("Malformed real logind inhibitor inventory")
  count = int(records[1])
  if len(records) != 2 + count * 6: raise ValueError("Incomplete inhibitor inventory")
  matches = [records[index:index + 6] for index in range(2, len(records), 6)
             if records[index] in ("sleep:shutdown", "shutdown:sleep")
             and records[index + 1:index + 6] == [WHO, WHY, "block", "0", str(pid)]]
  if len(matches) != 1: raise ValueError("Parent does not own the exact real block inhibitor")
  for property_name in ("PreparingForSleep", "PreparingForShutdown"):
    if _bus("get-property", LOGIN, property_name) != ["b", "false"]:
      raise ValueError("Power preparation is already in progress")
  scheduled = _bus("get-property", LOGIN, "ScheduledShutdown")
  # v261 logind retains the immediate operation's action with timeout zero
  # after return (logind-dbus.c property_get_scheduled_shutdown). A real
  # scheduled operation has a finite nonzero time. Reset/initial no-schedule
  # state is the exact empty-action USEC_INFINITY tuple (v261
  # logind-shutdown.c manager_reset_scheduled_shutdown); other combinations
  # remain rejected. Preparing/units/jobs are checked independently.
  retained_actions = ("", "poweroff", "reboot", "halt", "kexec", "soft-reboot", "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate")
  no_schedule = scheduled == ["(st)", "", "18446744073709551615"]
  retained_idle = len(scheduled) == 3 and scheduled[0] == "(st)" and scheduled[1] in retained_actions and scheduled[2] == "0"
  if not (no_schedule or retained_idle):
    raise ValueError("Scheduled shutdown prevents policy transition")
  jobs = _bus("call", MANAGER, "ListJobs")
  if ongoing_power:
    _ongoing_jobs(jobs)
  elif jobs != ["a(usssoo)", "0"]:
    raise ValueError("Queued system jobs prevent policy transition")
  raw = _command(("/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState", *POWER_UNITS))
  rows = []
  for block in raw.split("\n\n"):
    fields = dict(line.split("=", 1) for line in block.splitlines())
    if set(fields) != {"Id", "LoadState", "ActiveState"} or fields["ActiveState"] != "inactive" or fields["LoadState"] not in ("loaded", "not-found"):
      raise ValueError("Power unit is active or ambiguous")
    rows.append(fields["Id"])
  if len(rows) != len(POWER_UNITS) or set(rows) != set(POWER_UNITS): raise ValueError("Exact power-unit inventory required")


@contextmanager
def _exclusion(action, *, ongoing_power=False):
  """Strict entry, optionally power-only ongoing guards; no caller opts in yet."""
  if type(ongoing_power) is not bool:
    raise ValueError("Explicit boolean ongoing-power mode required")
  pid = os.getppid()
  identity = _parent_identity(pid, action)
  fd = os.pidfd_open(pid)
  scope_active = True
  try:
    def check(power_check):
      if not scope_active:
        raise ValueError("Power exclusion scope has expired")
      if select.select([fd], [], [], 0)[0] or _parent_identity(pid, action) != identity:
        raise ValueError("Original inhibitor parent exited or changed")
      power_check(pid)
      if select.select([fd], [], [], 0)[0] or _parent_identity(pid, action) != identity:
        raise ValueError("Original inhibitor parent changed during exclusion checks")
    def guard():
      check(_power_ongoing if ongoing_power else _power_idle)
    check(_power_idle)
    yield guard
  finally:
    scope_active = False
    os.close(fd)


def _precheck(engine, action, phase, capture=None):
  """`capture`, when given, records the audited resume tuple at "before" and requires the same at "after"."""
  product = engine.PRODUCT
  for directory in (STATE, STATE / "ledger", STATE / "archives"):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
      raise ValueError("Existing root-private product state required")
  config = product.TRIAL._private_json(STATE / "config.json")
  qualification = product.TRIAL._private_json(STATE / "qualification.json")
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  ledger = product.TX.Ledger(STATE / "ledger")
  arguments = {"ledger": ledger, "archive_directory": STATE / "archives", "root": ROOT}
  resume = report["audited_details"]["restore_protocol"]["resume"]
  if capture is not None:
    if phase == "before": capture["resume"] = json.loads(json.dumps(resume))
    elif capture.get("resume") != resume: raise ValueError("Audited resume target changed during the transition")
  if phase == "before":
    result = product.check(config, qualification, report, **arguments)
    engine.IMAGE_STATE.require_no_image(ROOT, resume)
    return result
  # Only this internal postcheck crosses our own pending admission veto. The
  # exact approved byte transition is verified separately by the engine; reuse
  # all original structural, artifact, readiness, session and ledger checks.
  receipt = product.validate(config, qualification, report)
  source_default = action == "activation"
  if product.BOOT_POLICY.verify(ROOT, config["staged_receipt_sha256"]) != source_default:
    raise ValueError("Post-transition policy state differs from action")
  product.TRIAL._verify_deployment(ROOT, config, report, source_default=source_default)
  result = product._admission_state(config, receipt, report, **arguments)
  engine.IMAGE_STATE.require_no_image(ROOT, resume)
  return result


def _resume(engine):
  product = engine.PRODUCT
  config = product.TRIAL._private_json(STATE / "config.json")
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  return report["audited_details"]["restore_protocol"]["resume"]


def _reviewed_identity(name):
  """Reviewed private bytes for one runtime file, bound to the approved inventory."""
  raw = _private_bytes(RUNTIME_HIBERNATE / name)
  review = json.loads(_private_bytes(STATE / "runtime-deployment-review.json"))
  expected = review["files"].get("packages/t2-suspend/hibernate/" + name)
  if expected != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
    raise ValueError("Reviewed runtime file differs from approved inventory: " + name)
  return raw


def _dropin_bytes():
  fd = os.open(DROPIN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    named = DROPIN.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 65536
        or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
      raise ValueError("Root-owned regular installed hibernate drop-in required")
    ancestors = [path for path in DROPIN.parents if path != Path("/")]
    for path in ancestors:
      parent = path.lstat()
      if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("Root-owned nonsymlink drop-in ancestors required")
    raw = os.read(fd, 65537)
    if len(raw) > 65536: raise ValueError("Oversized drop-in")
    return raw
  finally: os.close(fd)


def _hibernate_route():
  """Actual installed drop-in bytes and systemd's effective ExecStart, no reload."""
  if _dropin_bytes() != _reviewed_identity("systemd-hibernate.conf"):
    raise ValueError("Installed hibernate drop-in differs from reviewed bytes")
  _reviewed_identity("sleep_entry.py")
  raw = _command(("/usr/bin/systemctl", "show", "--no-pager", "--all", "--property=LoadState,FragmentPath,DropInPaths,ExecStart," + ",".join(EXEC_EXTRAS), "systemd-hibernate.service"))
  fields = {}
  for line in raw.splitlines():
    key, separator, value = line.partition("=")
    if not separator or key in fields: raise ValueError("Ambiguous systemd-hibernate.service properties")
    fields[key] = value
  required = {"LoadState", "FragmentPath", "DropInPaths", "ExecStart"}
  if not required <= set(fields) or set(fields) - required - set(EXEC_EXTRAS) or fields["LoadState"] != "loaded":
    raise ValueError("Exact systemd-hibernate.service property inventory required")
  # Empty properties may be omitted or printed empty; any other hook is unreviewed.
  if any(fields.get(name, "") for name in EXEC_EXTRAS):
    raise ValueError("Unreviewed pre/post/stop/condition commands on systemd-hibernate.service")
  if fields["FragmentPath"] != VENDOR_UNIT or fields["DropInPaths"] != str(DROPIN):
    raise ValueError("Unexpected systemd-hibernate.service fragment or drop-in set")
  execution = fields["ExecStart"]
  if execution.count("{") != 1 or execution.count("}") != 1 or execution.count("argv[]=") != 1 or not (execution.startswith("{ ") and execution.endswith(" }")):
    raise ValueError("Exactly one effective ExecStart required")
  parts = execution[2:-2].split(" ; ")
  if parts[0] != "path=/usr/bin/python3" or parts[1] != "argv[]=/usr/bin/python3 -B " + str(SLEEP_ENTRY):
    raise ValueError("Effective ExecStart is not the reviewed sleep entry")
  if "ignore_errors=no" not in parts or any(part.startswith("ignore_errors=") and part != "ignore_errors=no" for part in parts):
    raise ValueError("Effective ExecStart must not ignore errors")


def _load_reviewed(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def _probe_base():
  """Fixed private base for synthetic probe roots; ownership and mode are verified."""
  try: PROBE_BASE.mkdir(mode=0o700)
  except FileExistsError: pass
  info = PROBE_BASE.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
    raise ValueError("Owned private probe directory required")
  return PROBE_BASE


def _maintenance_vetoes(engine):
  """Behavioral proof that reviewed sleep, product and activation code honor the marker.

  Uses only a private temporary synthetic root under the fixed root-private
  PROBE_BASE (never TMPDIR); a control without the marker must pass so a vacuous
  or always-refusing probe cannot be mistaken for policy.

  Limit: this proves the reviewed veto FUNCTIONS reject the marker. That the real
  callers use them (sleep_entry main -> reject_pending; product admission ->
  verify_deployment) rests on the inventory byte pins and the effective
  ExecStart check in _hibernate_route, not on this probe.
  """
  sleep_entry = _load_reviewed("native_reviewed_sleep_entry", SLEEP_ENTRY)
  if MAINTENANCE_NAME not in sleep_entry.PENDING: raise ValueError("Reviewed sleep entry lacks maintenance veto")
  with tempfile.TemporaryDirectory(dir=_probe_base()) as directory:
    root = Path(directory).resolve()
    state = root / engine.P.STATE
    state.mkdir(parents=True, mode=0o700)
    for path in (state, *state.parents):
      if path == root.parent: break
      path.chmod(0o700)
    sleep_entry.reject_pending(root)  # control: absent marker admits
    marker = state / MAINTENANCE_NAME
    marker.write_bytes(b"synthetic marker")
    def refuses(operation, text):
      try: operation()
      except ValueError as error:
        if text not in str(error): raise
        return
      raise ValueError("Reviewed code does not veto package maintenance marker")
    refuses(lambda: sleep_entry.reject_pending(root), "package maintenance")
    refuses(lambda: engine.PRODUCT.verify_deployment(root, {}, {}), "package maintenance")
    def refuse(*arguments): raise AssertionError("activation reached admission despite maintenance marker")
    refuses(lambda: engine._transition(root, "activation", precheck=refuse, guard=lambda: None), "maintenance intent")


def _maintenance_gate(engine, root, phase, pinned=None):
  """Fixed read-only prerequisites, before any write and again before pending retirement.

  "final" (publisher, marker just written) re-derives the audited resume tuple and
  requires it to equal the `pinned` one just archived. "retained" (re-entry) reads
  the archived tuple from authenticated evidence and NEVER derives artifacts: a
  kernel/UKI update legitimately invalidates the qualified audit while the
  inactive maintenance state stays valid.
  """
  if root != ROOT or phase not in engine.GATE_PHASES: raise ValueError("Fixed live root and known gate phase required")
  _hibernate_route()
  _maintenance_vetoes(engine)
  if phase == "before":
    # The exact stock configuration retained before activation must bind the actual production UKI.
    engine.verify_fallback(ROOT, engine._read(ROOT, engine.P.BACKUP))
  else:
    engine.verify_fallback(ROOT)
  if phase == "final":
    resume = _resume(engine)
    if pinned is not None and resume != pinned.get("resume"): raise ValueError("Audited resume target differs from the archived evidence")
    engine.IMAGE_STATE.require_no_image(ROOT, resume)
  elif phase == "retained":
    # `reactivate` pins the archived tuple: its own activation pending makes the guard's derivation refuse.
    pinned_resume = None if pinned is None else pinned.get("resume")
    engine.IMAGE_STATE.require_no_image(ROOT, engine._pinned_resume(ROOT) if pinned_resume is None else pinned_resume)


def _driver_capture(root, release):
  return _load_reviewed("native_reviewed_root_driver_inventory", RUNTIME_HIBERNATE / "root_driver_inventory.py").capture_baseline(root, release)


def _control_capture(root):
  return _load_reviewed("native_reviewed_root_control_inventory", RUNTIME_HIBERNATE / "root_control_inventory.py").capture(root, baseline=True)


def _running_release(): return os.uname().release


def _absolute(root, path):
  path = Path(path)
  if not path.is_absolute(): raise ValueError("Absolute qualified artifact path required")
  return Path(root) / path.relative_to("/")


def _file(engine, root, path, limit, artifact=False):
  value, _ = engine._stable_bytes(root, path.relative_to(root), limit, artifact=artifact)
  return value


def _small(engine, root, path, artifact=False):
  value, raw = engine._stable_bytes(root, path.relative_to(root), MAX_SMALL, keep=True, artifact=artifact)
  return value, raw


def _pinned_uki(engine, root, state, role):
  """A configured artifact UKI, read as the product audit reads it and pinned to the qualified manifest."""
  directory = _absolute(root, state["config"][role + "_directory"])
  value = _file(engine, root, directory / "mba-t2-hibernation-candidate.efi", engine.MAX_UKI, artifact=True)
  expected = state["config"]["manifest"].get(role + "_sha256")
  if type(expected) is not str or value["sha256"] != expected:
    raise ValueError("Qualified " + role + " UKI differs from the manifest pin")
  return value


def _digest(engine, value): return engine.P.digest(engine._encoded(value))


def _node_digests(engine, values):
  return {name: _digest(engine, node) for name, node in sorted(values.items())}


def _item_kernel(engine, root, state):
  modules = root / "usr/lib/modules"
  engine.G._ancestors(root, modules / "member", engine._owner(root))
  return {"running_release": _running_release(), "qualified_release": state["release"],
          "installed_releases": sorted(entry.name for entry in modules.iterdir())}


def _item_module_stack(engine, root, state):
  identity = {"runtime_sha256": state["config"]["manifest"]["runtime_sha256"],
              "runtime_modules_sha256": _digest(engine, state["source_provenance"].get("modules"))}
  for role in ("source", "restore"):
    directory = _absolute(root, state["config"][role + "_directory"])
    identity[role + "_provenance_sha256"] = _small(engine, root, directory / "provenance.json", artifact=True)[0]["sha256"]
    identity[role + "_initrd_sha256"] = _file(engine, root, directory / "mba-t2-hibernation-candidate.initrd", MAX_IMAGE, artifact=True)["sha256"]
  return identity


def _item_driver(engine, root, state):
  """(driver_modules, firmware) items; each part is an exception instance when only it failed to capture."""
  capture = _driver_capture(root, state["release"])
  errors = capture["errors"]
  def part(key, build):
    if capture[key] is None: return ValueError(errors.get(key, key + " capture unavailable"))
    return build(capture[key])
  return (part("modules", lambda modules: {"kernel_release": capture["kernel_release"], "capture_sha256": _digest(engine, modules),
                                            "modules": _node_digests(engine, modules)}),
          part("firmware", lambda firmware: {"capture_sha256": _digest(engine, firmware), "files": _node_digests(engine, firmware)}))


def _item_control(engine, root, state):
  capture = _control_capture(root)
  files = {name: node for name, node in capture["files"].items() if name not in CONTROL_EXCLUDED}
  filtered = {"files": files, "directories": capture["directories"]}
  return {"excluded": list(CONTROL_EXCLUDED), "capture_sha256": _digest(engine, filtered),
          "files": _node_digests(engine, files), "directories": _node_digests(engine, capture["directories"])}


def _control_volatile(key):
  return any(key == root or key.startswith(root + "/") for root in ("run", "var/run", "tmp", "var/tmp", "dev", "proc", "sys"))


def _comparable(name, item):
  """Item in comparison form. control_inventory drops volatile-root keys and the aggregate digest.

  Baselines published before volatile roots were excluded contain per-boot /run
  entries and an aggregate over them; the per-item digest maps are compared with
  every volatile key filtered on both sides instead. Everything else is exact.
  """
  if name != "control_inventory" or type(item) is not dict: return item
  value = {key: part for key, part in item.items() if key != "capture_sha256"}
  for section in ("files", "directories"):
    if type(value.get(section)) is dict:
      value[section] = {key: part for key, part in value[section].items() if not _control_volatile(key)}
  return value


def _item_bootloader(engine, root, state):
  files = {}
  for name in BOOTLOADERS:
    try: files[name] = _file(engine, root, root / name, MAX_IMAGE)
    except FileNotFoundError: files[name] = {"present": False}
  return {"files": files}


def generation_items(engine, root=ROOT, *, config_name="config.json", qualification_name="qualification.json"):
  """Identity items of the generation the qualified config names, in the baseline's exact shape.

  Read-only and shared by the publisher (baseline provider) and `assess`, so both
  sides recompute identically. `rebind` passes the staged file names to capture the
  generation its replacement authority names before installing it. Failures never raise: each item becomes
  {"unavailable": reason}. Returns (items, errors), errors mapping every
  unavailable item to its reason; the publisher refuses only when a
  CRITICAL_ITEMS entry is unavailable, so an unusual host still publishes and
  assessment later reports the other items unknown instead of blocking updates.
  """
  root, items, errors, state = Path(root), {}, {}, {}
  def need(key):
    if key not in state: raise ValueError("Prerequisite unavailable: " + key)
    return state[key]
  def config():
    raw = engine._read(root, engine.P.STATE / config_name)
    state["config"] = parsed = engine.P._json(raw)
    return {"sha256": engine.P.digest(raw), "audited_details_sha256": parsed["audited_details_sha256"],
            "staged_receipt_sha256": parsed["staged_receipt_sha256"]}
  def manifest():
    value = need("config")["manifest"]
    if type(value) is not dict: raise ValueError("Qualified manifest required")
    return {"sha256": _digest(engine, value), "fields": value}
  def provenance():
    directory = _absolute(root, need("config")["source_directory"])
    state["source_provenance"] = parsed = engine.P._json(_small(engine, root, directory / "provenance.json", artifact=True)[1])
    if type(parsed.get("kernel_release")) is not str: raise ValueError("Qualified kernel release required")
    state["release"] = parsed["kernel_release"]
  def uki(role):
    return lambda: _pinned_uki(engine, root, {"config": need("config")}, role)
  driver = {}
  def drivers():
    if not driver:
      try: driver["value"] = _item_driver(engine, root, {"release": need("release")})
      except Exception as error: driver["value"] = (error, error)
    return driver["value"]
  def driver_part(index):
    value = drivers()[index]
    if isinstance(value, Exception): raise value
    return value
  def run(name, thunk):
    try: items[name] = thunk()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
      errors[name] = type(error).__name__ + ": " + str(error)[:200]
      items[name] = {"unavailable": errors[name]}
  run("config", config)
  run("qualification", lambda: {"sha256": engine.P.digest(engine._read(root, engine.P.STATE / qualification_name))})
  run("manifest", manifest)
  run("_provenance", lambda: provenance() or {})
  items.pop("_provenance"); errors.pop("_provenance", None)
  run("kernel", lambda: _item_kernel(engine, root, {"release": need("release")}))
  run("production_uki", lambda: _file(engine, root, root / engine.PRODUCTION, engine.MAX_UKI))
  run("source_uki", uki("source"))
  run("restore_uki", uki("restore"))
  run("module_stack", lambda: _item_module_stack(engine, root, {"config": need("config"), "source_provenance": need("source_provenance")}))
  run("driver_modules", lambda: driver_part(0))
  run("firmware", lambda: driver_part(1))
  run("control_inventory", lambda: _item_control(engine, root, None))
  run("bootloader", lambda: _item_bootloader(engine, root, None))
  return {name: items[name] for name in engine.BASELINE_ITEMS}, errors


def _baseline(engine, root=ROOT):
  """Publisher's provider: the qualified generation, or refuse to publish without its core identity."""
  items, errors = generation_items(engine, root)
  fatal = {name: errors[name] for name in CRITICAL_ITEMS if name in errors}
  if fatal: raise ValueError("Qualified generation identity unavailable for the baseline: " + json.dumps(fatal, sort_keys=True))
  return items


def _differences(recorded, current, path="", depth=0):
  """Paths that differ between two JSON-plain values, bounded and deterministic."""
  if recorded == current: return []
  if type(recorded) is dict and type(current) is dict and depth < 3:
    found = []
    for key in sorted(set(recorded) | set(current)):
      found += _differences(recorded.get(key), current.get(key), path + "/" + key, depth + 1)
    return found
  return [path or "/"]


def assess(engine, root=ROOT):
  """Classify the current generation against the archived publish-time baseline.

  Strictly read-only: no writes, no db.lck, no inhibitor, no admission or
  derive_artifacts (a kernel/UKI update legitimately invalidates those). The
  physical cycle lock is only probed non-blockingly and released; a busy lock,
  ledger or package transaction reports `unknown`, never blocks. A result of
  `unchanged` says the recomputed partial inventories equal the baseline's; it is
  not update safety, qualification or permission to reactivate. Snapshot churn in
  Limine's //Snapshots region never changes the class: limine is reported as
  exact bytes and as the guard's stock projection, and only a projection change
  counts.

  The classification itself is _assess_core, which takes already-validated
  evidence and never probes a lock, so `reactivate` can run it under its own
  db.lck and physical lock without always reporting `unknown`.
  """
  root = Path(root)
  report = _assess_report()
  def unknown(reason, **extra):
    return {**report, "class": "unknown", "reason": reason, **extra}
  if engine._present(root / engine.DB_LOCK): return unknown("A package transaction holds db.lck", busy=True)
  owner = engine._owner(root)
  # Probe only: a read-only, advisory evaluation needs no exclusion, and holding the
  # lock through hashing would make a concurrent pacman guard refuse. Release now.
  try: fd, _ = engine.G._physical(root, owner)
  except ValueError as error: return unknown(str(error), busy="holds the physical lock" in str(error))
  os.close(fd)
  try:
    evidence = engine.G._maintenance(root)
    marker = engine._read(root, engine.MAINTENANCE)
  except (OSError, ValueError, BlockingIOError) as error:
    return unknown("Maintenance evidence not validated: " + type(error).__name__ + ": " + str(error)[:200])
  # No lock is held while hashing, so a transaction may have started meanwhile.
  return _assess_core(engine, root, evidence, marker, busy=lambda: engine._present(root / engine.DB_LOCK))


def _assess_report(): return {"protocol": ASSESSMENT_SCHEMA, "read_only": True, "reactivation_evaluated": False, "qualification_issued": False}


def _assess_core(engine, root, evidence, marker, *, busy=lambda: False):
  """Lock-free classification of already-validated maintenance evidence against its baseline.

  `evidence` is engine.G._maintenance(root)'s result and `marker` the bytes it
  validated. Never probes db.lck or the physical lock (the caller's business:
  `assess` probes, `reactivate` owns both); `busy()` is the caller's hook for a
  transaction that may have started while hashing.
  """
  root = Path(root)
  report = _assess_report()
  def unknown(reason, **extra):
    return {**report, "class": "unknown", "reason": reason, **extra}
  report["transition_id"] = evidence["transition_id"]
  report["maintenance_intent_sha256"] = evidence["maintenance_intent_sha256"]
  try: baseline = engine.read_baseline(root, marker)
  except FileNotFoundError: return unknown("Generation baseline is missing", baseline="missing")
  except (OSError, ValueError) as error: return unknown("Generation baseline is invalid: " + str(error)[:200], baseline="invalid")
  current, errors = generation_items(engine, root)
  if engine._read(root, engine.MAINTENANCE) != marker: return unknown("Maintenance marker changed during assessment")
  if busy(): return unknown("A package transaction started during assessment", busy=True)
  raw = engine._read(root, engine.P.LIMINE, private=False)
  try: stock = engine.stock_identity(raw)
  except ValueError as error: return unknown("Current Limine configuration is not stock: " + str(error)[:200])
  items = {}
  for name in (*CRITICAL_ITEMS, *TOLERATED_ITEMS):
    if "unavailable" in baseline[name]: items[name] = {"state": "unknown", "reason": "baseline item unavailable: " + baseline[name]["unavailable"]}
    elif name in errors: items[name] = {"state": "unknown", "reason": errors[name]}
    elif _comparable(name, baseline[name]) == _comparable(name, current[name]): items[name] = {"state": "equal"}
    else: items[name] = {"state": "changed", "paths": _differences(_comparable(name, baseline[name]), _comparable(name, current[name]))[:32]}
  recorded = baseline["limine"]
  projection = recorded.get("projection_sha256") == stock["projection_sha256"]
  limine = {"exact_equal": recorded.get("exact_sha256") == stock["exact_sha256"], "stock_projection_equal": projection,
            "state": "equal" if projection else "changed"}
  changed = sorted(name for name, item in items.items() if item["state"] == "changed") + ([] if projection else ["limine"])
  missing = sorted(name for name, item in items.items() if item["state"] == "unknown")
  classification = "requalification-required" if changed else ("unknown" if missing else "unchanged")
  return {**report, "class": classification, "baseline": "valid", "items": items, "limine": limine,
          "changed_items": changed, "unknown_items": missing}


def _reactivation_config(engine):
  """Fresh qualified config, qualification and derived report from the fixed state (read-only)."""
  product = engine.PRODUCT
  config = product.TRIAL._private_json(STATE / "config.json")
  qualification = product.TRIAL._private_json(STATE / "qualification.json")
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  return config, qualification, report


def _reactivation_inspect(engine, evidence):
  """R0.5/R0.7: the derived resume equals the pinned one, and product.validate accepts the qualified configuration."""
  config, qualification, report = _reactivation_config(engine)
  if report["audited_details"]["restore_protocol"]["resume"] != evidence["resume"]:
    raise ValueError("Derived resume target differs from the archived maintenance evidence")
  engine.PRODUCT.validate(config, qualification, report)
  return {"config": config, "manifest": report["manifest"]}


def _reactivation_postchecks(engine, root, baseline):
  """W6 native checks: deployment as source default, product validation, no image, generation == baseline."""
  product = engine.PRODUCT
  config, qualification, report = _reactivation_config(engine)
  resume = report["audited_details"]["restore_protocol"]["resume"]
  product.validate(config, qualification, report)
  product.TRIAL._verify_deployment(root, config, report, source_default=True)
  engine.IMAGE_STATE.require_no_image(root, resume)
  items, errors = generation_items(engine, root)
  if errors or any(_comparable(name, items[name]) != _comparable(name, baseline[name]) for name in engine.BASELINE_ITEMS):
    raise ValueError("Generation items differ from the baseline after reactivation")


def _rebind_inspect(engine, evidence, staged):
  """Product-level validation of the STAGED replacement authority, before anything is installed (read-only).

  The derived audit must reproduce the archived resume target (the swap location is not requalified here), the
  product validator must accept the staged config and qualification for the derived manifest, the new pair must
  verify as staged stock, and the fresh generation baseline is captured from the staged names.
  """
  product = engine.PRODUCT
  config, qualification = staged["config"], staged["qualification"]
  report = product.ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  if report["audited_details"]["restore_protocol"]["resume"] != evidence["resume"]:
    raise ValueError("Derived resume target differs from the archived maintenance evidence")
  product.validate(config, qualification, report)
  product.TRIAL._verify_deployment(ROOT, config, report, source_default=False)
  engine.IMAGE_STATE.require_no_image(ROOT, evidence["resume"])
  items, errors = generation_items(engine, ROOT, config_name="rebind-config.json", qualification_name="rebind-qualification.json")
  fatal = {name: errors[name] for name in CRITICAL_ITEMS if name in errors}
  if fatal: raise ValueError("Fresh generation identity unavailable: " + json.dumps(fatal, sort_keys=True))
  return {"manifest": report["manifest"], "baseline": items}


def _rebind_postchecks(engine, root, fresh):
  """W7 native checks on the INSTALLED authority: deployment as source default, product validation, no image, generation == fresh baseline."""
  product = engine.PRODUCT
  config, qualification, report = _reactivation_config(engine)
  resume = report["audited_details"]["restore_protocol"]["resume"]
  product.validate(config, qualification, report)
  product.TRIAL._verify_deployment(root, config, report, source_default=True)
  engine.IMAGE_STATE.require_no_image(root, resume)
  items, errors = generation_items(engine, root)
  fatal = {name: errors[name] for name in CRITICAL_ITEMS if name in errors}
  if fatal: raise ValueError("Generation identity unavailable after rebind: " + json.dumps(fatal, sort_keys=True))
  for name in engine.BASELINE_ITEMS:
    if name in TOLERATED_ITEMS and (name in errors or "unavailable" in fresh[name]): continue  # tolerated items may be unreadable on either side
    if _comparable(name, items[name]) != _comparable(name, fresh[name]):
      raise ValueError("Generation item differs from the fresh baseline after rebind: " + name)


def _refuse_reactivation_pending(engine):
  if engine.reactivation_pending(ROOT):
    raise ValueError("A reactivation is pending or interrupted; re-run `reactivate` to recover it (it rolls back or finishes retirement) before any maintenance action")
  if engine.rebind_pending(ROOT) is True:
    raise ValueError("A rebind is pending or interrupted; re-run `rebind` to recover it (it rolls back or finishes retirement) before any maintenance action")


@contextmanager
def _signals_raise():
  """SIGHUP, SIGTERM and SIGINT become SystemExit, so the `finally` clauses release db.lck.

  A dropped ssh session or a Ctrl-C must not leak the package lock. The write sequences are already recoverable by re-running
  the same action (the pending veto stays until it proves rollback or completion), so raising at any point is safe. SIGKILL and
  power loss cannot be caught; the runbook covers a leaked lock. Previous handlers are restored on exit.
  """
  def raiser(number, _frame): raise SystemExit(128 + number)
  previous = {number: signal.signal(number, raiser) for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)}
  try: yield
  finally:
    for number, handler in previous.items(): signal.signal(number, handler)


def native(action):
  """Fixed host action; no roots, runners, prechecks, force or approval APIs."""
  if action not in (*ACTIONS, *READ_ONLY): raise ValueError("Explicit policy action required")
  engine = _installed()
  if action == "assess":
    # Read-only: no inhibitor re-exec, exclusion, lock file or write of any kind.
    return assess(engine, ROOT)
  parent = Path("/proc") / str(os.getppid()) / "exe"
  if parent.readlink() != Path("/usr/bin/systemd-inhibit"):
    command = _inhibit_command(action)
    os.execve(command[0], command, ENV)
    raise RuntimeError("Inhibitor exec unexpectedly returned")
  with _signals_raise(), _exclusion(action) as guard:
    if action == "reactivate":
      capture = {}
      gate = lambda root, phase: _maintenance_gate(engine, root, phase, capture)
      result = engine._reactivate(ROOT, guard=guard, gate=gate, native=engine._NATIVE_MAINTENANCE, pinned=capture,
                                  assess=lambda evidence, marker: _assess_core(engine, ROOT, evidence, marker),
                                  inspect=lambda evidence: _reactivation_inspect(engine, evidence),
                                  postchecks=lambda root, baseline: _reactivation_postchecks(engine, root, baseline))
      return {**result, "live_execution": True, "power_operation": False}
    if action == "rebind":
      capture = {}
      gate = lambda root, phase: _maintenance_gate(engine, root, phase, capture)
      result = engine._rebind(ROOT, guard=guard, gate=gate, native=engine._NATIVE_MAINTENANCE, pinned=capture,
                              assess=lambda evidence, marker: _assess_core(engine, ROOT, evidence, marker),
                              inspect=lambda evidence, staged: _rebind_inspect(engine, evidence, staged),
                              postchecks=lambda root, fresh: _rebind_postchecks(engine, root, fresh))
      return {**result, "live_execution": True, "power_operation": False}
    if action == "maintenance":
      _refuse_reactivation_pending(engine)
      capture = {}
      gate = lambda root, phase: _maintenance_gate(engine, root, phase, capture)
      if engine._present(ROOT / engine.MAINTENANCE) and engine._present(ROOT / engine.PENDINGS["deactivation"]):
        # Crash/gate failure between marker and pending retirement: finish that one step only.
        result = engine._complete_interrupted_maintenance(ROOT, guard=guard, gate=gate, native=engine._NATIVE_MAINTENANCE, pinned=capture)
      elif engine._present(ROOT / engine.MAINTENANCE):
        # Idempotent re-entry reuses the guard's exact inactive validator, never rewrites.
        result = engine._verify_existing_maintenance(ROOT, guard=guard, gate=gate, native=engine._NATIVE_MAINTENANCE)
      else:
        result = engine._transition(ROOT, action, precheck=lambda root, requested, phase: _precheck(engine, requested, phase, capture),
                                    guard=guard, maintenance_gate=gate, native=engine._NATIVE_MAINTENANCE,
                                    maintenance_resume=lambda: capture["resume"],
                                    maintenance_baseline=lambda: _baseline(engine, ROOT))
      return {**result, "live_execution": True, "power_operation": False}
    # The only live callback is this fixed adapter's own read-only verifier.
    result = engine._transition(ROOT, action, precheck=lambda root, requested, phase: _precheck(engine, requested, phase), guard=guard)
    return {**result, "live_execution": True, "power_operation": False}


def main(argv=None):
  parser = argparse.ArgumentParser(description="Reviewed installed source-default activation, exact stock fallback or inactive maintenance; no power transition")
  parser.add_argument("action", choices=(*ACTIONS, *READ_ONLY))
  args = parser.parse_args(argv)
  print(json.dumps(native(args.action), sort_keys=True))
  return 0


if __name__ == "__main__": raise SystemExit(main())
