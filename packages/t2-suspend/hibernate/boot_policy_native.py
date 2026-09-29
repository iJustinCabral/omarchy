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
"""
import argparse
from contextlib import contextmanager
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
ACTIONS = ("activation", "deactivation", "maintenance")
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


def _precheck(engine, action, phase):
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
  if phase == "before":
    result = product.check(config, qualification, report, **arguments)
    engine.IMAGE_STATE.require_no_image(ROOT, report["audited_details"]["restore_protocol"]["resume"])
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
  engine.IMAGE_STATE.require_no_image(ROOT, report["audited_details"]["restore_protocol"]["resume"])
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
  raw = _command(("/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState,FragmentPath,DropInPaths,ExecStart", "systemd-hibernate.service"))
  fields = {}
  for line in raw.splitlines():
    key, separator, value = line.partition("=")
    if not separator or key in fields: raise ValueError("Ambiguous systemd-hibernate.service properties")
    fields[key] = value
  if set(fields) != {"LoadState", "FragmentPath", "DropInPaths", "ExecStart"} or fields["LoadState"] != "loaded":
    raise ValueError("Exact systemd-hibernate.service property inventory required")
  if fields["FragmentPath"] != VENDOR_UNIT or fields["DropInPaths"] != str(DROPIN):
    raise ValueError("Unexpected systemd-hibernate.service fragment or drop-in set")
  execution = fields["ExecStart"]
  if execution.count("{") != 1 or execution.count("}") != 1 or execution.count("argv[]=") != 1 or not (execution.startswith("{ ") and execution.endswith(" }")):
    raise ValueError("Exactly one effective ExecStart required")
  parts = execution[2:-2].split(" ; ")
  if parts[0] != "path=/usr/bin/python3" or parts[1] != "argv[]=/usr/bin/python3 -B " + str(SLEEP_ENTRY):
    raise ValueError("Effective ExecStart is not the reviewed sleep entry")


def _load_reviewed(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def _maintenance_vetoes(engine):
  """Behavioral proof that reviewed sleep, product and activation code honor the marker.

  Uses only a private temporary synthetic root; a control without the marker
  must pass so a vacuous or always-refusing probe cannot be mistaken for policy.
  """
  sleep_entry = _load_reviewed("native_reviewed_sleep_entry", SLEEP_ENTRY)
  if MAINTENANCE_NAME not in sleep_entry.PENDING: raise ValueError("Reviewed sleep entry lacks maintenance veto")
  with tempfile.TemporaryDirectory() as directory:
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


def _maintenance_gate(engine, root, phase):
  """Fixed read-only prerequisites, before any write and again before pending retirement."""
  if root != ROOT or phase not in engine.GATE_PHASES: raise ValueError("Fixed live root and known gate phase required")
  _hibernate_route()
  _maintenance_vetoes(engine)
  if phase == "before":
    # The exact stock configuration retained before activation must bind the actual production UKI.
    engine.verify_fallback(ROOT, engine._read(ROOT, engine.P.BACKUP))
  else:
    engine.verify_fallback(ROOT)
  if phase in ("final", "retained"):
    engine.IMAGE_STATE.require_no_image(ROOT, _resume(engine))


def native(action):
  """Fixed host action; no roots, runners, prechecks, force or approval APIs."""
  if action not in ACTIONS: raise ValueError("Explicit policy action required")
  engine = _installed()
  parent = Path("/proc") / str(os.getppid()) / "exe"
  if parent.readlink() != Path("/usr/bin/systemd-inhibit"):
    command = _inhibit_command(action)
    os.execve(command[0], command, ENV)
    raise RuntimeError("Inhibitor exec unexpectedly returned")
  with _exclusion(action) as guard:
    if action == "maintenance":
      gate = lambda root, phase: _maintenance_gate(engine, root, phase)
      if engine._present(ROOT / engine.MAINTENANCE):
        # Idempotent re-entry validates the retained inactive state, never rewrites it.
        result = engine._verify_existing_maintenance(ROOT, guard=guard, gate=gate, native=engine._NATIVE_MAINTENANCE)
      else:
        result = engine._transition(ROOT, action, precheck=lambda root, requested, phase: _precheck(engine, requested, phase),
                                    guard=guard, maintenance_gate=gate, native=engine._NATIVE_MAINTENANCE)
      return {**result, "live_execution": True, "power_operation": False}
    # The only live callback is this fixed adapter's own read-only verifier.
    result = engine._transition(ROOT, action, precheck=lambda root, requested, phase: _precheck(engine, requested, phase), guard=guard)
    return {**result, "live_execution": True, "power_operation": False}


def main(argv=None):
  parser = argparse.ArgumentParser(description="Reviewed installed source-default activation, exact stock fallback or inactive maintenance; no power transition")
  parser.add_argument("action", choices=ACTIONS)
  args = parser.parse_args(argv)
  print(json.dumps(native(args.action), sort_keys=True))
  return 0


if __name__ == "__main__": raise SystemExit(main())
