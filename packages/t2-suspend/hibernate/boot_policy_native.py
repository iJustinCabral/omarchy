"""Fixed installed source-default transition, with no power or authority issuance.

Run only the externally reviewed root-private snapshot with isolated Python.
systemd-inhibit owns the block FD in the parent (systemd v261.2 inhibit.c,
lines 289-307); its child closes inherited FDs and has a parent-death SIGTERM.
The worker verifies that parent and its real logind record at every write
boundary. Direct privileged systemctl operations can bypass logind inhibitors;
the pending router veto, physical lock and power-state checks cover cooperating
callers, not a hostile root. All queued jobs are conservatively refused.
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

sys.dont_write_bytecode = True
ROOT = Path("/")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
SCRIPT = STATE / "runtime/packages/t2-suspend/hibernate/boot_policy_native.py"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
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


def _power_idle(pid):
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
  # scheduled operation has a nonzero time; preparing/units/jobs are separate.
  retained_actions = ("", "poweroff", "reboot", "halt", "kexec", "soft-reboot", "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate")
  if len(scheduled) != 3 or scheduled[0] != "(st)" or scheduled[1] not in retained_actions or scheduled[2] != "0":
    raise ValueError("Scheduled shutdown prevents policy transition")
  if _bus("call", MANAGER, "ListJobs") != ["a(usssoo)", "0"]:
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
def _exclusion(action):
  pid = os.getppid()
  identity = _parent_identity(pid, action)
  fd = os.pidfd_open(pid)
  try:
    def guard():
      if select.select([fd], [], [], 0)[0] or _parent_identity(pid, action) != identity:
        raise ValueError("Original inhibitor parent exited or changed")
      _power_idle(pid)
      if select.select([fd], [], [], 0)[0] or _parent_identity(pid, action) != identity:
        raise ValueError("Original inhibitor parent changed during exclusion checks")
    guard()
    yield guard
  finally: os.close(fd)


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
    return product.check(config, qualification, report, **arguments)
  # Only this internal postcheck crosses our own pending admission veto. The
  # exact approved byte transition is verified separately by the engine; reuse
  # all original structural, artifact, readiness, session and ledger checks.
  receipt = product.validate(config, qualification, report)
  source_default = action == "activation"
  if product.BOOT_POLICY.verify(ROOT, config["staged_receipt_sha256"]) != source_default:
    raise ValueError("Post-transition policy state differs from action")
  product.TRIAL._verify_deployment(ROOT, config, report, source_default=source_default)
  return product._admission_state(config, receipt, report, **arguments)


def native(action):
  """Fixed host action; no roots, runners, prechecks, force or approval APIs."""
  if action not in ("activation", "deactivation"): raise ValueError("Explicit policy action required")
  engine = _installed()
  parent = Path("/proc") / str(os.getppid()) / "exe"
  if parent.readlink() != Path("/usr/bin/systemd-inhibit"):
    command = _inhibit_command(action)
    os.execve(command[0], command, ENV)
    raise RuntimeError("Inhibitor exec unexpectedly returned")
  with _exclusion(action) as guard:
    # The only live callback is this fixed adapter's own read-only verifier.
    result = engine._transition(ROOT, action, precheck=lambda root, requested, phase: _precheck(engine, requested, phase), guard=guard)
    return {**result, "live_execution": True, "power_operation": False}


def main(argv=None):
  parser = argparse.ArgumentParser(description="Reviewed installed source-default activation or exact stock fallback; no power transition")
  parser.add_argument("action", choices=("activation", "deactivation"))
  args = parser.parse_args(argv)
  print(json.dumps(native(args.action), sort_keys=True))
  return 0


if __name__ == "__main__": raise SystemExit(main())
