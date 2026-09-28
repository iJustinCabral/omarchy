"""Fixed public unprivileged client; source-only, NOT installed/admitted.

Proposed reviewed public layout: this entry at CLIENT (root0644); exact public
handoff/launcher/peer sibling copies at LIBRARY (root0755/root0644). No private
0700 runtime is imported. Root-controlled metadata is not an external byte
review: the eventual native owner MUST bind this entire public inventory to
its approved deployment inventory before enabling admission. Native entry is
currently disabled and creates no endpoint; this client reports its refusal.
The five-second wait is only endpoint publication after reviewed bootstrap/
origin checks, NOT a deadline for expensive artifact/package admission. A
root namespace peer is not proof it belongs to our newly launched sudo: the
future owner must bind the actual socket peer to its exact initiating Origin
before sending a challenge/accepting a descriptor; stale endpoints are never
removed or trusted as native package grants by this client.

The initiating process itself sends V2 context and its original already-held
lock via a fresh H socket, then remains the sudo ancestor until child exit.
Lock-FD environment is only a locator, never authority; no lock substitute,
root environment/PID assertion, sudo -C, owner signal or shell is used.
Interactive run first uses fixed sudo -v with inherited terminal stdio; -y
never authenticates/prompts and exact sudo -n fails truthfully without cached
authority. No claim that later phase sudo timestamps/PTYs cannot prompt.

Cooperative INT/HUP while waiting are recorded with best-effort FD retention;
fatal signals/client death require the future owner's loss recovery. SIGKILL,
TTY loss or a killed sudo/inhibitor cannot be made safe by this helper alone.
"""
import argparse
import contextlib
import importlib.util
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import time


CLIENT = Path("/usr/lib/omarchy/t2-hibernate-maintenance-client.py")
LIBRARY = Path("/usr/lib/omarchy/t2-hibernate-maintenance")
DEPENDENCIES = ("maintenance_handoff.py", "maintenance_launcher.py", "maintenance_peer.py")
OWNER = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_native.py"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
ENDPOINT_TIMEOUT = 5.0


def _sudo_command():
  return ("/usr/bin/sudo", "-n", "--", "/usr/bin/systemd-inhibit", "--what=sleep:shutdown",
    "--mode=block", "--who=omarchy-t2-package-maintenance", "--why=reviewed-package-maintenance",
    "--no-ask-password", "/usr/bin/python3", "-I", "-B", OWNER)


def _auth_command(): return ("/usr/bin/sudo", "-v")


def _inventory():
  if {path.name for path in LIBRARY.iterdir()} != set(DEPENDENCIES):
    raise ValueError("Exact three-file public source inventory required; no cache/extras")


def _installed():
  if Path(__file__) != CLIENT or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    raise ValueError("Fixed installed isolated public client required")
  for path in {CLIENT, *CLIENT.parents, LIBRARY, *LIBRARY.parents, *(LIBRARY / name for name in DEPENDENCIES)}:
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022:
      raise ValueError("Root-controlled public client/library namespace required")
    if path == CLIENT or path.parent == LIBRARY:
      if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1:
        raise ValueError("Exact root-owned readable public source required")
    elif not stat.S_ISDIR(info.st_mode): raise ValueError("Nonsymlink public source ancestors required")
  _inventory()  # -B forbids writes, not reading an unreviewed existing pyc


def _handoff():
  _installed()  # before ANY public sibling import
  spec = importlib.util.spec_from_file_location("public_maintenance_handoff", LIBRARY / "maintenance_handoff.py")
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def _runtime(uid): return Path("/run/user") / str(uid)


def capture_environment(handoff, *, unattended=False):
  """Snapshot account context, not user/session authorization or sudo env."""
  uid = os.getuid()
  if uid <= 0 or os.getresuid() != (uid,) * 3: raise ValueError("Actual unprivileged initiating account required")
  account = pwd.getpwuid(uid)
  value = {key: item for key, item in os.environ.items() if key in handoff.L.ENV_KEYS}
  value.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name,
    SHELL=account.pw_shell, XDG_RUNTIME_DIR=str(_runtime(uid)))
  if unattended: value["OMARCHY_UPDATE_UNATTENDED"] = "1"
  else: value.pop("OMARCHY_UPDATE_UNATTENDED", None)
  return handoff._environment(value, uid, _runtime(uid))


def _original_lock(handoff):
  raw = os.environ.get("OMARCHY_UPDATE_LOCK_FD", "")
  if not re.fullmatch(r"[1-9][0-9]{0,9}", raw) or not 3 <= int(raw) <= 2**31 - 1:
    raise ValueError("Canonical original inherited update-lock FD locator required")
  fd, uid = int(raw), os.getuid()
  directory, identity = handoff._runtime(_runtime(uid), uid)
  handoff._validate(fd, directory, uid, identity)
  os.set_inheritable(fd, False)  # keep own descriptor, never pass it into sudo
  return fd


@contextlib.contextmanager
def _interruptions():
  pending = []
  def record(number, frame):
    if number not in pending: pending.append(number)
  previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGHUP)}
  try:
    for number in previous: signal.signal(number, record)
    yield pending
  finally:
    for number, handler in previous.items(): signal.signal(number, handler)


def _spawn(command):
  return subprocess.Popen(command, env=ENV, close_fds=True)  # stdio inherited, NO pass_fds/shell


def _wait(process):
  while True:
    try: return process.wait()
    except InterruptedError: continue


def _endpoint(handoff, process, pending):
  deadline = time.monotonic() + ENDPOINT_TIMEOUT
  while True:
    if process.poll() is not None: return False
    if pending: raise InterruptedError("Client interrupted before handoff; waiting for owner recovery")
    try:
      handoff._root_endpoint()
      return True
    except FileNotFoundError:
      if time.monotonic() >= deadline: raise TimeoutError("Root handoff endpoint readiness expired")
      time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def _diagnostic(error, code):
  print("Maintenance handoff refused: " + str(error) + "; actual owner status=" + str(code), file=sys.stderr)


def run(*, unattended=False):
  """Return actual sudo status; status0 without handoff is explicit refusal125.

  Does not close/unlock the caller's original FD. No arbitrary owner lifetime
  timeout or terminate/kill cleanup: handoff refusal still waits exact child.
  """
  if type(unattended) is not bool: raise ValueError("Typed unattended selection required")
  uid = os.getuid()
  if uid <= 0 or os.getresuid() != (uid,) * 3 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
    raise ValueError("Actual nonroot sole-reaper client required")
  handoff = _handoff()
  environment = capture_environment(handoff, unattended=unattended)
  fd = _original_lock(handoff)
  with _interruptions() as pending:
    if not unattended:
      auth = _spawn(_auth_command())
      code = _wait(auth)
      if code != 0: return code
      if pending: return 128 + pending[0]
    process = _spawn(_sudo_command())
    accepted, error = False, None
    try:
      if _endpoint(handoff, process, pending):
        handoff.send_native_lock(fd, timeout=1.0, environment=environment)
        accepted = True
    except Exception as failure: error = failure
    finally:
      # Even a failed/uncertain acknowledgement may have delivered our OFD.
      # Do not terminate privileged ancestry or release own original lock.
      code = _wait(process)
    if not accepted or pending:
      error = error or ValueError("Owner exited before contextual handoff" if not accepted else "Client interrupted")
      _diagnostic(error, code)
      if code == 0: return 125
    return code


def main(argv=None):
  argv = list(sys.argv[1:] if argv is None else argv)
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=("run",))
  parser.add_argument("-y", action="store_true", dest="unattended")
  if argv not in (["run"], ["run", "-y"]): parser.error("Exact usage: run [-y]")
  args = parser.parse_args(argv)
  try: code = run(unattended=args.unattended)
  except (OSError, ValueError) as error:
    print("Maintenance client refused: " + str(error), file=sys.stderr)
    return 125
  return code if code >= 0 else 128 - code


if __name__ == "__main__": sys.exit(main())
