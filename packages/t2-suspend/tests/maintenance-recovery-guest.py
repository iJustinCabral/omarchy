"""Dedicated disposable VM integration, NEVER run this root fixture on host.

Real C/T/M/B plus real held user scopes, lock OFD and logind inhibitor. Policy
and UKIs are synthetic F.Transitions bytes. No actual package/boot/power action,
native owner/client admission or reactivation is enabled. An unresolved repair
keeps the owner inside both exclusions until the external VM timeout destroys
this disposable guest; no automatic phase replay occurs.
"""
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch


BASE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend")
SCRIPT = "/maintenance-recovery-test.py"
WHO, WHY = "recovery-fixture", "guest-retained-maintenance-recovery"
PROBE = r'''import fcntl,json,os,signal,time
from pathlib import Path
lock=int(os.environ['OMARCHY_UPDATE_LOCK_FD'])
report=Path(os.environ['XDG_STATE_HOME'])/'descendant.json'
first=os.fork()
if first==0:
  os.setsid()
  if os.fork()!=0: os._exit(0)
  signal.signal(signal.SIGTERM,signal.SIG_IGN)
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  value={'pid':os.getpid(),'uids':list(os.getresuid()),'gids':list(os.getresgid()),
    'groups':sorted(os.getgroups()),'cgroup':Path('/proc/self/cgroup').read_text(),'sid':os.getsid(0)}
  temporary=report.with_suffix('.tmp');temporary.write_text(json.dumps(value));temporary.replace(report)
  while True: time.sleep(1)
os.waitpid(first,0)
while not report.exists(): time.sleep(.01)
if os.environ['TERM']=='client-loss':
  while True: time.sleep(1)
'''


def require(condition, message):
  if not condition: raise RuntimeError(message)


def load(name, path):
  spec = importlib.util.spec_from_file_location("recovery_guest_" + name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def busy(path):
  fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Original exclusion lock released during recovery: " + str(path))
  finally: os.close(fd)


def wait_report(path):
  deadline = time.monotonic() + 12
  while not path.exists():
    if time.monotonic() > deadline: raise TimeoutError("User scope descendant report missing")
    time.sleep(.01)
  return json.loads(path.read_bytes())


def client(endpoint, directory, environment):
  require(os.getresuid() == (1000,) * 3, "Actual nonroot V2 stub client required")
  H = load("client_handoff", BASE / "hibernate/maintenance_handoff.py")
  H.ROOT_ENDPOINT = Path(endpoint)  # explicit disposable namespace ONLY
  fd = os.open(Path(directory) / "omarchy-update.lock", os.O_RDWR | os.O_CLOEXEC)
  try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
      original = H._root_endpoint()
      stream.settimeout(3)
      stream.connect(endpoint)
      owner = H._RootPeer(stream, original)
      try:
        # Strict generic Peer intentionally cannot inspect root /proc/exe.
        # This VM stub uses the existing fixed-root-namespace kernel pin, not
        # a weakened exact Peer or the not-yet-deployed public native client.
        H._send_exchange(stream, fd, directory, H.P._timeout(3), owner.check, environment)
      finally: owner.close()
    while True: time.sleep(1)
  finally: os.close(fd)


def worker(case):
  C = load("coordinator", BASE / "hibernate/maintenance_coordinator.py")
  S = load("scope", BASE / "hibernate/maintenance_scope.py")
  N = load("power", BASE / "hibernate/boot_policy_native.py")
  F = load("transition_fixture", BASE / "tests/test-hibernate-boot-policy-transition.py")
  # Seed ONLY public test-fixture bytes under /run, never private host assets.
  original_temporary = tempfile.TemporaryDirectory
  fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
  with patch.object(tempfile, "TemporaryDirectory", side_effect=lambda: original_temporary(prefix="maintenance-recovery-", dir="/run")):
    fixture.setUp()
  root, data = fixture.root, fixture.f
  root.parent.chmod(0o755)
  root.chmod(0o755)
  data.write(C.M.BOOT, b"0f909934-0ecf-4407-863d-6822c81cb2df")
  fixture.run_action()
  # fixture writes intentionally privatize ancestor directories; restore only
  # disposable root traversal, not root-private product state.
  root.parent.chmod(0o755)
  root.chmod(0o755)
  runtime, omarchy, reports = root / "runtime", root / "omarchy", root / "reports"
  runtime.mkdir(mode=0o700)
  reports.mkdir(mode=0o700)
  for path in (runtime, reports): os.chown(path, 1000, 1000)
  initial_lock = os.open(runtime / "omarchy-update.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  os.fchown(initial_lock, 1000, 1000)
  os.close(initial_lock)  # client creates/holds the original locked OFD itself
  (omarchy / "bin").mkdir(parents=True, mode=0o755)
  omarchy.chmod(0o755)
  (omarchy / "probe.py").write_text(PROBE)
  for name, command in C.L.PHASES.items():
    path = omarchy / "bin" / command[0]
    path.write_text('#!/bin/bash\nexec /usr/bin/python3 -I -B "' + str(omarchy / "probe.py") + '" "$@"\n')
    path.chmod(0o755)
  os.chown("/home/worker", 1000, 1000)
  environment = {"HOME": "/home/worker", "USER": "worker", "LOGNAME": "worker", "SHELL": "/bin/bash",
    "OMARCHY_PATH": str(omarchy), "PATH": str(omarchy / "bin") + ":/usr/bin:/bin",
    "XDG_RUNTIME_DIR": str(runtime), "XDG_STATE_HOME": str(reports), "TERM": case, "LANG": "C", "LC_ALL": "C"}
  report = reports / "descendant.json"
  endpoint = root / "handoff.sock"
  N.WHO, N.WHY = WHO, WHY  # private guest query-only module; no native methods
  parent = os.getppid()
  identity = C.B.P._identity(parent)
  parent_fd = os.pidfd_open(parent)
  scopes, held = [], []
  state = {"drain_fault": case == "client-loss", "veto_fault": False, "recovery": False,
    "callback_interrupt": False, "wait_interrupt": False, "attempts": 0, "descendant_fd": None}
  process = monitor = None
  original_sync, original_new, original_sleep = C.M.T._sync, C.M.T._new, time.sleep
  errors = []

  def power():
    C.B.P._alive(parent_fd)
    require(C.B.P._identity(parent) == identity, "Original inhibitor parent changed")
    N._power_ongoing(parent)
    C.B.P._alive(parent_fd)

  def pin_descendant():
    value = wait_report(report)
    require(value["uids"] == [1000] * 3 and value["gids"] == [1000] * 3 and value["groups"] == [1000, 1001], "Phase lost dropped user credentials")
    require(value["cgroup"] == "0::" + scopes[0].control_group + "\n", "Detached descendant escaped owned scope")
    require(value["sid"] != os.getsid(0), "TERM-ignore descendant was not detached")
    if state["descendant_fd"] is None: state["descendant_fd"] = os.pidfd_open(value["pid"])
    return value

  @contextmanager
  def exclusion():
    N._power_idle(parent)
    try: yield power
    finally:
      require(all(scope.closed and scope.settled for scope in scopes), "Unsettled scope left physical/inhibitor lifetime")
      require(all(value.payload_fd is None and value.process.returncode is not None for value in held), "Held child/descriptors left owner lifetime")
      require(state["descendant_fd"] is not None and bool(select.select([state["descendant_fd"]], [], [], 0)[0]), "Owned descendant alive at owner exclusion exit")
      raw = (root / C.M.T.MAINTENANCE).read_bytes()
      intent = json.loads(raw)
      require(raw == (root / C.M.T.HISTORY / intent["transition_id"] / "maintenance-intent.json").read_bytes(), "Exact archived veto missing at safe exit")
      power()
      print("MAINTENANCE_RECOVERY_SAFE_EXIT " + case, flush=True)

  def attach(ready):
    held.append(ready)
    require(not ready.released and not report.exists(), "User phase ran before placement")
    scope = S.prepare(ready)
    scopes.append(scope)
    drain = scope.drain
    def observed_drain():
      pin_descendant() if ready.released else None
      if state["drain_fault"]:
        scope.error = RuntimeError("injected first scope drain failure")
        return False
      return drain(timeout=4)
    scope.drain = observed_drain
    print("MAINTENANCE_RECOVERY_SCOPE " + json.dumps({"case": case, "unit": scope.name,
      "group": scope.control_group, "owner": os.getpid(), "child": ready.process.pid,
      "ready": scope.ready, "error": repr(scope.error)}), flush=True)
    return scope

  def recover(error, attempt):
    state["recovery"] = True
    state["attempts"] += 1
    busy(root / C.M.T.PHYSICAL_LOCK)
    busy(runtime / "omarchy-update.lock")
    power()
    value = pin_descendant()
    print("MAINTENANCE_RECOVERY_RETAINED " + json.dumps({"case": case, "attempt": attempt,
      "error": type(error).__name__, "descendant": value["pid"], "scope_settled": scopes[0].settled,
      "physical_update_locks_held": True, "inhibitor_held": True}), flush=True)
    if not state["callback_interrupt"]:
      state["callback_interrupt"] = True
      raise KeyboardInterrupt("fixture recovery cancellation must retain owner")
    state["drain_fault"] = state["veto_fault"] = False

  def pause(seconds):
    if state["recovery"] and not state["wait_interrupt"]:
      state["wait_interrupt"] = True
      busy(root / C.M.T.PHYSICAL_LOCK)
      busy(runtime / "omarchy-update.lock")
      power()
      raise KeyboardInterrupt("fixture backoff interruption must retain owner")
    return original_sleep(seconds)

  def sync(directory):
    if state["veto_fault"] and directory == root / C.M.T.P.STATE:
      raise OSError("injected maintenance veto directory fsync failure")
    return original_sync(directory)

  def publish(path, raw, mode=0o600):
    if case == "veto-fsync" and path.name.endswith("-observed-exit.json"):
      pin_descendant()
      require(scopes[0].settled, "Status write preceded descendant settlement")
      (root / C.M.T.MAINTENANCE).unlink()
      state["veto_fault"] = True
      raise OSError("injected postwait diagnostic/veto failure")
    return original_new(path, raw, mode)

  def lose_client():
    try:
      pin_descendant()
      process.terminate()  # actual owned client, never an asserted numeric PID
    except BaseException as error: errors.append(error)

  try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
      listener.bind(str(endpoint))
      endpoint.chmod(0o666)
      listener.listen()
      listener.settimeout(4)
      argv = ["/usr/bin/python3", "-I", "-B", SCRIPT, "client", str(endpoint), str(runtime), json.dumps(environment)]
      process = subprocess.Popen(argv, user=1000, group=1000, extra_groups=[1000, 1001],
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, close_fds=True)
      stream, _ = listener.accept()
      if case == "client-loss":
        monitor = threading.Thread(target=lose_client)
        monitor.start()
      with stream, patch.object(C.M.T, "_sync", side_effect=sync), patch.object(C.M.T, "_new", side_effect=publish), patch.object(time, "sleep", side_effect=pause):
        try:
          C.coordinate(root, stream, sender_identity={"uid": 1000, "exe": str(Path(argv[0]).resolve()), "argv": argv},
            runtime_directory=runtime, user_environment=None, precheck=fixture.check, exclusion=exclusion,
            hook_identity={"uid": 0, "exe": str(Path(argv[0]).resolve()), "argv": argv},
            intermediary_identity={"uid": 1000, "exe": str(Path(argv[0]).resolve())},
            scope_factory=attach, recover=recover, phase_timeout=15, handoff_timeout=3)
        except (OSError, ValueError) as error:
          print("MAINTENANCE_RECOVERY_ORIGINAL_FAILURE " + case + " " + type(error).__name__, flush=True)
        else: raise RuntimeError("Injected failure incorrectly completed package maintenance")
    if monitor is not None: monitor.join(timeout=2)
    require(not errors and (monitor is None or not monitor.is_alive()), "Client loss monitor failed")
    require(len(scopes) == len(held) == 1 and state["attempts"] >= 2 and state["wait_interrupt"], "Repair bypassed retained scope/interrupt checks")
    intent = json.loads((root / C.M.T.MAINTENANCE).read_bytes())
    archive = root / C.M.T.HISTORY / intent["transition_id"]
    require((archive / "package-maintenance-failure.json").is_file(), "Original failure evidence missing")
    require(not (archive / "package-maintenance-complete.json").exists() and not list(archive.glob("package-phase-01-*-start.json")), "Failure advanced or claimed completion")
    require(not (root / C.HOOK_SOCKET).exists(), "Hook listener remained after safe exit")
    print("MAINTENANCE_RECOVERY_WORKER_PASS " + case, flush=True)
  finally:
    # All normal paths above prove settlement/veto before releasing resources.
    # Unresolved retained loops never reach this finally; external VM timeout
    # destroys the entire guest instead of dropping an unconfirmed exclusion.
    if process is not None:
      if process.poll() is None: process.terminate()
      process.wait(timeout=2)
    for fd in (state["descendant_fd"], parent_fd):
      if fd is not None: os.close(fd)
    fixture.doCleanups()


def main():
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM only")
  if len(sys.argv) == 5 and sys.argv[1] == "client":
    return client(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))
  require(os.getresuid() == (0,) * 3, "Guest root owner required")
  account = pwd.getpwnam("worker")
  require((account.pw_uid, account.pw_gid, account.pw_dir) == (1000, 1000, "/home/worker"), "Synthetic guest account required")
  if len(sys.argv) == 3 and sys.argv[1] == "worker" and sys.argv[2] in ("client-loss", "veto-fsync"):
    return worker(sys.argv[2])
  require(not sys.argv[1:], "Fixed VM cases only")
  for case in ("client-loss", "veto-fsync"):
    argv = ["/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block", "--who=" + WHO,
      "--why=" + WHY, "--no-ask-password", "/usr/bin/python3", "-I", "-B", SCRIPT, "worker", case]
    require(subprocess.run(argv, close_fds=True).returncode == 0, "Integrated recovery worker failed: " + case)
    N = load("released_power", BASE / "hibernate/boot_policy_native.py")
    deadline = time.monotonic() + 2
    while WHO in N._bus("call", N.LOGIN, "ListInhibitors"):
      require(time.monotonic() < deadline, "Real inhibitor survived settled worker exit")
      time.sleep(.01)
    print("MAINTENANCE_RECOVERY_INHIBITOR_RELEASED " + case, flush=True)
  print("MAINTENANCE_RECOVERY_VM_PASS", flush=True)


if __name__ == "__main__": main()
