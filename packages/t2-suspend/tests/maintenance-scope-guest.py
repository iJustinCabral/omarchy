"""Dedicated networkless VM experiment; never run this root fixture on host.

Tests inherited cooperative scope membership, not unrelated system services or
hostile root migration. No native admission/hook/package/boot action. If exact
emptiness is unobservable, prints diagnostics and retains fixture locks and
real inhibitor until the external disposable-VM timeout destroys the guest.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import signal
import subprocess
import sys
import tempfile
import time


INSTALLED = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate")
PROBE = r'''import fcntl,json,os,signal,sys,time
from pathlib import Path
lock=int(os.environ['OMARCHY_UPDATE_LOCK_FD'])
case=os.environ['TERM']
report=Path(os.environ['XDG_STATE_HOME'])/('scope-descendant-'+case+'.json')
first=os.fork()
if first==0:
  os.setsid()
  if os.fork()!=0: os._exit(0)
  if case=='term-ignore': signal.signal(signal.SIGTERM,signal.SIG_IGN)
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  os.lseek(lock,71,os.SEEK_SET)
  value={'pid':os.getpid(),'ppid':os.getppid(),'uids':list(os.getresuid()),
    'gids':list(os.getresgid()),'groups':sorted(os.getgroups()),
    'cgroup':Path('/proc/self/cgroup').read_text(),'sid':os.getsid(0),
    'stdio':[[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in (0,1,2)]}
  temporary=report.with_suffix('.tmp')
  temporary.write_text(json.dumps(value))
  temporary.replace(report)
  while True: time.sleep(1)
os.waitpid(first,0)
until=time.monotonic()+3
while not report.exists():
  if time.monotonic()>until: sys.exit(125)
  time.sleep(.01)
sys.exit(23)
'''


def require(condition, message):
  if not condition: raise RuntimeError(message)


def load(name):
  spec = importlib.util.spec_from_file_location("guest_" + name, INSTALLED / (name + ".py"))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def busy(path):
  fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Fixture exclusion lock released prematurely")
  finally: os.close(fd)


def inhibitors():
  return subprocess.check_output(["/usr/bin/busctl", "--system", "--no-pager", "call",
    "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
    "ListInhibitors"], env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, timeout=2).decode()


def worker(case):
  L, S = load("maintenance_launcher"), load("maintenance_scope")
  root = Path(tempfile.mkdtemp(prefix="maintenance-scope-fixture-", dir="/run"))
  root.chmod(0o755)
  (root / "bin").mkdir(mode=0o755)
  (root / "probe.py").write_text(PROBE)
  command = root / "bin/omarchy-snapshot"
  command.write_text('#!/bin/bash\nexec /usr/bin/python3 -I -B "' + str(root / "probe.py") + '" "$@"\n')
  command.chmod(0o755)
  runtime = root / "runtime"
  runtime.mkdir(mode=0o700)
  os.chown(runtime, 1000, 1000)
  home = Path("/home/worker")
  os.chown(home, 1000, 1000)
  lock_path, physical_path = runtime / "omarchy-update.lock", root / "physical.lock"
  lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  physical = os.open(physical_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  os.fchown(lock, 1000, 1000)
  for fd in (lock, physical): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
  sentinel = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-c", "import time\nwhile True: time.sleep(1)"], close_fds=True)
  sentinel_fd = os.pidfd_open(sentinel.pid)
  held = scope = None
  descendant_fd = None
  try:
    environment = {"HOME": str(home), "USER": "worker", "LOGNAME": "worker", "SHELL": "/bin/bash",
      "OMARCHY_PATH": str(root), "PATH": str(root / "bin") + ":/usr/bin:/bin",
      "XDG_RUNTIME_DIR": str(runtime), "XDG_STATE_HOME": str(home), "LANG": "C", "LC_ALL": "C", "TERM": case}
    report = home / ("scope-descendant-" + case + ".json")
    stdio = [[os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd in (0, 1, 2)]
    held = L.launch("snapshot", uid=1000, environment=environment, update_lock_fd=lock)
    started = time.monotonic()
    scope = S.prepare(held)
    while not scope.ready and time.monotonic() - started < 3:
      scope.check_ready(timeout=0.5)
    require(scope.ready, "Held scope attachment failed: " + repr(scope.error))
    require(not report.exists(), "Untrusted phase ran before placement/release")
    require(S._membership(os.getpid()) != scope.control_group, "Exclusion owner placed inside kill scope")
    require(S._membership(sentinel.pid) != scope.control_group, "Outside sentinel entered phase scope")
    print("MAINTENANCE_SCOPE_ATTACHED " + json.dumps({"case": case, "unit": scope.name, "group": scope.control_group,
      "directory_identity": scope.directory_identity, "events_identity": scope.events_identity,
      "held": held.process.pid, "owner": os.getpid(), "sentinel": sentinel.pid}), flush=True)
    held.release()
    require(held.process.wait(timeout=4) == 23, "Real direct-child exit status lost")
    value = json.loads(report.read_text())
    require(value["uids"] == [1000] * 3 and value["gids"] == [1000] * 3 and value["groups"] == [1000, 1001], "Phase credentials changed")
    require(value["cgroup"] == "0::" + scope.control_group + "\n", "Doublefork descendant escaped inherited scope")
    require(value["stdio"] == stdio, "Scope placement changed inherited stdio")
    require(value["sid"] != os.getsid(0), "Fixture did not create detached descendant")
    require(os.lseek(lock, 0, os.SEEK_CUR) == 71, "Scope lost original lock OFD")
    descendant_fd = os.pidfd_open(value["pid"])
    require(not select.select([descendant_fd], [], [], 0)[0] and scope._populated(), "Leader exit incorrectly counted descendants empty")
    busy(lock_path)
    busy(physical_path)
    require("scope-fixture" in inhibitors(), "Real guest inhibitor was not held")
    settled = scope.drain(timeout=4)
    diagnostic = {"case": case, "settled": settled, "error": repr(scope.error), "path_exists": scope.path.exists(),
      "descendant_exited": bool(select.select([descendant_fd], [], [], 0)[0]),
      "sentinel_alive": not bool(select.select([sentinel_fd], [], [], 0)[0]), "direct_status": held.process.returncode}
    for label, fd in (("directory", scope.directory_fd), ("events", scope.events_fd)):
      try:
        info = os.fstat(fd)
        diagnostic[label + "_pin"] = {"dev": info.st_dev, "ino": info.st_ino, "nlink": info.st_nlink,
          "link": os.readlink("/proc/self/fd/" + str(fd))}
      except OSError as error: diagnostic[label + "_pin_error"] = repr(error)
    try:
      os.lseek(scope.events_fd, 0, os.SEEK_SET)
      diagnostic["pinned_events_raw"] = os.read(scope.events_fd, 4096).decode()
    except OSError as error: diagnostic["pinned_events_error"] = repr(error)
    print("MAINTENANCE_SCOPE_DRAIN " + json.dumps(diagnostic, sort_keys=True), flush=True)
    busy(lock_path)
    busy(physical_path)
    require("scope-fixture" in inhibitors() and diagnostic["sentinel_alive"], "Owner/inhibitor/outside sentinel lost during drain")
    if not settled:
      print("MAINTENANCE_SCOPE_VM_UNSETTLED retaining fixture physical lock, update lock, scope handle and real inhibitor until external VM timeout", flush=True)
      while True: time.sleep(1)
    require(diagnostic["descendant_exited"], "Empty verdict preceded owned descendant exit")
    scope.close()
    print("MAINTENANCE_SCOPE_WORKER_PASS " + case + " " + json.dumps(value, sort_keys=True), flush=True)
  finally:
    # This is reached only on settled proof or setup assertion failure, never
    # the unsettled drain branch. No PID-ancestry or blanket descendant killing.
    if held is not None: held.abort()
    sentinel.terminate()
    sentinel.wait(timeout=2)
    for fd in (sentinel_fd, descendant_fd, lock, physical):
      if fd is not None: os.close(fd)


def main():
  require(os.getresuid() == (0,) * 3 and os.getresgid() == (0,) * 3, "Guest root required")
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM only")
  account = pwd.getpwnam("worker")
  require((account.pw_uid, account.pw_gid, account.pw_dir, account.pw_shell) == (1000, 1000, "/home/worker", "/bin/bash"), "Synthetic account required")
  if len(sys.argv) == 3 and sys.argv[1] == "worker" and sys.argv[2] in ("term-ignore", "graceful"):
    return worker(sys.argv[2])
  require(not sys.argv[1:], "Fixed fixture mode only")
  for case in ("term-ignore", "graceful"):
    command = ["/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block", "--who=scope-fixture",
      "--why=guest-descendant-containment", "--no-ask-password", "/usr/bin/python3", "-I", "-B", "/maintenance-scope-test.py", "worker", case]
    require(subprocess.run(command, close_fds=True).returncode == 0, "Scope worker failed: " + case)
    require("scope-fixture" not in inhibitors(), "Inhibitor survived completed worker scope: " + case)
  print("MAINTENANCE_SCOPE_VM_PASS", flush=True)


if __name__ == "__main__": main()
