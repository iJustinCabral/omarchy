"""Root-only disposable VM launcher proof using synthetic phase commands.

Do not run on the host: the dedicated networkless VM mode alone supplies the
fixed private source path and the guest-only passwd entry must match exactly.
No package command, broker grant, inhibitor, boot or host power API is called.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import signal
import stat
import tempfile
import time


PROBE = r'''import fcntl
import json
import os
from pathlib import Path
import sys

lock = int(os.environ["OMARCHY_UPDATE_LOCK_FD"])
home = Path(os.environ["HOME"])
case = os.environ["TERM"]
descriptors = []
for entry in Path("/proc/self/fd").iterdir():
  try: os.fstat(int(entry.name))
  except OSError: continue
  descriptors.append(int(entry.name))
stdio = [[os.fstat(fd).st_dev, os.fstat(fd).st_ino, os.fstat(fd).st_mode] for fd in (0, 1, 2)]
lock_info = os.fstat(lock)
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
os.lseek(lock, 71, os.SEEK_SET)
line = os.read(0, 128)
os.write(1, b"FIXTURE_STDOUT\n")
os.write(2, b"FIXTURE_STDERR\n")
try:
  os.setuid(0)
except PermissionError:
  root_refused = True
else:
  root_refused = False
record = {"uid": list(os.getresuid()), "gid": list(os.getresgid()), "groups": sorted(os.getgroups()),
          "stdio": stdio, "fds": sorted(descriptors), "lock_fd": lock,
          "lock": [lock_info.st_dev, lock_info.st_ino, lock_info.st_mode],
          "stdin": line.decode(), "argv": sys.argv[1:], "pid": os.getpid(),
          "env_marker": (home / (case + ".env")).read_text(), "root_refused": root_refused}
(home / (case + ".json")).write_text(json.dumps(record, sort_keys=True))
sys.exit(37)
'''


def require(condition, message):
  if not condition:
    raise RuntimeError(message)


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def metadata(fd):
  info = os.fstat(fd)
  return [info.st_dev, info.st_ino, info.st_mode]


def busy(path):
  fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Fixture update lock was not continuously held")
  finally: os.close(fd)


def credentials(pid):
  values = {}
  for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
    key, _, value = line.partition(":")
    if key in ("Uid", "Gid", "Groups"):
      values[key] = [int(part) for part in value.split()]
  return values


def output(fd):
  require(bool(select.select([fd], [], [], 1)[0]), "Fixture output descriptor timed out")
  return os.read(fd, 128)


def environment(root, case):
  home = Path("/home/worker")
  return {"PATH": str(root / "bin") + ":/usr/bin:/bin", "HOME": str(home), "USER": "worker",
          "LOGNAME": "worker", "SHELL": "/bin/bash", "LANG": "C", "LC_ALL": "C",
          "OMARCHY_PATH": str(root), "TERM": case, "XDG_RUNTIME_DIR": str(root / "runtime")}


def exercise(launcher, root, lock_path, lock_fd, *, release):
  case = "released" if release else "aborted"
  env = environment(root, case)
  marker, report = Path(env["HOME"]) / (case + ".env"), Path(env["HOME"]) / (case + ".json")
  source_pipes = [os.pipe2(os.O_CLOEXEC) for _ in range(3)]
  saved = [os.dup(fd) for fd in (0, 1, 2)]
  sentinel = os.open(root / "unrelated-secret", os.O_RDONLY)
  os.set_inheritable(sentinel, True)
  ready, pin = None, None
  try:
    # Install genuine stdio temporarily; the launcher must inherit these exact
    # descriptions while closing every unrelated inheritable descriptor.
    installed = (source_pipes[0][0], source_pipes[1][1], source_pipes[2][1])
    stdio = [metadata(fd) for fd in installed]
    old_bash_env = os.environ.get("BASH_ENV")
    old_lock_env = os.environ.get("OMARCHY_UPDATE_LOCK_FD")
    try:
      os.environ["BASH_ENV"] = str(root / "parent-poison.sh")
      os.environ["OMARCHY_UPDATE_LOCK_FD"] = "999999"
      for target, source in enumerate(installed): os.dup2(source, target)
      ready = launcher.launch("snapshot", uid=1000, environment=env, update_lock_fd=lock_fd, timeout=3.0)
    finally:
      for target, original in enumerate(saved): os.dup2(original, target)
      if old_bash_env is None: os.environ.pop("BASH_ENV", None)
      else: os.environ["BASH_ENV"] = old_bash_env
      if old_lock_env is None: os.environ.pop("OMARCHY_UPDATE_LOCK_FD", None)
      else: os.environ["OMARCHY_UPDATE_LOCK_FD"] = old_lock_env
    require(ready.process.returncode is None, "Readiness reaped or completed the phase")
    pin = launcher.P.ChildPin(ready.process, **ready.identity)
    before = credentials(ready.process.pid)
    require(before == {"Uid": [1000] * 4, "Gid": [1000] * 4, "Groups": [1000, 1001]}, "Bootstrap did not drop all UID/GID/groups fields: " + repr(before))
    bootstrap_environment = dict(part.split(b"=", 1) for part in (Path("/proc") / str(ready.process.pid) / "environ").read_bytes().split(b"\0") if part)
    require(bootstrap_environment == {key.encode(): value.encode() for key, value in launcher.BOOTSTRAP_ENV.items()}, "Held bootstrap received user or parent environment")
    require(not marker.exists() and not report.exists(), "User environment/phase executed before release")
    require(os.waitid(os.P_PID, ready.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None, "Held bootstrap already exited")
    time.sleep(0.1)
    pin.identity()
    require(not marker.exists() and not report.exists(), "Held readiness did not keep user code blocked")
    busy(lock_path)
    print("MAINTENANCE_LAUNCHER_HELD " + case + " " + str(ready.process.pid), flush=True)
    if release:
      os.write(source_pipes[0][1], b"fixture stdin\n")
      ready.release()
      result = ready.process.wait(timeout=5)
      require(result == 37, "Launcher replaced the real nonzero child exit status: " + str(result))
      value = json.loads(report.read_text())
      require(value["uid"] == [1000] * 3 and value["gid"] == [1000] * 3 and value["groups"] == [1000, 1001] and value["root_refused"], "Executed phase retained root credentials")
      require(value["stdio"] == stdio and value["stdin"] == "fixture stdin\n", "Phase lost inherited stdio")
      require(output(source_pipes[1][0]) == b"FIXTURE_STDOUT\n" and output(source_pipes[2][0]) == b"FIXTURE_STDERR\n", "Phase output did not reach inherited descriptors")
      require(value["lock_fd"] == lock_fd and value["lock"] == metadata(lock_fd) and value["fds"] == sorted([0, 1, 2, lock_fd]), "Phase inherited unintended descriptors or lost its update lock")
      require(os.lseek(lock_fd, 0, os.SEEK_CUR) == 71, "Update lock descriptor does not share the owner's open file description")
      require(value["argv"] == ["create"] and value["env_marker"] == "released" and value["pid"] == ready.process.pid, "Fixed snapshot command or environment release changed")
      require(not (Path(env["HOME"]) / "parent-env-executed").exists(), "Launcher inherited unallowlisted parent shell environment")
      busy(lock_path)
      print("MAINTENANCE_LAUNCHER_RELEASE_PASS " + json.dumps(value, sort_keys=True), flush=True)
    else:
      ready.abort()
      require(ready.process.returncode == -signal.SIGTERM, "Abort did not retain its actual signal status")
      require(not marker.exists() and not report.exists(), "Aborted held bootstrap executed user code")
      busy(lock_path)
      print("MAINTENANCE_LAUNCHER_ABORT_PASS " + str(ready.process.returncode), flush=True)
  finally:
    if pin is not None: pin.close()
    if ready is not None and ready.process.returncode is None: ready.abort()
    for fd in (*saved, sentinel, *(fd for pair in source_pipes for fd in pair)):
      os.close(fd)


def main():
  require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "Disposable guest test requires guest root")
  user = pwd.getpwnam("worker")
  require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) == (1000, 1000, "/home/worker", "/bin/bash"), "Exact synthetic guest worker account required")
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM environment required")
  require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "Proof must be the sole direct-child reaper")
  launcher = load("guest_maintenance_launcher", "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_launcher.py")
  os.chown(user.pw_dir, 1000, 1000)
  root = Path(tempfile.mkdtemp(prefix="maintenance-fixture-", dir="/run"))
  root.chmod(0o755)
  (root / "bin").mkdir(mode=0o755)
  (root / "probe.py").write_text(PROBE)
  (root / "parent-poison.sh").write_text('printf "%s" poison > /home/worker/parent-env-executed\n')
  environment_probe = root / "bin/fixture-user-env"
  environment_probe.write_text('#!/bin/bash\nprintf "%s" released > "$HOME/$TERM.env"\n')
  environment_probe.chmod(0o755)
  command = root / "bin/omarchy-snapshot"
  command.write_text('#!/bin/bash\nfixture-user-env\nexec /usr/bin/python3 -I -B "' + str(root / "probe.py") + '" "$@"\n')
  command.chmod(0o755)
  (root / "unrelated-secret").write_text("must not be inherited")
  (root / "unrelated-secret").chmod(0o600)
  runtime = root / "runtime"
  runtime.mkdir(mode=0o700)
  os.chown(runtime, 1000, 1000)
  lock_path = runtime / "omarchy-update.lock"
  lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  try:
    os.fchown(lock_fd, 1000, 1000)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    require(stat.S_ISREG(os.fstat(lock_fd).st_mode), "Synthetic regular update lock required")
    print("MAINTENANCE_LAUNCHER_SCOPE guest root and nonroot stub phases; no package commands or broker admission", flush=True)
    exercise(launcher, root, lock_path, lock_fd, release=False)
    exercise(launcher, root, lock_path, lock_fd, release=True)
    print("MAINTENANCE_LAUNCHER_VM_PASS", flush=True)
  finally: os.close(lock_fd)


if __name__ == "__main__": main()
