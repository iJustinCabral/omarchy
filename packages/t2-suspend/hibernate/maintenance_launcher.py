"""Fixed dropped-user phase launcher; NOT a native admission/coordinator CLI.

The native caller must authenticate the initiating user/session, verify this
installed runtime and supply the original update-lock OFD (future SCM_RIGHTS),
not reopen a pathname or trust SUDO/env claims. Context validation is not origin
authentication. Root always derives passwd/group data and drops credentials in
Popen, never preexec_fn. Same-user unprivileged fixtures cannot test root drop.

The isolated fixed Python bootstrap receives NO user environment/code before
readiness. Owner pins held.process with held.identity, then invokes release.
Only private pipes and the explicit lock are inherited alongside terminal stdio;
only the lock survives exec. No terminal/session/process-group changes. Release
is single-use and transports bounded JSON privately, not command-line secrets.
Sole-reaper ownership transfers to the broker; abort after broker exit only
terminates/reaps the still-owned direct child. Descendant draining, real native
eligibility/admission/inhibitor and generation reactivation remain separate.
"""
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import select
import signal
import stat
import subprocess
import time


spec = importlib.util.spec_from_file_location("launcher_peer", Path(__file__).with_name("maintenance_peer.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
INSTALLED = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_launcher.py")
PYTHON = "/usr/bin/python3"
PHASES = {
  "pkg-prune": ("omarchy-update-pkg-prune",), "snapshot": ("omarchy-snapshot", "create"),
  "dev": ("omarchy-update-dev",), "keyring": ("omarchy-update-keyring",),
  "system-pkgs": ("omarchy-update-system-pkgs",), "migrate": ("omarchy-migrate",),
  "post-update": ("omarchy-hook", "post-update"), "aur-pkgs": ("omarchy-update-aur-pkgs",),
  "mise": ("omarchy-update-mise",), "orphan-pkgs": ("omarchy-update-orphan-pkgs",),
}
ENV_KEYS = frozenset(("HOME", "USER", "LOGNAME", "SHELL", "PATH", "OMARCHY_PATH", "TERM", "COLORTERM",
  "LANG", "LC_ALL", "LC_CTYPE", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
  "XDG_CACHE_HOME", "XDG_SESSION_ID", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY",
  "DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "OMARCHY_UPDATE_UNATTENDED"))
BOOTSTRAP_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
MAX_PAYLOAD = 4096
BOOTSTRAP = '''import json,os,select,struct,sys
ready,payload,lock=map(int,sys.argv[1:])
if os.getuid()==0 or os.getuid()!=os.geteuid(): sys.exit(125)
os.write(ready,b"ready\\n");os.close(ready)
if not select.select([payload],[],[],5)[0]: sys.exit(125)
def read(count):
  raw=b""
  while len(raw)<count:
    part=os.read(payload,count-len(raw))
    if not part: sys.exit(125)
    raw+=part
  return raw
size=struct.unpack("!I",read(4))[0]
if not 0<size<=4092: sys.exit(125)
value=json.loads(read(size).decode("utf-8"))
os.close(payload)
if set(value)!={"argv","environment"}: sys.exit(125)
os.set_inheritable(lock,True)
os.execve(value["argv"][0],value["argv"],value["environment"])
'''


def _native():
  if Path(__file__) != INSTALLED: raise ValueError("Root launch requires fixed installed reviewed module")
  for path in (*reversed(INSTALLED.parents), INSTALLED):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or (path != INSTALLED and not stat.S_ISDIR(info.st_mode)) or (path == INSTALLED and not stat.S_ISREG(info.st_mode)):
      raise ValueError("Root-private installed launcher ancestry required")


def _context(uid, environment):
  if type(uid) is not int or uid <= 0: raise ValueError("Explicit nonroot user required")
  try: account = pwd.getpwuid(uid)
  except KeyError: raise ValueError("Known passwd user required") from None
  groups = sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))
  if account.pw_gid <= 0 or any(value <= 0 for value in groups): raise ValueError("Nonroot account groups required")
  if type(environment) is not dict or not set(environment) <= ENV_KEYS or any(type(key) is not str or type(value) is not str or "\0" in value for key, value in environment.items()):
    raise ValueError("Explicit allowlisted user environment required")
  expected = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name, "SHELL": account.pw_shell}
  if any(environment.get(key) != value for key, value in expected.items()): raise ValueError("Passwd-bound user context required")
  for key in ("OMARCHY_PATH", "PATH"):
    if key not in environment: raise ValueError("Explicit OMARCHY_PATH/PATH required; no defaults")
  directory = Path(environment["OMARCHY_PATH"])
  if not directory.is_absolute() or not directory.is_dir(): raise ValueError("Absolute explicit Omarchy path required")
  # Normal omarchy dev links are valid user context. Commands use the resolved
  # target; the original explicit environment value is preserved after drop.
  directory = directory.resolve()
  if any(not entry or not Path(entry).is_absolute() for entry in environment["PATH"].split(":")):
    raise ValueError("Absolute explicit user PATH entries required")
  if "OMARCHY_UPDATE_UNATTENDED" in environment and environment["OMARCHY_UPDATE_UNATTENDED"] != "1": raise ValueError("Exact unattended context required")
  credentials = {"user": uid, "group": account.pw_gid}
  if os.geteuid() == 0:
    _native()
    credentials["extra_groups"] = groups
  elif os.getresuid() != (uid,) * 3 or os.getresgid() != (account.pw_gid,) * 3 or sorted(set(os.getgroups())) != groups:
    raise ValueError("Unprivileged fixture must already have exact account credentials")
  return directory, credentials


def _lock(fd, uid, environment):
  if type(fd) is not int or fd < 3: raise ValueError("Explicit inherited update-lock FD required")
  info = os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022 or info.st_nlink != 1:
    raise ValueError("Owned regular update-lock OFD required")
  path = Path(environment.get("XDG_RUNTIME_DIR", "/tmp")) / "omarchy-update.lock"
  if not path.is_absolute() or path.resolve() != path or os.readlink("/proc/self/fd/" + str(fd)) != str(path):
    raise ValueError("Update-lock descriptor does not match supplied runtime context")
  named = path.lstat()
  if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino): raise ValueError("Update-lock pathname/FD differ")
  if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY: raise ValueError("Original writable update-lock descriptor required")
  fresh = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    current = os.fstat(fresh)
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino): raise ValueError("Update-lock changed during ownership check")
    try: fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: pass
    else: raise ValueError("Update-lock was not already held")
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise ValueError("Passed descriptor does not own update lock") from None
    if (path.lstat().st_dev, path.lstat().st_ino) != (info.st_dev, info.st_ino): raise ValueError("Update-lock changed after ownership check")
  finally: os.close(fresh)


class ReadyPhase:
  def __init__(self, process, identity, pin, payload_fd, payload):
    self.process, self.identity, self.pin = process, identity, pin
    self.payload_fd, self.payload = payload_fd, payload
    self.owner, self.released = os.getpid(), False

  def release(self):
    if os.getpid() != self.owner or self.released or self.payload_fd is None: raise ValueError("Owned single-use held phase required")
    P._match(self.pin.identity(), **self.identity)
    deadline = time.monotonic() + 1
    try:
      while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError("Phase release deadline expired")
        if not select.select([], [self.payload_fd], [], remaining)[1]: raise TimeoutError("Phase release deadline expired")
        try: count = os.write(self.payload_fd, self.payload)
        except BlockingIOError: continue
        if count != len(self.payload): raise ValueError("Atomic phase release write incomplete")
        self.released = True
        break
    finally:
      os.close(self.payload_fd)
      self.payload_fd = None
      self.pin.close()

  def abort(self):
    if os.getpid() != self.owner: raise ValueError("Only phase owner may close/abort")
    try:
      if self.process.returncode is None:
        os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        self.process.terminate()
        try: self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
          self.process.kill()
          self.process.wait(timeout=1)
    finally:
      if self.payload_fd is not None:
        os.close(self.payload_fd)
        self.payload_fd = None
      self.pin.close()

  close = abort


def launch(phase, *, uid, environment, update_lock_fd, timeout=2.0):
  """Ready held child; authenticate caller/lock exclusion separately, pin then release."""
  if type(phase) is not str or phase not in PHASES: raise ValueError("Fixed update phase required")
  if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
    raise ValueError("Bounded readiness and sole-reaper/default SIGCHLD required")
  directory, credentials = _context(uid, environment)
  _lock(update_lock_fd, uid, environment)
  user_env = dict(environment, OMARCHY_UPDATE_LOCK_FD=str(update_lock_fd))
  command, *args = PHASES[phase]
  raw = json.dumps({"argv": [str(directory / "bin" / command), *args], "environment": user_env}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
  if not 0 < len(raw) <= MAX_PAYLOAD - 4: raise ValueError("Private phase payload exceeds bound")
  process, pin = None, None
  fds = set()
  try:
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    fds.update((ready_r, ready_w))
    payload_r, payload_w = os.pipe2(os.O_CLOEXEC)
    fds.update((payload_r, payload_w))
    if len(raw) + 4 > os.fpathconf(payload_w, "PC_PIPE_BUF"): raise ValueError("Atomic bounded phase payload required")
    os.set_blocking(payload_w, False)
    argv = [PYTHON, "-I", "-B", "-c", BOOTSTRAP, str(ready_w), str(payload_r), str(update_lock_fd)]
    identity = {"uid": uid, "exe": str(Path(PYTHON).resolve()), "argv": argv}
    process = subprocess.Popen(argv, env=BOOTSTRAP_ENV, close_fds=True, pass_fds=(ready_w, payload_r, update_lock_fd), **credentials)
    for fd in (ready_w, payload_r):
      os.close(fd)
      fds.remove(fd)
    deadline, observed = time.monotonic() + timeout, b""
    while observed != b"ready\n":
      remaining = deadline - time.monotonic()
      if remaining <= 0 or not select.select([ready_r], [], [], remaining)[0]: raise TimeoutError("Child bootstrap readiness expired")
      part = os.read(ready_r, 7 - len(observed))
      if not part: raise ValueError("Held bootstrap exited before readiness")
      observed += part
      if not observed or not b"ready\n".startswith(observed): raise ValueError("Exact held bootstrap readiness required")
    os.close(ready_r)
    fds.remove(ready_r)
    pin = P.ChildPin(process, **identity)
    result = ReadyPhase(process, identity, pin, payload_w, len(raw).to_bytes(4, "big") + raw)
    fds.remove(payload_w)
    return result
  except BaseException:
    if process is not None:
      process.terminate()
      try: process.wait(timeout=1)
      except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)
    raise
  finally:
    try:
      if pin is not None and payload_w in fds: pin.close()
    finally:
      for fd in fds: os.close(fd)
