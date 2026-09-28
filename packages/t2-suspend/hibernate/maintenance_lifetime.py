"""Retained process/executable observations, NOT native maintenance permission.

Lifetime duplicates an already authenticated kernel pidfd after strict startup
and opens the actual /proc/PID/exe inode. Ongoing checks do not follow the old
executable pathname: legitimate rename/unlink/replacement is allowed, but an
observed exec to a different inode or changed UID/argv/parent/start is refused.
Generic maintenance_peer strict identity semantics remain unchanged.

IMPORTANT: pidfd and starttime identify a process lifetime, NOT an exec epoch.
Same-inode re-exec with identical argv/UIDs/parent is indistinguishable here and
can pass. Changes between observations can also be missed. This is not a no-
exec monitor, code/hash/review/session authentication, script/library inventory,
or package admission proof. Caller must establish reviewed startup bytes and
trusted proc/filesystem namespaces and retain all other maintenance exclusions.
Linux ETXTBSY normally prevents writable access to the running main executable;
it does not protect mapped libraries/scripts/process memory or against hostile
root. Stable file metadata excludes nlink/ctime, which legitimate unlink changes.
No process launch, signal, wait, configuration, package or power action occurs.
"""
import importlib.util
import os
from pathlib import Path
import stat
from types import MappingProxyType


spec = importlib.util.spec_from_file_location("lifetime_peer", Path(__file__).with_name("maintenance_peer.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
FIELDS = frozenset(("pid", "ppid", "starttime", "uids", "exe", "argv"))


def _expected(value):
  if type(value) is not dict or set(value) != FIELDS:
    raise ValueError("Exact strict-startup process identity required")
  for key in ("pid", "ppid", "starttime"):
    if type(value[key]) is not int or value[key] < (0 if key == "starttime" else 1):
      raise ValueError("Exact positive process/parent and bounded start identity required")
  uids, argv, exe = value["uids"], value["argv"], value["exe"]
  if type(uids) not in (tuple, list) or len(uids) != 4 or any(type(uid) is not int or not 0 <= uid < 2 ** 32 for uid in uids):
    raise ValueError("Exact four process UID observations required")
  if type(exe) is not str or not Path(exe).is_absolute() or "\0" in exe:
    raise ValueError("Exact absolute startup executable required")
  if type(argv) not in (tuple, list) or not argv or any(type(arg) is not str or "\0" in arg for arg in argv) or sum(len(arg.encode("utf-8")) + 1 for arg in argv) > P.MAX_ARGV:
    raise ValueError("Exact bounded startup arguments required")
  return {**value, "uids": tuple(uids), "argv": tuple(argv)}


def _file(info):
  if not stat.S_ISREG(info.st_mode): raise ValueError("Actual regular executable inode required")
  return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size


def _core(value): return {key: value[key] for key in FIELDS if key != "exe"}


def _exe(pid):
  # Follow ONLY this kernel proc magic link, never a supplied ongoing pathname.
  return os.open(Path("/proc") / str(pid) / "exe", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)


class Lifetime:
  """Owner-scoped duplicated pidfd + executable FD; check is observation only.

  Input pidfd must come from the caller's authenticated startup proof, not a
  claimed PID or file payload. Caller retains ownership of the original FD;
  this handle owns its duplicate/executable descriptors. No competing close,
  descriptor mutation or cross-fork use. Same-inode re-exec is NOT rejected.
  """
  def __init__(self, pidfd, *, expected_identity):
    expected = _expected(expected_identity)
    if type(pidfd) is not int or pidfd < 0: raise ValueError("Existing authenticated kernel pidfd required")
    self.owner, self.active = os.getpid(), True
    self.pidfd = self.executable_fd = None
    self.expected = MappingProxyType(expected)
    try:
      self.pidfd = os.dup(pidfd)  # duplicate BEFORE numeric proc observation
      os.set_inheritable(self.pidfd, False)
      P._alive(self.pidfd)
      if P._pidfd_pid(self.pidfd) != expected["pid"] or P._identity(expected["pid"]) != expected:
        raise ValueError("Strict startup process instance differs")
      self.executable_fd = _exe(expected["pid"])
      self.executable_identity = _file(os.fstat(self.executable_fd))
      if _file(os.stat(expected["exe"], follow_symlinks=False)) != self.executable_identity:
        raise ValueError("Startup named executable differs from actual inode")
      if P._identity(expected["pid"]) != expected: raise ValueError("Startup changed while retaining executable")
      self.check()
    except BaseException:
      self.close()
      raise

  def check(self):
    if not self.active: raise ValueError("Process lifetime scope expired")
    if os.getpid() != self.owner: raise ValueError("Original process lifetime owner required")
    P._alive(self.pidfd)
    pid = self.expected["pid"]
    if P._pidfd_pid(self.pidfd) != pid: raise ValueError("Retained kernel process instance differs")
    before = P._identity(pid)
    if _core(before) != _core(self.expected): raise ValueError("Retained process changed/reparented")
    current = _exe(pid)
    try:
      if _file(os.fstat(current)) != self.executable_identity or _file(os.fstat(self.executable_fd)) != self.executable_identity:
        raise ValueError("Retained executable inode/metadata changed")
      if P._identity(pid) != before or _file(os.fstat(current)) != self.executable_identity:
        raise ValueError("Process/executable changed during observation")
      P._alive(self.pidfd)
      if P._pidfd_pid(self.pidfd) != pid: raise ValueError("Retained kernel process instance changed")
      return before  # current exe-link text is truthful, never stripped/normalized
    finally: os.close(current)

  def close(self):
    self.active = False  # expiry BEFORE descriptor closure/reuse
    try:
      if self.executable_fd is not None:
        fd, self.executable_fd = self.executable_fd, None
        os.close(fd)
    finally:
      if self.pidfd is not None:
        fd, self.pidfd = self.pidfd, None
        os.close(fd)

  def __enter__(self): return self
  def __exit__(self, *args): self.close()
