"""Source-only cooperative phase containment; NO native owner integration/CLI.

prepare() attaches an already-held, sole-reaper-owned direct Popen, without
releasing, polling, waiting, changing credentials/stdio or reopening its lock.
The future reviewed owner MUST retain physical lock and inhibitor on any
unsettled handle, including ambiguous StartTransientUnit completion. This
module owns neither exclusion and never turns a cleanup timeout into success.
No automatic finalizer/context exit drops unsettled ownership.

Claims cover descendants inheriting scope membership, not unrelated services
started/restarted by package scripts or hostile root migrating tasks. Scope
ActiveState is NOT emptiness: v261 scope.c can enter dead after SIGKILL timeout
with tasks remaining. Recursive populated=0 on the exact pinned cgroup is
the primary settlement proof. Exact original cgroup2 pins both unlinked with
the directory's exact deleted link also prove removal: Linux v6.17
cgroup_destroy_locked refuses populated/live children before offlining and
kernfs_remove. Path absence/replacement or ENODEV alone never settles. The child remains the
caller's responsibility to reap, even after the scope is empty.

Verified interfaces: systemd v261 org.freedesktop.systemd1.xml
StartTransientUnit ssa(sv)a(sa(sv)); dbus-scope.c PIDs au and TimeoutStopUSec t;
Linux cgroup-v2.rst cgroup.events populated includes all descendant groups.
"""
import importlib.util
import ctypes
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import time


spec = importlib.util.spec_from_file_location("scope_peer", Path(__file__).with_name("maintenance_peer.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
INSTALLED = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_scope.py")
CGROUP = Path("/sys/fs/cgroup")
SERVICE, MANAGER = "org.freedesktop.systemd1", "/org/freedesktop/systemd1"
UNIT_IFACE, SCOPE_IFACE = SERVICE + ".Unit", SERVICE + ".Scope"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
STOP_USEC = 2_000_000
CGROUP2_MAGIC = 0x63677270


class _StatFS(ctypes.Structure):
  # Linux x86-64 glibc <bits/statfs.h>; this product adapter refuses other ABIs.
  _fields_ = [("type", ctypes.c_long), ("bsize", ctypes.c_long),
    ("blocks", ctypes.c_ulong), ("bfree", ctypes.c_ulong), ("bavail", ctypes.c_ulong),
    ("files", ctypes.c_ulong), ("ffree", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
    ("namelen", ctypes.c_long), ("frsize", ctypes.c_long), ("flags", ctypes.c_long),
    ("spare", ctypes.c_long * 4)]


def _filesystem(fd):
  if os.uname().machine != "x86_64" or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(_StatFS) != 120:
    raise ValueError("Verified Linux x86-64 statfs ABI required")
  library = ctypes.CDLL(None, use_errno=True)
  library.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFS))
  library.fstatfs.restype = ctypes.c_int
  result = _StatFS()
  if library.fstatfs(fd, ctypes.byref(result)) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
  return result.type, tuple(result.fsid)


def _deadline(timeout):
  if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
    raise ValueError("Explicit bounded scope deadline 0..5 seconds required")
  return time.monotonic() + timeout


def _native():
  if os.getresuid() != (0,) * 3 or Path(__file__) != INSTALLED:
    raise ValueError("Fixed installed root scope adapter required; no CLI")
  for path in (*reversed(INSTALLED.parents), INSTALLED):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISREG(info.st_mode) if path == INSTALLED else stat.S_ISDIR(info.st_mode)):
      raise ValueError("Root-controlled nonsymlink scope code ancestry required")
  # This gate is NOT native origin/session/code-review authentication. The
  # eventual owner must establish all of those before invoking this adapter.
  mounts = P._read(Path("/proc/self/mountinfo"), 1024 * 1024).decode("utf-8", "strict")
  rows = [row.split() for row in mounts.splitlines()]
  if len([row for row in rows if len(row) > 6 and row[4] == str(CGROUP) and "-" in row and row[row.index("-") + 1] == "cgroup2"]) != 1:
    raise ValueError("Fixed unified cgroup2 mount required")


def _run(argv, deadline):
  left = deadline - time.monotonic()
  if left <= 0: raise TimeoutError("Scope operation deadline expired")
  result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, close_fds=True, timeout=left, check=True)
  if len(result.stdout) > 8192: raise ValueError("Bounded typed manager reply required")
  return shlex.split(result.stdout.decode("utf-8", "strict"))


def _call(method, signature, args, deadline):
  return _run(["/usr/bin/busctl", "--system", "--no-pager", "--allow-interactive-authorization=no", "--timeout=5s",
    "call", SERVICE, MANAGER, SERVICE + ".Manager", method, signature, *args], deadline)


def _unit_path(name):
  # systemd bus-label encoding: leading digits and every nonalphanumeric byte
  # become _xx; the generated prefix starts with a letter.
  return MANAGER + "/unit/" + "".join(char if char.isascii() and char.isalnum() else "_%02x" % ord(char) for char in name)


def _property(name, interface, key, deadline):
  return _run(["/usr/bin/busctl", "--system", "--no-pager", "--allow-interactive-authorization=no", "--timeout=5s",
    "get-property", SERVICE, _unit_path(name), interface, key], deadline)


def _job(value):
  if len(value) != 2 or value[0] != "o" or not re.fullmatch(r"/org/freedesktop/systemd1/job/[1-9][0-9]*", value[1]):
    raise ValueError("Exact manager job object required")
  return value[1]


def _identity(info): return info.st_dev, info.st_ino


def _secure(info, *, directory):
  if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
    raise ValueError("Root-owned nonsymlink cgroup identity required")


def _membership(pid):
  raw = P._read(Path("/proc") / str(pid) / "cgroup", 8192).decode("utf-8", "strict")
  rows = raw.splitlines()
  if len(rows) != 1 or not rows[0].startswith("0::/"): raise ValueError("Exact unified child cgroup required")
  return rows[0][3:]


class Scope:
  """Owner-retained handle, including failed/ambiguous attachment.

  ready/check_ready are admission prerequisites, not admission grants.
  drain(False) MUST keep the enclosing lock/inhibitor and this handle alive.
  error records why the last attempt failed; retry does not erase ownership.
  close() only closes descriptors after observed emptiness, never kills/reaps.
  """
  def __init__(self, held, pin, name):
    self.held, self.pin, self.name = held, pin, name
    self.owner = os.getpid()
    self.control_group = "/system.slice/" + name
    self.path = CGROUP / self.control_group.lstrip("/")
    self.directory_fd = self.events_fd = None
    self.directory_identity = self.events_identity = None
    self.filesystem_identity = self.filesystem_device = None
    self.ready = self.settled = self.closed = self.draining = False
    self.attempted = False
    self.creation_confirmed = False
    self.job = self.error = None

  def _owner(self):
    if self.closed or self.owner != os.getpid(): raise ValueError("Live original scope owner required")

  def _owned_unit(self, deadline):
    for interface, key, expected in (
      (UNIT_IFACE, "Id", ["s", self.name]), (UNIT_IFACE, "Transient", ["b", "true"]),
      (SCOPE_IFACE, "Slice", ["s", "system.slice"]),
      (SCOPE_IFACE, "ControlGroup", ["s", self.control_group]),
      (SCOPE_IFACE, "Delegate", ["b", "false"]),
      (SCOPE_IFACE, "KillMode", ["s", "control-group"]),
      (SCOPE_IFACE, "SendSIGKILL", ["b", "true"]),
      (SCOPE_IFACE, "TimeoutStopUSec", ["t", str(STOP_USEC)])):
      if _property(self.name, interface, key, deadline) != expected:
        raise ValueError("Exact owned transient scope/cgroup required")

  def _pin_group(self):
    if self.directory_fd is None:
      parent = os.open(CGROUP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
      try:
        _secure(os.fstat(parent), directory=True)
        filesystem = _filesystem(parent)
        if filesystem[0] != CGROUP2_MAGIC: raise ValueError("Actual cgroup2 backing required")
        self.filesystem_identity, self.filesystem_device = filesystem, os.fstat(parent).st_dev
        for component in ("system.slice", self.name):
          child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
          os.close(parent)
          parent = child
          _secure(os.fstat(parent), directory=True)
          if _filesystem(parent) != self.filesystem_identity or os.fstat(parent).st_dev != self.filesystem_device:
            raise ValueError("Scope must remain on pinned cgroup2 filesystem")
        self.directory_fd, parent = parent, None
        self.directory_identity = _identity(os.fstat(self.directory_fd))
      finally:
        if parent is not None: os.close(parent)
    if _identity(self.path.lstat()) != self.directory_identity:
      raise ValueError("Owned directory changed before events pin")
    if self.events_fd is None:
      events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.directory_fd)
      try:
        _secure(os.fstat(events), directory=False)
        if _filesystem(events) != self.filesystem_identity or os.fstat(events).st_dev != self.filesystem_device:
          raise ValueError("Events must share pinned cgroup2 filesystem")
        identity = _identity(os.fstat(events))
      except BaseException:
        os.close(events)
        raise
      self.events_fd, self.events_identity = events, identity
    self._same_group()

  def _creation(self):
    if self.creation_confirmed: return
    # A mode=fail successful job reply proves creation. With a lost/failed
    # reply, exact properties/random name alone cannot authorize killing an
    # existing unit: require our still-live unreaped held child inside it.
    P._match(self.pin.identity(), **self.held.identity)
    if _membership(self.pin.pid) != self.control_group:
      raise ValueError("Scope creation unconfirmed; held child outside unit")

  def _owner_outside(self):
    group = _membership(self.owner)
    if group == self.control_group or group.startswith(self.control_group + "/"):
      raise ValueError("Exclusion owner must remain outside phase scope")

  def _same_group(self):
    self._same_pins()
    if _identity(self.path.lstat()) != self.directory_identity:
      raise ValueError("Owned cgroup directory disappeared/replaced")
    named = os.stat("cgroup.events", dir_fd=self.directory_fd, follow_symlinks=False)
    if _identity(named) != self.events_identity:
      raise ValueError("Owned cgroup events disappeared/replaced")
    _secure(self.path.lstat(), directory=True)
    _secure(named, directory=False)

  def _same_pins(self):
    if self.directory_fd is None or self.events_fd is None: raise ValueError("Pinned cgroup/events required")
    infos = []
    for fd, identity, directory in ((self.directory_fd, self.directory_identity, True), (self.events_fd, self.events_identity, False)):
      info = os.fstat(fd)
      _secure(info, directory=directory)
      if _identity(info) != identity or info.st_dev != self.filesystem_device or _filesystem(fd) != self.filesystem_identity or self.filesystem_identity[0] != CGROUP2_MAGIC:
        raise ValueError("Original pinned cgroup2 identity/filesystem changed")
      infos.append(info)
    return infos

  def _removed(self):
    # A new pathname must never inherit the old scope's settlement/stop rights.
    # lstat also refuses a dangling replacement symlink, unlike exists().
    def absent():
      try: self.path.lstat()
      except FileNotFoundError: return
      raise ValueError("Removed scope path replaced or still present")
    absent()
    for info in self._same_pins():
      if info.st_nlink != 0: raise ValueError("Both original cgroup pins must be unlinked")
    if os.readlink("/proc/self/fd/" + str(self.directory_fd)) != str(self.path) + " (deleted)":
      raise ValueError("Exact original deleted cgroup directory link required")
    events = str(self.path / "cgroup.events")
    if os.readlink("/proc/self/fd/" + str(self.events_fd)) not in (events, events + " (deleted)"):
      raise ValueError("Exact original removed cgroup events link required")
    for info in self._same_pins():
      if info.st_nlink != 0: raise ValueError("Removed pinned cgroup identity changed")
    absent()
    return True

  def _empty(self):
    try: return not self._populated()
    except OSError:
      return self._removed()

  def _populated(self):
    self._same_group()
    os.lseek(self.events_fd, 0, os.SEEK_SET)
    raw = os.read(self.events_fd, 4097)
    if len(raw) > 4096 or not raw.endswith(b"\n"): raise ValueError("Bounded complete cgroup.events required")
    values = {}
    for row in raw.splitlines():
      parts = row.split()
      if len(parts) != 2 or parts[0] in values or not re.fullmatch(rb"[a-z_]+", parts[0]) or parts[1] not in (b"0", b"1"):
        raise ValueError("Malformed/duplicate cgroup.events fields")
      values[parts[0]] = parts[1]
    if b"populated" not in values: raise ValueError("Recursive populated field required")
    self._same_group()
    return values[b"populated"] == b"1"

  def check_ready(self, *, timeout=2.0):
    self._owner()
    if self.draining or self.held.released: raise ValueError("Unreleased non-draining held phase required")
    deadline = _deadline(timeout)
    self.ready = False
    try:
      self._owned_unit(deadline)
      self._creation()
      if _property(self.name, UNIT_IFACE, "Job", deadline) != ["(uo)", "0", "/"] or _property(self.name, UNIT_IFACE, "ActiveState", deadline) != ["s", "active"]:
        raise ValueError("Completed active scope start required")
      self._pin_group()
      self._owner_outside()
      P._match(self.pin.identity(), **self.held.identity)
      if _membership(self.pin.pid) != self.control_group or not self._populated():
        raise ValueError("Held child not inside populated owned scope")
      P._match(self.pin.identity(), **self.held.identity)
      if _membership(self.pin.pid) != self.control_group: raise ValueError("Held child placement changed")
      self.creation_confirmed = True
      self.ready, self.error = True, None
      return True
    except BaseException as error:
      self.error = error
      return False

  def drain(self, *, timeout=2.0):
    self._owner()
    deadline = _deadline(timeout)
    self.draining, self.ready = True, False
    if self.settled: return True
    try:
      self._creation()
      if self.events_fd is None:
        self._owned_unit(deadline)
        self._pin_group()
      if self._empty():
        self.settled, self.error = True, None
        return True
      self._owned_unit(deadline)  # never stop an alias/replaced/foreign unit
      self._owner_outside()
      _job(_call("StopUnit", "ss", [self.name, "fail"], deadline))
      while True:
        if self._empty():
          self.settled, self.error = True, None
          return True
        left = deadline - time.monotonic()
        if left <= 0: raise TimeoutError("Scope remains populated; owner must retain exclusions")
        time.sleep(min(0.01, left))
    except BaseException as error:
      self.error = error
      return False

  def close(self):
    self._owner()
    if not self.settled: raise ValueError("Unsettled scope ownership cannot be closed")
    self.closed = True
    for key in ("events_fd", "directory_fd"):
      fd = getattr(self, key)
      setattr(self, key, None)
      if fd is not None: os.close(fd)
    self.pin.close()


def prepare(held, *, timeout=2.0):
  """Returns a handle even on uncertain attachment; never releases the child.

  Pre-mutation argument/native/pin failures raise. Once the manager call is
  attempted ALL exceptions (including interrupts) are recorded on the returned
  handle; caller must retain it and its exclusions until drain() returns True.
  """
  deadline = _deadline(timeout)
  _native()
  if held.owner != os.getpid() or held.released or held.payload_fd is None:
    raise ValueError("Original owner of ready unreleased phase required")
  if type(held.identity) is not dict or set(held.identity) != {"uid", "exe", "argv"} or type(held.identity["uid"]) is not int or held.identity["uid"] <= 0:
    raise ValueError("Exact dropped nonroot held phase required")
  pin = P.ChildPin(held.process, **held.identity)
  try:
    scope = Scope(held, pin, "omarchy-t2-maintenance-" + secrets.token_hex(16) + ".scope")
  except BaseException:
    pin.close()
    raise
  try:
    scope.attempted = True
    scope.job = _job(_call("StartTransientUnit", "ssa(sv)a(sa(sv))", [scope.name, "fail", "7",
      "Slice", "s", "system.slice", "PIDs", "au", "1", str(pin.pid), "Delegate", "b", "false",
      "KillMode", "s", "control-group", "SendSIGKILL", "b", "true",
      "TimeoutStopUSec", "t", str(STOP_USEC), "Description", "s", "Omarchy held maintenance phase", "0"], deadline))
    scope.creation_confirmed = True
    left = deadline - time.monotonic()
    if left <= 0: raise TimeoutError("Scope attachment confirmation expired")
    scope.check_ready(timeout=left)
  except BaseException as error:
    scope.ready, scope.error = False, error
  return scope
