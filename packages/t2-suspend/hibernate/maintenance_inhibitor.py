"""Source-only owner-held logind block; NOT maintenance/package authority.

The future reviewed native owner acquires this additional FD before publishing
an endpoint or mutating policy. Its existing parent inhibitor remains intact.
Admission still requires the live exact origin/peer. Recovery checks this own
PID's inhibitor instead, retaining C/T/M/B/S locks until descendants settle and
the exact veto is durable. Only that retaining caller may explicitly close the
FD and restore handlers after safe exit; neither exceptions nor finalizers do
so here. No CLI or current native caller exists.

systemd v261 org.freedesktop.login1.xml documents Inhibit(ssss)->h and release
only after all FD duplicates close. inhibit.c duplicates the message-owned h
with F_DUPFD_CLOEXEC before unref, and forks a child with parent-death SIGTERM.
logind-inhibit.c returns a nonblocking write FIFO. These are the same ABI and
FD ownership rules used below. A recorded TERM/HUP/INT is a stop request, not a
Python exception inside ALPM. This helper does not implement phase cancellation
policy, survive SIGKILL, defend against privileged bypass, or recover a lost
logind block automatically. It grants no packages even while recovery retains
an inhibitor indefinitely pending a durable safe condition.
"""
import ctypes
import fcntl
import os
from pathlib import Path
import select
import signal
import stat
import sys
import threading


INSTALLED = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_inhibitor.py")
POWER = INSTALLED.with_name("boot_policy_native.py")
LIBSYSTEMD = "/usr/lib/libsystemd.so.0"
WHO, WHY = "omarchy-t2-package-maintenance", "reviewed-package-maintenance"
LOGIN = (b"org.freedesktop.login1", b"/org/freedesktop/login1", b"org.freedesktop.login1.Manager")
TIMEOUT_USEC = 5_000_000
STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def _native():
  if os.getresuid() != (0, 0, 0) or not sys.flags.isolated or Path(__file__).absolute() != INSTALLED:
    raise ValueError("Fixed installed root isolated owner inhibitor required")
  for path in (INSTALLED, *INSTALLED.parents):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
      raise ValueError("Root-controlled nonsymlink inhibitor ancestry required")
    if path == INSTALLED:
      if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Private nonlinked installed inhibitor required")
    elif not stat.S_ISDIR(info.st_mode):
      raise ValueError("Installed inhibitor directory required")
  # Metadata is only an accidental-host-call gate, not the owner's origin,
  # registered user/session, public-client or whole-inventory review proof.


def _power(power):
  if (Path(getattr(power, "__file__", "")).absolute() != POWER or
      (getattr(power, "WHO", None), getattr(power, "WHY", None)) != (WHO, WHY) or
      not callable(getattr(power, "_power_idle", None)) or not callable(getattr(power, "_power_ongoing", None))):
    raise ValueError("Passed reviewed private maintenance power context required")


def _library():
  lib = ctypes.CDLL(LIBSYSTEMD)
  pointer = ctypes.c_void_p
  definitions = {
    "sd_bus_open_system": ([ctypes.POINTER(pointer)], ctypes.c_int),
    "sd_bus_set_allow_interactive_authorization": ([pointer, ctypes.c_int], ctypes.c_int),
    "sd_bus_set_method_call_timeout": ([pointer, ctypes.c_uint64], ctypes.c_int),
    "sd_bus_call_method": ([pointer, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
      ctypes.c_char_p, pointer, ctypes.POINTER(pointer), ctypes.c_char_p], ctypes.c_int),
    "sd_bus_message_has_signature": ([pointer, ctypes.c_char_p], ctypes.c_int),
    "sd_bus_message_read_basic": ([pointer, ctypes.c_char, pointer], ctypes.c_int),
    "sd_bus_message_at_end": ([pointer, ctypes.c_int], ctypes.c_int),
    "sd_bus_message_unref": ([pointer], pointer),
    "sd_bus_flush_close_unref": ([pointer], pointer),
  }
  for name, (arguments, result) in definitions.items():
    function = getattr(lib, name)
    function.argtypes, function.restype = arguments, result
  return lib


def _result(value, operation):
  if value < 0: raise OSError(-value, "logind inhibitor " + operation)
  return value


def _acquire_fd():
  """Private ABI seam. Public acquisition gates BEFORE loading/calling it."""
  lib = _library()
  bus, reply = ctypes.c_void_p(), ctypes.c_void_p()
  duplicate = None
  try:
    try:
      _result(lib.sd_bus_open_system(ctypes.byref(bus)), "connect")
      if not bus.value: raise ValueError("Missing system bus handle")
      _result(lib.sd_bus_set_allow_interactive_authorization(bus, 0), "noninteractive authorization")
      _result(lib.sd_bus_set_method_call_timeout(bus, TIMEOUT_USEC), "finite method timeout")
      _result(lib.sd_bus_call_method(bus, *LOGIN, b"Inhibit", None, ctypes.byref(reply), b"ssss",
        *(ctypes.c_char_p(value) for value in (b"sleep:shutdown", WHO.encode(), WHY.encode(), b"block"))), "Inhibit")
      if not reply.value or lib.sd_bus_message_has_signature(reply, b"h") != 1:
        raise ValueError("Exact single-FD inhibitor reply required")
      borrowed = ctypes.c_int(-1)
      if _result(lib.sd_bus_message_read_basic(reply, b"h", ctypes.byref(borrowed)), "read FD") != 1 or borrowed.value < 3:
        raise ValueError("Missing nonstdio message-owned inhibitor FD")
      if lib.sd_bus_message_at_end(reply, 1) != 1:
        raise ValueError("Trailing inhibitor reply fields")
      # read_basic borrows the descriptor. NEVER close borrowed independently;
      # message unref closes it. Pin our own duplicate before that cleanup.
      duplicate = fcntl.fcntl(borrowed.value, fcntl.F_DUPFD_CLOEXEC, 3)
      os.set_inheritable(duplicate, False)
    finally:
      try:
        if reply.value: lib.sd_bus_message_unref(reply)
      finally:
        if bus.value: lib.sd_bus_flush_close_unref(bus)
  except BaseException:
    if duplicate is not None: os.close(duplicate)
    raise
  return duplicate


def _descriptor(fd):
  info = os.fstat(fd)
  flags = fcntl.fcntl(fd, fcntl.F_GETFL)
  if (not stat.S_ISFIFO(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or
      flags & os.O_ACCMODE != os.O_WRONLY or not flags & os.O_NONBLOCK or os.get_inheritable(fd)):
    raise ValueError("Noninherited root-owned nonblocking write FIFO required")
  return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


class OwnerInhibitor:
  """Explicit retained owner FD. No context manager, destructor or auto-close."""
  def __init__(self, fd, power):
    self.fd, self.power, self.owner = fd, power, os.getpid()
    self.identity = _descriptor(fd)

  def _check_fd(self):
    if os.getpid() != self.owner or self.fd is None:
      raise ValueError("Live original owner inhibitor scope required")
    if _descriptor(self.fd) != self.identity:
      raise ValueError("Original inhibitor FIFO identity changed")
    poll = select.poll()
    # A FIFO write end cannot be read. poll reports ERR/HUP/NVAL even with
    # requested events zero; reader loss is an error, not a live FD proof.
    poll.register(self.fd, 0)
    if poll.poll(0): raise ValueError("Inhibitor FIFO reader lost or descriptor invalid")

  def check(self):
    self._check_fd()
    _power(self.power)
    self.power._power_ongoing(self.owner)
    self._check_fd()

  def close(self):
    """Caller ONLY after exact durable veto + all owned scopes settled.

    This adapter cannot prove that external condition and does not pretend an
    argument/boolean is proof. Runtime check failure NEVER invokes close.
    """
    if os.getpid() != self.owner: raise ValueError("Only acquiring owner may release")
    if self.fd is not None:
      if _descriptor(self.fd) != self.identity:
        raise ValueError("Refusing to close a replaced inhibitor descriptor")
      fd, self.fd = self.fd, None
      os.close(fd)


def acquire(power):
  """Before any mutation: fixed gate, acquire own FD, strict idle verification.

  Future owner must prove Origin before AND after this call, and arm StopLatch
  before beginning protected mutation. Failed startup may release its FD;
  successful runtime failures retain it until caller's durable safe exit.
  """
  _native()
  _power(power)
  fd = _acquire_fd()
  try:
    handle = OwnerInhibitor(fd, power)
    handle._check_fd()
    power._power_idle(handle.owner)
    handle._check_fd()
    return handle
  except BaseException:
    os.close(fd)
    raise


class StopRequested(ValueError):
  pass


class StopLatch:
  """Main-thread TERM/HUP/INT record-only handlers; explicit safe restoration.

  No __exit__: exceptions during mutation/recovery must not restore terminating
  defaults. Future grant/watch policy consumes this latch; retained settlement
  must ignore the stop request and continue under OwnerInhibitor.check().
  """
  def __init__(self):
    self.owner, self.previous, self.signals = os.getpid(), None, ()
    self.handler = self._record

  def _record(self, number, frame):
    if number not in self.signals: self.signals += (number,)

  @property
  def requested(self): return bool(self.signals)

  def _owner(self):
    if os.getpid() != self.owner or threading.current_thread() is not threading.main_thread():
      raise ValueError("Original main-thread stop latch owner required")

  def arm(self):
    self._owner()
    if self.previous is not None: raise ValueError("Stop latch already armed")
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    previous, installed = {}, []
    try:
      for number in STOP_SIGNALS:
        previous[number] = signal.getsignal(number)
        signal.signal(number, self.handler)
        installed.append(number)
      self.previous = previous
    except BaseException:
      for number in installed: signal.signal(number, previous[number])
      raise
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    return self

  def check(self):
    self._owner()
    if self.previous is None: raise ValueError("Armed stop latch required")
    if any(signal.getsignal(number) != self.handler for number in STOP_SIGNALS):
      raise ValueError("Original stop handlers required before granting")
    if self.requested: raise StopRequested("Owner stop requested; no new maintenance grants")

  def safe_exit(self):
    """Explicitly after safe settlement or pre-mutation refusal, never finally."""
    self._owner()
    if self.previous is None: raise ValueError("Armed stop latch required")
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
      if any(signal.getsignal(number) != self.handler for number in STOP_SIGNALS):
        raise ValueError("Stop handlers changed; refusing ambiguous restoration")
      for number in STOP_SIGNALS: signal.signal(number, self.previous[number])
      self.previous = None
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
