"""Fresh peer-authenticated transfer of one original held update-lock OFD.

Not native maintenance authorization: callers must authenticate the initiating
session and fixed sudo/inhibitor/owner chain separately. Peer credentials refer
to the endpoint creator, so each process must create/connect its own socket;
never inherit connected endpoints. Native eligibility must additionally bind
the runtime directory to /run/user/UID, not a caller environment claim.

No pathname reopening substitutes for the transferred descriptor. Validation
reuses launcher._lock without invoking its root-launch/context APIs. The sender
keeps its original lock; ReceivedLock owns only the duplicate and a live Peer,
not the caller's stream. check() refreshes observations, not perpetual authority.
No package, boot, EFI, power or privileged coordinator/admission CLI exists here.

send_native_lock is separately root-namespace authenticated: Linux denies an
ordinary user root /proc/exe reads, so it cannot claim exact root argv/code.
It binds UID0 kernel endpoint/lifetime plus the fixed root-only namespace, under
the nonhostile-root trust model. The root owner must review itself and verify
the real client/session/ancestry before receive_lock; this is not that proof.
The private installed runtime is not user-readable; a reviewed public client
entry/package remains future integration, not enabled by this module.
"""
import array
import importlib.util
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


P = _module("handoff_peer", "maintenance_peer.py")
L = _module("handoff_launcher", "maintenance_launcher.py")
PROTOCOL = "omarchy-t2-update-lock-handoff-v1"
MAX_FDS = 16
ROOT_ENDPOINT = Path("/run/omarchy-t2-maintenance/handoff.sock")


def _identity(value):
  if type(value) is not dict or set(value) != {"uid", "exe", "argv"}: raise ValueError("Explicit exact peer identity required")
  P._match({"uids": (value["uid"],) * 4, "exe": value["exe"], "argv": tuple(value["argv"])}, **value)
  return {"uid": value["uid"], "exe": value["exe"], "argv": tuple(value["argv"])}


def _runtime(directory, uid):
  path = Path(directory)
  if not path.is_absolute() or path.resolve() != path: raise ValueError("Canonical nonsymlink runtime directory required")
  info = path.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
    raise ValueError("Actual sender-owned safe runtime directory required")
  return path, (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def _validate(fd, directory, uid, original):
  path, current = _runtime(directory, uid)
  if current != original: raise ValueError("Runtime directory changed during handoff")
  L._lock(fd, uid, {"XDG_RUNTIME_DIR": str(path)})


def _left(deadline):
  remaining = deadline - time.monotonic()
  if remaining <= 0: raise TimeoutError("Lock handoff deadline expired")
  return remaining


def _nonce(value):
  if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value): raise ValueError("Exact owner challenge required")
  return value


def _receive_fd(stream, deadline):
  descriptors, invalid = [], False
  try:
    stream.settimeout(_left(deadline))
    raw, controls, flags, _ = stream.recvmsg(1, socket.CMSG_SPACE(MAX_FDS * array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC)
    # Collect ALL kernel-installed descriptors before rejecting any other
    # malformed field. Linux closes descriptors not delivered on CTRUNC.
    for level, kind, payload in controls:
      if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
        size = array.array("i").itemsize
        complete = len(payload) - len(payload) % size
        values = array.array("i")
        values.frombytes(payload[:complete])
        descriptors.extend(values)
        invalid |= complete != len(payload)
      else: invalid = True
    if invalid or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or raw != b"L" or len(controls) != 1 or len(descriptors) != 1:
      raise ValueError("Exact one complete SCM_RIGHTS lock descriptor required")
    fd = descriptors[0]
    if fd < 0 or os.get_inheritable(fd): raise ValueError("Kernel CLOEXEC lock receipt required")
    descriptors.clear()
    return fd
  finally:
    for fd in descriptors: os.close(fd)


class ReceivedLock:
  def __init__(self, fd, peer, expected, directory, runtime_identity):
    self.fd, self.peer, self.expected = fd, peer, expected
    self.directory, self.runtime_identity, self.owner = directory, runtime_identity, os.getpid()

  def check(self):
    if self.fd is None or os.getpid() != self.owner: raise ValueError("Owned live lock receipt required")
    observed = self.peer.require_identity(**self.expected)
    _validate(self.fd, self.directory, self.peer.uid, self.runtime_identity)
    self.peer.require_identity(**self.expected)
    return observed

  def close(self):
    if os.getpid() != self.owner: raise ValueError("Only receipt owner may close")
    try:
      if self.fd is not None:
        fd, self.fd = self.fd, None
        os.close(fd)
    finally: self.peer.close()

  def __enter__(self): return self
  def __exit__(self, *args): self.close()


def receive_lock(stream, *, sender_identity, runtime_directory, timeout=1.0):
  """Challenge actual fresh sender; accept only its original already-held OFD."""
  expected, deadline, previous = _identity(sender_identity), P._timeout(timeout), stream.gettimeout()
  peer, fd = None, None
  try:
    peer = P.Peer(stream)
    peer.require_identity(**expected)
    directory, original = _runtime(runtime_directory, peer.uid)
    nonce = secrets.token_hex(32)
    P.send_frame(stream, {"protocol": PROTOCOL, "challenge": nonce}, timeout=_left(deadline))
    request = P.recv_frame(stream, timeout=_left(deadline))
    if request != {"protocol": PROTOCOL, "nonce": nonce}: raise ValueError("Exact current handoff request required")
    fd = _receive_fd(stream, deadline)
    peer.require_identity(**expected)
    _validate(fd, directory, peer.uid, original)
    peer.require_identity(**expected)
    P.send_frame(stream, {"protocol": PROTOCOL, "nonce": nonce, "accepted": True}, timeout=_left(deadline))
    peer.require_identity(**expected)
    result = ReceivedLock(fd, peer, expected, directory, original)
    fd, peer = None, None
    return result
  finally:
    try:
      if fd is not None: os.close(fd)
    finally:
      if peer is not None: peer.close()
      stream.settimeout(previous)


def _send_exchange(stream, fd, directory, deadline, recheck):
  recheck()
  directory, original = _runtime(directory, os.geteuid())
  _validate(fd, directory, os.geteuid(), original)
  challenge = P.recv_frame(stream, timeout=_left(deadline))
  if set(challenge) != {"protocol", "challenge"} or challenge["protocol"] != PROTOCOL: raise ValueError("Exact handoff owner challenge required")
  nonce = _nonce(challenge["challenge"])
  recheck()
  P.send_frame(stream, {"protocol": PROTOCOL, "nonce": nonce}, timeout=_left(deadline))
  stream.settimeout(_left(deadline))
  if stream.sendmsg([b"L"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]) != 1:
    raise ValueError("Complete descriptor token send required")
  reply = P.recv_frame(stream, timeout=_left(deadline))
  if set(reply) != {"protocol", "nonce", "accepted"} or reply["protocol"] != PROTOCOL or reply["nonce"] != nonce or reply["accepted"] is not True:
    raise ValueError("Exact validated lock acceptance required")
  recheck()
  _validate(fd, directory, os.geteuid(), original)
  return reply


def send_lock(stream, fd, *, receiver_identity, runtime_directory, timeout=1.0):
  """Strict exact-peer transport, for callers able to inspect the receiver."""
  expected, deadline, previous = _identity(receiver_identity), P._timeout(timeout), stream.gettimeout()
  try:
    with P.Peer(stream) as peer:
      return _send_exchange(stream, fd, runtime_directory, deadline, lambda: peer.require_identity(**expected))
  finally: stream.settimeout(previous)


def _root_endpoint():
  path = ROOT_ENDPOINT
  for directory in reversed(path.parents):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
      raise ValueError("Fixed root-owned nonsymlink endpoint namespace required")
  info = path.lstat()
  if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o666:
    raise ValueError("Fixed root socket with explicit connection permissions required")
  return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


class _RootPeer:
  """UID0 kernel endpoint/lifetime, intentionally NOT root executable identity."""
  def __init__(self, stream, original):
    self.fd, self.original = None, original
    pid, uid, _ = struct.unpack("iII", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")))
    if pid <= 0 or uid != 0: raise ValueError("Actual UID0 root endpoint required")
    self.pid = pid
    try:
      self.fd = struct.unpack("i", stream.getsockopt(socket.SOL_SOCKET, P.SO_PEERPIDFD, struct.calcsize("i")))[0]
      if self.fd < 0: raise ValueError("Kernel root peer descriptor required")
      os.set_inheritable(self.fd, False)
      self.check()
    except BaseException:
      self.close()
      raise

  def check(self):
    P._alive(self.fd)
    if P._pidfd_pid(self.fd) != self.pid or _root_endpoint() != self.original:
      raise ValueError("Root endpoint identity or namespace changed")
    P._alive(self.fd)

  def close(self):
    if self.fd is not None:
      fd, self.fd = self.fd, None
      os.close(fd)


def send_native_lock(fd, *, timeout=1.0):
  """Nonroot fresh client to FIXED root namespace; not sudo/session authority."""
  if os.getuid() <= 0 or os.getresuid() != (os.getuid(),) * 3: raise ValueError("Actual nonroot initiating client required")
  deadline = P._timeout(timeout)
  directory = Path("/run/user") / str(os.getuid())
  original = _root_endpoint()
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(_left(deadline))
    stream.connect(str(ROOT_ENDPOINT))
    if _root_endpoint() != original: raise ValueError("Root socket changed during connection")
    peer = _RootPeer(stream, original)
    try: return _send_exchange(stream, fd, directory, deadline, peer.check)
    finally: peer.close()
