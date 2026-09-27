"""Kernel-authenticated UNIX peer/process primitives, not package authority.

Native owner consumer: create/listen in the owner itself; accept fresh hook
connections, pin their actual peer, require the exact reviewed hook UID/exe/argv,
and require ancestry through real pacman into its currently launched ChildPin.
Hook consumer: fresh-connect in the hook itself and require the fixed reviewed
owner UID/exe/argv. Both consumers still verify code, boot, nonce/protocol,
maintenance evidence and physical/inhibitor scope for EACH grant. Payload PIDs,
environment flags, socket paths and this module alone grant nothing.

SO_PEERCRED/SO_PEERPIDFD identify the endpoint creator, not a process inheriting
its socket. Never share/inherit connected clients or fork an owner listener.
ChildPin requires the sole reaper of a direct, still-unreaped Popen child, before
any poll/wait, with SIGCHLD default (not SIG_IGN/SA_NOCLDWAIT/custom reapers).
Initial launch identity is exact; a pinned phase may legitimately exec later.
An executable reported as deleted is not normalized; exact identity refuses it.
No package, boot, EFI, device, configuration or power operation exists here.
"""
import json
import math
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

SO_PEERPIDFD = 77
MAX_FRAME = 4096
MAX_PROC = 8192
MAX_ARGV = 65536
MAX_ANCESTORS = 32
MAX_JSON_DEPTH = 16


def _read(path, limit):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try: raw = os.read(fd, limit + 1)
  finally: os.close(fd)
  if len(raw) > limit: raise ValueError("Process identity exceeds bound")
  return raw


def _once(pid):
  base = Path("/proc") / str(pid)
  raw = _read(base / "stat", MAX_PROC)
  end = raw.rfind(b") ")
  if not raw.startswith(str(pid).encode() + b" (") or end < 0: raise ValueError("Malformed process stat")
  fields = raw[end + 2:].split()
  if len(fields) < 20: raise ValueError("Truncated process stat")
  uid = [line.split()[1:] for line in _read(base / "status", MAX_PROC).splitlines() if line.startswith(b"Uid:")]
  if len(uid) != 1 or len(uid[0]) != 4: raise ValueError("Exact process UID fields required")
  argv = _read(base / "cmdline", MAX_ARGV)
  if not argv or not argv.endswith(b"\0"): raise ValueError("Live bounded process argv required")
  return {"pid": pid, "ppid": int(fields[1]), "starttime": int(fields[19]),
          "uids": tuple(int(value) for value in uid[0]), "exe": os.readlink(base / "exe"),
          "argv": tuple(part.decode("utf-8", "strict") for part in argv[:-1].split(b"\0"))}


def _identity(pid):
  try:
    first = _once(pid)
    if _once(pid) != first: raise ValueError("Process identity changed during observation")
    return first
  except OSError as error: raise ValueError("Process identity unavailable") from error


def _alive(fd):
  if fd is None or select.select([fd], [], [], 0)[0]: raise ValueError("Pinned process exited or scope closed")


def _pidfd_pid(fd):
  if os.readlink("/proc/self/fd/" + str(fd)) != "anon_inode:[pidfd]": raise ValueError("Kernel process descriptor required")
  rows = [line.split()[1:] for line in _read(Path("/proc/self/fdinfo") / str(fd), MAX_PROC).splitlines() if line.startswith(b"Pid:")]
  if len(rows) != 1 or len(rows[0]) != 1: raise ValueError("Exact kernel pidfd identity required")
  return int(rows[0][0])


def _match(identity, uid, exe, argv):
  if type(uid) is not int or uid < 0 or type(exe) is not str or type(argv) not in (tuple, list): raise ValueError("Explicit exact launch identity required")
  if identity["uids"] != (uid,) * 4 or identity["exe"] != exe or identity["argv"] != tuple(argv):
    raise ValueError("Process UID/executable/argv mismatch")


class Peer:
  def __init__(self, stream):
    self.fd = None
    if stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM: raise ValueError("Connected UNIX stream required")
    self.pid, self.uid, self.gid = struct.unpack("iII", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")))
    if self.pid <= 0: raise ValueError("Actual UNIX peer PID required")
    try:
      self.fd = struct.unpack("i", stream.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize("i")))[0]
      if self.fd < 0: raise ValueError("Kernel UNIX peer pidfd required")
      os.set_inheritable(self.fd, False)
      if _pidfd_pid(self.fd) != self.pid: raise ValueError("UNIX peer credentials/pidfd differ")
      self.identity()
    except BaseException:
      self.close()
      raise

  def identity(self):
    _alive(self.fd)
    value = _identity(self.pid)
    _alive(self.fd)
    if _pidfd_pid(self.fd) != self.pid: raise ValueError("Kernel peer instance changed")
    return value

  def require_identity(self, uid, exe, argv):
    value = self.identity()
    if self.uid != uid: raise ValueError("UNIX peer UID mismatch")
    _match(value, uid, exe, argv)
    return value

  def require_descendant(self, child, *, intermediary_exe, intermediary_uid):
    """Require an ancestor intermediary; phase anchor may count after exec.

    The leaf never counts. Twice-observed links plus live endpoint/child pins
    refuse observed reparenting; this is not an atomic process-tree snapshot.
    """
    if type(child) is not ChildPin or type(intermediary_exe) is not str or type(intermediary_uid) is not int or intermediary_uid < 0:
      raise ValueError("Actual owned phase pin and exact intermediary UID/exe required")
    child.identity()
    first = self.identity()
    chain, seen, pid = [], False, first["pid"]
    for _ in range(MAX_ANCESTORS):
      value = _identity(pid)
      chain.append(value)
      seen |= len(chain) > 1 and value["exe"] == intermediary_exe and value["uids"] == (intermediary_uid,) * 4
      if pid == child.pid:
        if value["starttime"] != child.starttime or value["ppid"] != child.parent or not seen:
          raise ValueError("Phase/intermediary ancestry differs")
        break
      if value["ppid"] <= 0 or value["ppid"] == pid: raise ValueError("Peer is outside launched phase ancestry")
      pid = value["ppid"]
    else: raise ValueError("Peer ancestry exceeds bound")
    for value in chain:
      if _identity(value["pid"]) != value: raise ValueError("Ancestry changed/reparented during check")
    if self.identity() != first: raise ValueError("Peer changed during ancestry check")
    child.identity()
    return tuple(value["pid"] for value in chain)

  def close(self):
    if self.fd is not None:
      fd, self.fd = self.fd, None
      os.close(fd)

  def __enter__(self): return self
  def __exit__(self, *args): self.close()


class ChildPin:
  def __init__(self, process, *, uid, exe, argv):
    self.fd = None
    if type(process) is not subprocess.Popen or process.returncode is not None or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
      raise ValueError("Sole unreaped direct Popen child with default SIGCHLD required")
    self.pid, self.parent = process.pid, os.getpid()
    # WNOWAIT confirms direct child ownership without reaping; a numeric PID is
    # safe here only because the caller must own the sole reaper responsibility.
    if os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
      raise ValueError("Phase already exited before pin")
    try:
      before = _identity(self.pid)
      _match(before, uid, exe, argv)
      if before["ppid"] != self.parent: raise ValueError("Phase is not the owner's direct child")
      self.fd = os.pidfd_open(self.pid)
      os.set_inheritable(self.fd, False)
      if _pidfd_pid(self.fd) != self.pid: raise ValueError("Child kernel instance differs")
      self.starttime = before["starttime"]
      if self.identity() != before: raise ValueError("Child changed while pinning launch")
    except BaseException:
      self.close()
      raise

  def identity(self):
    _alive(self.fd)
    value = _identity(self.pid)
    _alive(self.fd)
    if value["starttime"] != self.starttime or value["ppid"] != self.parent or os.getpid() != self.parent:
      raise ValueError("Launched child changed/reparented")
    return value

  def close(self):
    if self.fd is not None:
      fd, self.fd = self.fd, None
      os.close(fd)

  def __enter__(self): return self
  def __exit__(self, *args): self.close()


def _timeout(value):
  if type(value) not in (int, float) or not 0 < value <= 5: raise ValueError("Explicit transport timeout 0..5 seconds required")
  return time.monotonic() + value


def _depth(value):
  pending = [(value, 0)]
  while pending:
    item, depth = pending.pop()
    if depth > MAX_JSON_DEPTH: raise ValueError("JSON frame nesting exceeds bound")
    if type(item) is dict: pending.extend((child, depth + 1) for child in item.values())
    elif type(item) is list: pending.extend((child, depth + 1) for child in item)


def send_frame(stream, value, *, timeout=1.0):
  deadline = _timeout(timeout)
  if type(value) is not dict: raise ValueError("JSON object frame required")
  _depth(value)
  raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
  if not 0 < len(raw) <= MAX_FRAME: raise ValueError("Frame exceeds bound")
  previous = stream.gettimeout()
  try:
    left = deadline - time.monotonic()
    if left <= 0: raise TimeoutError("Frame deadline expired before send")
    stream.settimeout(left)
    stream.sendall(struct.pack("!I", len(raw)) + raw)
  finally: stream.settimeout(previous)


def recv_frame(stream, *, timeout=1.0):
  deadline, previous = _timeout(timeout), stream.gettimeout()
  def read(count):
    raw = bytearray()
    while len(raw) < count:
      left = deadline - time.monotonic()
      if left <= 0: raise TimeoutError("Frame deadline expired")
      stream.settimeout(left)
      part = stream.recv(count - len(raw))
      if not part: raise ValueError("Truncated frame")
      raw.extend(part)
    return bytes(raw)
  def pairs(items):
    value = {}
    for key, item in items:
      if key in value: raise ValueError("Duplicate frame field")
      value[key] = item
    return value
  def invalid(value): raise ValueError("Nonfinite JSON frame")
  def finite(value):
    number = float(value)
    if not math.isfinite(number): raise ValueError("Nonfinite JSON frame")
    return number
  try:
    length = struct.unpack("!I", read(4))[0]
    if not 0 < length <= MAX_FRAME: raise ValueError("Frame exceeds bound")
    try: value = json.loads(read(length).decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)
    except (RecursionError, UnicodeError) as error: raise ValueError("Malformed JSON frame") from error
    if type(value) is not dict: raise ValueError("JSON object frame required")
    _depth(value)
    return value
  finally: stream.settimeout(previous)
