"""Disposable-root process/IPC dispatcher, NOT native package admission.

run_phase is the actual owner/sole reaper: launch must return a ready, unreaped
direct Popen child (no competing wait/poll or SIGCHLD reaper). Its fixture
handshake must complete initial exec before ChildPin. The owner itself creates
the listener and services fresh hooks while waiting for that child. A future
reviewed native launcher must replace fixture callbacks, validate the nonroot
user, preserve terminal/update-lock context and maintain real power exclusion.

gate must raise unless package_maintenance.check_maintenance and its physical/
inhibitor requirements hold; its return value is not an authority flag. Each
request is bound to an owner-issued per-connection nonce, exact endpoints and observed
intermediary ancestry. Successful IPC alone is NOT update/boot/qualification
evidence. Public native guards remain unchanged. No replay or reactivation.
Only the direct owned child is terminated on failure, never arbitrary ancestry.
"""
import importlib.util
import math
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import time


spec = importlib.util.spec_from_file_location("broker_peer", Path(__file__).with_name("maintenance_peer.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
PROTOCOL = "omarchy-t2-maintenance-hook-v1"


def _fixture(root):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir() or root == Path("/"):
    raise ValueError("Fixture broker refuses live root and aliases")
  return root


def _path(root, path):
  path = Path(path)
  try: relative = path.relative_to(root)
  except ValueError: raise ValueError("Socket must stay in disposable root") from None
  if not relative.parts or any(part in (".", "..") for part in relative.parts): raise ValueError("Exact fixture socket path required")
  current = root
  for part in ("", *relative.parts[:-1]):
    if part: current /= part
    info = current.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink socket ancestors required")
  return path


def _identity(value):
  if type(value) is not dict or set(value) != {"uid", "exe", "argv"}: raise ValueError("Exact process identity required")
  # Validate even before a launch/callback or socket operation.
  P._match({"uids": (value["uid"],) * 4, "exe": value["exe"], "argv": tuple(value["argv"])}, **value)
  return {"uid": value["uid"], "exe": value["exe"], "argv": tuple(value["argv"])}


def _socket(path, owned):
  info = path.lstat()
  if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != owned:
    raise ValueError("Broker socket replaced or changed")


def _budget(deadline):
  remaining = deadline - time.monotonic()
  if remaining <= 0: raise TimeoutError("Broker phase deadline expired")
  return min(1.0, remaining)


def request(root, path, *, owner_identity, timeout=1.0):
  """Fresh hook connection, exact actual owner; no inherited client transport."""
  root = _fixture(root)
  path = _path(root, path)
  owner = _identity(owner_identity)
  info = path.lstat()
  owned = (info.st_dev, info.st_ino, os.geteuid(), 0o600)
  _socket(path, owned)
  deadline = P._timeout(timeout)
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(_budget(deadline))
    stream.connect(str(path))
    _socket(path, owned)
    with P.Peer(stream) as peer:
      peer.require_identity(**owner)
      _socket(path, owned)
      challenge = P.recv_frame(stream, timeout=_budget(deadline))
      if set(challenge) != {"protocol", "challenge"} or challenge["protocol"] != PROTOCOL:
        raise ValueError("Exact owner challenge required")
      nonce = challenge["challenge"]
      if type(nonce) is not str or len(nonce) != 64 or any(char not in "0123456789abcdef" for char in nonce):
        raise ValueError("Exact broker nonce required")
      peer.require_identity(**owner)
      P.send_frame(stream, {"protocol": PROTOCOL, "nonce": nonce}, timeout=_budget(deadline))
      reply = P.recv_frame(stream, timeout=_budget(deadline))
      peer.require_identity(**owner)
      _socket(path, owned)
      if reply != {"protocol": PROTOCOL, "nonce": nonce, "decision": "allow"}:
        raise ValueError("Broker did not grant exact phase request")
      return reply


def run_phase(root, path, *, launch, phase_identity, owner_identity, hook_identity,
              intermediary_identity, gate, timeout=10.0):
  """Run/wait one real fixture child while concurrently answering hook requests.

  launch(endpoint) performs a bounded synthetic readiness handshake and
  returns its direct child. Deadline includes launch; no child status is claimed
  by the hook. Negative signal returncodes are preserved, not forged as success.
  A new invocation never consumes an existing socket or interrupted phase.
  """
  root = _fixture(root)
  path = _path(root, path)
  owner, phase, hook = (_identity(value) for value in (owner_identity, phase_identity, hook_identity))
  if type(intermediary_identity) is not dict or set(intermediary_identity) != {"uid", "exe"}:
    raise ValueError("Exact intermediary UID/executable required")
  intermediary = dict(intermediary_identity)
  if type(intermediary["uid"]) is not int or intermediary["uid"] < 0 or type(intermediary["exe"]) is not str:
    raise ValueError("Exact intermediary UID/executable required")
  if not callable(launch) or not callable(gate) or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
    raise ValueError("Bounded explicit fixture launcher/gate/deadline required")
  P._match(P._identity(os.getpid()), **owner)
  deadline = time.monotonic() + timeout
  listener, process, pin, owned = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), None, None, None
  cleanup_owned = False
  try:
    # bind fails on ANY existing entry; never unlink a stale/foreign endpoint.
    listener.bind(str(path))
    info = path.lstat()
    owned = (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
    _socket(path, owned)
    if info.st_uid != os.geteuid(): raise ValueError("Owned broker endpoint required")
    os.chmod(path, 0o600, follow_symlinks=False)
    owned = (*owned[:3], 0o600)
    _socket(path, owned)
    listener.listen(8)
    process = launch(str(path))
    if type(process) is not P.subprocess.Popen or process.returncode is not None or P.signal.getsignal(P.signal.SIGCHLD) != P.signal.SIG_DFL:
      raise ValueError("Sole unreaped direct Popen child required")
    # Establish waitable direct-child ownership BEFORE any cleanup method. This
    # may observe an exited child without reaping; pin will truthfully refuse it.
    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    cleanup_owned = True
    pin = P.ChildPin(process, **phase)
    while True:
      _budget(deadline)
      _socket(path, owned)
      P._match(P._identity(os.getpid()), **owner)
      ready = select.select([listener, pin.fd], [], [], _budget(deadline))[0]
      if pin.fd in ready:
        return process.wait()  # the only reaper, actual kernel child status
      if listener not in ready: continue
      with listener.accept()[0] as stream, P.Peer(stream) as peer:
        peer.require_identity(**hook)
        peer.require_descendant(pin, intermediary_exe=intermediary["exe"], intermediary_uid=intermediary["uid"])
        nonce = secrets.token_hex(32)
        P.send_frame(stream, {"protocol": PROTOCOL, "challenge": nonce}, timeout=_budget(deadline))
        frame = P.recv_frame(stream, timeout=_budget(deadline))
        if frame != {"protocol": PROTOCOL, "nonce": nonce}: raise ValueError("Exact current-phase request required")
        gate()
        _socket(path, owned)
        P._match(P._identity(os.getpid()), **owner)
        peer.require_identity(**hook)
        peer.require_descendant(pin, intermediary_exe=intermediary["exe"], intermediary_uid=intermediary["uid"])
        P.send_frame(stream, {"protocol": PROTOCOL, "nonce": nonce, "decision": "allow"}, timeout=_budget(deadline))
  finally:
    # Child remains an owned, unreaped direct child until wait; no foreign PID or
    # process-tree kill. Popen retained returncode skips an already reaped child.
    try:
      if cleanup_owned and process.returncode is None:
        process.terminate()
        try: process.wait(timeout=1)
        except P.subprocess.TimeoutExpired:
          process.kill()
          process.wait(timeout=1)
    finally:
      try:
        if pin is not None: pin.close()
      finally:
        listener.close()
        if owned is not None:
          try: info = path.lstat()
          except FileNotFoundError: pass
          else:
            if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == owned[:2]: path.unlink()
