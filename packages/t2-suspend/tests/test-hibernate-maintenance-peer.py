"""Real unprivileged UNIX/subprocess fixtures; no native update or power action."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("tested_maintenance_peer", Path(__file__).parents[1] / "hibernate/maintenance_peer.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
PYTHON = str(Path(sys.executable).resolve())
CLIENT = """import json,os,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
raw=json.dumps({'nonce':'fixture','claimed_pid':os.getpid()}).encode()
s.sendall(struct.pack('!I',len(raw))+raw)
print('ready',flush=True)
s.recv(1)
"""


class Peers(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.path = str(Path(temporary.name) / "owner.sock")
    self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.listener.bind(self.path)
    self.listener.listen()
    self.listener.settimeout(2)
    self.addCleanup(self.listener.close)

  def spawn(self, code, *args, **kwargs):
    argv = [sys.executable, "-u", "-c", code, *args]
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
    def cleanup():
      if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired:
          child.kill()
          child.wait(timeout=2)
      for stream in (child.stdin, child.stdout, child.stderr): stream.close()
    self.addCleanup(cleanup)
    return child, argv

  def accept(self):
    stream, _ = self.listener.accept()
    self.addCleanup(stream.close)
    return stream

  def phase(self, *, intermediary=False):
    descendant = "import subprocess,sys; hook=subprocess.Popen([sys.executable,'-u','-c'," + repr(CLIENT) + ",sys.argv[1]]); hook.wait()" if intermediary else CLIENT
    code = "import subprocess,sys\nprint('ready',flush=True)\nsys.stdin.readline()\nhook=subprocess.Popen([sys.executable,'-u','-c'," + repr(descendant) + ",sys.argv[1]])\nhook.wait()\nsys.stdin.readline()\n"
    child, argv = self.spawn(code, self.path)
    self.assertEqual(child.stdout.readline().strip(), "ready")
    pin = P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv)
    self.addCleanup(pin.close)
    child.stdin.write("connect\n")
    child.stdin.flush()
    stream = self.accept()
    return child, pin, stream

  def test_fresh_real_client_credentials_pidfd_and_exact_identity(self):
    child, argv = self.spawn(CLIENT, self.path)
    stream = self.accept()
    before = len(os.listdir("/proc/self/fd"))
    with P.Peer(stream) as peer:
      self.assertEqual(peer.pid, child.pid)
      self.assertEqual(peer.uid, os.geteuid())
      self.assertFalse(os.get_inheritable(peer.fd))
      self.assertEqual(peer.require_identity(os.geteuid(), PYTHON, argv)["pid"], child.pid)
      frame = P.recv_frame(stream)
      self.assertEqual(frame["claimed_pid"], child.pid)
      for uid, exe, args in ((os.geteuid() + 1, PYTHON, argv), (os.geteuid(), "/wrong", argv), (os.geteuid(), PYTHON, ["wrong"])):
        with self.assertRaises(ValueError): peer.require_identity(uid, exe, args)
      with P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv) as pin:
        with self.assertRaises(ValueError): peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    with self.assertRaises(ValueError): peer.identity()
    stream.sendall(b"x")

  def test_real_hook_ancestry_into_owned_phase_and_intermediary_uid(self):
    child, pin, stream = self.phase()
    with P.Peer(stream) as peer:
      chain = peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
      self.assertEqual(chain, (peer.pid, child.pid))
      with self.assertRaises(ValueError): peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid() + 1)
      with self.assertRaises(ValueError): peer.require_descendant(pin, intermediary_exe="/wrong", intermediary_uid=os.geteuid())
      identity = P._identity
      def saved_uid(pid):
        value = identity(pid)
        if pid == child.pid: value["uids"] = (os.geteuid(), os.geteuid(), os.geteuid() + 1, os.geteuid())
        return value
      with patch.object(P, "_identity", side_effect=saved_uid), self.assertRaises(ValueError):
        peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
      stream.sendall(b"x")

  def test_distinct_intermediary_process_in_real_three_level_chain(self):
    child, pin, stream = self.phase(intermediary=True)
    with P.Peer(stream) as peer:
      chain = peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
      self.assertEqual(len(chain), 3)
      self.assertEqual(len(set(chain)), 3)
      self.assertEqual(chain[0], peer.pid)
      self.assertEqual(chain[-1], child.pid)
      stream.sendall(b"x")

  def test_foreign_phase_and_reparent_after_phase_death_refuse(self):
    child, pin, stream = self.phase()
    other, argv = self.spawn("import sys; print('ready',flush=True); sys.stdin.readline()")
    self.assertEqual(other.stdout.readline().strip(), "ready")
    with P.ChildPin(other, uid=os.geteuid(), exe=PYTHON, argv=argv) as foreign, P.Peer(stream) as peer:
      with self.assertRaises(ValueError): peer.require_descendant(foreign, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
      child.terminate()
      child.wait(timeout=2)
      with self.assertRaises(ValueError): peer.require_descendant(pin, intermediary_exe=PYTHON, intermediary_uid=os.geteuid())
      stream.sendall(b"x")

  def test_peer_client_death_rejects_even_with_connected_socket(self):
    child, _ = self.spawn(CLIENT, self.path)
    stream = self.accept()
    with P.Peer(stream) as peer:
      child.terminate()
      child.wait(timeout=2)
      with self.assertRaises(ValueError): peer.identity()

  def test_owner_created_listener_and_owner_death_are_kernel_bound(self):
    path = self.path + "-child"
    code = "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(); print('ready',flush=True); c,_=s.accept(); c.recv(1)"
    owner, argv = self.spawn(code, path)
    self.assertEqual(owner.stdout.readline().strip(), "ready")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.addCleanup(client.close)
    client.connect(path)
    with P.Peer(client) as peer:
      self.assertEqual(peer.pid, owner.pid)
      peer.require_identity(os.geteuid(), PYTHON, argv)
      owner.terminate()
      owner.wait(timeout=2)
      with self.assertRaises(ValueError): peer.identity()

  def test_inherited_connected_client_identifies_creator_not_claimed_sender(self):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.addCleanup(client.close)
    client.connect(self.path)
    accepted = self.accept()
    code = "import socket,json,os,struct,sys; s=socket.socket(fileno=int(sys.argv[1])); raw=json.dumps({'claimed_pid':os.getpid()}).encode(); s.sendall(struct.pack('!I',len(raw))+raw); s.recv(1)"
    sender, argv = self.spawn(code, str(client.fileno()), pass_fds=(client.fileno(),))
    with P.Peer(accepted) as peer:
      frame = P.recv_frame(accepted)
      self.assertEqual(frame["claimed_pid"], sender.pid)
      self.assertEqual(peer.pid, os.getpid())
      with self.assertRaises(ValueError): peer.require_identity(os.geteuid(), PYTHON, argv)
      accepted.sendall(b"x")

  def test_child_pin_rejects_wrong_launch_reaped_child_and_sigchld_reaper(self):
    child, argv = self.spawn("import sys; print('ready',flush=True); sys.stdin.readline()")
    self.assertEqual(child.stdout.readline().strip(), "ready")
    for uid, exe, args in ((os.geteuid() + 1, PYTHON, argv), (os.geteuid(), "/wrong", argv), (os.geteuid(), PYTHON, ["wrong"])):
      with self.assertRaises(ValueError): P.ChildPin(child, uid=uid, exe=exe, argv=args)
    with patch.object(P.signal, "getsignal", return_value=signal.SIG_IGN), self.assertRaises(ValueError):
      P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv)
    child.terminate()
    child.wait(timeout=2)
    with self.assertRaises(ValueError): P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv)

  def test_exact_uid_requires_real_effective_saved_and_filesystem_ids(self):
    identity = {"uids": (7, 7, 0, 7), "exe": "/fixture", "argv": ("fixture",)}
    with self.assertRaises(ValueError): P._match(identity, 7, "/fixture", ("fixture",))
    identity["uids"] = (7, 7, 7, 7)
    P._match(identity, 7, "/fixture", ("fixture",))

  def test_child_pin_persists_instance_across_legitimate_exec(self):
    code = "import os,sys; print('ready',flush=True); sys.stdin.readline(); os.execv(sys.executable,[sys.executable,'-u','-c',\"import sys; print('execed',flush=True); sys.stdin.readline()\"])"
    child, argv = self.spawn(code)
    self.assertEqual(child.stdout.readline().strip(), "ready")
    with P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv) as pin:
      child.stdin.write("exec\n")
      child.stdin.flush()
      self.assertEqual(child.stdout.readline().strip(), "execed")
      self.assertEqual(pin.identity()["pid"], child.pid)
      self.assertNotEqual(pin.identity()["argv"], tuple(argv))

  def test_peer_constructor_failure_closes_kernel_fd_and_unsupported_option_refuses(self):
    child, _ = self.spawn(CLIENT, self.path)
    stream = self.accept()
    before = len(os.listdir("/proc/self/fd"))
    with patch.object(P, "_pidfd_pid", return_value=-1), self.assertRaises(ValueError): P.Peer(stream)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    with patch.object(P, "SO_PEERPIDFD", 9999), self.assertRaises(OSError): P.Peer(stream)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    stream.sendall(b"x")

  def test_child_pin_constructor_failure_closes_opened_descriptor(self):
    child, argv = self.spawn("import sys; print('ready',flush=True); sys.stdin.readline()")
    self.assertEqual(child.stdout.readline().strip(), "ready")
    before = len(os.listdir("/proc/self/fd"))
    with patch.object(P, "_pidfd_pid", return_value=-1), self.assertRaises(ValueError):
      P.ChildPin(child, uid=os.geteuid(), exe=PYTHON, argv=argv)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class Frames(unittest.TestCase):
  def pair(self):
    left, right = socket.socketpair()
    self.addCleanup(left.close)
    self.addCleanup(right.close)
    return left, right

  def test_roundtrip_and_timeout_setting_preserved(self):
    left, right = self.pair()
    left.settimeout(2)
    right.settimeout(2)
    P.send_frame(left, {"protocol": "fixture", "nonce": "a" * 64})
    self.assertEqual(P.recv_frame(right), {"protocol": "fixture", "nonce": "a" * 64})
    self.assertEqual(left.gettimeout(), 2)
    self.assertEqual(right.gettimeout(), 2)

  def test_malformed_nonfinite_duplicates_trailing_and_nonobject_frames_refuse(self):
    for raw in (b"{", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":{"overflow":1e999}}', b'{} junk', b'[]', b'\xff', '{}'.encode("utf-16"), b'{"a":' + b'[' * 1200 + b']' * 1200 + b'}'):
      with self.subTest(raw=raw[:24]):
        left, right = self.pair()
        left.sendall(struct.pack("!I", len(raw)) + raw)
        with self.assertRaises(ValueError): P.recv_frame(right)

  def test_oversized_zero_and_truncated_frames_refuse(self):
    for raw in (struct.pack("!I", P.MAX_FRAME + 1), struct.pack("!I", 0), b"\0\0", struct.pack("!I", 4) + b"{}"):
      left, right = self.pair()
      left.sendall(raw)
      left.shutdown(socket.SHUT_WR)
      with self.assertRaises(ValueError): P.recv_frame(right)
    left, _ = self.pair()
    for value in ([], {"large": "x" * P.MAX_FRAME}, {"number": float("nan")}):
      with self.assertRaises(ValueError): P.send_frame(left, value)

  def test_receive_deadline_bounds_header_and_trickle_body(self):
    left, right = self.pair()
    started = time.monotonic()
    with self.assertRaises(TimeoutError): P.recv_frame(right, timeout=0.05)
    self.assertLess(time.monotonic() - started, 0.5)
    raw = b'{"hello":"world"}'
    left.sendall(struct.pack("!I", len(raw)))
    def trickle():
      try:
        for item in raw:
          time.sleep(0.02)
          left.sendall(bytes([item]))
      except OSError: pass
    worker = threading.Thread(target=trickle)
    worker.start()
    try:
      with self.assertRaises(TimeoutError): P.recv_frame(right, timeout=0.05)
    finally:
      right.close()
      worker.join(timeout=1)
    self.assertFalse(worker.is_alive())

  def test_send_deadline_and_invalid_timeout(self):
    left, _ = self.pair()
    left.setblocking(False)
    while True:
      try: left.send(b"x" * 4096)
      except BlockingIOError: break
    left.settimeout(None)
    with self.assertRaises(TimeoutError): P.send_frame(left, {"nonce": "x"}, timeout=0.05)
    self.assertIsNone(left.gettimeout())
    for value in (0, 6, True, float("nan")):
      with self.assertRaises(ValueError): P.recv_frame(left, timeout=value)

  def test_send_refuses_deadline_expired_during_serialization(self):
    left, right = self.pair()
    with patch.object(P.time, "monotonic", side_effect=(1.0, 3.0)), self.assertRaises(TimeoutError):
      P.send_frame(left, {"nonce": "fixture"}, timeout=1)
    right.setblocking(False)
    with self.assertRaises(BlockingIOError): right.recv(1)


if __name__ == "__main__": unittest.main()
