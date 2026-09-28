"""Real unprivileged OFD/UNIX fixtures; no sudo, packages or native root owner."""
import array
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HERE = Path(__file__).parents[1]
H = load("tested_maintenance_handoff", HERE / "hibernate/maintenance_handoff.py")
L = load("handoff_test_launcher", HERE / "hibernate/maintenance_launcher.py")
B = load("handoff_test_broker", HERE / "hibernate/maintenance_broker.py")
PYTHON = str(Path("/usr/bin/python3").resolve())
CLIENT = '''import array,importlib.util,json,os,socket,sys,time
s=importlib.util.spec_from_file_location('h',os.environ['HANDOFF']);h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.connect(os.environ['ENDPOINT'])
fd=int(os.environ['LOCK']);mode=os.environ.get('MODE','normal')
try:
  if mode=='normal':
    h.send_lock(c,fd,receiver_identity=json.loads(os.environ['OWNER']),runtime_directory=os.environ['RUNTIME'])
  else:
    with h.P.Peer(c) as p:
      p.require_identity(**json.loads(os.environ['OWNER']))
      challenge=h.P.recv_frame(c)
      if mode=='silent': time.sleep(2)
      elif mode=='truncated': c.sendall(b'\\0\\0');c.close()
      else:
        h.P.send_frame(c,{'protocol':h.PROTOCOL,'nonce':'0'*64 if mode=='wrongnonce' else challenge['challenge']})
        if mode=='dead': c.close();sys.exit(0)
        if mode=='foreign': fd=os.open(os.environ['FOREIGN'],os.O_RDWR)
        if mode=='unheld': fd=os.open(os.environ['RUNTIME']+'/omarchy-update.lock',os.O_RDWR)
        count=32 if mode=='ctrunc' else 2 if mode=='multi' else 0 if mode=='missing' else 1
        controls=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]*count))] if count else []
        c.sendmsg([b'X' if mode=='badtoken' else b'L'],controls)
        h.P.recv_frame(c)
  print('accepted',flush=True)
except (OSError,ValueError) as error: print('error:'+type(error).__name__,flush=True)
sys.stdin.readline()
'''


class Handoff(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Real root-peer proof is isolated VM only")
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.runtime = self.root / "runtime"
    self.runtime.mkdir(mode=0o700)
    self.path = self.root / "handoff.sock"
    self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.listener.bind(str(self.path))
    self.listener.listen()
    self.listener.settimeout(2)
    self.addCleanup(self.listener.close)
    self.lock = self.runtime / "omarchy-update.lock"
    self.fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    os.write(self.fd, b"original OFD")
    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    self.addCleanup(os.close, self.fd)
    self.client = self.root / "client.py"
    self.client.write_text(CLIENT)
    self.owner = {"uid": os.geteuid(), "exe": H.P._identity(os.getpid())["exe"], "argv": list(H.P._identity(os.getpid())["argv"])}
    self.children, self.receipts = [], []
    self.addCleanup(self.cleanup)

  def cleanup(self):
    for receipt in self.receipts: receipt.close()
    for process in self.children:
      if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait(timeout=2)
      for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None: stream.close()

  def spawn(self, mode="normal", *, owner_identity=None, **env):
    environment = dict(os.environ, HANDOFF=str(HERE / "hibernate/maintenance_handoff.py"), ENDPOINT=str(self.path),
      OWNER=json.dumps(self.owner if owner_identity is None else owner_identity), LOCK=str(self.fd), RUNTIME=str(self.runtime), MODE=mode, **env)
    argv = ["/usr/bin/python3", str(self.client)]
    child = subprocess.Popen(argv, env=environment, pass_fds=(self.fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(child)
    stream, _ = self.listener.accept()
    stream.settimeout(.7)
    self.addCleanup(stream.close)
    return child, stream, {"uid": os.geteuid(), "exe": PYTHON, "argv": argv}

  def receive(self, mode="normal", **env):
    child, stream, expected = self.spawn(mode, **env)
    receipt = H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime)
    self.assertEqual(stream.gettimeout(), .7)
    self.receipts.append(receipt)
    self.assertTrue(select.select([child.stdout], [], [], 2)[0])
    self.assertEqual(child.stdout.readline(), b"accepted\n")
    return child, receipt

  def assert_original_held(self):
    fresh = os.open(self.lock, os.O_RDWR)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(fresh)

  def test_real_fresh_child_transfers_original_ofd_cloexec_and_live_peer(self):
    child, receipt = self.receive()
    self.assertFalse(os.get_inheritable(receipt.fd))
    self.assertEqual(receipt.peer.pid, child.pid)
    self.assertEqual(receipt.check()["pid"], child.pid)
    os.lseek(self.fd, 3, os.SEEK_SET)
    self.assertEqual(os.lseek(receipt.fd, 0, os.SEEK_CUR), 3)
    os.write(receipt.fd, b"X")
    self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 4)
    receipt.close()
    self.assert_original_held()
    with self.assertRaises(ValueError): receipt.check()

  def test_sender_death_invalidates_receipt_but_original_parent_lock_survives(self):
    child, receipt = self.receive()
    child.stdin.write(b"exit\n")
    child.stdin.flush()
    child.wait(timeout=2)
    with self.assertRaises(ValueError): receipt.check()
    receipt.close()
    self.assert_original_held()

  def test_missing_multi_ctrunc_badtoken_wrongnonce_and_truncated_close_all_fds(self):
    for mode in ("missing", "multi", "ctrunc", "badtoken", "wrongnonce", "truncated", "dead"):
      child, stream, expected = self.spawn(mode)
      before = len(os.listdir("/proc/self/fd"))
      with self.assertRaises((ValueError, OSError)):
        H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime)
      self.assertEqual(len(os.listdir("/proc/self/fd")), before)
      self.assertEqual(stream.gettimeout(), .7)
      stream.close()
      self.assert_original_held()

  def test_foreign_and_same_inode_wrong_ofd_are_rejected_without_removing_files(self):
    foreign = self.root / "foreign.lock"
    foreign.write_bytes(b"foreign")
    for mode in ("foreign", "unheld"):
      child, stream, expected = self.spawn(mode, FOREIGN=str(foreign))
      before = len(os.listdir("/proc/self/fd"))
      with self.assertRaises(ValueError): H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime)
      self.assertEqual(len(os.listdir("/proc/self/fd")), before)
      self.assertEqual(foreign.read_bytes(), b"foreign")
      self.assert_original_held()
      stream.close()

  def test_actual_unheld_original_refused_and_not_acquired_or_removed(self):
    fcntl.flock(self.fd, fcntl.LOCK_UN)
    child, stream, expected = self.spawn("unheld")
    with self.assertRaises(ValueError): H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime)
    fresh = os.open(self.lock, os.O_RDWR)
    try: fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(fresh)
    self.assertTrue(self.lock.exists())

  def test_exact_sender_uid_exe_argv_and_runtime_ownership_are_not_payload_claims(self):
    for changed in ({"uid": os.geteuid() + 1}, {"exe": "/wrong"}, {"argv": ["wrong"]}):
      child, stream, expected = self.spawn()
      with self.assertRaises(ValueError): H.receive_lock(stream, sender_identity=dict(expected, **changed), runtime_directory=self.runtime)
      stream.close()
    child, stream, expected = self.spawn()
    self.runtime.chmod(0o777)
    with self.assertRaises(ValueError): H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime)
    self.runtime.chmod(0o700)
    stream.close()

  def test_timeout_restores_socket_timeout_and_no_descriptor_leak(self):
    child, stream, expected = self.spawn("silent")
    before = len(os.listdir("/proc/self/fd"))
    with self.assertRaises(TimeoutError): H.receive_lock(stream, sender_identity=expected, runtime_directory=self.runtime, timeout=.1)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    self.assertEqual(stream.gettimeout(), .7)
    self.assert_original_held()

  def test_runtime_alias_and_replaced_directory_refuse_live_receipt(self):
    alias = self.root / "alias"
    alias.symlink_to(self.runtime)
    child, stream, expected = self.spawn()
    with self.assertRaises(ValueError): H.receive_lock(stream, sender_identity=expected, runtime_directory=alias)
    stream.close()
    child, receipt = self.receive()
    old = self.runtime.with_name("old-runtime")
    self.runtime.rename(old)
    self.runtime.mkdir(mode=0o700)
    with self.assertRaises(ValueError): receipt.check()

  def test_malformed_ancillary_tail_closes_every_visible_integer_fd(self):
    duplicate = os.dup(self.fd)
    class Malformed:
      def settimeout(self, value): pass
      def recvmsg(self, *args): return b"L", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [duplicate]).tobytes() + b"x")], 0, None
    with self.assertRaises(ValueError): H._receive_fd(Malformed(), H.P._timeout(1))
    with self.assertRaises(OSError): os.fstat(duplicate)
    self.assert_original_held()

  def test_generic_sender_dead_receiver_never_transfers(self):
    # A fresh real child creates the listener itself; exact server credentials
    # identify that child, not an inherited parent's endpoint.
    path = self.root / "child-owner.sock"
    script = self.root / "owner.py"
    script.write_text("import importlib.util,socket,sys\ns=importlib.util.spec_from_file_location('h',sys.argv[1]);h=importlib.util.module_from_spec(s);s.loader.exec_module(h)\na=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);a.bind(sys.argv[2]);a.listen();print('ready',flush=True);c,_=a.accept();h.P.send_frame(c,{'protocol':h.PROTOCOL,'challenge':'a'*64})\n")
    argv = ["/usr/bin/python3", str(script), str(HERE / "hibernate/maintenance_handoff.py"), str(path)]
    owner = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(owner)
    self.assertTrue(select.select([owner.stdout], [], [], 2)[0])
    self.assertEqual(owner.stdout.readline(), b"ready\n")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
      stream.connect(str(path))
      with self.assertRaises((OSError, ValueError)):
        H.send_lock(stream, self.fd, receiver_identity={"uid": os.geteuid(), "exe": PYTHON, "argv": argv}, runtime_directory=self.runtime)
    owner.wait(timeout=2)
    self.assert_original_held()

  def test_generic_sender_wrong_receiver_uid_and_argv_refuse_before_any_wire_data(self):
    original = os.fstat(self.fd)
    for changed in ({"uid": os.geteuid() + 1}, {"argv": ["wrong-owner"]}):
      child, stream, expected = self.spawn(owner_identity=dict(self.owner, **changed))
      self.assertTrue(select.select([child.stdout], [], [], 2)[0])
      self.assertEqual(child.stdout.readline(), b"error:ValueError\n")
      # Sender remains alive holding its socket/OFD, but authentication failed
      # BEFORE even a protocol frame or descriptor token was sent.
      self.assertFalse(select.select([stream], [], [], 0)[0])
      self.assertEqual(os.fstat(self.fd), original)
      self.assert_original_held()
      stream.close()

  def test_native_fixed_namespace_and_actual_root_uid_fail_closed_without_host_connect(self):
    # Patch only the fixed namespace to a disposable socket; no live path opens.
    with patch.object(H, "ROOT_ENDPOINT", self.path), self.assertRaises(ValueError): H.send_native_lock(self.fd)
    self.assertFalse(select.select([self.listener], [], [], 0)[0])
    with patch.object(H, "ROOT_ENDPOINT", self.path), patch.object(H, "_root_endpoint", return_value=(1, 2, 0, 0o666)), self.assertRaises(ValueError):
      H.send_native_lock(self.fd)
    stream, _ = self.listener.accept()
    stream.close()
    self.assert_original_held()

  def test_received_ofd_into_held_launcher_and_broker_stub(self):
    child, receipt = self.receive()
    omarchy = self.root / "omarchy"
    (omarchy / "bin").mkdir(parents=True)
    marker = self.root / "phase-ran"
    script = omarchy / "bin" / "omarchy-snapshot"
    script.write_text("#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\nassert sys.argv[1:] == ['create']\nfd=int(os.environ['OMARCHY_UPDATE_LOCK_FD']);assert Path('/proc/self/fd/'+str(fd)).resolve()==Path(" + repr(str(self.lock)) + ")\nPath(" + repr(str(marker)) + ").write_text('returned')\n")
    script.chmod(0o755)
    account = pwd.getpwuid(os.geteuid())
    environment = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name, "SHELL": account.pw_shell,
      "PATH": str(omarchy / "bin") + ":/usr/bin:/bin", "OMARCHY_PATH": str(omarchy), "XDG_RUNTIME_DIR": str(self.runtime)}
    held = L.launch("snapshot", uid=os.geteuid(), environment=environment, update_lock_fd=receipt.fd)
    try:
      self.assertFalse(marker.exists())
      code = B.run_phase(self.root, self.root / "phase.sock", launch=lambda _: held.process, phase_identity=held.identity,
        release=held.release, owner_identity=self.owner, hook_identity={"uid": os.geteuid(), "exe": PYTHON, "argv": ["unused"]},
        intermediary_identity={"uid": os.geteuid(), "exe": PYTHON}, gate=lambda: self.fail("no package hook expected"))
      self.assertEqual(code, 0)
      self.assertEqual(marker.read_text(), "returned")
      receipt.check()
      self.assert_original_held()
    finally: held.abort()


if __name__ == "__main__": unittest.main()
