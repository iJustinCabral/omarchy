"""Disposable-root Python subprocess IPC, never packages or host transitions."""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HERE = Path(__file__).parents[1]
B = load("tested_maintenance_broker", HERE / "hibernate/maintenance_broker.py")
M = load("broker_maintenance_fixture", HERE / "hibernate/package_maintenance.py")
F = load("broker_transition_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))
PYTHON = str(Path(sys.executable).resolve())
HOOK = '''import importlib.util,json,os,socket,sys,time
spec=importlib.util.spec_from_file_location('hook_broker',os.environ['BROKER'])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
mode=os.environ.get('HOOK_MODE','request')
if mode=='silent':
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(os.environ['ENDPOINT']);time.sleep(2)
elif mode=='wrongnonce':
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(os.environ['ENDPOINT'])
  with b.P.Peer(s) as p:
    p.require_identity(**json.loads(os.environ['OWNER']))
    c=b.P.recv_frame(s)
    b.P.send_frame(s,{'protocol':b.PROTOCOL,'nonce':'0'*64})
    b.P.recv_frame(s)
else:
  lock=os.environ.get('FIXTURE_DB')
  if lock:
    fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'simulated pacman');os.close(fd)
  try: b.request(os.environ['ROOT'],os.environ['ENDPOINT'],owner_identity=json.loads(os.environ['OWNER']))
  finally:
    if lock: os.unlink(lock)
'''
PHASE = '''import os,subprocess,sys,time
print('ready',flush=True)
if os.environ.get('PHASE_MODE')=='sleep': time.sleep(5)
elif os.environ.get('PHASE_MODE')=='signal':
  time.sleep(.05);os.kill(os.getpid(),15)
else:
  hook=subprocess.Popen([sys.executable,os.environ['HOOK']])
  code=hook.wait()
  sys.exit(int(os.environ.get('PHASE_RC',str(code))))
'''


class Broker(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.path = self.root / "owner.sock"
    self.hook, self.phase = self.root / "hook.py", self.root / "phase.py"
    self.hook.write_text(HOOK)
    self.phase.write_text(PHASE)
    self.owner = {"uid": os.geteuid(), "exe": PYTHON, "argv": list(B.P._identity(os.getpid())["argv"])}
    self.phase_id = {"uid": os.geteuid(), "exe": PYTHON, "argv": [sys.executable, str(self.phase)]}
    self.hook_id = {"uid": os.geteuid(), "exe": PYTHON, "argv": [sys.executable, str(self.hook)]}
    self.intermediary = {"uid": os.geteuid(), "exe": PYTHON}
    self.children, self.gates = [], []
    self.addCleanup(self.cleanup_children)

  def cleanup_children(self):
    for child in self.children:
      if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired:
          child.kill()
          child.wait(timeout=3)
      for stream in (child.stdin, child.stdout, child.stderr):
        if stream is not None: stream.close()

  def launch(self, endpoint, **env):
    environment = dict(os.environ, BROKER=str(HERE / "hibernate/maintenance_broker.py"), ROOT=str(self.root),
                       ENDPOINT=endpoint, OWNER=json.dumps(self.owner), HOOK=str(self.hook), **env)
    child = subprocess.Popen(self.phase_id["argv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    self.children.append(child)
    # Sole reaper; bounded readiness does NOT poll/wait before ChildPin.
    if not select.select([child.stdout], [], [], 2)[0] or child.stdout.readline() != b"ready\n":
      raise ValueError("Fixture launcher not ready")
    return child

  def run_broker(self, **kwargs):
    options = dict(launch=self.launch, phase_identity=self.phase_id, owner_identity=self.owner,
                   hook_identity=self.hook_id, intermediary_identity=self.intermediary,
                   gate=lambda: self.gates.append("grant"), timeout=3)
    options.update(kwargs)
    return B.run_phase(self.root, self.path, **options)

  def rehome(self, root):
    self.root, self.path = root, root / "owner.sock"
    self.hook, self.phase = root / "hook.py", root / "phase.py"
    self.hook.write_text(HOOK)
    self.phase.write_text(PHASE)
    self.phase_id["argv"] = [sys.executable, str(self.phase)]
    self.hook_id["argv"] = [sys.executable, str(self.hook)]

  def test_real_hook_serviced_while_owner_waits_actual_child_status(self):
    self.assertEqual(self.run_broker(), 0)
    self.assertEqual(self.gates, ["grant"])
    self.assertEqual(self.children[0].returncode, 0)
    self.assertFalse(self.path.exists())

  def test_actual_nonzero_and_signal_status_not_claimed_by_hook(self):
    self.assertEqual(self.run_broker(launch=lambda path: self.launch(path, PHASE_RC="7")), 7)
    self.assertEqual(self.run_broker(launch=lambda path: self.launch(path, PHASE_MODE="signal")), -signal.SIGTERM)
    self.assertFalse(self.path.exists())

  def test_gate_failure_kills_reaps_owned_phase_and_removes_owned_socket(self):
    def fail(): raise ValueError("fixture exclusion lost")
    with self.assertRaisesRegex(ValueError, "exclusion lost"): self.run_broker(gate=fail)
    self.assertIsNotNone(self.children[0].returncode)
    self.assertFalse(self.path.exists())
    self.assertEqual(self.gates, [])

  def test_invalid_release_refuses_before_launch(self):
    with self.assertRaisesRegex(ValueError, "release callback"):
      self.run_broker(release=True)
    self.assertEqual(self.children, [])
    self.assertFalse(self.path.exists())

  def test_release_failure_reaps_pinned_phase(self):
    observed = []
    original = B.P.ChildPin
    def pinned(*args, **kwargs):
      pin = original(*args, **kwargs)
      observed.append("pinned")
      return pin
    def release():
      self.assertEqual(observed, ["pinned"])
      raise ValueError("fixture release failed")
    with patch.object(B.P, "ChildPin", side_effect=pinned), self.assertRaisesRegex(ValueError, "release failed"):
      self.run_broker(launch=lambda path: self.launch(path, PHASE_MODE="sleep"), release=release)
    self.assertIsNotNone(self.children[-1].returncode)
    self.assertFalse(self.path.exists())

  def test_foreign_client_exact_hook_but_outside_phase_refuses(self):
    foreign = []
    def launch(path):
      phase = self.launch(path, PHASE_MODE="sleep")
      env = dict(os.environ, BROKER=str(HERE / "hibernate/maintenance_broker.py"), ROOT=str(self.root), ENDPOINT=path, OWNER=json.dumps(self.owner))
      child = subprocess.Popen(self.hook_id["argv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
      self.children.append(child)
      foreign.append(child)
      return phase
    with self.assertRaises(ValueError): self.run_broker(launch=launch)
    self.assertEqual(self.gates, [])
    foreign[0].wait(timeout=3)
    self.assertNotEqual(foreign[0].returncode, 0)

  def test_hook_uid_argv_and_intermediary_mismatch_never_gate(self):
    for options in ({"hook_identity": dict(self.hook_id, uid=os.geteuid() + 1)},
                    {"hook_identity": dict(self.hook_id, argv=["wrong"])},
                    {"intermediary_identity": dict(self.intermediary, uid=os.geteuid() + 1)}):
      with self.assertRaises(ValueError): self.run_broker(**options)
    self.assertEqual(self.gates, [])

  def test_wrong_nonce_and_silent_hook_timeout_never_gate(self):
    with self.assertRaisesRegex(ValueError, "current-phase"):
      self.run_broker(launch=lambda path: self.launch(path, HOOK_MODE="wrongnonce"))
    with self.assertRaises(TimeoutError):
      self.run_broker(launch=lambda path: self.launch(path, HOOK_MODE="silent"), timeout=.3)
    self.assertEqual(self.gates, [])

  def test_phase_timeout_and_exit_before_pin_no_false_success(self):
    with self.assertRaises(TimeoutError): self.run_broker(launch=lambda path: self.launch(path, PHASE_MODE="sleep"), timeout=.2)
    self.assertIsNotNone(self.children[-1].returncode)
    def exited(path):
      child = subprocess.Popen([sys.executable, "-c", "pass"])
      self.children.append(child)
      deadline = time.monotonic() + 2
      while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        if time.monotonic() > deadline: raise TimeoutError("fixture exit")
        time.sleep(.001)
      return child
    with self.assertRaises(ValueError): self.run_broker(launch=exited)
    self.assertEqual(self.children[-1].returncode, 0)
    self.assertEqual(self.gates, [])

  def test_preexisting_socket_file_and_dangling_link_are_not_unlinked(self):
    for kind in ("file", "symlink", "socket"):
      other = None
      if kind == "file": self.path.write_bytes(b"foreign")
      elif kind == "symlink": self.path.symlink_to("missing")
      else:
        other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        other.bind(str(self.path))
      identity = self.path.lstat()
      try:
        with self.assertRaises(OSError): self.run_broker()
        self.assertEqual(self.path.lstat().st_ino, identity.st_ino)
        self.assertEqual(self.children, [])
      finally:
        if other is not None: other.close()
        self.path.unlink()

  def test_foreign_socket_replacement_preserved_after_gate_failure(self):
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.addCleanup(foreign.close)
    saved = []
    def replace():
      self.path.unlink()
      foreign.bind(str(self.path))
      saved.append(self.path.lstat().st_ino)
    with self.assertRaisesRegex(ValueError, "socket replaced"): self.run_broker(gate=replace)
    self.assertEqual(self.path.lstat().st_ino, saved[0])
    self.assertIsNotNone(self.children[0].returncode)

  def test_fixture_root_alias_escaping_socket_and_live_calls_refuse_before_launch(self):
    for root in (Path("/"), Path("/tmp/..")):
      with self.assertRaises(ValueError): B.run_phase(root, self.path, launch=lambda *args: self.fail("launch"), phase_identity=self.phase_id,
        owner_identity=self.owner, hook_identity=self.hook_id, intermediary_identity=self.intermediary, gate=lambda: self.fail("gate"))
      with self.assertRaises(ValueError): B.request(root, self.path, owner_identity=self.owner)
    with self.assertRaises(ValueError): B.run_phase(self.root, self.root.parent / "outside.sock", launch=lambda *args: self.fail("launch"),
      phase_identity=self.phase_id, owner_identity=self.owner, hook_identity=self.hook_id, intermediary_identity=self.intermediary, gate=lambda: None)
    (self.root / "alias").symlink_to(self.root)
    with self.assertRaises(ValueError): B.request(self.root, self.root / "alias/owner.sock", owner_identity=self.owner)

  def test_client_rejects_foreign_owner_identity_before_request(self):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(self.path))
    os.chmod(self.path, 0o600)
    listener.listen()
    self.addCleanup(listener.close)
    with self.assertRaises(ValueError): B.request(self.root, self.path, owner_identity=dict(self.owner, argv=["foreign"]))

  def test_owner_death_after_authenticated_challenge_cannot_grant(self):
    script = self.root / "dead-owner.py"
    script.write_text("import importlib.util,os,socket,sys\nspec=importlib.util.spec_from_file_location('b',sys.argv[1]);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(sys.argv[2]);os.chmod(sys.argv[2],0o600);s.listen();print('ready',flush=True);c,_=s.accept();b.P.send_frame(c,{'protocol':b.PROTOCOL,'challenge':'a'*64})\n")
    argv = [sys.executable, str(script), str(HERE / "hibernate/maintenance_broker.py"), str(self.path)]
    owner = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(owner)
    self.assertTrue(select.select([owner.stdout], [], [], 2)[0])
    self.assertEqual(owner.stdout.readline(), b"ready\n")
    with self.assertRaises((ValueError, OSError)):
      B.request(self.root, self.path, owner_identity=dict(self.owner, argv=argv))
    owner.wait(timeout=3)

  def test_client_leaf_symlink_and_replaced_endpoint_refuse_without_external_connect(self):
    outside = self.root.parent / (self.root.name + "-external.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(outside))
    listener.listen()
    self.addCleanup(listener.close)
    self.addCleanup(outside.unlink)
    self.path.symlink_to(outside)
    with self.assertRaises(ValueError): B.request(self.root, self.path, owner_identity=self.owner)
    self.assertFalse(select.select([listener], [], [], 0)[0])
    self.path.unlink()
    local = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    local.bind(str(self.path))
    os.chmod(self.path, 0o600)
    local.listen()
    self.addCleanup(local.close)
    original = B._socket
    calls = []
    def replace(path, owned):
      calls.append(path)
      if len(calls) == 2:
        path.unlink()
        path.symlink_to(outside)
      return original(path, owned)
    with patch.object(B, "_socket", side_effect=replace), self.assertRaises(ValueError):
      B.request(self.root, self.path, owner_identity=self.owner)
    self.assertTrue(self.path.is_symlink())
    self.assertFalse(select.select([listener], [], [], 0)[0])

  def test_malformed_launcher_return_has_no_cleanup_method_calls(self):
    class Foreign:
      @property
      def returncode(self): raise AssertionError("foreign status")
      def terminate(self): raise AssertionError("foreign termination")
    for result in (None, Foreign()):
      with self.assertRaisesRegex(ValueError, "direct Popen"):
        self.run_broker(launch=lambda path: result)
      self.assertFalse(self.path.exists())

  def test_termination_failure_still_closes_pidfd_listener_and_owned_endpoint(self):
    before = len(os.listdir("/proc/self/fd"))
    def gate(): raise ValueError("fixture gate")
    with patch.object(subprocess.Popen, "terminate", side_effect=OSError("fixture terminate failure")), self.assertRaises(OSError):
      self.run_broker(gate=gate)
    self.assertFalse(self.path.exists())
    self.cleanup_children()
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)

  def test_child_exit_during_gate_refuses_reply_after_gate(self):
    def gate():
      self.children[-1].terminate()
      # Do not reap here: broker retains the only reaper responsibility.
      deadline = time.monotonic() + 2
      while os.waitid(os.P_PID, self.children[-1].pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        if time.monotonic() > deadline: raise TimeoutError("fixture phase exit")
        time.sleep(.001)
    with self.assertRaises(ValueError): self.run_broker(gate=gate)
    self.assertEqual(self.children[-1].returncode, -signal.SIGTERM)
    self.assertFalse(self.path.exists())

  def test_integrated_coordinate_records_actual_phases_and_keeps_veto(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    fixture.f.write(M.BOOT, b"0f909934-0ecf-4407-863d-6822c81cb2df")
    fixture.run_action()
    # All subprocess/socket paths are under the same disposable target root.
    self.rehome(fixture.root)
    records = []
    def phase(name, session):
      def gate():
        self.assertEqual((self.root / M.T.DB_LOCK).read_bytes(), b"simulated pacman")
        result = M.check_maintenance(self.root, session)
        self.assertEqual(result["classification"], "fallback-bytes-verified")
        records.append(name)
      return self.run_broker(gate=gate, launch=lambda path: self.launch(path, PHASE_RC="127" if name == "snapshot" else "0", FIXTURE_DB=str(self.root / M.T.DB_LOCK)))
    result = M.coordinate(self.root, precheck=fixture.check, run_phase=phase)
    self.assertEqual(records, list(M.PHASES))
    self.assertEqual(result["maintenance"]["hibernation"], "maintenance-disabled")
    intent = json.loads((self.root / M.T.MAINTENANCE).read_bytes())
    archive = self.root / M.T.HISTORY / intent["transition_id"]
    self.assertEqual(json.loads((archive / "package-phase-01-snapshot-result.json").read_bytes())["returncode"], 127)
    self.assertEqual(len(list(archive.glob("package-phase-*-result.json"))), len(M.PHASES))
    self.assertFalse((self.root / M.T.DB_LOCK).exists())
    self.assertFalse(self.path.exists())
    with self.assertRaises(ValueError): M.coordinate(self.root, precheck=fixture.check, run_phase=phase)

  def test_integrated_phase_failure_retains_marker_records_and_no_replay(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    fixture.f.write(M.BOOT, b"0f909934-0ecf-4407-863d-6822c81cb2df")
    fixture.run_action()
    self.rehome(fixture.root)
    calls = []
    def phase(name, session):
      calls.append(name)
      return self.run_broker(gate=lambda: M.check_maintenance(self.root, session), launch=lambda path: self.launch(path, PHASE_RC="9"))
    with self.assertRaises(RuntimeError): M.coordinate(self.root, precheck=fixture.check, run_phase=phase)
    self.assertEqual(calls, [M.PHASES[0]])
    intent = json.loads((self.root / M.T.MAINTENANCE).read_bytes())
    archive = self.root / M.T.HISTORY / intent["transition_id"]
    self.assertEqual(json.loads((archive / "package-phase-00-pkg-prune-result.json").read_bytes())["returncode"], 9)
    self.assertTrue((archive / "package-maintenance-failure.json").exists())
    self.assertFalse((archive / "package-maintenance-complete.json").exists())
    with self.assertRaises(ValueError): M.coordinate(self.root, precheck=fixture.check, run_phase=phase)

  def test_broker_failure_preserves_unrelated_db_file(self):
    lock = self.root / "foreign-db.lck"
    lock.write_bytes(b"foreign transaction evidence")
    with self.assertRaises(ValueError): self.run_broker(gate=lambda: (_ for _ in ()).throw(ValueError("fixture failure")))
    self.assertEqual(lock.read_bytes(), b"foreign transaction evidence")


if __name__ == "__main__": unittest.main()
