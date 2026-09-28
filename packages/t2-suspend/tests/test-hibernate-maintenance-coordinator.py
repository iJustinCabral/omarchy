"""Disposable maintenance join and real Python client/phases/hooks, never updates."""
from contextlib import contextmanager
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
import threading
import time
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  value = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(value)
  return value


HERE = Path(__file__).parents[1]
C = load("tested_maintenance_coordinator", HERE / "hibernate/maintenance_coordinator.py")
F = load("coordinator_transition_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))
PYTHON = str(Path("/usr/bin/python3").resolve())
CLIENT = '''import importlib.util,json,os,socket,sys
s=importlib.util.spec_from_file_location('h',sys.argv[1]);h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.connect(sys.argv[2])
h.send_lock(c,int(sys.argv[3]),receiver_identity=json.loads(sys.argv[5]),runtime_directory=sys.argv[4])
print('handoff',flush=True);sys.stdin.readline()
'''


class Coordinator(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Host tests are unprivileged fixtures only")
    self.fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.f = self.fixture.root, self.fixture.f
    self.f.write(C.M.BOOT, b"0f909934-0ecf-4407-863d-6822c81cb2df")
    self.fixture.run_action()
    self.runtime = self.root / "runtime"
    self.runtime.mkdir(mode=0o700)
    self.fd = os.open(self.runtime / "omarchy-update.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    self.addCleanup(os.close, self.fd)
    self.path = self.root / "handoff.sock"
    self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.listener.bind(str(self.path))
    self.listener.listen()
    self.listener.settimeout(2)
    self.addCleanup(self.listener.close)
    self.client_file = self.root / "client.py"
    self.client_file.write_text(CLIENT)
    current = C.B.P._identity(os.getpid())
    self.owner = {"uid": os.geteuid(), "exe": current["exe"], "argv": list(current["argv"])}
    self.omarchy = self.root / "omarchy"
    (self.omarchy / "bin").mkdir(parents=True)
    self.results = self.root / "results"
    self.results.mkdir()
    self.plan = self.root / "plan.json"
    self.plan.write_text(json.dumps({"statuses": {"snapshot": 127}, "hold_db": True}))
    self.hook_file = self.root / "hook.py"
    self.hook_file.write_text("import importlib.util,sys\ns=importlib.util.spec_from_file_location('b'," + repr(str(HERE / "hibernate/maintenance_broker.py")) + ");b=importlib.util.module_from_spec(s);s.loader.exec_module(b)\ntry: b.request(" + repr(str(self.root)) + "," + repr(str(self.root / C.HOOK_SOCKET)) + ",owner_identity=" + repr(self.owner) + ")\nexcept (OSError,ValueError): sys.exit(41)\n")
    self.hook = {"uid": os.geteuid(), "exe": PYTHON, "argv": ["/usr/bin/python3", str(self.hook_file)]}
    for name, command in C.L.PHASES.items():
      script = self.omarchy / "bin" / command[0]
      script.write_text("#!/usr/bin/python3\nimport json,os,subprocess,sys,time\nfrom pathlib import Path\nphase=" + repr(name) + "\nplan=json.loads(Path(" + repr(str(self.plan)) + ").read_bytes())\nPath(" + repr(str(self.results)) + ",phase).write_text('started')\nif plan.get('sleep_phase')==phase: time.sleep(plan.get('sleep_seconds',5))\nlock=Path(" + repr(str(self.root / C.M.T.DB_LOCK)) + ")\nif plan.get('hold_db'): lock.write_bytes(b'simulated pacman')\ntry:\n  code=subprocess.Popen(['/usr/bin/python3'," + repr(str(self.hook_file)) + "]).wait()\nfinally:\n  if plan.get('hold_db'): lock.unlink()\nsys.exit(code or plan.get('statuses',{}).get(phase,0))\n")
      script.chmod(0o755)
    account = pwd.getpwuid(os.geteuid())
    self.environment = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name, "SHELL": account.pw_shell,
      "PATH": str(self.omarchy / "bin") + ":/usr/bin:/bin", "OMARCHY_PATH": str(self.omarchy),
      "XDG_RUNTIME_DIR": str(self.runtime), "XDG_STATE_HOME": str(self.results)}
    self.clients, self.receipts, self.held = [], [], []
    self.events, self.power = [], True
    self.addCleanup(self.cleanup)

  def cleanup(self):
    for child in self.clients:
      if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired:
          child.kill()
          child.wait(timeout=2)
      for stream in (child.stdin, child.stdout, child.stderr): stream.close()

  def connect(self):
    argv = ["/usr/bin/python3", str(self.client_file), str(HERE / "hibernate/maintenance_handoff.py"), str(self.path),
      str(self.fd), str(self.runtime), json.dumps(self.owner)]
    child = subprocess.Popen(argv, pass_fds=(self.fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.clients.append(child)
    stream, _ = self.listener.accept()
    self.addCleanup(stream.close)
    return child, stream, {"uid": os.geteuid(), "exe": PYTHON, "argv": argv}

  @contextmanager
  def exclusion(self):
    self.events.append("exclusion-enter")
    try: yield self.guard
    finally:
      # Receipt and launch resources must close BEFORE the outer scope exits.
      for receipt in self.receipts:
        self.assertIsNone(receipt.fd)
        self.assertIsNone(receipt.peer.fd)
      for held in self.held:
        self.assertIsNone(held.payload_fd)
        self.assertIsNotNone(held.process.returncode)
      self.events.append("exclusion-exit")

  def guard(self):
    self.events.append("guard")
    if not self.power: raise ValueError("fixture power exclusion lost")

  def run_owner(self, **kwargs):
    child, stream, expected = self.connect()
    options = dict(sender_identity=expected, runtime_directory=self.runtime, user_environment=self.environment,
      precheck=self.fixture.check, exclusion=self.exclusion, hook_identity=self.hook,
      intermediary_identity={"uid": os.geteuid(), "exe": PYTHON})
    options.update(kwargs)
    receive, launch, gate = C.H.receive_lock, C.L.launch, C.M.check_maintenance
    def capture_receipt(*args, **kw):
      value = receive(*args, **kw)
      self.receipts.append(value)
      return value
    def capture_held(*args, **kw):
      value = launch(*args, **kw)
      self.held.append(value)
      return value
    def held_physical(*args):
      fresh = os.open(self.root / C.M.T.PHYSICAL_LOCK, os.O_RDONLY)
      try:
        with self.assertRaises(BlockingIOError): fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(fresh)
      return gate(*args)
    with patch.object(C.H, "receive_lock", side_effect=capture_receipt), patch.object(C.L, "launch", side_effect=capture_held), patch.object(C.M, "check_maintenance", side_effect=held_physical):
      return C.coordinate(self.root, stream, **options)

  def archive(self):
    intent = json.loads((self.root / C.M.T.MAINTENANCE).read_bytes())
    return self.root / C.M.T.HISTORY / intent["transition_id"]

  def wait_started(self, phase):
    deadline = time.monotonic() + 4
    while not (self.results / phase).exists():
      if time.monotonic() > deadline: raise TimeoutError("fixture phase startup")
      time.sleep(.005)

  def test_complete_real_client_handoff_fixed_phases_hooks_and_durable_records(self):
    original = (self.root / C.M.T.P.RECEIPT).read_bytes()
    result = self.run_owner()
    self.assertEqual(set(path.name for path in self.results.iterdir()), set(C.M.PHASES))
    self.assertEqual(result["maintenance"]["hibernation"], "maintenance-disabled")
    self.assertFalse(result["maintenance"]["reactivation_evaluated"])
    archive = self.archive()
    self.assertEqual(len(list(archive.glob("package-phase-*-result.json"))), len(C.M.PHASES))
    self.assertEqual(json.loads((archive / "package-phase-01-snapshot-result.json").read_bytes())["returncode"], 127)
    self.assertEqual((self.root / C.M.T.P.RECEIPT).read_bytes(), original)
    self.assertTrue((self.root / C.M.T.MAINTENANCE).exists())
    self.assertFalse((self.root / C.M.T.DB_LOCK).exists())
    self.assertFalse((self.root / C.HOOK_SOCKET).exists())
    self.assertEqual(self.events[0], "exclusion-enter")
    self.assertEqual(self.events[-1], "exclusion-exit")
    self.assertEqual(len(self.held), len(C.M.PHASES))
    with self.assertRaises(ValueError): self.run_owner()

  def test_actual_phase_failure_stops_following_phases_keeps_veto(self):
    self.plan.write_text(json.dumps({"statuses": {"keyring": 9}, "hold_db": True}))
    with self.assertRaises(RuntimeError): self.run_owner()
    self.assertEqual(set(path.name for path in self.results.iterdir()), set(C.M.PHASES[:4]))
    record = json.loads((self.archive() / "package-phase-03-keyring-result.json").read_bytes())
    self.assertEqual(record["returncode"], 9)
    self.assertTrue((self.archive() / "package-maintenance-failure.json").exists())
    self.assertFalse((self.archive() / "package-maintenance-complete.json").exists())
    self.assertTrue((self.root / C.M.T.MAINTENANCE).exists())

  def test_client_death_cancels_no_hook_phase_and_preserves_veto(self):
    self.plan.write_text(json.dumps({"sleep_phase": "pkg-prune", "sleep_seconds": 5}))
    def die():
      self.wait_started("pkg-prune")
      self.clients[0].terminate()
    thread = threading.Thread(target=die)
    thread.start()
    try:
      with self.assertRaises(ValueError): self.run_owner()
    finally: thread.join(timeout=5)
    self.assertFalse(thread.is_alive())
    self.assertEqual(len(self.held), 1)
    self.assertTrue((self.root / C.M.T.MAINTENANCE).exists())
    self.assertFalse((self.archive() / "package-maintenance-complete.json").exists())

  def test_power_guard_loss_during_no_hook_phase_stops_owner_inside_scope(self):
    self.plan.write_text(json.dumps({"sleep_phase": "pkg-prune", "sleep_seconds": 5}))
    def lose():
      self.wait_started("pkg-prune")
      self.power = False
    thread = threading.Thread(target=lose)
    thread.start()
    try:
      with self.assertRaisesRegex(ValueError, "power exclusion lost"): self.run_owner()
    finally: thread.join(timeout=5)
    self.assertFalse(thread.is_alive())
    self.assertTrue((self.archive() / "package-maintenance-failure.json").exists())
    self.assertEqual(self.events[-1], "exclusion-exit")

  def test_last_phase_client_loss_before_status_acceptance_is_not_complete(self):
    run = C.B.run_phase
    def lose_last(*args, **kwargs):
      code = run(*args, **kwargs)
      if (self.results / "orphan-pkgs").exists():
        self.clients[0].terminate()
        self.clients[0].wait(timeout=2)
      return code
    with patch.object(C.B, "run_phase", side_effect=lose_last), self.assertRaises(ValueError): self.run_owner()
    self.assertTrue((self.archive() / "package-maintenance-failure.json").exists())
    self.assertFalse((self.archive() / "package-maintenance-complete.json").exists())
    failure = json.loads((self.archive() / "package-maintenance-failure.json").read_bytes())
    self.assertEqual(failure["phase"], "orphan-pkgs")
    # A refused post-return gate retains a failure, not the already reaped
    # child's in-memory status. Do not claim every interruption has an exit record.
    self.assertFalse((self.archive() / "package-phase-09-orphan-pkgs-result.json").exists())

  def test_user_context_mismatch_refuses_before_deactivation_or_phase(self):
    before = (self.root / C.M.T.P.LIMINE).read_bytes()
    for env in (dict(self.environment, HOME="/root"), dict(self.environment, XDG_RUNTIME_DIR=str(self.root)), dict(self.environment, BASH_ENV="evil")):
      with self.assertRaises(ValueError): self.run_owner(user_environment=env)
      self.assertEqual((self.root / C.M.T.P.LIMINE).read_bytes(), before)
      self.assertTrue((self.root / C.M.T.P.POLICY).exists())
      self.assertFalse((self.root / C.M.T.MAINTENANCE).exists())
      self.assertEqual(list(self.results.iterdir()), [])

  def test_environment_snapshot_survives_caller_mutation(self):
    check = self.fixture.check
    def mutate(*args):
      check(*args)
      self.environment["OMARCHY_PATH"] = "/no-such-user-path"
    result = self.run_owner(precheck=mutate)
    self.assertEqual(result["maintenance"]["hibernation"], "maintenance-disabled")
    self.assertEqual(len(self.held), len(C.M.PHASES))

  def test_marker_deletion_hook_failure_rearmed(self):
    gate = C.M.check_maintenance
    deleted = False
    def delete_before_hook(*args):
      nonlocal deleted
      if (self.root / C.M.T.DB_LOCK).exists() and not deleted:
        deleted = True
        (self.root / C.M.T.MAINTENANCE).unlink()
      return gate(*args)
    with patch.object(C.M, "check_maintenance", side_effect=delete_before_hook), self.assertRaises((ValueError, OSError)): self.run_owner()
    self.assertTrue(deleted)
    self.assertEqual((self.root / C.M.T.MAINTENANCE).read_bytes(), (self.archive() / "maintenance-intent.json").read_bytes())

  def test_foreign_hook_socket_never_deleted(self):
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = self.root / C.HOOK_SOCKET
    foreign.bind(str(path))
    self.addCleanup(foreign.close)
    inode = path.lstat().st_ino
    with self.assertRaises(OSError): self.run_owner()
    self.assertEqual(path.lstat().st_ino, inode)
    self.assertTrue((self.root / C.M.T.MAINTENANCE).exists())
    self.assertEqual(list(self.results.iterdir()), [])

  def test_live_alias_relative_refuse_before_exclusion_handoff_or_callback(self):
    alias = self.root / "live-alias"
    alias.symlink_to("/")
    for root in ("/", "/tmp/..", "relative", alias):
      with patch.object(C.H, "receive_lock", side_effect=AssertionError("no handshake")), self.assertRaises(ValueError):
        C.coordinate(root, None, sender_identity={}, runtime_directory=self.runtime, user_environment={},
          precheck=lambda *args: self.fail("precheck"), exclusion=lambda: self.fail("exclusion"), hook_identity={}, intermediary_identity={})

  def test_external_omarchy_runtime_and_command_links_refuse_before_transition(self):
    before = (self.root / C.M.T.P.LIMINE).read_bytes()
    with tempfile.TemporaryDirectory() as outside:
      outside = Path(outside)
      for options in ({"user_environment": dict(self.environment, OMARCHY_PATH=str(outside))},
                      {"runtime_directory": outside}, {"intermediary_identity": {"uid": True, "exe": PYTHON}}):
        with self.assertRaises(ValueError): self.run_owner(**options)
        self.assertEqual((self.root / C.M.T.P.LIMINE).read_bytes(), before)
        self.assertFalse((self.root / C.M.T.MAINTENANCE).exists())
        self.assertEqual(list(self.results.iterdir()), [])
      command = self.omarchy / "bin" / "omarchy-snapshot"
      command.unlink()
      command.symlink_to(outside / "host-update")
      with self.assertRaises(ValueError): self.run_owner()
      self.assertEqual((self.root / C.M.T.P.LIMINE).read_bytes(), before)
      self.assertFalse((self.root / C.M.T.MAINTENANCE).exists())


if __name__ == "__main__": unittest.main()
