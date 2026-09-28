"""Unprivileged real-process/socket/OFD stubs; NEVER executes host sudo/root."""
import fcntl
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import select
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HERE = Path(__file__).parents[1] / "hibernate"
C = load("tested_public_maintenance_client", HERE / "maintenance_client.py")
original_handoff = C._handoff
H = load("public_client_fixture_handoff", HERE / "maintenance_handoff.py")
PYTHON = "/usr/bin/python3"
STUB = r'''import fcntl,importlib.util,json,os,signal,socket,sys,time
from pathlib import Path
config=json.loads(Path(sys.argv[1]).read_text());auth=sys.argv[2]=='auth'
fds={}
for entry in Path('/proc/self/fd').iterdir():
  try: fds[entry.name]=os.readlink(entry)
  except FileNotFoundError: pass
value={'pid':os.getpid(),'ppid':os.getppid(),'fds':fds,'environment':dict(os.environ),
  'stdio':[[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in (0,1,2)]}
if auth:
  Path(config['auth_report']).write_text(json.dumps(value));sys.exit(config['auth_code'])
value['stdin']=sys.stdin.readline();os.write(1,b'STUB_STDOUT\n');os.write(2,b'STUB_STDERR\n')
mode=config['mode']
if mode=='signal': os.kill(os.getpid(),signal.SIGTERM)
if mode=='handoff':
  spec=importlib.util.spec_from_file_location('h',config['handoff']);h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
  listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(config['socket']);listener.listen()
  with listener.accept()[0] as stream:
    with h.receive_lock(stream,sender_identity=config['client'],runtime_directory=config['runtime'],require_environment=True) as receipt:
      value['sender']=receipt.peer.pid;value['context']=receipt.environment
      value['offset_before']=os.lseek(receipt.fd,0,os.SEEK_CUR);os.lseek(receipt.fd,71,os.SEEK_SET)
      value['received_cloexec']=not os.get_inheritable(receipt.fd)
      receipt.check()
elif mode=='reject':
  listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(config['socket']);listener.listen()
fresh=os.open(config['runtime']+'/omarchy-update.lock',os.O_RDWR)
try:
  fcntl.flock(fresh,fcntl.LOCK_EX|fcntl.LOCK_NB);value['original_busy']=False
except BlockingIOError: value['original_busy']=True
os.close(fresh)
time.sleep(config['delay'])
value['survived']=True
Path(config['report']).write_text(json.dumps(value));sys.exit(config['owner_code'])
'''


class PublicClient(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Host tests must be unprivileged; root proof is disposable VM only")
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.runtime = self.root / "runtime"
    self.runtime.mkdir(mode=0o700)
    self.lock_path = self.runtime / "omarchy-update.lock"
    self.fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.lseek(self.fd, 17, os.SEEK_SET)
    self.addCleanup(os.close, self.fd)
    self.socket_path = self.root / "handoff.sock"
    self.report, self.auth_report = self.root / "owner.json", self.root / "auth.json"
    self.config_path = self.root / "config.json"
    self.stub = self.root / "owner.py"
    self.stub.write_text(STUB)
    self.owner_argv = [PYTHON, "-I", "-B", str(self.stub), str(self.config_path), "owner"]
    self.auth_argv = [*self.owner_argv[:-1], "auth"]
    self.config = {"handoff": str(HERE / "maintenance_handoff.py"), "runtime": str(self.runtime),
      "socket": str(self.socket_path), "report": str(self.report), "auth_report": str(self.auth_report),
      "mode": "handoff", "owner_code": 37, "auth_code": 0, "delay": .05,
      "client": {"uid": os.getuid(), "exe": H.P._identity(os.getpid())["exe"], "argv": list(H.P._identity(os.getpid())["argv"])}}
    self.send_calls = []
    account = pwd.getpwuid(os.getuid())
    self.environment = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name,
      "SHELL": account.pw_shell, "PATH": "/usr/bin:/bin", "OMARCHY_PATH": str(self.root),
      "XDG_RUNTIME_DIR": str(self.runtime), "OMARCHY_UPDATE_LOCK_FD": str(self.fd), "TERM": "fixture",
      "BASH_ENV": "/must-not-run", "SUDO_UID": "0", "ASSERTED_PID": "1"}
    for replacement in (
      patch.dict(os.environ, self.environment, clear=True), patch.object(C, "_handoff", return_value=H),
      patch.object(C, "_runtime", return_value=self.runtime), patch.object(C, "_sudo_command", return_value=tuple(self.owner_argv)),
      patch.object(C, "_auth_command", return_value=tuple(self.auth_argv)),
      patch.object(H, "_root_endpoint", self.endpoint), patch.object(H, "send_native_lock", self.send)):
      replacement.start()
      self.addCleanup(replacement.stop)

  def endpoint(self):
    self.socket_path.lstat()  # synthetic readiness only, NEVER native namespace
    return (1, 2, 0, 0o666)

  def send(self, fd, *, timeout, environment):
    self.send_calls.append((fd, dict(environment)))
    if self.config["mode"] == "reject": raise ValueError("synthetic authenticated refusal")
    with __import__("socket").socket(__import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM) as stream:
      stream.connect(str(self.socket_path))
      return H.send_lock(stream, fd, receiver_identity={"uid": os.getuid(), "exe": str(Path(PYTHON).resolve()),
        "argv": self.owner_argv}, runtime_directory=self.runtime, timeout=timeout, environment=environment)

  def busy(self):
    fresh = os.open(self.lock_path, os.O_RDWR | os.O_CLOEXEC)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(fresh)

  def exercise(self, *, unattended=True):
    self.config_path.write_text(json.dumps(self.config))
    pipes = [os.pipe2(os.O_CLOEXEC) for _ in range(3)]
    saved = [os.dup(fd) for fd in (0, 1, 2)]
    extra = os.open(self.root / "extra", os.O_RDWR | os.O_CREAT, 0o600)
    os.set_inheritable(extra, True)
    os.set_inheritable(self.fd, True)
    stdio = [[os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd in (pipes[0][0], pipes[1][1], pipes[2][1])]
    try:
      os.write(pipes[0][1], b"fixture stdin\n")
      for target, source in enumerate((pipes[0][0], pipes[1][1], pipes[2][1])): os.dup2(source, target)
      started = time.monotonic()
      result = C.run(unattended=unattended)
      elapsed = time.monotonic() - started
    finally:
      for target, fd in enumerate(saved): os.dup2(fd, target)
    try:
      stdout = os.read(pipes[1][0], 4096) if select.select([pipes[1][0]], [], [], .05)[0] else b""
      stderr = os.read(pipes[2][0], 4096) if select.select([pipes[2][0]], [], [], .05)[0] else b""
      self.busy()
      self.assertFalse(os.get_inheritable(self.fd))
      return result, stdio, stdout, stderr, elapsed
    finally:
      for fd in (*saved, extra, *(fd for pair in pipes for fd in pair)): os.close(fd)

  def test_real_same_client_v2_ofd_stdio_and_actual_nonzero_status(self):
    result, stdio, stdout, stderr, _ = self.exercise()
    self.assertEqual(result, 37)
    value = json.loads(self.report.read_text())
    self.assertEqual(value["ppid"], os.getpid())
    self.assertEqual(value["sender"], os.getpid())
    self.assertEqual(value["stdio"], stdio)
    self.assertEqual(value["stdin"], "fixture stdin\n")
    self.assertEqual(set(value["fds"]), {"0", "1", "2"})
    self.assertEqual(value["environment"], C.ENV)
    self.assertTrue(value["original_busy"] and value["received_cloexec"] and value["survived"])
    self.assertEqual(value["offset_before"], 17)
    self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 71)
    self.assertEqual(value["context"]["OMARCHY_UPDATE_UNATTENDED"], "1")
    self.assertNotIn("BASH_ENV", value["context"])
    self.assertNotIn("SUDO_UID", value["context"])
    self.assertNotIn("OMARCHY_UPDATE_LOCK_FD", value["context"])
    self.assertEqual(stdout, b"STUB_STDOUT\n")
    self.assertEqual(stderr, b"STUB_STDERR\n")
    self.assertFalse(self.auth_report.exists())

  def test_interactive_pre_auth_exact_owned_child_and_no_lock_leak(self):
    result, stdio, _, _, _ = self.exercise(unattended=False)
    self.assertEqual(result, 37)
    auth = json.loads(self.auth_report.read_text())
    self.assertEqual(auth["stdio"], stdio)
    self.assertEqual(set(auth["fds"]), {"0", "1", "2"})
    self.assertEqual(auth["environment"], C.ENV)
    self.assertNotIn("OMARCHY_UPDATE_UNATTENDED", self.send_calls[0][1])

  def test_auth_failure_never_starts_owner_or_socket(self):
    self.config["auth_code"] = 5
    result, _, _, _, _ = self.exercise(unattended=False)
    self.assertEqual(result, 5)
    self.assertFalse(self.report.exists() or self.socket_path.exists())
    self.assertEqual(self.send_calls, [])

  def test_handoff_refusal_keeps_original_until_exact_child_terminal(self):
    self.config.update(mode="reject", owner_code=9, delay=.12)
    result, _, _, stderr, elapsed = self.exercise()
    self.assertEqual(result, 9)
    self.assertGreaterEqual(elapsed, .12)
    self.assertTrue(json.loads(self.report.read_text())["survived"])
    self.assertIn(b"actual owner status=9", stderr)

  def test_owner_zero_without_handoff_is_refusal_125(self):
    self.config.update(mode="reject", owner_code=0)
    result, _, _, stderr, _ = self.exercise()
    self.assertEqual(result, 125)
    self.assertIn(b"actual owner status=0", stderr)

  def test_absent_endpoint_with_early_disabled_owner_preserves_status(self):
    self.config.update(mode="absent", owner_code=65, delay=0)
    result, _, _, stderr, elapsed = self.exercise()
    self.assertEqual(result, 65)
    self.assertLess(elapsed, 1)
    self.assertEqual(self.send_calls, [])
    self.assertIn(b"actual owner status=65", stderr)

  def test_endpoint_deadline_still_waits_and_never_kills_owner(self):
    self.config.update(mode="absent", owner_code=9, delay=.12)
    with patch.object(C, "ENDPOINT_TIMEOUT", .02): result, _, _, stderr, elapsed = self.exercise()
    self.assertEqual(result, 9)
    self.assertGreaterEqual(elapsed, .12)
    self.assertTrue(json.loads(self.report.read_text())["survived"])
    self.assertIn(b"readiness expired", stderr)

  def test_actual_signal_status_and_cli_conventional_mapping(self):
    self.config.update(mode="signal")
    result, _, _, stderr, _ = self.exercise()
    self.assertEqual(result, -signal.SIGTERM)
    with patch.object(C, "run", return_value=result): self.assertEqual(C.main(["run", "-y"]), 143)

  def test_bad_or_unheld_descriptor_refuses_before_sudo(self):
    with patch.object(C, "_spawn", side_effect=AssertionError("no process allowed")):
      for raw in ("", "0", "2", "03", "+3", "-3", "3;bad", "x", "9999999999", "2147483648", "10000000000"):
        with patch.dict(os.environ, OMARCHY_UPDATE_LOCK_FD=raw), self.assertRaises(ValueError): C.run(unattended=True)
      foreign = os.open(self.lock_path, os.O_RDWR | os.O_CLOEXEC)
      try:
        with patch.dict(os.environ, OMARCHY_UPDATE_LOCK_FD=str(foreign)), self.assertRaises(ValueError): C.run(unattended=True)
      finally: os.close(foreign)
    self.busy()

  def test_allowlisted_context_is_snapshot_and_actual_account_bound(self):
    value = C.capture_environment(H, unattended=True)
    self.assertEqual(value["XDG_RUNTIME_DIR"], str(self.runtime))
    with patch.dict(os.environ, HOME="/root", USER="root", OMARCHY_UPDATE_UNATTENDED="wrong"):
      normal = C.capture_environment(H)
    self.assertEqual(normal["HOME"], pwd.getpwuid(os.getuid()).pw_dir)
    self.assertEqual(normal["USER"], pwd.getpwuid(os.getuid()).pw_name)
    self.assertNotIn("OMARCHY_UPDATE_UNATTENDED", normal)
    with patch.dict(os.environ, TERM="changed"): self.assertEqual(value["TERM"], "fixture")

  def test_source_gate_before_public_import_or_private_runtime_access(self):
    with self.assertRaises(ValueError): C._installed()
    with patch.object(C, "_installed", side_effect=ValueError("unreviewed")), patch.object(C.importlib.util, "spec_from_file_location", side_effect=AssertionError("must not import")):
      with self.assertRaises(ValueError): original_handoff()

  def test_public_cache_and_extras_refuse_before_any_dependency_import(self):
    public = self.root / "public"
    public.mkdir()
    for name in C.DEPENDENCIES: (public / name).write_text("# fixture")
    for name in ("__pycache__", "unexpected.py"):
      extra = public / name
      extra.mkdir()
      with patch.object(C, "LIBRARY", public), patch.object(C, "_installed", C._inventory), patch.object(C.importlib.util, "spec_from_file_location", side_effect=AssertionError("no import allowed")):
        with self.assertRaises(ValueError): original_handoff()
      extra.rmdir()
    with patch.object(C, "LIBRARY", public): C._inventory()

  def test_fixed_commands_match_native_chain_without_execution(self):
    command = load("client_native_shape_fixture", HERE / "maintenance_native.py")._sudo_command()
    with patch.object(C, "_sudo_command", load("original_client_shape", HERE / "maintenance_client.py")._sudo_command):
      self.assertEqual(C._sudo_command(), command)
    self.assertEqual(load("original_client_auth_shape", HERE / "maintenance_client.py")._auth_command(), ("/usr/bin/sudo", "-v"))

  def test_cooperative_interrupt_records_and_restores_handler(self):
    previous = signal.getsignal(signal.SIGINT)
    with C._interruptions() as pending:
      os.kill(os.getpid(), signal.SIGINT)
      self.assertEqual(pending, [signal.SIGINT])
      self.busy()
    self.assertIs(signal.getsignal(signal.SIGINT), previous)

  def test_cli_exact_order_and_no_pid_environment_authority_arguments(self):
    with patch.object(C, "run", side_effect=AssertionError("must not start")), contextlib.redirect_stderr(io.StringIO()):
      for argv in ([], ["-y", "run"], ["run", "-y", "-y"], ["run", "--pid", "1"], ["run", "extra"]):
        with self.assertRaises(SystemExit) as error: C.main(argv)
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__": unittest.main()
