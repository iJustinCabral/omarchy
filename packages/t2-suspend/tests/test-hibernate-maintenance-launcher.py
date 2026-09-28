"""Unprivileged fixed-name stubs only; never executes actual update commands."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
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
L = load("tested_maintenance_launcher", HERE / "hibernate/maintenance_launcher.py")
B = load("launcher_broker_fixture", HERE / "hibernate/maintenance_broker.py")
M = load("launcher_maintenance_phases", HERE / "hibernate/package_maintenance.py")
PROBE = '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
fds={}
for fd in os.listdir('/proc/self/fd'):
  try: fds[fd]=os.readlink('/proc/self/fd/'+fd)
  except FileNotFoundError: pass
value={'argv':sys.argv,'environment':dict(os.environ),'uids':os.getresuid(),'gids':os.getresgid(),'groups':os.getgroups(),'fds':fds}
Path(os.environ['XDG_STATE_HOME'],'result-'+Path(sys.argv[0]).name+'.json').write_text(json.dumps(value))
sys.exit(7 if Path(sys.argv[0]).name=='omarchy-update-mise' else 0)
'''


class Launcher(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Host tests must be unprivileged; credential-drop proof belongs to disposable VM")
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.omarchy = self.root / "omarchy"
    (self.omarchy / "bin").mkdir(parents=True)
    self.runtime = self.root / "runtime"
    self.runtime.mkdir()
    self.results = self.root / "results"
    self.results.mkdir()
    for command, *args in L.PHASES.values():
      script = self.omarchy / "bin" / command
      script.write_text(PROBE)
      script.chmod(0o755)
    account = pwd.getpwuid(os.geteuid())
    self.environment = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name,
                        "SHELL": account.pw_shell, "PATH": str(self.omarchy / "bin") + ":/usr/bin:/bin",
                        "OMARCHY_PATH": str(self.omarchy), "XDG_RUNTIME_DIR": str(self.runtime),
                        "XDG_STATE_HOME": str(self.results), "TERM": "xterm-256color"}
    self.lock = self.runtime / "omarchy-update.lock"
    self.fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    self.addCleanup(os.close, self.fd)
    self.held = []
    self.addCleanup(self.cleanup_phases)

  def cleanup_phases(self):
    for held in self.held: held.abort()

  def launch(self, phase="snapshot", **kwargs):
    options = dict(uid=os.geteuid(), environment=self.environment, update_lock_fd=self.fd)
    options.update(kwargs)
    held = L.launch(phase, **options)
    self.held.append(held)
    return held

  def result(self, phase="snapshot"):
    return json.loads((self.results / ("result-" + L.PHASES[phase][0] + ".json")).read_bytes())

  def assert_lock_held(self):
    fresh = os.open(self.lock, os.O_RDWR)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(fresh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(fresh)

  def test_ready_before_user_code_and_release_after_exact_pin(self):
    held = self.launch()
    self.assertEqual(list(self.results.iterdir()), [])
    self.assertEqual(held.pin.identity()["exe"], str(Path(L.PYTHON).resolve()))
    with L.P.ChildPin(held.process, **held.identity):
      held.release()
      self.assertEqual(held.process.wait(timeout=3), 0)
    result = self.result()
    self.assertEqual(result["argv"][1:], ["create"])
    self.assertEqual(result["uids"], [os.geteuid()] * 3)
    self.assertEqual(result["gids"], [os.getegid()] * 3)
    self.assertEqual(sorted(result["groups"]), sorted(os.getgroups()))
    self.assertEqual(result["environment"]["OMARCHY_PATH"], self.environment["OMARCHY_PATH"])
    self.assert_lock_held()
    with self.assertRaises(ValueError): held.release()

  def test_only_stdio_and_same_lock_ofd_survive_exec(self):
    extra = os.open(self.root / "sentinel", os.O_CREAT | os.O_RDWR, 0o600)
    os.set_inheritable(extra, True)
    self.addCleanup(os.close, extra)
    before = os.get_inheritable(self.fd)
    held = self.launch()
    held.release()
    held.process.wait(timeout=3)
    result = self.result()
    self.assertEqual(set(result["fds"]), {"0", "1", "2", str(self.fd)})
    self.assertEqual(result["fds"][str(self.fd)], str(self.lock))
    self.assertEqual(result["environment"]["OMARCHY_UPDATE_LOCK_FD"], str(self.fd))
    self.assertEqual(os.get_inheritable(self.fd), before)
    self.assert_lock_held()

  def test_parent_python_shell_loader_environment_not_seen_before_readiness(self):
    marker = self.root / "premature"
    evil = self.root / "evil"
    evil.mkdir()
    (evil / "sitecustomize.py").write_text("from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('executed')")
    shell = self.root / "bash-env"
    shell.write_text("touch " + str(marker))
    with patch.dict(os.environ, {"PYTHONPATH": str(evil), "PYTHONSTARTUP": str(shell), "BASH_ENV": str(shell), "ENV": str(shell), "LD_PRELOAD": str(shell)}):
      held = self.launch()
    self.assertFalse(marker.exists())
    self.assertEqual(list(self.results.iterdir()), [])
    initial = Path("/proc", str(held.process.pid), "environ").read_bytes()
    self.assertEqual(set(initial.split(b"\0")[:-1]), {b"PATH=/usr/bin:/bin", b"LANG=C", b"LC_ALL=C"})
    held.release()
    self.assertEqual(held.process.wait(timeout=3), 0)
    self.assertFalse(marker.exists())

  def test_user_environment_private_not_in_bootstrap_argv_and_not_evaluated(self):
    text = "$(touch should-not-exist); quoted ' value"
    env = dict(self.environment, TERM=text)
    held = self.launch(environment=env)
    self.assertNotIn(text, " ".join(held.identity["argv"]))
    self.assertNotIn(self.environment["HOME"], " ".join(held.identity["argv"]))
    held.release()
    held.process.wait(timeout=3)
    self.assertEqual(self.result()["environment"]["TERM"], text)

  def test_phase_map_matches_dispatcher_and_actual_arguments(self):
    self.assertEqual(tuple(L.PHASES), M.PHASES)
    for phase in L.PHASES:
      held = self.launch(phase)
      held.release()
      self.assertEqual(held.process.wait(timeout=3), 7 if phase == "mise" else 0)
      self.assertEqual(self.result(phase)["argv"], [str(self.omarchy / "bin" / L.PHASES[phase][0]), *L.PHASES[phase][1:]])

  def test_omarchy_dev_symlink_environment_preserved_command_canonicalized(self):
    alias = self.root / "dev-link"
    alias.symlink_to(self.omarchy)
    held = self.launch(environment=dict(self.environment, OMARCHY_PATH=str(alias)))
    held.release()
    held.process.wait(timeout=3)
    self.assertEqual(self.result()["environment"]["OMARCHY_PATH"], str(alias))
    self.assertEqual(self.result()["argv"][0], str(self.omarchy / "bin" / "omarchy-snapshot"))

  def test_invalid_context_phase_payload_and_unheld_lock_refuse_before_popen(self):
    cases = [{"uid": 0}, {"uid": True}, {"environment": dict(self.environment, HOME="/root")},
             {"environment": dict(self.environment, BASH_ENV="evil")}, {"environment": dict(self.environment, ENV="evil")},
             {"environment": dict(self.environment, LD_PRELOAD="evil")}, {"environment": dict(self.environment, PATH=":/usr/bin")},
             {"environment": {key: value for key, value in self.environment.items() if key != "OMARCHY_PATH"}},
             {"environment": dict(self.environment, TERM="x" * L.MAX_PAYLOAD)}, {"update_lock_fd": 1}, {"timeout": True}]
    with patch.object(L.subprocess, "Popen", side_effect=AssertionError("must not launch")):
      for options in cases:
        with self.assertRaises(ValueError): self.launch(**options)
      with self.assertRaises(ValueError): self.launch("arbitrary-command")
      fcntl.flock(self.fd, fcntl.LOCK_UN)
      with self.assertRaisesRegex(ValueError, "not already held"): self.launch()
    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

  def test_foreign_lock_descriptor_and_hardlink_refuse_preserving_lock(self):
    fresh = os.open(self.lock, os.O_RDWR)
    try:
      with self.assertRaisesRegex(ValueError, "does not own"): self.launch(update_lock_fd=fresh)
    finally: os.close(fresh)
    self.assert_lock_held()
    os.link(self.lock, self.runtime / "hardlink")
    with self.assertRaises(ValueError): self.launch()
    self.assert_lock_held()

  def test_abort_held_phase_never_executes_and_owner_single_use(self):
    held = self.launch()
    held.abort()
    self.assertIsNotNone(held.process.returncode)
    self.assertEqual(list(self.results.iterdir()), [])
    with self.assertRaises(ValueError): held.release()
    held.abort()
    self.assert_lock_held()

  def test_child_death_before_release_refuses_no_user_code(self):
    held = self.launch()
    held.process.terminate()
    held.process.wait(timeout=3)
    with self.assertRaises(ValueError): held.release()
    self.assertEqual(list(self.results.iterdir()), [])

  def test_root_credentials_kwargs_derived_without_executing_root_popen(self):
    with patch.object(L.os, "geteuid", return_value=0), patch.object(L, "_native"):
      directory, credentials = L._context(os.getuid(), self.environment)
    account = pwd.getpwuid(os.getuid())
    self.assertEqual(credentials, {"user": os.getuid(), "group": account.pw_gid,
      "extra_groups": sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))})
    self.assertEqual(directory, self.omarchy)
    with self.assertRaises(ValueError): L._native()

  def test_popen_uses_isolated_bootstrap_inherited_stdio_no_preexec_or_session_change(self):
    original = L.subprocess.Popen.__init__
    calls = []
    def checked(process, *args, **kwargs):
      calls.append((args, kwargs))
      return original(process, *args, **kwargs)
    with patch.object(L.subprocess.Popen, "__init__", new=checked): held = self.launch()
    args, kwargs = calls[0]
    self.assertEqual(args[0][:4], [L.PYTHON, "-I", "-B", "-c"])
    self.assertEqual(kwargs["env"], L.BOOTSTRAP_ENV)
    self.assertTrue(kwargs["close_fds"])
    self.assertEqual(len(kwargs["pass_fds"]), 3)
    self.assertIn(self.fd, kwargs["pass_fds"])
    self.assertFalse(set(kwargs) & {"preexec_fn", "stdin", "stdout", "stderr", "start_new_session", "process_group"})
    held.abort()

  def test_pipe_allocation_and_child_readiness_failure_close_descriptors(self):
    before = len(os.listdir("/proc/self/fd"))
    original = L.os.pipe2
    calls = []
    def fail_second(flags):
      calls.append(flags)
      if len(calls) == 2: raise OSError("fixture allocation")
      return original(flags)
    with patch.object(L.os, "pipe2", side_effect=fail_second), self.assertRaises(OSError): self.launch()
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    with patch.object(L, "BOOTSTRAP", "import sys;sys.exit(125)"), self.assertRaises(ValueError): self.launch()
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)

  def test_release_io_failure_aborts_without_exec_and_fd_leak(self):
    held = self.launch()
    with patch.object(L.os, "write", side_effect=OSError("fixture release")), self.assertRaises(OSError): held.release()
    held.abort()
    self.assertEqual(list(self.results.iterdir()), [])
    self.assertFalse(held.released)

  def test_broker_exact_bootstrap_pin_before_release_and_real_hook_ancestry(self):
    endpoint = self.root / "owner.sock"
    owner = {"uid": os.geteuid(), "exe": L.P._identity(os.getpid())["exe"], "argv": list(L.P._identity(os.getpid())["argv"])}
    hook = self.root / "hook.py"
    hook.write_text("#!/usr/bin/python3\nimport importlib.util\ns=importlib.util.spec_from_file_location('b'," + repr(str(HERE / "hibernate/maintenance_broker.py")) + ");b=importlib.util.module_from_spec(s);s.loader.exec_module(b)\nb.request(" + repr(str(self.root)) + "," + repr(str(endpoint)) + ",owner_identity=" + repr(owner) + ")\n")
    command = self.omarchy / "bin" / "omarchy-snapshot"
    command.write_text("#!/usr/bin/python3\nimport subprocess,sys\nchild=subprocess.Popen(['/usr/bin/python3'," + repr(str(hook)) + "]);sys.exit(child.wait())\n")
    held = self.launch()
    self.assertEqual(list(self.results.iterdir()), [])
    gates = []
    code = B.run_phase(self.root, endpoint, launch=lambda _: held.process, phase_identity=held.identity,
      release=held.release, owner_identity=owner, hook_identity={"uid": os.geteuid(), "exe": str(Path(L.PYTHON).resolve()), "argv": ["/usr/bin/python3", str(hook)]},
      intermediary_identity={"uid": os.geteuid(), "exe": str(Path(L.PYTHON).resolve())}, gate=lambda: gates.append("grant"))
    self.assertEqual(code, 0)
    self.assertEqual(gates, ["grant"])
    self.assertTrue(held.released)

  def test_bad_broker_bootstrap_identity_never_releases_or_executes(self):
    held = self.launch()
    actual = L.P._identity(os.getpid())
    with self.assertRaises(ValueError):
      B.run_phase(self.root, self.root / "owner.sock", launch=lambda _: held.process, phase_identity=dict(held.identity, argv=["wrong"]),
        release=held.release, owner_identity={"uid": os.geteuid(), "exe": actual["exe"], "argv": list(actual["argv"])},
        hook_identity={"uid": os.geteuid(), "exe": actual["exe"], "argv": ["unused"]},
        intermediary_identity={"uid": os.geteuid(), "exe": actual["exe"]}, gate=lambda: self.fail("gate"))
    self.assertFalse(held.released)
    self.assertEqual(list(self.results.iterdir()), [])


if __name__ == "__main__": unittest.main()
