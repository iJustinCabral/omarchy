"""Offline bootstrap/topology plus real unprivileged peer/pidfd fixtures only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  value = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(value)
  return value


HERE = Path(__file__).parents[1]
N = load("tested_maintenance_native", HERE / "hibernate/maintenance_native.py")
P = load("native_test_peer", HERE / "hibernate/maintenance_peer.py")


def rows(count=1):
  uid = os.getuid()
  python = str(N.PYTHON.resolve())
  value = [dict(pid=101, ppid=102, starttime=10, uids=(0,) * 4, exe=python, argv=N._owner_command()),
           dict(pid=102, ppid=103, starttime=11, uids=(0,) * 4, exe="/usr/bin/systemd-inhibit", argv=N._inhibit_command())]
  for offset in range(count):
    value.append(dict(pid=103 + offset, ppid=104 + offset, starttime=12 + offset,
      uids=(uid, 0, 0, 0), exe="/usr/bin/sudo", argv=N._sudo_command()))
  value.append(dict(pid=103 + count, ppid=1, starttime=14, uids=(uid,) * 4, exe=python,
    argv=(str(N.PYTHON), "-I", "-B", str(N.CLIENT), "run")))
  return value


class Native(unittest.TestCase):
  def test_workspace_nonroot_nonisolated_refuse_before_import_or_host_query(self):
    with patch.object(N, "_load", side_effect=AssertionError("no imports")), patch.object(N, "_private", side_effect=AssertionError("no private reads")):
      with self.assertRaises(ValueError): N.native()

  def test_fixed_cli_rejects_every_action_root_force_and_environment_option(self):
    with patch.object(N, "native") as native:
      for argv in (["run"], ["proof"], ["--root", "/tmp"], ["--force"], ["-y"], ["--user", "1000"]):
        with self.assertRaises(SystemExit): N.main(argv)
      native.assert_not_called()

  def test_review_requires_explicit_true_commit_and_no_duplicate_fields(self):
    value = {"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True, "reviewed_commit": "a" * 40, "files": {}}
    self.assertEqual(N._review(json.dumps(value)), value)
    for changed in ({"approved": 1}, {"approved": False}, {"reviewed_commit": "draft"}, {"files": []}):
      with self.assertRaises(ValueError): N._review(json.dumps(dict(value, **changed)))
    with self.assertRaises(ValueError): N._review('{"approved":true,"approved":true}')

  def installed_fixture(self):
    raw = {N.SCRIPT: b"reviewed owner", N.SCRIPT.with_name("runtime_deployment.py"): b"reviewed bootstrap"}
    review = {"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True, "reviewed_commit": "a" * 40,
      "files": {path.relative_to(N.RUNTIME).as_posix(): {"size": len(value), "sha256": hashlib.sha256(value).hexdigest()} for path, value in raw.items()}}
    raw[N.STATE / "runtime-deployment-review.json"] = json.dumps(review).encode()
    events = []
    def read(path):
      events.append(("read", path.name))
      return raw[path]
    def metadata(path):
      directory = path != N.SCRIPT
      return SimpleNamespace(st_uid=0, st_mode=(stat.S_IFDIR | (0o700 if path in (N.STATE, N.RUNTIME) else 0o755)) if directory else stat.S_IFREG | 0o600, st_nlink=1)
    power = SimpleNamespace(WHO="omarchy-t2-source-default", WHY="reviewed-boot-policy-transition", SCRIPT="untouched")
    def imports(name, path):
      events.append(("import", path.name))
      if path.name == "runtime_deployment.py": return SimpleNamespace(_verify_tree=lambda *args: events.append(("verify", "whole-tree")))
      if path.name == "boot_policy_native.py": return power
      return object()
    return raw, events, read, metadata, imports, power

  def gate_patches(self, read, metadata, imports):
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch.object(N.os, "getresuid", return_value=(0,) * 3))
    stack.enter_context(patch.object(N.sys, "flags", SimpleNamespace(isolated=True)))
    stack.enter_context(patch.object(N, "__file__", str(N.SCRIPT)))
    stack.enter_context(patch.object(Path, "lstat", new=metadata))
    stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
    stack.enter_context(patch.object(Path, "rglob", return_value=[]))
    stack.enter_context(patch.object(N, "_private", side_effect=read))
    stack.enter_context(patch.object(N, "_load", side_effect=imports))
    stack.enter_context(patch.object(N, "_binary", return_value="fixed"))
    return stack

  def test_self_bootstrap_pins_and_whole_inventory_precede_all_other_imports(self):
    raw, events, read, metadata, imports, power = self.installed_fixture()
    with self.gate_patches(read, metadata, imports): result = N._installed()
    first = events.index(("import", "runtime_deployment.py"))
    self.assertIn(("read", "maintenance_native.py"), events[:first])
    self.assertIn(("read", "runtime_deployment.py"), events[:first])
    full = events.index(("verify", "whole-tree"))
    for name in ("maintenance_peer.py", "boot_policy_native.py", "maintenance_handoff.py"):
      self.assertGreater(events.index(("import", name)), full)
    self.assertEqual((power.WHO, power.WHY), (N.WHO, N.WHY))
    self.assertEqual(power.SCRIPT, "untouched")
    self.assertIs(result.power, power)

  def test_self_or_bootstrap_mismatch_refuses_without_any_import(self):
    for path in (N.SCRIPT, N.SCRIPT.with_name("runtime_deployment.py")):
      raw, events, read, metadata, imports, power = self.installed_fixture()
      raw[path] += b" changed"
      with self.gate_patches(read, metadata, imports), self.assertRaises(ValueError): N._installed()
      self.assertFalse(any(kind == "import" for kind, name in events))

  def test_full_inventory_failure_never_imports_peer_power_or_handoff(self):
    raw, events, read, metadata, imports, power = self.installed_fixture()
    def fail(name, path):
      if path.name == "runtime_deployment.py":
        return SimpleNamespace(_verify_tree=Mock(side_effect=ValueError("fixture inventory drift")))
      self.fail("unverified sibling import")
    with self.gate_patches(read, metadata, fail), self.assertRaises(ValueError): N._installed()

  def test_private_power_context_does_not_rebind_other_loaded_adapter_or_script(self):
    original = load("native_original_power", HERE / "hibernate/boot_policy_native.py")
    constants = (original.WHO, original.WHY, original.SCRIPT)
    raw, events, read, metadata, imports, power = self.installed_fixture()
    with self.gate_patches(read, metadata, imports): N._installed()
    self.assertEqual((original.WHO, original.WHY, original.SCRIPT), constants)

  def test_observed_one_and_two_sudo_shapes_accept_without_session_assumptions(self):
    for count in (1, 2):
      value = rows(count)
      for index, row in enumerate(value): row.update(sid=400 + index, tty_nr=500 + index)
      self.assertEqual(N._topology(value, 101).pw_uid, os.getuid())
      value[-1]["argv"] += ("-y",)
      self.assertEqual(N._topology(value, 101).pw_uid, os.getuid())

  def test_malformed_or_foreign_topology_rejects_no_sudo_env_authority(self):
    cases = []
    for index, changed in ((0, {"uids": (os.getuid(),) * 4}), (0, {"argv": ("python", "-c", "fake")}),
                           (1, {"exe": "/wrong"}), (1, {"argv": (*N._inhibit_command(), "extra")}),
                           (2, {"uids": (0,) * 4}), (2, {"uids": (os.getuid(), os.getuid(), 0, 0)}),
                           (2, {"argv": ("sudo", "--", "anything")}), (3, {"uids": (os.getuid(), os.getuid(), 0, os.getuid())}),
                           (3, {"argv": (str(N.PYTHON), "-c", "pretend client")}), (0, {"ppid": 999})):
      value = rows()
      value[index].update(changed)
      cases.append(value)
    cases.extend((rows()[:-1], rows(3), [rows()[0], *rows()]))
    with patch.dict(os.environ, {"SUDO_UID": str(os.getuid()), "SUDO_USER": "trusted", "SUDO_COMMAND": "approved"}):
      for value in cases:
        with self.assertRaises(ValueError): N._topology(value, 101)

  def test_native_entry_stays_disabled_after_successful_origin_proof(self):
    scope = Mock()
    scope.__enter__ = Mock(return_value=scope)
    scope.__exit__ = Mock(return_value=False)
    with patch.object(N, "_installed", return_value="reviewed"), patch.object(N, "Origin", return_value=scope), patch.object(N.os, "execve", side_effect=AssertionError("no phases")):
      with self.assertRaisesRegex(ValueError, "disabled pending"): N.native()
    scope.check.assert_called_once_with()
    scope.__exit__.assert_called_once()

  def test_root_binary_resolution_validates_actual_python_symlink(self):
    self.assertEqual(N._binary(N.PYTHON), str(N.PYTHON.resolve()))
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "fake"
      path.write_bytes(b"not root owned")
      with self.assertRaises(ValueError): N._binary(path)

  def test_binary_link_cannot_hide_intermediate_alias_namespace(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      executable = root / "python3.14"
      executable.write_bytes(b"fixture binary")
      executable.chmod(0o755)
      alias = root / "alias"
      alias.symlink_to(executable.name)
      path = root / "python3"
      path.symlink_to(alias.name)
      original = Path.lstat
      def root_metadata(value):
        info = original(value)
        # Synthetic root-owned namespace, never a privileged fixture write.
        return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
          st_mode=info.st_mode & ~0o022, st_uid=0, st_gid=0, st_nlink=info.st_nlink,
          st_size=info.st_size, st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
      with patch.object(Path, "lstat", new=root_metadata):
        with self.assertRaisesRegex(ValueError, "regular"): N._binary(path)
        path.unlink()
        path.symlink_to(executable.name)
        self.assertEqual(N._binary(path), str(executable))
        path.unlink()
        external = root / "namespace"
        external.mkdir()
        (external / "alias").symlink_to(executable)
        path.symlink_to(external / "alias")
        with self.assertRaisesRegex(ValueError, "single-hop"): N._binary(path)


class ProcessBinding(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.path = self.root / "origin.sock"
    self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.listener.bind(str(self.path))
    self.listener.listen()
    self.listener.settimeout(2)
    self.addCleanup(self.listener.close)
    self.client = self.root / "client.py"
    self.client.write_text("import os,socket\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(" + repr(str(self.path)) + ")\nprint('ready',flush=True)\ns.recv(1)\n")
    self.children = []
    self.addCleanup(self.cleanup)

  def cleanup(self):
    for child in self.children:
      if child.poll() is None:
        child.terminate()
        child.wait(timeout=2)
      for stream in (child.stdin, child.stdout, child.stderr):
        if stream is not None: stream.close()

  def spawn(self, client=False):
    argv = ["/usr/bin/python3", "-I", "-B", str(self.client), "run"] if client else ["/usr/bin/python3", "-c", "import sys;print('ready',flush=True);sys.stdin.readline()"]
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(child)
    self.assertTrue(select.select([child.stdout], [], [], 2)[0])
    self.assertEqual(child.stdout.readline(), b"ready\n")
    return child

  def fixture(self):
    client, inhibitor, sudo = self.spawn(True), self.spawn(), self.spawn()
    # Shape is synthetic; all four endpoints/pidfds below are real unprivileged
    # processes. This tests instance binding, NOT an actual privileged sudo chain.
    identity = P._identity
    client_row = identity(client.pid)
    values = [dict(identity(os.getpid()), uids=(0,) * 4, argv=N._owner_command(), ppid=inhibitor.pid),
              dict(identity(inhibitor.pid), uids=(0,) * 4, exe="/usr/bin/systemd-inhibit", argv=N._inhibit_command(), ppid=sudo.pid),
              dict(identity(sudo.pid), uids=(os.getuid(), 0, 0, 0), exe="/usr/bin/sudo", argv=N._sudo_command(), ppid=client.pid), client_row]
    lookup = {value["pid"]: value for value in values}
    def observe(pid): return dict(lookup[pid]) if pid in lookup else identity(pid)
    power = SimpleNamespace(_power_idle=Mock())
    reviewed = SimpleNamespace(peer=P, handoff=SimpleNamespace(P=P), power=power)
    return reviewed, lookup, observe, client, inhibitor, sudo

  def test_real_kernel_peer_same_instance_matches_origin_foreign_identical_argv_refuses(self):
    with patch.object(N, "CLIENT", self.client):
      reviewed, lookup, observe, client, inhibitor, sudo = self.fixture()
      with patch.object(P, "_identity", side_effect=observe), N.Origin(reviewed) as origin:
        stream, _ = self.listener.accept()
        with stream, P.Peer(stream) as peer:
          self.assertEqual(origin.bind_peer(peer)["pid"], client.pid)
          foreign = self.spawn(True)
          other, _ = self.listener.accept()
          with other, P.Peer(other) as foreign_peer:
            with self.assertRaisesRegex(ValueError, "pinned initiating ancestor"): origin.bind_peer(foreign_peer)
          with self.assertRaises(ValueError): origin.bind_peer(SimpleNamespace())
      before = reviewed.power._power_idle.call_count
      with patch.object(P, "_identity", side_effect=AssertionError("expired query")), self.assertRaisesRegex(ValueError, "expired"): origin.check()
      self.assertEqual(reviewed.power._power_idle.call_count, before)

  def test_reparent_changed_identity_or_dead_ancestor_refuses_and_closes_pins(self):
    with patch.object(N, "CLIENT", self.client):
      reviewed, lookup, observe, client, inhibitor, sudo = self.fixture()
      with patch.object(P, "_identity", side_effect=observe), N.Origin(reviewed) as origin:
        original = lookup[sudo.pid]
        lookup[sudo.pid] = dict(original, ppid=1)
        with self.assertRaises(ValueError): origin.check()
        lookup[sudo.pid] = original
        inhibitor.terminate()
        inhibitor.wait(timeout=2)
        with self.assertRaises(ValueError): origin.check()
      self.assertEqual(origin.pins, [])

  def test_partial_pidfd_failure_leaks_no_descriptors(self):
    with patch.object(N, "CLIENT", self.client):
      reviewed, lookup, observe, client, inhibitor, sudo = self.fixture()
      opening = os.pidfd_open
      before = len(os.listdir("/proc/self/fd"))
      count = []
      def fail(pid):
        count.append(pid)
        if len(count) == 3: raise OSError("fixture pin failure")
        return opening(pid)
      with patch.object(P, "_identity", side_effect=observe), patch.object(N.os, "pidfd_open", side_effect=fail), self.assertRaises(OSError): N.Origin(reviewed)
      self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__": unittest.main()
