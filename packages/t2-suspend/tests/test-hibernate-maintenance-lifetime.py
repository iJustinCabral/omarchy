"""Real copied unprivileged executable/pidfd fixtures; no native/package action."""
import errno
import importlib.util
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("tested_lifetime", Path(__file__).parents[1] / "hibernate/maintenance_lifetime.py")
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
CODE = '''import os,sys,time
print('ready',flush=True)
action=sys.stdin.readline().strip()
if action=='same': os.execv(sys.executable,sys.orig_argv)
if action.startswith('other '): os.execv(action[6:],sys.orig_argv)
if action=='argv': os.execv(sys.executable,[*sys.orig_argv,'changed'])
while True: time.sleep(1)
'''


class Lifetimes(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Unprivileged local process fixtures only")
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.binary = self.copy("python-fixture")
    self.children, self.descriptors = [], []
    self.addCleanup(self.cleanup)

  def copy(self, name):
    path = self.root / name
    shutil.copyfile(Path(sys.executable).resolve(), path)
    path.chmod(0o755)
    return path

  def cleanup(self):
    for child in self.children:
      if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired:
          child.kill()
          child.wait(timeout=2)
      for stream in (child.stdin, child.stdout, child.stderr):
        if stream is not None: stream.close()
    for fd in self.descriptors: os.close(fd)

  def line(self, child):
    self.assertTrue(select.select([child.stdout], [], [], 2)[0], "bounded fixture readiness")
    self.assertEqual(child.stdout.readline(), b"ready\n")

  def spawn(self):
    argv = [str(self.binary), "-I", "-B", "-u", "-c", CODE]
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(child)
    self.line(child)
    return child

  def pin(self, child):
    # Caller owns this live direct Popen and the sole reaper; no poll/wait
    # occurred before capturing the actual kernel pin and startup observation.
    fd = os.pidfd_open(child.pid)
    self.descriptors.append(fd)
    identity = L.P._identity(child.pid)
    retained = L.Lifetime(fd, expected_identity=identity)
    self.addCleanup(retained.close)
    return retained, fd, identity

  def action(self, child, value):
    child.stdin.write(value.encode() + b"\n")
    child.stdin.flush()
    self.line(child)

  def test_real_pin_cloexec_expiry_and_original_descriptor_ownership(self):
    child = self.spawn()
    retained, original, identity = self.pin(child)
    self.assertEqual(retained.check(), identity)
    self.assertFalse(os.get_inheritable(retained.pidfd))
    self.assertFalse(os.get_inheritable(retained.executable_fd))
    self.assertNotEqual(retained.pidfd, original)
    retained.close()
    L.P._alive(original)
    with patch.object(L.P, "_identity", side_effect=AssertionError("expired scope cannot query")), patch.object(L.P, "_alive", side_effect=AssertionError("expired scope cannot query")):
      with self.assertRaisesRegex(ValueError, "expired"): retained.check()
    self.assertIsNone(retained.pidfd)
    self.assertIsNone(retained.executable_fd)

  def test_unlinked_original_executable_retains_inode_and_truthful_deleted_link(self):
    retained, _, identity = self.pin(self.spawn())
    self.binary.unlink()
    observed = retained.check()
    self.assertEqual(observed["exe"], identity["exe"] + " (deleted)")
    self.assertEqual(os.fstat(retained.executable_fd).st_nlink, 0)
    self.assertEqual(L._core(observed), L._core(identity))

  def test_path_replacement_does_not_admit_replacement_inode_as_running_code(self):
    retained, _, identity = self.pin(self.spawn())
    replacement = self.copy("replacement")
    replacement.replace(self.binary)
    self.assertNotEqual(os.stat(self.binary).st_ino, os.fstat(retained.executable_fd).st_ino)
    self.assertEqual(retained.check()["exe"], identity["exe"] + " (deleted)")

  def test_rename_only_keeps_same_inode_without_normalizing_path_text(self):
    retained, _, _ = self.pin(self.spawn())
    target = self.root / "renamed-running-python"
    self.binary.rename(target)
    self.assertEqual(retained.check()["exe"], str(target))

  def test_same_inode_reexec_is_explicitly_not_detectable_by_this_primitive(self):
    child = self.spawn()
    retained, _, identity = self.pin(child)
    self.action(child, "same")
    # A real exec occurred, but pid/start/argv/UID/parent/exe inode are identical.
    # Acceptance is a documented LIMITATION, not a no-exec safety proof.
    self.assertEqual(retained.check(), identity)

  def test_different_executable_exec_refuses_even_with_same_argv_start_uid(self):
    child = self.spawn()
    retained, _, identity = self.pin(child)
    self.action(child, "other " + str(self.copy("different-python-inode")))
    self.assertEqual(L._core(L.P._identity(child.pid)), L._core(identity))
    with self.assertRaisesRegex(ValueError, "inode/metadata"): retained.check()

  def test_same_executable_changed_arguments_refuse(self):
    child = self.spawn()
    retained, _, _ = self.pin(child)
    self.action(child, "argv")
    with self.assertRaisesRegex(ValueError, "changed/reparented"): retained.check()

  def test_process_death_refuses_with_executable_fd_still_open(self):
    child = self.spawn()
    retained, _, _ = self.pin(child)
    child.terminate()
    child.wait(timeout=2)
    self.assertGreater(os.fstat(retained.executable_fd).st_size, 0)
    with self.assertRaises(ValueError): retained.check()

  def test_stable_file_metadata_changes_refuse_and_linux_text_write_is_busy(self):
    retained, _, _ = self.pin(self.spawn())
    with self.assertRaises(OSError) as busy: os.open(self.binary, os.O_WRONLY)
    self.assertEqual(busy.exception.errno, errno.ETXTBSY)
    self.binary.chmod(0o744)
    with self.assertRaisesRegex(ValueError, "inode/metadata"): retained.check()

  def test_expected_snapshot_mutation_does_not_change_retained_binding(self):
    retained, _, expected = self.pin(self.spawn())
    expected["argv"] = ("forged",)
    expected["uids"] = (0,) * 4
    self.assertNotEqual(retained.check()["argv"], expected["argv"])
    with self.assertRaises(TypeError): retained.expected["ppid"] = 1

  def test_foreign_owner_and_malformed_expected_refuse_before_proc_access(self):
    retained, fd, expected = self.pin(self.spawn())
    with patch.object(L.os, "getpid", return_value=retained.owner + 1), patch.object(L.P, "_identity", side_effect=AssertionError("wrong owner cannot query")):
      with self.assertRaisesRegex(ValueError, "owner"): retained.check()
    cases = [None, {}, dict(expected, extra=True), dict(expected, pid=True), dict(expected, uids=(1, 2)),
      dict(expected, uids=(True,) * 4), dict(expected, exe="relative"), dict(expected, argv=("nul\0",))]
    with patch.object(L.P, "_identity", side_effect=AssertionError("malformed cannot query")):
      for value in cases:
        with self.assertRaises(ValueError): L.Lifetime(fd, expected_identity=value)

  def test_foreign_pidfd_or_stale_startup_refuse_and_close_duplicates(self):
    first, second = self.spawn(), self.spawn()
    retained, fd, expected = self.pin(first)
    other = os.pidfd_open(second.pid)
    self.descriptors.append(other)
    before = len(os.listdir("/proc/self/fd"))
    for descriptor, identity in ((other, expected), (fd, dict(expected, starttime=expected["starttime"] + 1))):
      with self.assertRaises(ValueError): L.Lifetime(descriptor, expected_identity=identity)
      self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    retained.check()

  def test_partial_executable_acquisition_failure_closes_only_owned_duplicate(self):
    child = self.spawn()
    retained, fd, expected = self.pin(child)
    before = len(os.listdir("/proc/self/fd"))
    with patch.object(L, "_exe", side_effect=OSError("fixture open failure")):
      with self.assertRaises(OSError): L.Lifetime(fd, expected_identity=expected)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    with patch.object(L, "_exe", side_effect=lambda _: os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)):
      with self.assertRaises(ValueError): L.Lifetime(fd, expected_identity=expected)
    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
    retained.check()

  def test_actual_reparented_live_process_refuses_without_killing_foreign_tasks(self):
    argv = [str(self.binary), "-I", "-B", "-u", "-c", CODE]
    code = "import os,subprocess,sys\nchild=subprocess.Popen(" + repr(argv) + ",stdin=subprocess.PIPE,stdout=subprocess.PIPE)\nassert child.stdout.readline()==b'ready\\n'\nprint(child.pid,flush=True)\nsys.stdin.readline();os._exit(0)\n"
    parent = subprocess.Popen([sys.executable, "-I", "-B", "-u", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    self.children.append(parent)
    self.assertTrue(select.select([parent.stdout], [], [], 2)[0])
    pid = int(parent.stdout.readline())
    fd = os.pidfd_open(pid)
    self.descriptors.append(fd)
    self.addCleanup(lambda: signal.pidfd_send_signal(fd, signal.SIGTERM) if not select.select([fd], [], [], 0)[0] else None)
    expected = L.P._identity(pid)
    self.assertEqual(expected["ppid"], parent.pid)
    with L.Lifetime(fd, expected_identity=expected) as retained:
      parent.stdin.write(b"exit\n")
      parent.stdin.flush()
      parent.wait(timeout=2)
      L.P._alive(fd)
      with self.assertRaisesRegex(ValueError, "changed/reparented"): retained.check()


if __name__ == "__main__": unittest.main()
