"""Synthetic manager/cgroup fixtures only; NEVER creates a host systemd unit."""
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("tested_maintenance_scope", Path(__file__).parents[1] / "hibernate/maintenance_scope.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
load_filesystem = S._filesystem
PYTHON = "/usr/bin/python3"
BOOTSTRAP = "import os,sys;os.write(int(sys.argv[2]),b'ready\\n');os.close(int(sys.argv[2]));os.read(int(sys.argv[1]),1);sys.exit(23)"


class Containment(unittest.TestCase):
  def setUp(self):
    if os.geteuid() == 0: self.skipTest("Synthetic host subprocess tests require nonroot; root-drop proof belongs to disposable VM")
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    (self.root / "system.slice").mkdir()
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    argv = [PYTHON, "-I", "-B", "-c", BOOTSTRAP, str(read), str(ready_write)]
    process = subprocess.Popen(argv, pass_fds=(read, ready_write), close_fds=True)
    os.close(read)
    os.close(ready_write)
    self.assertTrue(select.select([ready_read], [], [], 2)[0], "Synthetic child did not reach exact bootstrap")
    self.assertEqual(os.read(ready_read, 7), b"ready\n")
    os.close(ready_read)
    self.held = SimpleNamespace(owner=os.getpid(), released=False, payload_fd=write,
      process=process, identity={"uid": os.getuid(), "exe": str(Path(PYTHON).resolve()), "argv": argv})
    self.handles, self.calls = [], []
    self.name, self.group, self.membership = None, None, None
    self.start_error, self.stop_error = None, None
    self.stop_empties, self.job_pending = True, False
    self.owner_membership = "/"
    self.overrides = {}
    self.addCleanup(self.cleanup)
    for name, value in (("CGROUP", self.root), ("_native", lambda: None),
      ("_secure", lambda *args, **kwargs: None), ("_run", self.manager),
      ("_filesystem", lambda fd: (S.CGROUP2_MAGIC, (123, 456))),
      ("_membership", lambda pid: self.membership if pid == process.pid else self.owner_membership)):
      replacement = patch.object(S, name, value)
      replacement.start()
      self.addCleanup(replacement.stop)

  def cleanup(self):
    # Fixture-only forced descriptor cleanup after deliberately unsettled
    # tests; NOT a production abandonment API and never calls a manager.
    for handle in self.handles:
      for key in ("events_fd", "directory_fd"):
        fd = getattr(handle, key)
        if fd is not None:
          os.close(fd)
          setattr(handle, key, None)
      handle.pin.close()
    os.close(self.held.payload_fd)
    if self.held.process.returncode is None:
      self.held.process.terminate()
      self.held.process.wait(timeout=2)

  def manager(self, argv, deadline):
    self.calls.append(list(argv))
    if "call" in argv:
      offset = argv.index("call")
      method, signature, *args = argv[offset + 4:]
      if method == "StartTransientUnit":
        self.name = args[0]
        self.group = self.root / "system.slice" / self.name
        self.group.mkdir()
        self.events(b"populated 1\nfrozen 0\n")
        self.membership = "/system.slice/" + self.name
        if self.start_error is not None: raise self.start_error
        return ["o", "/org/freedesktop/systemd1/job/91"]
      self.assertEqual((method, signature, args), ("StopUnit", "ss", [self.name, "fail"]))
      if self.stop_error is not None: raise self.stop_error
      if self.stop_empties: self.events(b"populated 0\nfrozen 0\n")
      return ["o", "/org/freedesktop/systemd1/job/92"]
    offset = argv.index("get-property")
    service, unit, interface, key = argv[offset + 1:]
    self.assertEqual(service, S.SERVICE)
    self.assertEqual(unit, S._unit_path(self.name))
    values = {"Id": ["s", self.name], "Transient": ["b", "true"],
      "Slice": ["s", "system.slice"], "ControlGroup": ["s", "/system.slice/" + self.name],
      "Delegate": ["b", "false"], "KillMode": ["s", "control-group"],
      "SendSIGKILL": ["b", "true"], "TimeoutStopUSec": ["t", "2000000"],
      "ActiveState": ["s", "active"], "Job": ["(uo)", "0", "/"]}
    self.assertEqual(interface, S.UNIT_IFACE if key in ("Id", "Transient", "ActiveState", "Job") else S.SCOPE_IFACE)
    if self.job_pending: values["Job"] = ["(uo)", "91", "/org/freedesktop/systemd1/job/91"]
    return self.overrides.get(key, values[key])

  def events(self, raw):
    (self.group / "cgroup.events").write_bytes(raw)

  def prepare(self, **kwargs):
    handle = S.prepare(self.held, **kwargs)
    self.handles.append(handle)
    return handle

  def test_typed_attach_preserves_held_direct_process_and_reaper(self):
    handle = self.prepare()
    self.assertTrue(handle.ready)
    self.assertFalse(handle.settled)
    self.assertFalse(self.held.released)
    self.assertIsNone(self.held.process.returncode)
    self.assertEqual(handle.pin.pid, self.held.process.pid)
    self.assertFalse(os.get_inheritable(handle.pin.fd))
    self.assertFalse(os.get_inheritable(handle.directory_fd))
    self.assertFalse(os.get_inheritable(handle.events_fd))
    command = self.calls[0]
    self.assertEqual(command[:6], ["/usr/bin/busctl", "--system", "--no-pager", "--allow-interactive-authorization=no", "--timeout=5s", "call"])
    self.assertRegex(handle.name, r"^omarchy-t2-maintenance-[0-9a-f]{32}\.scope$")
    self.assertEqual(command[10:], ["ssa(sv)a(sa(sv))", handle.name, "fail", "7",
      "Slice", "s", "system.slice", "PIDs", "au", "1", str(self.held.process.pid),
      "Delegate", "b", "false", "KillMode", "s", "control-group", "SendSIGKILL", "b", "true",
      "TimeoutStopUSec", "t", "2000000", "Description", "s", "Omarchy held maintenance phase", "0"])
    self.assertTrue(handle.drain())
    handle.close()
    self.assertIsNone(self.held.process.returncode)  # never poll/reap/release

  def test_start_timeout_retains_handle_and_recovers_owned_scope(self):
    self.start_error = TimeoutError("manager reply lost after attach")
    handle = self.prepare()
    self.assertTrue(handle.attempted)
    self.assertFalse(handle.ready)
    self.assertIs(handle.error, self.start_error)
    self.assertIsNotNone(handle.pin.fd)
    with self.assertRaises(ValueError): handle.close()
    self.assertTrue(handle.drain())
    handle.close()

  def test_interrupt_during_attach_does_not_raise_away_ownership(self):
    self.start_error = KeyboardInterrupt()
    handle = self.prepare()
    self.assertIs(handle.error, self.start_error)
    self.assertFalse(handle.ready)
    self.assertTrue(handle.drain())
    handle.close()

  def test_failed_creation_cannot_stop_existing_foreign_unit(self):
    self.start_error = subprocess.CalledProcessError(1, ["synthetic-busctl"], stderr=b"existing unit")
    handle = self.prepare()
    self.membership = "/unrelated.scope"
    self.events(b"populated 0\nfrozen 0\n")
    self.assertFalse(handle.drain())
    self.assertFalse(handle.creation_confirmed)
    self.assertFalse(handle.settled)
    self.assertFalse(any("StopUnit" in call for call in self.calls))

  def test_uncertain_creation_and_exited_child_retains_ownership(self):
    self.start_error = TimeoutError("lost start reply")
    handle = self.prepare()
    os.write(self.held.payload_fd, b"x")
    self.held.process.wait(timeout=2)
    self.assertFalse(handle.drain())
    self.assertFalse(any("StopUnit" in call for call in self.calls))

  def test_explicit_confirmation_of_uncertain_start_survives_leader_exit(self):
    self.start_error = TimeoutError("lost start reply")
    handle = self.prepare()
    self.assertFalse(handle.creation_confirmed)
    self.assertTrue(handle.check_ready())
    self.assertTrue(handle.creation_confirmed)
    self.held.released = True
    os.write(self.held.payload_fd, b"x")
    self.held.process.wait(timeout=2)
    self.assertTrue(handle.drain())
    handle.close()

  def test_name_allocation_failure_closes_pre_mutation_pin(self):
    original = S.P.ChildPin
    pins = []
    def capture(*args, **kwargs):
      pin = original(*args, **kwargs)
      pins.append(pin)
      return pin
    with patch.object(S.P, "ChildPin", capture), patch.object(S.secrets, "token_hex", side_effect=OSError("random failure")):
      with self.assertRaises(OSError): self.prepare()
    self.assertIsNone(pins[0].fd)
    self.assertEqual(self.calls, [])

  def test_events_pin_security_failure_closes_incomplete_fd_and_retries(self):
    def secure(info, *, directory):
      if not directory: raise ValueError("fixture events rejected")
    with patch.object(S, "_secure", secure):
      handle = self.prepare()
    self.assertFalse(handle.ready)
    self.assertIsNone(handle.events_fd)
    self.assertIsNotNone(handle.directory_fd)
    self.assertTrue(handle.drain())
    handle.close()

  def test_incomplete_start_job_never_ready(self):
    self.job_pending = True
    handle = self.prepare()
    self.assertFalse(handle.ready)
    self.assertIsInstance(handle.error, ValueError)
    self.assertTrue(handle.drain())
    handle.close()

  def test_wrong_placement_never_ready(self):
    handle = self.prepare()
    self.membership = "/user.slice/unrelated.scope"
    self.assertFalse(handle.check_ready())
    self.assertFalse(handle.ready)
    self.assertTrue(handle.drain())
    handle.close()

  def test_wrong_unit_refuses_stop_and_retains_handle(self):
    handle = self.prepare()
    self.overrides["Id"] = ["s", "foreign.scope"]
    self.assertFalse(handle.drain())
    self.assertFalse(any("StopUnit" in call for call in self.calls))
    self.assertIsNotNone(handle.events_fd)
    with self.assertRaises(ValueError): handle.close()

  def test_failed_or_inactive_state_is_not_emptiness(self):
    handle = self.prepare()
    self.overrides["ActiveState"] = ["s", "failed"]
    self.stop_empties = False
    self.assertFalse(handle.drain(timeout=0.02))
    self.assertIsInstance(handle.error, TimeoutError)
    self.assertFalse(handle.settled)
    with self.assertRaises(ValueError): handle.close()
    self.events(b"populated 0\nfrozen 0\n")
    self.assertTrue(handle.drain())
    handle.close()

  def test_recursive_populated_not_empty_direct_procs(self):
    handle = self.prepare()
    (self.group / "cgroup.procs").write_bytes(b"")
    (self.group / "descendant").mkdir()
    self.stop_empties = False
    self.assertFalse(handle.drain(timeout=0.02))
    self.events(b"populated 0\nfrozen 0\n")
    self.assertTrue(handle.drain())
    handle.close()

  def test_direct_exit_status_remains_callers_to_reap(self):
    handle = self.prepare()
    self.held.released = True
    os.write(self.held.payload_fd, b"x")
    self.assertEqual(self.held.process.wait(timeout=2), 23)
    self.assertTrue(handle.drain())
    handle.close()

  def test_reused_directory_path_cannot_supply_empty_verdict(self):
    handle = self.prepare()
    old = self.group.with_name(self.name + "-old")
    self.group.rename(old)
    self.group.mkdir()
    self.events(b"populated 0\nfrozen 0\n")
    self.assertFalse(handle.drain())
    self.assertFalse(handle.settled)
    self.assertFalse(any("StopUnit" in call for call in self.calls))
    with self.assertRaises(ValueError): handle.close()

  def test_reused_events_inode_cannot_supply_empty_verdict(self):
    handle = self.prepare()
    (self.group / "cgroup.events").rename(self.group / "old-events")
    self.events(b"populated 0\nfrozen 0\n")
    self.assertFalse(handle.drain())
    self.assertFalse(handle.settled)

  def test_exact_removed_cgroup2_pins_settle_after_disappearance(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    self.assertTrue(handle.drain())
    self.assertTrue(handle.settled)
    self.assertIsNotNone(handle.events_fd)
    handle.close()

  def test_absent_path_but_linked_original_pins_refuse(self):
    handle = self.prepare()
    self.group.rename(self.group.with_name(self.name + "-renamed"))
    self.assertFalse(handle.drain())
    self.assertFalse(handle.settled)

  def test_only_events_unlinked_is_not_removed_cgroup_proof(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rename(self.group.with_name(self.name + "-renamed"))
    self.assertEqual(os.fstat(handle.events_fd).st_nlink, 0)
    self.assertNotEqual(os.fstat(handle.directory_fd).st_nlink, 0)
    self.assertFalse(handle.drain())

  def test_removed_original_with_replacement_path_refuses_and_preserves(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    self.group.mkdir()
    foreign = self.group / "foreign"
    foreign.write_text("preserve")
    self.assertFalse(handle.drain())
    self.assertEqual(foreign.read_text(), "preserve")
    self.assertFalse(any("StopUnit" in call for call in self.calls))

  def test_removed_original_with_dangling_symlink_refuses(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    self.group.symlink_to(self.root / "absent-target")
    self.assertFalse(self.group.exists())
    self.assertFalse(handle.drain())
    self.assertTrue(self.group.is_symlink())

  def test_replacement_during_removed_pin_readback_refuses(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    original, calls = handle._same_pins, []
    def pins():
      infos = original()
      calls.append(True)
      if len(calls) == 3: self.group.mkdir()
      return infos
    with patch.object(handle, "_same_pins", pins): self.assertFalse(handle.drain())
    self.assertTrue(self.group.is_dir())

  def test_removed_path_mismatched_pin_refuses(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    handle.events_identity = (handle.events_identity[0], handle.events_identity[1] + 1)
    self.assertFalse(handle.drain())

  def test_removed_path_wrong_deleted_link_refuses(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    original = os.readlink
    def readlink(path):
      if path == "/proc/self/fd/" + str(handle.directory_fd): return str(handle.path)
      return original(path)
    with patch.object(S.os, "readlink", readlink): self.assertFalse(handle.drain())

  def test_removed_path_wrong_filesystem_or_fsid_refuses(self):
    handle = self.prepare()
    (self.group / "cgroup.events").unlink()
    self.group.rmdir()
    for filesystem in ((0xEF53, (123, 456)), (S.CGROUP2_MAGIC, (789, 456))):
      with patch.object(S, "_filesystem", return_value=filesystem): self.assertFalse(handle.drain())

  def test_actual_noncgroup_fixture_filesystem_refuses_acquisition(self):
    # Real read-only libc fstatfs on a disposable file, never a live cgroup.
    fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
      original = load_filesystem
      self.assertNotEqual(original(fd)[0], S.CGROUP2_MAGIC)
      with patch.object(S, "_filesystem", original):
        handle = self.prepare()
        self.assertFalse(handle.ready)
        self.assertFalse(handle.drain())
    finally: os.close(fd)

  def test_malformed_duplicate_missing_events_refuse(self):
    handle = self.prepare()
    for raw in (b"populated 0\npopulated 0\n", b"frozen 0\n", b"populated 2\n",
      b"populated 0", b"populated 0 trailing\n", b"populated 0\n" + b"x" * 4096):
      with self.subTest(raw=raw[:50]):
        self.events(raw)
        self.assertFalse(handle.drain())
        self.assertFalse(handle.settled)
    self.events(b"populated 0\nfrozen 0\n")
    self.assertTrue(handle.drain())
    handle.close()

  def test_stop_reply_failure_retains_pins_for_retry(self):
    handle = self.prepare()
    self.stop_error = TimeoutError("stop reply uncertain")
    self.assertFalse(handle.drain())
    self.assertIsNotNone(handle.directory_fd)
    self.stop_error = None
    self.assertTrue(handle.drain())
    handle.close()

  def test_interrupt_while_draining_returns_unsettled_ownership(self):
    handle = self.prepare()
    self.stop_error = KeyboardInterrupt()
    self.assertFalse(handle.drain())
    self.assertIs(handle.error, self.stop_error)
    with self.assertRaises(ValueError): handle.close()

  def test_owner_inside_scope_refuses_ready_and_stop(self):
    handle = self.prepare()
    self.owner_membership = handle.control_group + "/nested"
    self.assertFalse(handle.check_ready())
    self.assertFalse(handle.drain())
    self.assertFalse(any("StopUnit" in call for call in self.calls))

  def test_close_expiration_refuses_reuse_and_ready_after_drain(self):
    handle = self.prepare()
    self.assertTrue(handle.drain())
    with self.assertRaises(ValueError): handle.check_ready()
    handle.close()
    for action in (handle.drain, handle.close, handle.check_ready):
      with self.assertRaises(ValueError): action()

  def test_invalid_deadlines_and_held_state_never_call_manager(self):
    for timeout in (True, 0, -1, float("inf"), float("nan"), 6):
      with self.assertRaises(ValueError): self.prepare(timeout=timeout)
    self.held.released = True
    with self.assertRaises(ValueError): self.prepare()
    self.assertEqual(self.calls, [])

  def test_native_gate_refuses_source_before_pin_or_manager(self):
    with patch.object(S, "_native", side_effect=ValueError("unreviewed source")):
      with self.assertRaises(ValueError): self.prepare()
    self.assertEqual(self.calls, [])

  def test_typed_properties_refuse_aliases_and_malformed_types(self):
    for key, value in (("Transient", ["s", "true"]), ("Slice", ["s", "user.slice"]),
      ("ControlGroup", ["s", "/system.slice/other.scope"]), ("ActiveState", ["s", "activating"]),
      ("Delegate", ["b", "true"]), ("KillMode", ["s", "process"]),
      ("SendSIGKILL", ["b", "false"]), ("TimeoutStopUSec", ["t", "2000001"]),
      ("Job", ["(uo)", "00", "/"])):
      with self.subTest(key=key):
        self.overrides[key] = value
        handle = self.prepare()
        self.assertFalse(handle.ready)
        self.overrides.clear()
        self.assertTrue(handle.drain())
        handle.close()


if __name__ == "__main__": unittest.main()
