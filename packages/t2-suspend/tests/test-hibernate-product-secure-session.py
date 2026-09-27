#!/usr/bin/python3
"""Session/IPC fixtures only; never lock the running desktop."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("secure_session", Path(__file__).parents[1] / "hibernate/secure_session.py")
secure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secure)


class Sessions(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.uid = os.getuid() if os.getuid() != 0 else pwd.getpwnam("nobody").pw_uid
    self.gid = pwd.getpwuid(self.uid).pw_gid
    self.session = {"Id": "2", "User": str(self.uid), "Leader": "917", "Seat": "seat0", "Active": "yes",
                    "Remote": "no", "Type": "wayland", "Class": "user", "State": "active", "TimestampMonotonic": "1234"}
    leader = self.root / "proc/917"
    leader.mkdir(parents=True)
    (leader / "status").write_text("Uid:\t0\t0\t0\t0\n")
    (leader / "stat").write_text("917 (sddm helper) " + " ".join(["S"] + ["0"] * 18 + ["9999"]))
    runtime = self.root / "run/user" / str(self.uid)
    runtime.mkdir(parents=True)
    self.socket = socket.socket(socket.AF_UNIX)
    self.socket.bind(str(runtime / "wayland-1"))
    self.addCleanup(self.socket.close)
    if os.geteuid() == 0: os.chown(runtime / "wayland-1", self.uid, self.gid)
    self.environment = {"XDG_SESSION_ID": "2", "XDG_RUNTIME_DIR": "/run/user/" + str(self.uid),
                        "WAYLAND_DISPLAY": "wayland-1", "OMARCHY_PATH": "/untrusted/desktop"}
    self.status = {"secure": True, "requested": True}
    self.calls = []
    self.change_on_ipc = None
    self.extra_session = False
    self.fail_ipc = False
    self.gate = secure.Gate(self.root, command_runner=self.command)

  def command(self, argv, env, uid, gid):
    self.calls.append((argv, env, uid, gid))
    if argv[1] == "list-sessions": return "2 1000 jjc seat0\n" + ("3 1000 jjc seat0\n" if self.extra_session else "")
    if argv[1] == "show-session":
      values = {**self.session, "Id": argv[2]}
      return "\n".join(key + "=" + values[key] for key in secure.PROPERTIES)
    self.assertEqual((uid, gid), (self.uid, self.gid))
    self.assertNotIn("LD_PRELOAD", env)
    if argv[0] == "/usr/bin/systemctl": return "\n".join(key + "=" + value for key, value in self.environment.items())
    self.assertEqual(argv, ("/usr/bin/bash", "/untrusted/desktop/bin/omarchy-shell", "lock", "status"))
    if self.fail_ipc: raise TimeoutError("fixture IPC timeout")
    if self.change_on_ipc: self.session.update(self.change_on_ipc)
    return self.status if type(self.status) is str else json.dumps(self.status)

  def test_bound_secure_lock_and_root_helper_are_accepted_without_root_ipc(self):
    binding = self.gate.require_secure()
    self.assertEqual(binding["leader_uids"], ("0",) * 4)
    self.assertEqual(self.gate.require_secure(binding), binding)
    self.assertEqual(len([call for call in self.calls if call[0][0] == "/usr/bin/bash"]), 2)

  def test_pending_lockedhint_missing_pam_invalid_and_timeout_fail_closed(self):
    for status in ({"secure": False, "requested": True}, {"isLocked": True}, {"secure": 1},
                   {"secure": "true"}, "missing-pam", "", "[]", '{"secure": false, "secure": true}'):
      self.status = status
      with self.assertRaises((ValueError, json.JSONDecodeError)): self.gate.require_secure()
    self.fail_ipc = True
    with self.assertRaises(TimeoutError): self.gate.require_secure()

  def test_remote_inactive_multiple_and_missing_session_fail_closed(self):
    original = self.session.copy()
    for changed in ({"Remote": "yes"}, {"Active": "no"}, {"Seat": ""}, {"Type": "tty"}, {"State": "closing"}):
      self.session = {**original, **changed}
      with self.assertRaises(ValueError): self.gate.require_secure()
    self.session = original
    self.extra_session = True
    with self.assertRaises(ValueError): self.gate.require_secure()

  def test_session_and_leader_change_between_checks_fail_before_ipc(self):
    binding = self.gate.require_secure()
    (self.root / "proc/917/stat").write_text("917 (new helper) " + " ".join(["S"] + ["0"] * 18 + ["10000"]))
    before = len(self.calls)
    with self.assertRaises(ValueError): self.gate.require_secure(binding)
    self.assertFalse(any(call[0][0] == "/usr/bin/bash" for call in self.calls[before:]))

  def test_change_during_ipc_and_wrong_environment_fail_closed(self):
    self.change_on_ipc = {"TimestampMonotonic": "5678"}
    with self.assertRaises(ValueError): self.gate.require_secure()
    self.change_on_ipc = None
    self.environment["XDG_SESSION_ID"] = "3"
    with self.assertRaises(ValueError): self.gate.require_secure()
    self.environment["XDG_SESSION_ID"] = "2"
    self.environment["WAYLAND_DISPLAY"] = "../other-session"
    with self.assertRaises(ValueError): self.gate.require_secure()

  def test_missing_socket_and_live_injection_are_rejected(self):
    (self.root / "run/user" / str(self.uid) / "wayland-1").unlink()
    with self.assertRaises(FileNotFoundError): self.gate.require_secure()
    with self.assertRaises(ValueError): secure.Gate(Path("/"), command_runner=self.command)
    with self.assertRaises(ValueError): secure.Gate(self.root)

  def test_frozen_identity_recheck_resets_deadline_and_never_uses_user_ipc(self):
    binding = self.gate.require_secure()
    self.gate.deadline = 0
    before = len(self.calls)
    self.gate.require_same_session(binding)
    self.assertTrue(all(call[2] is None for call in self.calls[before:]))
    self.session["Active"] = "no"
    with self.assertRaises(ValueError): self.gate.require_same_session(binding)


if __name__ == "__main__": unittest.main()
