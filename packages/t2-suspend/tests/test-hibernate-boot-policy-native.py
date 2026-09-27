"""Offline native wiring tests; never invoke host power/inhibitor/lock operations."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parents[1]
def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module
N = load("native_adapter", HERE / "hibernate/boot_policy_native.py")
F = load("native_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))


class Native(unittest.TestCase):
  def query(self, argv):
    self.commands.append(argv)
    if argv[0] == "/usr/bin/systemctl": return self.units
    return self.responses[argv[-1]]

  def setUp(self):
    self.commands = []
    self.units = "\n\n".join("Id=" + unit + "\nLoadState=loaded\nActiveState=inactive" for unit in N.POWER_UNITS)
    self.responses = {"ListInhibitors": 'a(ssssuu) 1 "shutdown:sleep" "' + N.WHO + '" "' + N.WHY + '" "block" 0 321',
                      "PreparingForSleep": "b false", "PreparingForShutdown": "b false",
                      "ScheduledShutdown": '(st) "" 0', "ListJobs": "a(usssoo) 0"}

  def test_workspace_and_nonisolated_invocations_refuse_before_effect(self):
    with patch.object(N.os, "execve", side_effect=AssertionError("no inhibitor")), patch.object(N, "_command", side_effect=AssertionError("no host queries")):
      with self.assertRaises(ValueError): N.native("activation")
      with self.assertRaises(ValueError): N.native("deactivation")
      with self.assertRaises(ValueError): N.native("force")

  def test_cli_has_only_required_fixed_actions(self):
    with patch.object(N, "native") as native:
      for args in ([], ["check"], ["activation", "--root", "/tmp"], ["deactivation", "--force"], ["activation", "--approve"]):
        with self.assertRaises(SystemExit): N.main(args)
      native.assert_not_called()

  def test_fixed_inhibitor_reexec_after_inventory_gate(self):
    class ExecCalled(Exception): pass
    with patch.object(N, "_installed", return_value=object()) as installed, patch.object(Path, "readlink", return_value=Path("/usr/bin/bash")), patch.object(N.os, "execve", side_effect=ExecCalled) as execute:
      with self.assertRaises(ExecCalled): N.native("activation")
    installed.assert_called_once_with()
    execute.assert_called_once_with("/usr/bin/systemd-inhibit", N._inhibit_command("activation"), N.ENV)
    self.assertEqual(N._inhibit_command("activation")[-5:], ("/usr/bin/python3", "-I", "-B", str(N.SCRIPT), "activation"))

  def test_valid_owned_inhibitor_and_idle_power(self):
    with patch.object(N, "_command", side_effect=self.query): N._power_idle(321)
    self.assertEqual(len(self.commands), 6)
    self.assertTrue(all(argv[0] in ("/usr/bin/busctl", "/usr/bin/systemctl") for argv in self.commands))

  def test_returned_hibernate_zero_schedule_is_idle_but_unknown_action_refuses(self):
    with patch.object(N, "_command", side_effect=self.query):
      self.responses["ScheduledShutdown"] = '(st) "hibernate" 0'
      N._power_idle(321)
      for invalid in ('(st) "hibernate" 1', '(st) "unknown" 0', '(st) "hibernate"', '(st) "hibernate" 00'):
        self.responses["ScheduledShutdown"] = invalid
        with self.assertRaises(ValueError): N._power_idle(321)

  def test_fresh_empty_action_infinity_is_no_schedule_exactly(self):
    with patch.object(N, "_command", side_effect=self.query):
      self.responses["ScheduledShutdown"] = '(st) "" 18446744073709551615'
      N._power_idle(321)
      for invalid in ('(st) "hibernate" 18446744073709551615', '(st) "reboot" 18446744073709551615',
                      '(st) "" 18446744073709551614', '(st) "" 18446744073709551616',
                      '(st) "" 018446744073709551615', '(st) "" -1', '(st) "" 100',
                      '(st) ""', '(st) "" 18446744073709551615 extra'):
        with self.subTest(invalid=invalid):
          self.responses["ScheduledShutdown"] = invalid
          with self.assertRaises(ValueError): N._power_idle(321)

  def test_wrong_pid_uid_mask_and_mode_refuse(self):
    original = self.responses["ListInhibitors"]
    for invalid in (original.replace(" 321", " 322"), original.replace(" 0 321", " 1000 321"),
                    original.replace('"block"', '"delay"'), original.replace("shutdown:sleep", "sleep"),
                    original.replace(N.WHO, "foreign"), original.replace(N.WHY, "foreign"),
                    'a(ssssuu) 0', original.replace(" 1 ", " 2 "), original + " extra"):
      with self.subTest(invalid=invalid), patch.object(N, "_command", side_effect=self.query):
        self.responses["ListInhibitors"] = invalid
        with self.assertRaises(ValueError): N._power_idle(321)

  def test_preparing_scheduled_and_queued_operations_refuse(self):
    for member, invalid in (("PreparingForSleep", "b true"), ("PreparingForShutdown", "b true"),
                            ("ScheduledShutdown", '(st) "reboot" 100'), ("ListJobs", 'a(usssoo) 1 7 "reboot.target" "start" "running" "/job" "/unit"')):
      original = self.responses[member]
      self.responses[member] = invalid
      with self.subTest(member=member), patch.object(N, "_command", side_effect=self.query):
        with self.assertRaises(ValueError): N._power_idle(321)
      self.responses[member] = original

  def test_active_service_and_incomplete_unit_inventory_refuse(self):
    original = self.units
    for invalid in (original.replace("ActiveState=inactive", "ActiveState=activating", 1),
                    original.replace("Id=systemd-reboot.service\nLoadState=loaded\nActiveState=inactive", "Id=systemd-reboot.service\nLoadState=loaded\nActiveState=active"),
                    original.split("\n\n", 1)[1], original.replace("LoadState=loaded", "LoadState=error", 1)):
      self.units = invalid
      with patch.object(N, "_command", side_effect=self.query):
        with self.assertRaises(ValueError): N._power_idle(321)

  def test_parent_liveness_and_starttime_guard_repeated(self):
    read_fd, write_fd = os.pipe()
    try:
      with patch.object(N.os, "getppid", return_value=321), patch.object(N.os, "pidfd_open", return_value=os.dup(read_fd)), patch.object(N, "_parent_identity", return_value="123") as identity, patch.object(N, "_power_idle") as idle:
        with N._exclusion("activation") as guard:
          guard()
          identity.return_value = "456"
          with self.assertRaises(ValueError): guard()
        self.assertEqual(idle.call_count, 2)
      with patch.object(N.os, "getppid", return_value=321), patch.object(N.os, "pidfd_open", return_value=os.dup(read_fd)), patch.object(N, "_parent_identity", return_value="123"), patch.object(N, "_power_idle") as idle:
        os.write(write_fd, b"dead")
        with self.assertRaises(ValueError):
          with N._exclusion("activation"): pass
        idle.assert_not_called()
    finally:
      os.close(read_fd)
      os.close(write_fd)

  def test_exact_parent_command_and_root_identity(self):
    command = b"\0".join(item.encode() for item in N._inhibit_command("activation")) + b"\0"
    metadata = "321 (inhibit) " + " ".join(["0"] * 19 + ["999"])
    with patch.object(N.os, "getppid", return_value=321), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o100755, st_uid=0)), patch.object(Path, "read_bytes", return_value=command), patch.object(Path, "read_text", autospec=True, side_effect=lambda path: "Uid:\t0\t0\t0\t0\n" if path.name == "status" else metadata):
      self.assertEqual(N._parent_identity(321, "activation"), "999")
      with self.assertRaises(ValueError): N._parent_identity(321, "deactivation")

  def test_native_dispatch_supplies_only_fixed_root_and_callbacks(self):
    from contextlib import contextmanager
    guards = []
    @contextmanager
    def exclusion(action):
      self.assertEqual(action, "activation")
      yield lambda: guards.append(True)
    engine = Mock()
    engine._transition.return_value = {"live_execution": False, "qualification_issued": False}
    with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), patch.object(N, "_exclusion", side_effect=exclusion), patch.object(N, "_precheck") as precheck:
      result = N.native("activation")
      arguments = engine._transition.call_args
      self.assertEqual(arguments.args, (Path("/"), "activation"))
      arguments.kwargs["guard"]()
      arguments.kwargs["precheck"](Path("/"), "activation", "after")
      precheck.assert_called_once_with(engine, "activation", "after")
      self.assertTrue(result["live_execution"])
      self.assertFalse(result["power_operation"])
      self.assertFalse(result["qualification_issued"])

  def test_precheck_reuses_admission_and_only_internal_postcheck_crosses_pending(self):
    product = Mock()
    config = {"source_directory": "/source", "restore_directory": "/restore", "production_uki": "/production", "staged_receipt_sha256": "a" * 64}
    product.TRIAL._private_json.side_effect = lambda path: config if path.name == "config.json" else {"approved": True}
    product.BOOT_POLICY.verify.return_value = True
    metadata = SimpleNamespace(st_mode=0o40700, st_uid=0)
    with patch.object(Path, "lstat", return_value=metadata):
      N._precheck(SimpleNamespace(PRODUCT=product), "activation", "before")
      product.check.assert_called_once()
      product._admission_state.assert_not_called()
      N._precheck(SimpleNamespace(PRODUCT=product), "activation", "after")
      product.TRIAL._verify_deployment.assert_called_once_with(N.ROOT, config, product.ARTIFACTS.derive_artifacts.return_value, source_default=True)
      arguments = product._admission_state.call_args.kwargs
      self.assertEqual(arguments["root"], Path("/"))
      self.assertNotIn("query", arguments)
      self.assertEqual(product.check.call_count, 1)
      with self.assertRaises(ValueError): N._precheck(SimpleNamespace(PRODUCT=product), "deactivation", "after")

  def test_untrusted_dependency_metadata_blocks_before_any_import(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    runtime = fixture.root / F.T.P.STATE / "runtime"
    dependency = next(runtime.rglob("fixture.py"))
    original = Path.lstat
    def owned(path):
      info = original(path)
      return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
    with patch.object(N, "STATE", fixture.root / F.T.P.STATE), patch.object(N, "SCRIPT", runtime / "packages/t2-suspend/hibernate/boot_policy_native.py"), patch.object(Path, "lstat", autospec=True, side_effect=owned), patch.object(N.importlib.util, "spec_from_file_location", side_effect=AssertionError("unverified code must not import")):
      dependency.chmod(0o666)
      with self.assertRaises(ValueError): N._reviewed_tree()
      dependency.chmod(0o600)
      runtime.chmod(0o755)
      with self.assertRaises(ValueError): N._reviewed_tree()
      runtime.chmod(0o700)
      # A review owned by the fixture user also cannot authorize a live import.
      with self.assertRaises(ValueError): N._reviewed_tree()

  def test_reviewed_bootstrap_checks_entire_inventory_before_engine_import(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    runtime = fixture.root / F.T.P.STATE / "runtime"
    for name in ("boot_policy_native.py", "runtime_deployment.py"):
      fixture.f.write(F.T.P.STATE / "runtime/packages/t2-suspend/hibernate" / name, (HERE / "hibernate" / name).read_bytes())
    review = {"protocol": F.T.D.SCHEMA, "approved": True, "reviewed_commit": "a" * 40, "files": F.T.D.inventory(runtime)}
    fixture.f.write(F.T.P.STATE / "runtime-deployment-review.json", json.dumps(review).encode())
    original = Path.lstat
    def owned(path):
      info = original(path)
      return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
    with patch.object(N, "STATE", fixture.root / F.T.P.STATE), patch.object(N, "SCRIPT", runtime / "packages/t2-suspend/hibernate/boot_policy_native.py"), patch.object(Path, "lstat", autospec=True, side_effect=owned), patch.object(N, "_private_bytes", side_effect=lambda path: path.read_bytes()):
      N._reviewed_tree()
      dependency = next(runtime.rglob("fixture.py"))
      dependency.write_bytes(b"changed reviewed dependency\n")
      with self.assertRaises(ValueError): N._reviewed_tree()
      bootstrap = N.SCRIPT.with_name("runtime_deployment.py")
      bootstrap.write_bytes(b"changed bootstrap\n")
      with patch.object(N.importlib.util, "spec_from_file_location", side_effect=AssertionError("changed bootstrap must never import")):
        with self.assertRaises(ValueError): N._reviewed_tree()

  def test_engine_exclusion_loss_after_optin_unlink_preserves_pending(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    fixture.run_action()
    def guard():
      if not (fixture.root / F.T.OPT_IN).exists(): raise ValueError("lost inhibitor")
    with self.assertRaises(ValueError):
      F.T._transition(fixture.root, "deactivation", precheck=fixture.check, guard=guard)
    self.assertTrue(fixture.pending("deactivation").exists())
    self.assertTrue((fixture.root / F.T.P.POLICY).exists())
    self.assertEqual((fixture.root / F.T.P.LIMINE).read_bytes(), fixture.f.proposal["after"])
    self.assertFalse((fixture.root / F.T.DB_LOCK).exists())


if __name__ == "__main__": unittest.main()
