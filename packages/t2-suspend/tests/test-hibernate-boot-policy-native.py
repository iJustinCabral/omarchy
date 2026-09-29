"""Offline native wiring tests; never invoke host power/inhibitor/lock operations."""
import fcntl
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
import unittest
import uuid
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
      for args in ([], ["check"], ["maintenance", "--root", "/tmp"], ["maintenance", "--force"], ["activation", "--root", "/tmp"], ["deactivation", "--force"], ["activation", "--approve"]):
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

  def test_nonpower_jobs_are_allowed_only_during_ongoing_checks(self):
    self.responses["ListJobs"] = ('a(usssoo) 2 7 "dbus.service" "restart" "running" '
                                  '"/org/freedesktop/systemd1/job/7" "/org/freedesktop/systemd1/unit/dbus_2eservice" '
                                  '8 "1worker@package-update.service" "start" "waiting" '
                                  '"/org/freedesktop/systemd1/job/8" "/org/freedesktop/systemd1/unit/_31worker_40package_2dupdate_2eservice"')
    with patch.object(N, "_command", side_effect=self.query):
      N._power_ongoing(321)
      with self.assertRaisesRegex(ValueError, "Queued system jobs"): N._power_idle(321)

  def test_ongoing_job_inventory_rejects_every_power_unit_and_job_state(self):
    with patch.object(N, "_command", side_effect=self.query):
      for unit in N.POWER_UNITS:
        label = unit.replace("-", "_2d").replace(".", "_2e")
        for state in ("waiting", "running"):
          with self.subTest(unit=unit, state=state):
            self.responses["ListJobs"] = ('a(usssoo) 1 7 "' + unit + '" "stop" "' + state +
                                          '" "/org/freedesktop/systemd1/job/7" "/org/freedesktop/systemd1/unit/' + label + '"')
            with self.assertRaisesRegex(ValueError, "Queued power jobs"): N._power_ongoing(321)

  def test_ongoing_checks_allow_typed_nonpower_mount_socket_and_distinct_nop_jobs(self):
    self.responses["ListJobs"] = ('a(usssoo) 4 7 "var-cache.mount" "start" "waiting" '
                                  '"/org/freedesktop/systemd1/job/7" "/org/freedesktop/systemd1/unit/var_2dcache_2emount" '
                                  '8 "package_worker.socket" "stop" "running" '
                                  '"/org/freedesktop/systemd1/job/8" "/org/freedesktop/systemd1/unit/package_5fworker_2esocket" '
                                  '9 "dbus.service" "restart" "running" '
                                  '"/org/freedesktop/systemd1/job/9" "/org/freedesktop/systemd1/unit/dbus_2eservice" '
                                  '10 "dbus.service" "nop" "waiting" '
                                  '"/org/freedesktop/systemd1/job/10" "/org/freedesktop/systemd1/unit/dbus_2eservice"')
    with patch.object(N, "_command", side_effect=self.query): N._power_ongoing(321)

  def test_ongoing_job_inventory_requires_complete_canonical_typed_tuples(self):
    row = '7 "dbus.service" "restart" "running" "/org/freedesktop/systemd1/job/7" "/org/freedesktop/systemd1/unit/dbus_2eservice"'
    valid = "a(usssoo) 1 " + row
    invalid = ["", "a(usssoo)", "a(ssssuu) 0", "a(usssoo) -1", "a(usssoo) 00", "a(usssoo) 4294967296",
               "a(usssoo) 1", "a(usssoo) 0 " + row, "a(usssoo) 2 " + row, valid + " extra",
               " ".join(valid.split()[:-1]), "a(usssoo) 2 " + row + " " + row,
               valid.replace(" 7 ", " 0 ", 1), valid.replace(" 7 ", " -7 ", 1),
               valid.replace(" 7 ", " 07 ", 1), valid.replace(" 7 ", " 4294967296 ", 1),
               valid.replace(" 7 ", " ٧ ", 1), valid.replace('"dbus.service"', '""'),
               valid.replace('"dbus.service"', '"dbus service"'), valid.replace('"dbus.service"', '"dbüs.service"'),
               valid.replace('"restart"', '"unknown"'), valid.replace('"restart"', '""'),
               valid.replace('"running"', '"finished"'), valid.replace('"running"', '""'),
               valid.replace('"/org/freedesktop/systemd1/job/7"', '"/org/freedesktop/systemd1/job/8"'),
               valid.replace('"/org/freedesktop/systemd1/job/7"', '"job/7"'),
               valid.replace('"/org/freedesktop/systemd1/unit/dbus_2eservice"', '"/org/freedesktop/systemd1/unit/hibernate_2etarget"'),
               valid.replace('"/org/freedesktop/systemd1/unit/dbus_2eservice"', '"/org/freedesktop/systemd1/unit/dbus.service"')]
    with patch.object(N, "_command", side_effect=self.query):
      N._power_ongoing(321)
      for response in invalid:
        with self.subTest(response=response):
          self.responses["ListJobs"] = response
          with self.assertRaises(ValueError): N._power_ongoing(321)

  def test_ongoing_checks_keep_all_inhibitor_and_power_state_refusals(self):
    inhibitor = self.responses["ListInhibitors"]
    invalid = [("ListInhibitors", "a(ssssuu) 0"),
               ("ListInhibitors", inhibitor.replace(" 321", " 322")),
               ("ListInhibitors", inhibitor.replace(" 0 321", " 1000 321")),
               ("ListInhibitors", inhibitor.replace('"block"', '"delay"')),
               ("ListInhibitors", inhibitor.replace("shutdown:sleep", "sleep")),
               ("ListInhibitors", inhibitor.replace(N.WHO, "foreign")),
               ("ListInhibitors", inhibitor.replace(N.WHY, "foreign")),
               ("PreparingForSleep", "b true"), ("PreparingForShutdown", "b true"),
               ("ScheduledShutdown", '(st) "hibernate" 1'), ("ScheduledShutdown", '(st) "unknown" 0')]
    with patch.object(N, "_command", side_effect=self.query):
      for member, response in invalid:
        original = self.responses[member]
        with self.subTest(member=member, response=response):
          self.responses[member] = response
          with self.assertRaises(ValueError): N._power_ongoing(321)
        self.responses[member] = original
      original = self.units
      for unit in N.POWER_UNITS:
        with self.subTest(active_unit=unit):
          self.units = original.replace("Id=" + unit + "\nLoadState=loaded\nActiveState=inactive", "Id=" + unit + "\nLoadState=loaded\nActiveState=active")
          with self.assertRaises(ValueError): N._power_ongoing(321)

  def test_ongoing_exclusion_entry_is_strict_then_uses_power_only_guard(self):
    read_fd, write_fd = os.pipe()
    self.addCleanup(os.close, read_fd)
    self.addCleanup(os.close, write_fd)
    jobs = 'a(usssoo) 1 7 "dbus.service" "restart" "running" "/org/freedesktop/systemd1/job/7" "/org/freedesktop/systemd1/unit/dbus_2eservice"'
    with patch.object(N.os, "getppid", return_value=321), patch.object(N.os, "pidfd_open", side_effect=lambda pid: os.dup(read_fd)), patch.object(N, "_parent_identity", return_value="123"), patch.object(N, "_command", side_effect=self.query):
      with N._exclusion("activation", ongoing_power=True) as guard:
        self.responses["ListJobs"] = jobs
        guard()
        self.responses["ListInhibitors"] = "a(ssssuu) 0"
        with self.assertRaises(ValueError): guard()
      self.responses["ListInhibitors"] = 'a(ssssuu) 1 "shutdown:sleep" "' + N.WHO + '" "' + N.WHY + '" "block" 0 321'
      with self.assertRaisesRegex(ValueError, "Queued system jobs"):
        with N._exclusion("activation", ongoing_power=True): self.fail("nonempty startup jobs admitted")
      self.responses["ListJobs"] = "a(usssoo) 0"
      with N._exclusion("activation") as guard:
        self.responses["ListJobs"] = jobs
        with self.assertRaisesRegex(ValueError, "Queued system jobs"): guard()

  def test_ongoing_exclusion_retains_parent_identity_and_lifetime_checks(self):
    read_fd, write_fd = os.pipe()
    self.addCleanup(os.close, read_fd)
    self.addCleanup(os.close, write_fd)
    with patch.object(N.os, "getppid", return_value=321), patch.object(N.os, "pidfd_open", side_effect=lambda pid: os.dup(read_fd)), patch.object(N, "_parent_identity", return_value="123") as identity, patch.object(N, "_power_idle") as idle, patch.object(N, "_power_ongoing") as ongoing:
      with N._exclusion("activation", ongoing_power=True) as guard:
        guard()
        idle.assert_called_once_with(321)
        ongoing.assert_called_once_with(321)
        identity.return_value = "456"
        with self.assertRaisesRegex(ValueError, "exited or changed"): guard()
        self.assertEqual(ongoing.call_count, 1)
        identity.return_value = "123"
        ongoing.side_effect = lambda pid: setattr(identity, "return_value", "456")
        with self.assertRaisesRegex(ValueError, "during exclusion checks"): guard()
        identity.return_value = "123"
        ongoing.side_effect = None
        os.write(write_fd, b"dead")
        with self.assertRaisesRegex(ValueError, "exited or changed"): guard()
        self.assertEqual(ongoing.call_count, 2)
      for invalid in (None, "true", 1):
        with self.subTest(mode=invalid), self.assertRaises(ValueError):
          with N._exclusion("activation", ongoing_power=invalid): self.fail("ambiguous mode admitted")

  def test_escaped_exclusion_guard_refuses_before_queries_after_exact_fd_reuse(self):
    read_fd, write_fd = os.pipe()
    self.addCleanup(os.close, read_fd)
    self.addCleanup(os.close, write_fd)
    for mode in (False, True):
      opened = []
      def pidfd(pid):
        opened.append(os.dup(read_fd))
        return opened[-1]
      with self.subTest(ongoing_power=mode), patch.object(N.os, "getppid", return_value=321), patch.object(N.os, "pidfd_open", side_effect=pidfd), patch.object(N, "_parent_identity", return_value="123") as identity, patch.object(N, "_power_idle") as idle, patch.object(N, "_power_ongoing") as ongoing:
        with N._exclusion("activation", ongoing_power=mode) as guard: guard()
        # Reuse the closed pidfd number for a live unreadable pipe: liveness
        # and unchanged parent mocks alone would let an unscoped guard pass.
        reused = os.dup2(read_fd, opened[0])
        try:
          self.assertEqual(N.select.select([reused], [], [], 0)[0], [])
          identity.reset_mock()
          idle.reset_mock()
          ongoing.reset_mock()
          with patch.object(N.select, "select", side_effect=AssertionError("expired scope must not inspect a reused fd")):
            with self.assertRaisesRegex(ValueError, "scope has expired"): guard()
          identity.assert_not_called()
          idle.assert_not_called()
          ongoing.assert_not_called()
        finally: os.close(reused)

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
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1923214}
    report = {"audited_details": {"restore_protocol": {"resume": resume}}}
    product.ARTIFACTS.derive_artifacts.return_value = report
    product.TRIAL._private_json.side_effect = lambda path: config if path.name == "config.json" else {"approved": True}
    product.BOOT_POLICY.verify.return_value = True
    image_state = Mock()
    engine = SimpleNamespace(PRODUCT=product, IMAGE_STATE=image_state)
    metadata = SimpleNamespace(st_mode=0o40700, st_uid=0)
    with patch.object(Path, "lstat", return_value=metadata):
      N._precheck(engine, "activation", "before")
      product.check.assert_called_once()
      product._admission_state.assert_not_called()
      N._precheck(engine, "activation", "after")
      product.TRIAL._verify_deployment.assert_called_once_with(N.ROOT, config, report, source_default=True)
      arguments = product._admission_state.call_args.kwargs
      self.assertEqual(arguments["root"], Path("/"))
      self.assertNotIn("query", arguments)
      self.assertEqual(product.check.call_count, 1)
      self.assertEqual(image_state.require_no_image.call_args_list[0].args, (N.ROOT, resume))
      self.assertEqual(image_state.require_no_image.call_count, 2)
      with self.assertRaises(ValueError): N._precheck(engine, "deactivation", "after")
      self.assertEqual(image_state.require_no_image.call_count, 2)

  def test_precheck_captures_audited_resume_and_requires_it_unchanged(self):
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1923214}
    def run(phase, capture, current=resume):
      product = Mock()
      product.TRIAL._private_json.side_effect = lambda path: {
        "source_directory": "/source", "restore_directory": "/restore", "production_uki": "/production",
        "staged_receipt_sha256": "a" * 64} if path.name == "config.json" else {"approved": True}
      product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": current}}}
      product.BOOT_POLICY.verify.return_value = False
      with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)):
        return N._precheck(SimpleNamespace(PRODUCT=product, IMAGE_STATE=Mock()), "deactivation", phase, capture)
    capture = {}
    run("before", capture)
    self.assertEqual(capture["resume"], resume)
    self.assertIsNot(capture["resume"], resume)  # a private copy
    run("after", capture)
    with self.assertRaisesRegex(ValueError, "resume target changed"): run("after", capture, {**resume, "offset": 5})
    with self.assertRaisesRegex(ValueError, "resume target changed"): run("after", {})

  def test_no_image_required_after_admission_for_both_actions_and_phases(self):
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1923214}
    report = {"audited_details": {"restore_protocol": {"resume": resume}}}
    metadata = SimpleNamespace(st_mode=0o40700, st_uid=0)
    for action in ("activation", "deactivation"):
      for phase in ("before", "after"):
        with self.subTest(action=action, phase=phase):
          product, image_state = Mock(), Mock()
          product.TRIAL._private_json.side_effect = lambda path: {
            "source_directory": "/source", "restore_directory": "/restore", "production_uki": "/production",
            "staged_receipt_sha256": "a" * 64} if path.name == "config.json" else {"approved": True}
          product.ARTIFACTS.derive_artifacts.return_value = report
          product.BOOT_POLICY.verify.return_value = action == "activation"
          image_state.require_no_image.side_effect = ValueError("pending image")
          with patch.object(Path, "lstat", return_value=metadata), self.assertRaisesRegex(ValueError, "pending image"):
            N._precheck(SimpleNamespace(PRODUCT=product, IMAGE_STATE=image_state), action, phase)
          image_state.require_no_image.assert_called_once_with(N.ROOT, resume)
          if phase == "before":
            product.check.assert_called_once()
            product._admission_state.assert_not_called()
          else:
            product._admission_state.assert_called_once()

  def test_failed_product_admission_never_calls_image_check_as_substitute(self):
    metadata = SimpleNamespace(st_mode=0o40700, st_uid=0)
    for phase in ("before", "after"):
      product, image_state = Mock(), Mock()
      product.TRIAL._private_json.side_effect = lambda path: {
        "source_directory": "/source", "restore_directory": "/restore", "production_uki": "/production",
        "staged_receipt_sha256": "a" * 64} if path.name == "config.json" else {"approved": True}
      product.ARTIFACTS.derive_artifacts.return_value = {"audited_details": {"restore_protocol": {"resume": {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1}}}}
      product.BOOT_POLICY.verify.return_value = True
      if phase == "before": product.check.side_effect = ValueError("admission failed")
      else: product._admission_state.side_effect = ValueError("admission failed")
      with self.subTest(phase=phase), patch.object(Path, "lstat", return_value=metadata), self.assertRaisesRegex(ValueError, "admission failed"):
        N._precheck(SimpleNamespace(PRODUCT=product, IMAGE_STATE=image_state), "activation", phase)
      image_state.require_no_image.assert_not_called()

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

  def test_installed_image_import_follows_complete_inventory_gate(self):
    script = HERE / "hibernate/boot_policy_native.py"
    events = []
    engine = SimpleNamespace(_runtime=lambda root: events.append("engine runtime"))
    image = SimpleNamespace(require_no_image=Mock())
    def metadata(path):
      mode = 0o100600 if path == script else 0o40700
      return SimpleNamespace(st_mode=mode, st_uid=0, st_nlink=1)
    def specification(name, filename):
      events.append("import " + name)
      return SimpleNamespace(name=name, loader=SimpleNamespace(exec_module=lambda module: None))
    def module(specification):
      return engine if specification.name == "native_transition" else image
    with patch.object(N, "SCRIPT", script), patch.object(N.os, "geteuid", return_value=0), \
         patch.object(N.sys, "flags", SimpleNamespace(isolated=1)), patch.object(Path, "lstat", autospec=True, side_effect=metadata), \
         patch.object(Path, "is_symlink", return_value=False), patch.object(N, "_reviewed_tree", side_effect=lambda: events.append("reviewed tree")), \
         patch.object(N.importlib.util, "spec_from_file_location", side_effect=specification), \
         patch.object(N.importlib.util, "module_from_spec", side_effect=module):
      self.assertIs(N._installed().IMAGE_STATE, image)
    self.assertEqual(events, ["reviewed tree", "import native_transition", "engine runtime", "import native_reviewed_image_state"])

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


class Maintenance(unittest.TestCase):
  """Native maintenance wiring; every host query and reviewed byte source is mocked."""
  EXEC = ('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -B ' + str(N.SLEEP_ENTRY) +
          ' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }')

  def setUp(self):
    self.properties = {"LoadState": "loaded", "FragmentPath": N.VENDOR_UNIT, "DropInPaths": str(N.DROPIN), "ExecStart": self.EXEC}
    self.dropin = b"reviewed drop-in\n"
    self.reviewed = {"systemd-hibernate.conf": self.dropin, "sleep_entry.py": b"reviewed entry\n"}

  def show(self, argv):
    self.assertEqual(argv[:3], ("/usr/bin/systemctl", "show", "--no-pager"))
    return "\n".join(key + "=" + value for key, value in self.properties.items())

  def route(self):
    with patch.object(N, "_dropin_bytes", side_effect=lambda: self.dropin), patch.object(N, "_reviewed_identity", side_effect=lambda name: self.reviewed[name]), patch.object(N, "_command", side_effect=self.show):
      N._hibernate_route()

  def test_cli_accepts_only_fixed_maintenance_action(self):
    with patch.object(N, "native", return_value={"ok": True}) as native, patch("builtins.print"):
      self.assertEqual(N.main(["maintenance"]), 0)
      self.assertEqual(N.main(["assess"]), 0)
      for args in (["assess", "--root", "/tmp"], ["assess", "--force"], ["reactivate"], ["assess", "maintenance"]):
        with self.assertRaises(SystemExit): N.main(args)
    self.assertEqual([call.args for call in native.call_args_list], [("maintenance",), ("assess",)])
    self.assertEqual(N._inhibit_command("maintenance")[-1], "maintenance")

  def test_matching_reviewed_drop_in_and_effective_exec_start_pass(self):
    self.route()

  def test_drop_in_and_exec_start_drift_fail_closed(self):
    original = dict(self.properties)
    self.dropin = b"drifted drop-in\n"
    with self.assertRaisesRegex(ValueError, "drop-in differs"): self.route()
    self.dropin = self.reviewed["systemd-hibernate.conf"]
    variants = {
      "ExecStart": [self.EXEC.replace("-B ", "-I "), self.EXEC.replace(str(N.SLEEP_ENTRY), "/tmp/sleep_entry.py"),
                    self.EXEC.replace("path=/usr/bin/python3", "path=/usr/bin/python"), "", self.EXEC + " " + self.EXEC,
                    self.EXEC.replace("{ path", "{ ignore ; path"), self.EXEC.replace("ignore_errors=no", "ignore_errors=yes"),
                    self.EXEC.replace(" ; ignore_errors=no", "")],
      "ExecStartPre": ["{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }"],
      "ExecStartPost": ["{ path=/usr/bin/true }"], "ExecStop": ["{ path=/usr/bin/true }"],
      "ExecStopPost": ["{ path=/usr/bin/true }"], "ExecCondition": ["{ path=/usr/bin/true }"],
      "DropInPaths": ["", str(N.DROPIN) + " /etc/systemd/system/systemd-hibernate.service.d/other.conf"],
      "FragmentPath": ["/etc/systemd/system/systemd-hibernate.service", ""],
      "LoadState": ["masked", "not-found"]}
    for key, values in variants.items():
      for value in values:
        with self.subTest(key=key, value=value):
          self.properties = {**original, key: value}
          with self.assertRaises(ValueError): self.route()
    for name in N.EXEC_EXTRAS:
      # Empty (printed by --all) or omitted extras are fine.
      self.properties = {**original, name: ""}
      self.route()
    self.properties = {**original, "Extra": "x"}
    with self.assertRaises(ValueError): self.route()
    self.properties = {key: value for key, value in original.items() if key != "ExecStart"}
    with self.assertRaises(ValueError): self.route()

  def test_unreviewed_sleep_entry_bytes_fail_closed(self):
    with patch.object(N, "_dropin_bytes", return_value=self.dropin), patch.object(N, "_command", side_effect=self.show):
      def identity(name):
        if name == "sleep_entry.py": raise ValueError("Reviewed runtime file differs from approved inventory")
        return self.dropin
      with patch.object(N, "_reviewed_identity", side_effect=identity), self.assertRaisesRegex(ValueError, "approved inventory"):
        N._hibernate_route()

  def test_reviewed_identity_binds_bytes_to_inventory(self):
    raw = b"reviewed entry\n"
    review = json.dumps({"files": {"packages/t2-suspend/hibernate/sleep_entry.py": {"sha256": N.hashlib.sha256(raw).hexdigest(), "size": len(raw)}}}).encode()
    def private(path): return review if path.name == "runtime-deployment-review.json" else raw
    with patch.object(N, "_private_bytes", side_effect=private):
      self.assertEqual(N._reviewed_identity("sleep_entry.py"), raw)
      with self.assertRaisesRegex(ValueError, "approved inventory"): N._reviewed_identity("systemd-hibernate.conf")
    with patch.object(N, "_private_bytes", side_effect=lambda path: review if path.name == "runtime-deployment-review.json" else raw + b"x"):
      with self.assertRaisesRegex(ValueError, "approved inventory"): N._reviewed_identity("sleep_entry.py")

  def engine(self):
    fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    return fixture, SimpleNamespace(P=F.T.P, PRODUCT=F.T.PRODUCT, _transition=F.T._transition, _read=F.T._read,
                                    verify_fallback=F.T.verify_fallback, GATE_PHASES=F.T.GATE_PHASES, IMAGE_STATE=Mock())

  def test_vetoes_are_proven_behaviorally_against_reviewed_code(self):
    _, engine = self.engine()
    base = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "probe"
    with patch.object(N, "PROBE_BASE", base), patch.object(N, "SLEEP_ENTRY", HERE / "hibernate/sleep_entry.py"):
      N._maintenance_vetoes(engine)
      # An old sleep entry that ignores the marker name is refused.
      old = HERE / "hibernate/sleep_entry.py"
      stale = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "sleep_entry.py"
      stale.write_bytes(old.read_bytes().replace(b', "package-maintenance.pending"', b""))
      with patch.object(N, "SLEEP_ENTRY", stale), self.assertRaisesRegex(ValueError, "lacks maintenance veto"):
        N._maintenance_vetoes(engine)
      engine.PRODUCT = SimpleNamespace(verify_deployment=lambda *args: None)
      with self.assertRaisesRegex(ValueError, "does not veto"): N._maintenance_vetoes(engine)
      engine.PRODUCT = F.T.PRODUCT
      engine._transition = lambda *args, **kwargs: None
      with self.assertRaisesRegex(ValueError, "does not veto"): N._maintenance_vetoes(engine)

  def test_probe_base_is_fixed_private_and_ignores_tmpdir(self):
    parent = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
    base = parent / "probe"
    _, engine = self.engine()
    seen = []
    original = N.tempfile.TemporaryDirectory
    def record(*args, **kwargs):
      seen.append(kwargs.get("dir"))
      return original(*args, **kwargs)
    with patch.dict(os.environ, {"TMPDIR": str(parent / "hostile")}), patch.object(N, "PROBE_BASE", base), \
         patch.object(N, "SLEEP_ENTRY", HERE / "hibernate/sleep_entry.py"), patch.object(N.tempfile, "TemporaryDirectory", side_effect=record):
      N._maintenance_vetoes(engine)
    self.assertEqual(seen, [base])
    self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
    for prepare in (lambda: base.chmod(0o755), lambda: (base.rmdir(), base.symlink_to(parent))):
      prepare()
      with patch.object(N, "PROBE_BASE", base), self.assertRaisesRegex(ValueError, "private probe directory"): N._probe_base()
      if base.is_symlink(): base.unlink()
      else: base.chmod(0o700)
    with patch.object(N.os, "geteuid", return_value=os.geteuid() + 1), patch.object(N, "PROBE_BASE", parent / "other"):
      with self.assertRaisesRegex(ValueError, "private probe directory"): N._probe_base()

  def test_gate_phases_bind_backup_then_live_fallback_and_final_no_image(self):
    fixture, engine = self.engine()
    fixture.run_action()
    events = []
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1}
    pinned = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 2}  # archived evidence, deliberately not what a fresh audit yields
    engine._pinned_resume = lambda root: pinned
    engine.IMAGE_STATE.require_no_image.side_effect = lambda root, value: events.append(("image", value))
    engine.verify_fallback = lambda root, raw=None: events.append(("fallback", raw is not None))
    with patch.object(N, "ROOT", fixture.root), patch.object(N, "_hibernate_route", side_effect=lambda: events.append("route")), \
         patch.object(N, "_maintenance_vetoes", side_effect=lambda engine: events.append("vetoes")), patch.object(N, "_resume", side_effect=lambda engine: events.append("derive") or resume):
      expected = {"before": ["route", "vetoes", ("fallback", True)], "after": ["route", "vetoes", ("fallback", False)],
                  "final": ["route", "vetoes", ("fallback", False), "derive", ("image", resume)],
                  "retained": ["route", "vetoes", ("fallback", False), ("image", pinned)]}  # retained never derives artifacts
      for phase, sequence in expected.items():
        events.clear()
        with self.subTest(phase=phase):
          N._maintenance_gate(engine, fixture.root, phase)
          self.assertEqual(events, sequence)
      events.clear()
      N._maintenance_gate(engine, fixture.root, "final", {"resume": resume})  # publisher: fresh audit equals the archived tuple
      with self.assertRaisesRegex(ValueError, "archived evidence"): N._maintenance_gate(engine, fixture.root, "final", {"resume": pinned})
      with self.assertRaisesRegex(ValueError, "archived evidence"): N._maintenance_gate(engine, fixture.root, "final", {})
      with self.assertRaises(ValueError): N._maintenance_gate(engine, fixture.root, "unknown")
      with self.assertRaises(ValueError): N._maintenance_gate(engine, fixture.root.parent, "before")
      # Each prerequisite failure propagates; the image check cannot be skipped by a later phase.
      engine.IMAGE_STATE.require_no_image.side_effect = ValueError("saved image present")
      with self.assertRaisesRegex(ValueError, "saved image"): N._maintenance_gate(engine, fixture.root, "final")
      engine.IMAGE_STATE.require_no_image.side_effect = None
      for name in ("_hibernate_route", "_maintenance_vetoes"):
        with patch.object(N, name, side_effect=ValueError("drift")), self.assertRaisesRegex(ValueError, "drift"):
          N._maintenance_gate(engine, fixture.root, "before")

  def dispatch(self, marker_present, callbacks=lambda engine: None, pending_present=False):
    from contextlib import contextmanager
    @contextmanager
    def exclusion(action):
      self.assertEqual(action, "maintenance")
      yield lambda: None
    engine = Mock()
    engine.MAINTENANCE = Path("var/lib/omarchy/t2-hibernate-product/package-maintenance.pending")
    engine.PENDINGS = {"deactivation": Path("var/lib/omarchy/t2-hibernate-product/source-default-deactivation.pending")}
    engine._present.side_effect = lambda path: marker_present if path.name == "package-maintenance.pending" else pending_present
    engine._complete_interrupted_maintenance.return_value = {"completed_interrupted_maintenance": True, "qualification_issued": False}
    engine._transition.return_value = {"qualification_issued": False, "live_execution": False}
    engine._verify_existing_maintenance.return_value = {"already_inactive": True, "qualification_issued": False}
    with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_exclusion", side_effect=exclusion), patch.object(N, "_maintenance_gate") as gate:
      precheck = None  # tests patch N._precheck themselves when they need it
      result = N.native("maintenance")
      callbacks(engine)
    return engine, precheck, gate, result

  def test_native_maintenance_dispatch_uses_fixed_root_capability_and_gate(self):
    def callbacks(engine):
      arguments = engine._transition.call_args
      arguments.kwargs["precheck"](Path("/"), "deactivation", "before")
      arguments.kwargs["maintenance_gate"](Path("/"), "final")
      self.captured = precheck_capture()
      self.provider = arguments.kwargs["maintenance_resume"]
    precheck_capture = lambda: precheck_mock.call_args.args[3]
    def record(*args):  # stand in for _precheck: it stores the audited tuple in the shared capture
      args[3]["resume"] = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 9}
    with patch.object(N, "_precheck", side_effect=record) as precheck_mock:
      engine, precheck, gate, result = self.dispatch(False, callbacks)
    self.assertEqual(self.provider(), {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 9})  # archived tuple = audited tuple
    with patch.object(N, "_baseline", return_value={"kernel": {}}) as baseline:  # live publication always supplies the baseline provider
      self.assertEqual(engine._transition.call_args.kwargs["maintenance_baseline"](), {"kernel": {}})
      baseline.assert_called_once_with(engine, Path("/"))
    arguments = engine._transition.call_args
    self.assertEqual(arguments.args, (Path("/"), "maintenance"))
    self.assertIs(arguments.kwargs["native"], engine._NATIVE_MAINTENANCE)
    self.assertNotIn("recover", arguments.kwargs)
    self.assertNotIn("maintenance_continuation", arguments.kwargs)
    precheck_mock.assert_called_once_with(engine, "deactivation", "before", self.captured)
    gate.assert_called_once_with(engine, Path("/"), "final", self.captured)
    engine._verify_existing_maintenance.assert_not_called()
    self.assertTrue(result["live_execution"])
    self.assertFalse(result["power_operation"])
    self.assertFalse(result["qualification_issued"])

  def test_native_maintenance_completes_only_marker_plus_deactivation_pending(self):
    engine, precheck, gate, result = self.dispatch(True, lambda engine: engine._complete_interrupted_maintenance.call_args.kwargs["gate"](Path("/"), "final"), pending_present=True)
    engine._transition.assert_not_called()
    engine._verify_existing_maintenance.assert_not_called()
    arguments = engine._complete_interrupted_maintenance.call_args
    self.assertEqual(arguments.args, (Path("/"),))
    self.assertIs(arguments.kwargs["native"], engine._NATIVE_MAINTENANCE)
    self.assertEqual(gate.call_args.args[:3], (engine, Path("/"), "final"))
    self.assertIs(gate.call_args.args[3], arguments.kwargs["pinned"])  # archived tuple flows into the final gate's pin
    self.assertTrue(result["completed_interrupted_maintenance"] and result["live_execution"] and not result["power_operation"])
    # A pending without a marker is still the publisher's incomplete state, never completed here.
    engine, *_ = self.dispatch(False, pending_present=True)
    engine._complete_interrupted_maintenance.assert_not_called()
    engine._transition.assert_called_once()

  def test_native_maintenance_reentry_is_read_only_verification(self):
    engine, precheck, gate, result = self.dispatch(True, lambda engine: engine._verify_existing_maintenance.call_args.kwargs["gate"](Path("/"), "retained"))
    engine._transition.assert_not_called()
    arguments = engine._verify_existing_maintenance.call_args
    self.assertEqual(arguments.args, (Path("/"),))
    self.assertIs(arguments.kwargs["native"], engine._NATIVE_MAINTENANCE)
    self.assertEqual(gate.call_args.args[:3], (engine, Path("/"), "retained"))
    gate.assert_called_once()
    self.assertTrue(result["already_inactive"])
    self.assertTrue(result["live_execution"])

  def test_native_maintenance_still_refuses_workspace_and_nonisolated_invocation(self):
    with patch.object(N.os, "execve", side_effect=AssertionError("no inhibitor")), patch.object(N, "_command", side_effect=AssertionError("no host queries")):
      with self.assertRaises(ValueError): N.native("maintenance")


DRIVER = load("assess_driver_inventory", HERE / "hibernate/root_driver_inventory.py")
CONTROL = load("assess_control_inventory", HERE / "hibernate/root_control_inventory.py")
STATE_DIR = "var/lib/omarchy/t2-hibernate-product"
ARTIFACTS = "/" + STATE_DIR + "/artifacts"


class Assess(unittest.TestCase):
  """Baseline sidecar and read-only assessment against a disposable root; nothing touches the host."""
  RELEASE = "7.2.6-fixture-t2"

  def query(self, argv):
    if argv[1] == "-b":
      name = argv[-1]
      return str(self.root / "lib/modules" / self.RELEASE / "updates/dkms" / (name + ".ko.zst"))
    if argv[2] == "srcversion": return "A1B2C3D4E5F60718293A4B5C"
    return self.RELEASE + " SMP preempt mod_unload"

  def write(self, relative, raw, mode=0o600):
    path = self.f.write(relative, raw)
    path.chmod(mode)
    return path

  def setUp(self):
    self.fx = F.NativeMaintenance("test_happy_path_publishes_durable_marker_and_vetoes_every_route")
    self.fx.setUp()
    self.addCleanup(self.fx.doCleanups)
    self.root, self.f, self.T = self.fx.root, self.fx.f, F.T
    self.running = self.RELEASE
    for target, replacement in (("_driver_capture", lambda root, release: DRIVER.capture(root, release, query=self.query)),
                                ("_control_capture", CONTROL.capture), ("_running_release", lambda: self.running)):
      patcher = patch.object(N, target, replacement)
      patcher.start()
      self.addCleanup(patcher.stop)
    self.config = {"source_directory": ARTIFACTS + "/source", "restore_directory": ARTIFACTS + "/restore",
                   "production_uki": "/boot/EFI/Linux/omarchy_linux-t2.efi", "audited_details_sha256": "a" * 64,
                   "staged_receipt_sha256": self.T.P.digest(self.f.raw),
                   "manifest": {"protocol": "fixture", "runtime_sha256": "b" * 64, "source_sha256": "c" * 64}}
    self.write_config()
    self.write(STATE_DIR + "/qualification.json", b'{"approved":true}')
    for role in ("source", "restore"):
      self.write(STATE_DIR + "/artifacts/" + role + "/provenance.json", json.dumps({"kernel_release": self.RELEASE, "modules": {"t2bce_core": {"sha256": role}}}).encode())
      self.write(STATE_DIR + "/artifacts/" + role + "/mba-t2-hibernation-candidate.efi", (role + " uki").encode())
      self.write(STATE_DIR + "/artifacts/" + role + "/mba-t2-hibernation-candidate.initrd", (role + " initrd").encode())
    (self.root / "lib").symlink_to("usr/lib")
    for name in DRIVER.MODULES: self.write("usr/lib/modules/" + self.RELEASE + "/updates/dkms/" + name + ".ko.zst", (name + " bytes").encode())
    for suffix in DRIVER.SUFFIXES: self.write("usr/lib/firmware/brcm/" + DRIVER.FORMOSA + suffix, ("firmware " + suffix).encode())

  def write_config(self, **changes):
    self.write(STATE_DIR + "/config.json", json.dumps({**self.config, **changes}).encode())

  def publish(self):
    return self.T._transition(self.root, "maintenance", precheck=self.fx.fixture.check, guard=lambda: None, maintenance_gate=self.fx.gate,
                              maintenance_resume=lambda: dict(F.RESUME), maintenance_baseline=lambda: N._baseline(self.T, self.root))

  def assess(self): return N.assess(self.T, self.root)

  def published(self):
    self.result = self.publish()
    return self

  def fresh(self):
    other = Assess("test_unchanged_generation_reports_every_item_equal")
    other.setUp()
    self.addCleanup(other.doCleanups)
    return other.published()

  def archive(self): return self.root / self.T.HISTORY / self.result["transition_id"]

  def snapshot(self):
    state = {}
    for path in sorted(self.root.rglob("*")) + [self.root]:
      info = path.lstat()
      content = os.readlink(path) if stat.S_ISLNK(info.st_mode) else (path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
      state[str(path.relative_to(self.root))] = (info.st_mode, info.st_ino, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns, content)
    return state

  def coherent_kernel_update(self, image=b"updated production image"):
    old = (self.root / self.T.PRODUCTION).read_bytes()
    limine = (self.root / self.T.P.LIMINE).read_bytes()
    (self.root / self.T.PRODUCTION).write_bytes(image)
    self.f.write(self.T.P.LIMINE, limine.replace(hashlib.blake2b(old).hexdigest().encode(), hashlib.blake2b(image).hexdigest().encode()))

  def test_unchanged_generation_reports_every_item_equal(self):
    self.published()
    report = self.assess()
    self.assertEqual(report["class"], "unchanged")
    self.assertEqual(set(report["items"]), set(self.T.BASELINE_ITEMS))
    self.assertTrue(all(item == {"state": "equal"} for item in report["items"].values()))
    self.assertEqual(report["limine"], {"exact_equal": True, "stock_projection_equal": True, "state": "equal"})
    self.assertEqual((report["changed_items"], report["unknown_items"]), ([], []))
    self.assertEqual(report["transition_id"], self.result["transition_id"])
    self.assertEqual(report["maintenance_intent_sha256"], self.result["maintenance_intent_sha256"])
    self.assertEqual((report["read_only"], report["reactivation_evaluated"], report["qualification_issued"]), (True, False, False))
    self.assertEqual(json.loads(json.dumps(report, sort_keys=True)), report)
    baseline = self.T.read_baseline(self.root)
    self.assertEqual(baseline["kernel"], {"running_release": self.RELEASE, "qualified_release": self.RELEASE, "installed_releases": [self.RELEASE]})
    self.assertEqual(baseline["source_uki"], {"sha256": hashlib.sha256(b"source uki").hexdigest(), "blake2b": hashlib.blake2b(b"source uki").hexdigest(), "size": 10})
    self.assertEqual(baseline["production_uki"]["sha256"], hashlib.sha256((self.root / self.T.PRODUCTION).read_bytes()).hexdigest())
    self.assertEqual(baseline["config"]["sha256"], hashlib.sha256((self.root / self.T.P.STATE / "config.json").read_bytes()).hexdigest())
    self.assertEqual(baseline["manifest"]["fields"], self.config["manifest"])
    self.assertEqual(set(baseline["driver_modules"]["modules"]), set(DRIVER.MODULES))
    self.assertEqual(len(baseline["firmware"]["files"]), 5)
    self.assertNotIn("boot/limine.conf", baseline["control_inventory"]["files"])  # rewritten by every snapshot sync and by our own deactivation
    self.assertEqual(baseline["bootloader"]["files"], {name: {"present": False} for name in N.BOOTLOADERS})
    self.assertEqual(baseline["limine"], self.T.stock_identity(self.f.before))

  def test_each_changed_item_requires_requalification(self):
    def limine_cmdline(other):
      raw = (other.root / other.T.P.LIMINE).read_bytes()
      other.f.write(other.T.P.LIMINE, raw.replace(b"protocol: efi\n", b"protocol: efi\ncmdline: root=/dev/other\n", 1))
    def config_changes(other): other.write_config(audited_details_sha256="d" * 64)
    def manifest_changes(other): other.write_config(manifest={**other.config["manifest"], "source_sha256": "e" * 64})
    def write(relative, raw=b"changed"): return lambda other: other.write(relative, raw)
    state, module = STATE_DIR + "/artifacts/", "usr/lib/modules/" + self.RELEASE + "/updates/dkms/t2bce_core.ko.zst"
    cases = {
      "kernel": (lambda other: (other.root / "usr/lib/modules/7.3.0-new").mkdir(), ["kernel"]),
      "production_uki": (lambda other: other.coherent_kernel_update(), ["production_uki"]),
      "source_uki": (write(state + "source/mba-t2-hibernation-candidate.efi"), ["source_uki"]),
      "restore_uki": (write(state + "restore/mba-t2-hibernation-candidate.efi"), ["restore_uki"]),
      "module_stack initrd": (write(state + "restore/mba-t2-hibernation-candidate.initrd"), ["module_stack"]),
      "module_stack provenance": (write(state + "source/provenance.json", json.dumps({"kernel_release": self.RELEASE, "modules": {"t2bce_core": {"sha256": "new"}}}).encode()), ["module_stack"]),
      "config": (config_changes, ["config"]), "manifest": (manifest_changes, None),
      "qualification": (write(STATE_DIR + "/qualification.json", b'{"approved":true,"new":1}'), ["qualification"]),
      "driver_modules": (write(module), ["driver_modules"]),
      "firmware": (write("usr/lib/firmware/brcm/" + DRIVER.FORMOSA + ".bin"), ["firmware"]),
      "control_inventory": (write("etc/modprobe.d/t2.conf"), ["control_inventory"]),
      "bootloader": (write("boot/EFI/BOOT/BOOTX64.EFI"), ["bootloader"]),
      "limine stock projection": (limine_cmdline, ["limine"])}
    for label, (mutate, expected) in cases.items():
      with self.subTest(label):
        other = self.fresh()
        before = other.assess()
        self.assertEqual(before["class"], "unchanged")
        mutate(other)
        report = other.assess()
        self.assertEqual(report["class"], "requalification-required")
        if expected is not None: self.assertEqual(report["changed_items"], expected)
        else: self.assertIn(label, report["changed_items"])
        self.assertEqual(report["unknown_items"], [])
    other = self.fresh()  # the running kernel alone
    other.running = "7.3.0-new"
    report = other.assess()
    self.assertEqual((report["class"], report["changed_items"]), ("requalification-required", ["kernel"]))
    self.assertEqual(report["items"]["kernel"]["paths"], ["/running_release"])

  def test_snapshot_churn_alone_never_requires_requalification(self):
    self.published()
    for numbers, reverse in (([1], False), ([1, 2], False), ([2, 3, 4], True), ([], False)):
      self.f.write(self.T.P.LIMINE, F.with_snapshots((self.root / self.T.P.LIMINE).read_bytes(), numbers, reverse))
      report = self.assess()
      self.assertEqual(report["class"], "unchanged", numbers)
      self.assertTrue(report["limine"]["stock_projection_equal"])
      self.assertEqual(report["limine"]["exact_equal"], not numbers)
      self.assertEqual(report["changed_items"], [])
    self.f.write(self.T.P.LIMINE, F.with_snapshots((self.root / self.T.P.LIMINE).read_bytes(), [5]))
    self.coherent_kernel_update(b"kernel update with churn")
    report = self.assess()
    self.assertEqual((report["class"], report["changed_items"]), ("requalification-required", ["production_uki"]))
    self.assertEqual((report["limine"]["exact_equal"], report["limine"]["stock_projection_equal"]), (False, True))
    self.f.write(self.T.P.LIMINE, (self.root / self.T.P.LIMINE).read_bytes().replace(b"default_entry: 2", b"default_entry: 5"))
    report = self.assess()  # a promoted snapshot default is not stock: the guard's validator refuses the evidence
    self.assertEqual(report["class"], "unknown")
    self.assertIn("canonical stock default 2", report["reason"])

  def test_missing_or_forged_baseline_means_unknown(self):
    other = self.fresh()
    path = other.archive() / self.T.BASELINE_NAME
    good = path.read_bytes()
    document = json.loads(good)
    path.unlink()
    report = other.assess()
    self.assertEqual((report["class"], report["baseline"]), ("unknown", "missing"))
    self.assertNotIn("items", report)
    forged = {"garbage": b"{", "not canonical": good + b"\n", "other transition": self.T._encoded({**document, "transition_id": str(uuid.uuid4())}),
              "other intent": self.T._encoded({**document, "maintenance_intent_sha256": "0" * 64}),
              "extra item": self.T._encoded({**document, "items": {**document["items"], "extra": {}}}),
              "everything equal but unbound": self.T._encoded({**document, "old_policy_sha256": "1" * 64}),
              "extra field": self.T._encoded({**document, "extra": 1})}
    for label, raw in forged.items():
      with self.subTest(label):
        path.write_bytes(raw)
        path.chmod(0o600)
        report = other.assess()
        self.assertEqual((report["class"], report["baseline"]), ("unknown", "invalid"))
    path.write_bytes(good)
    self.assertEqual(other.assess()["class"], "unchanged")
    # The marker cannot vouch for item values (its field set is fixed by the guard): a canonical, correctly bound
    # document with edited values is trusted as written, and such an edit can only surface as a difference.
    path.write_bytes(good.replace(b'"installed_releases":["' + self.RELEASE.encode() + b'"]', b'"installed_releases":[]'))
    self.assertEqual(other.assess()["changed_items"], ["kernel"])
    path.write_bytes(good)
    # A fixture publication without a provider archives no sidecar, so nothing can be claimed later.
    older = Assess("test_unchanged_generation_reports_every_item_equal")
    older.setUp()
    self.addCleanup(older.doCleanups)
    older.result = older.T._transition(older.root, "maintenance", precheck=older.fx.fixture.check, guard=lambda: None,
                                       maintenance_gate=older.fx.gate, maintenance_resume=lambda: dict(F.RESUME))
    self.assertFalse((older.archive() / self.T.BASELINE_NAME).exists())
    self.assertEqual(older.assess()["baseline"], "missing")
    self.assertEqual(older.assess()["class"], "unknown")

  def test_unreadable_items_are_unknown_and_never_unchanged(self):
    other = self.fresh()
    for name in list((other.root / "usr/lib/firmware/brcm").iterdir()): name.unlink()
    report = other.assess()
    self.assertEqual(report["class"], "unknown")
    self.assertEqual(report["unknown_items"], ["driver_modules", "firmware"])
    self.assertEqual(report["items"]["control_inventory"], {"state": "equal"})
    self.assertIn("firmware", report["items"]["firmware"]["reason"])
    # A definite change outranks an unreadable item.
    other.coherent_kernel_update()
    report = other.assess()
    self.assertEqual((report["class"], report["changed_items"], report["unknown_items"]), ("requalification-required", ["production_uki"], ["driver_modules", "firmware"]))
    # A tolerated item that could not be captured at publication stays unknown, the core items still compare.
    third = Assess("test_unchanged_generation_reports_every_item_equal")
    third.setUp()
    self.addCleanup(third.doCleanups)
    with patch.object(N, "_control_capture", side_effect=ValueError("control unreadable at publication")):
      third.published()
    self.assertIn("unavailable", third.T.read_baseline(third.root)["control_inventory"])
    report = third.assess()
    self.assertEqual((report["class"], report["unknown_items"]), ("unknown", ["control_inventory"]))
    self.assertIn("baseline item unavailable", report["items"]["control_inventory"]["reason"])

  def test_publication_refuses_when_the_qualified_core_identity_is_unavailable(self):
    for label, relative in (("source uki", STATE_DIR + "/artifacts/source/mba-t2-hibernation-candidate.efi"), ("config", STATE_DIR + "/config.json"),
                            ("provenance", STATE_DIR + "/artifacts/restore/provenance.json"), ("qualification", STATE_DIR + "/qualification.json"),
                            ("production", "boot/EFI/Linux/omarchy_linux-t2.efi")):
      with self.subTest(label):
        other = Assess("test_unchanged_generation_reports_every_item_equal")
        other.setUp()
        self.addCleanup(other.doCleanups)
        (other.root / relative).unlink()
        before = other.fx.tree()
        with self.assertRaises((ValueError, FileNotFoundError)): other.publish()
        self.assertEqual(other.fx.tree(), before)
        self.assertFalse(any(other.fx.pending_names()) or (other.root / self.T.MAINTENANCE).exists())

  def test_assess_writes_nothing_leaves_no_lock_and_never_blocks(self):
    other = self.fresh()
    opened = []
    real_open = os.open
    def spy(path, flags, *args, **kwargs):
      if flags & (os.O_WRONLY | os.O_TRUNC | os.O_EXCL) or (flags & os.O_CREAT and not os.path.lexists(path)):
        raise AssertionError("assess opened for writing/creation: " + str(path))
      opened.append(str(path))
      return real_open(path, flags, *args, **kwargs)
    scenarios = {"unchanged": lambda: None, "snapshot churn": lambda: other.f.write(self.T.P.LIMINE, F.with_snapshots((other.root / self.T.P.LIMINE).read_bytes(), [3])),
                 "changed": lambda: other.coherent_kernel_update(), "missing baseline": lambda: (other.archive() / self.T.BASELINE_NAME).unlink()}
    for label, mutate in scenarios.items():
      with self.subTest(label):
        mutate()
        before = other.snapshot()
        with patch.object(N.os, "open", side_effect=spy):
          report = other.assess()
        after = other.snapshot()
        self.assertEqual([name for name in after if after[name] != before.get(name)], [], label)  # every byte, mode, inode and timestamp
        self.assertEqual(set(after), set(before))
        self.assertFalse((other.root / self.T.DB_LOCK).exists())
        self.assertTrue(report["read_only"])
        held = os.open(other.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
        try: fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released: assess left no flock behind
        finally: os.close(held)
        ledger = os.open(other.root / self.T.P.STATE / "ledger/lock", os.O_RDWR)
        try: fcntl.flock(ledger, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(ledger)
    self.assertTrue(opened)
    # Busy locks report unknown without waiting, changing anything or leaving a lock.
    before = other.snapshot()
    held = os.open(other.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      busy = other.assess()
    finally: os.close(held)
    self.assertEqual((busy["class"], busy["busy"]), ("unknown", True))
    ledger = os.open(other.root / self.T.P.STATE / "ledger/lock", os.O_RDWR)
    try:
      fcntl.flock(ledger, fcntl.LOCK_EX | fcntl.LOCK_NB)
      self.assertEqual(other.assess()["class"], "unknown")
    finally: os.close(ledger)
    (other.root / self.T.DB_LOCK).write_bytes(b"pacman")
    pacman = other.assess()
    self.assertEqual((pacman["class"], pacman["busy"]), ("unknown", True))
    self.assertEqual((other.root / self.T.DB_LOCK).read_bytes(), b"pacman")
    (other.root / self.T.DB_LOCK).unlink()
    settled = other.snapshot()  # only the test's own db.lck write touched its directory entry
    self.assertEqual({k: v for k, v in settled.items() if k != "var/lib/pacman"}, {k: v for k, v in before.items() if k != "var/lib/pacman"})

  def test_assess_without_maintenance_evidence_is_unknown_and_does_not_wire_admission(self):
    report = self.assess()  # the fixture is still active source-default: no marker exists
    self.assertEqual(report["class"], "unknown")
    self.assertFalse((self.root / self.T.MAINTENANCE).exists())
    self.published()
    with patch.object(self.T.PRODUCT, "check", side_effect=AssertionError("no product admission")), \
         patch.object(self.T.PRODUCT.ARTIFACTS, "derive_artifacts", side_effect=AssertionError("no artifact derivation")):
      self.assertEqual(self.assess()["class"], "unchanged")
    (self.root / self.T.MAINTENANCE).write_bytes(b"foreign")
    self.assertEqual(self.assess()["class"], "unknown")

  def test_native_assess_takes_no_inhibitor_and_no_exclusion(self):
    engine = Mock()
    with patch.object(N, "_installed", return_value=engine), patch.object(N, "assess", return_value={"class": "unchanged"}) as assess, \
         patch.object(N.os, "execve", side_effect=AssertionError("no inhibitor")), patch.object(N, "_exclusion", side_effect=AssertionError("no exclusion")):
      self.assertEqual(N.native("assess"), {"class": "unchanged"})
    assess.assert_called_once_with(engine, Path("/"))
    engine._transition.assert_not_called()
    with patch.object(N.os, "execve", side_effect=AssertionError("no inhibitor")), patch.object(N, "_command", side_effect=AssertionError("no host queries")):
      with self.assertRaises(ValueError): N.native("assess")  # workspace/nonroot invocation refuses before anything runs


if __name__ == "__main__": unittest.main()
