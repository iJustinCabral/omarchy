"""Offline native wiring tests; never invoke host power/inhibitor/lock operations."""
import contextlib
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
      self.assertEqual(N.main(["reactivate"]), 0)
      for args in (["assess", "--root", "/tmp"], ["assess", "--force"], ["reactivate", "--root", "/tmp"], ["reactivate", "--force"], ["reactivate", "--approve"], ["assess", "maintenance"]):
        with self.assertRaises(SystemExit): N.main(args)
    self.assertEqual([call.args for call in native.call_args_list], [("maintenance",), ("assess",), ("reactivate",)])
    self.assertEqual(N._inhibit_command("maintenance")[-1], "maintenance")
    self.assertEqual(N._inhibit_command("reactivate")[-1], "reactivate")

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
    engine.reactivation_pending.return_value = False
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


class AssessFixture(unittest.TestCase):
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
    for target, replacement in (("_driver_capture", lambda root, release: DRIVER.capture_baseline(root, release, query=self.query)),
                                ("_control_capture", lambda root: CONTROL.capture(root, baseline=True)), ("_running_release", lambda: self.running)):
      patcher = patch.object(N, target, replacement)
      patcher.start()
      self.addCleanup(patcher.stop)
    self.config = {"source_directory": ARTIFACTS + "/source", "restore_directory": ARTIFACTS + "/restore",
                   "production_uki": "/boot/EFI/Linux/omarchy_linux-t2.efi", "audited_details_sha256": "a" * 64,
                   "staged_receipt_sha256": self.T.P.digest(self.f.raw),
                   "manifest": {"protocol": "fixture", "runtime_sha256": "b" * 64,
                                **{role + "_sha256": hashlib.sha256((role + " uki").encode()).hexdigest() for role in ("source", "restore")}}}
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

  def mutation_cases(self):
    """Every single-item change the assessment must classify as requalification-required: label -> (mutate(other), changed items or None)."""
    def limine_cmdline(other):
      raw = (other.root / other.T.P.LIMINE).read_bytes()
      other.f.write(other.T.P.LIMINE, raw.replace(b"protocol: efi\n", b"protocol: efi\ncmdline: root=/dev/other\n", 1))
    def config_changes(other): other.write_config(audited_details_sha256="d" * 64)
    def manifest_changes(other): other.write_config(manifest={**other.config["manifest"], "protocol": "fixture-2"})
    def write(relative, raw=b"changed"): return lambda other: other.write(relative, raw)
    state, module = STATE_DIR + "/artifacts/", "usr/lib/modules/" + self.RELEASE + "/updates/dkms/hci_bcm4377.ko.zst"
    cases = {
      "kernel": (lambda other: (other.root / "usr/lib/modules/7.3.0-new").mkdir(), ["kernel"]),
      "production_uki": (lambda other: other.coherent_kernel_update(), ["production_uki"]),
      # A changed source/restore UKI no longer matches the manifest pin: fail closed as unknown (see ArtifactOwnership).
      "module_stack initrd": (write(state + "restore/mba-t2-hibernation-candidate.initrd"), ["module_stack"]),
      "module_stack provenance": (write(state + "source/provenance.json", json.dumps({"kernel_release": self.RELEASE, "modules": {"t2bce_core": {"sha256": "new"}}}).encode()), ["module_stack"]),
      "config": (config_changes, ["config"]), "manifest": (manifest_changes, None),
      "qualification": (write(STATE_DIR + "/qualification.json", b'{"approved":true,"new":1}'), ["qualification"]),
      "driver_modules": (write(module), ["driver_modules"]),
      "firmware": (write("usr/lib/firmware/brcm/" + DRIVER.FORMOSA + ".bin"), ["firmware"]),
      "control_inventory": (write("etc/modprobe.d/t2.conf"), ["control_inventory"]),
      "bootloader": (write("boot/EFI/BOOT/BOOTX64.EFI"), ["bootloader"]),
      "limine stock projection": (limine_cmdline, ["limine"])}
    return cases



USER_UID = 4242


class ArtifactOwnership(AssessFixture):
  """The live gate: qualified artifacts belong to the operator's account while the runtime and its state are root's.

  A different-owner fixture cannot be chowned unprivileged, so the artifact tree
  is presented under another uid exactly where the check reads metadata.
  """
  def as_user(self, *, file_uid=USER_UID):
    real_lstat, real_fstat = Path.lstat, os.fstat
    marker = "/" + STATE_DIR + "/artifacts"
    def view(info, path):
      path = str(path)
      if marker not in path: return info
      uid = file_uid if path.endswith((".efi", ".initrd", ".json")) else USER_UID
      fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
      return SimpleNamespace(**{**fields, "st_uid": uid})
    def lstat(path, *args, **kwargs): return view(real_lstat(path, *args, **kwargs), path)
    def fstat(fd): return view(real_fstat(fd), os.readlink("/proc/self/fd/" + str(fd)))
    stack = contextlib.ExitStack()
    stack.enter_context(patch.object(Path, "lstat", lstat))
    stack.enter_context(patch.object(os, "fstat", fstat))
    return stack

  def dir(self, role): return self.root / STATE_DIR / "artifacts" / role

  def test_user_owned_artifacts_publish_and_record_the_manifest_identities(self):
    with self.as_user():
      self.published()
      baseline = self.T.read_baseline(self.root)
      for role in ("source", "restore"):
        self.assertEqual(baseline[role + "_uki"]["sha256"], self.config["manifest"][role + "_sha256"])
      self.assertEqual(baseline["kernel"]["qualified_release"], self.RELEASE)
      self.assertNotIn("unavailable", baseline["module_stack"])
      report = self.assess()
    self.assertEqual((report["class"], report["unknown_items"], report["changed_items"]), ("unchanged", [], []))

  def test_manifest_pin_mismatch_fails_closed(self):
    with self.as_user():
      for role in ("source", "restore"):
        self.write_config(manifest={**self.config["manifest"], role + "_sha256": "e" * 64})
        items, errors = N.generation_items(self.T, self.root)
        self.assertIn("manifest pin", errors[role + "_uki"])
        self.assertIn(role + "_uki", errors)
        with self.assertRaisesRegex(ValueError, "identity unavailable"): N._baseline(self.T, self.root)
        self.write_config()

  def test_symlinked_artifact_directory_is_refused(self):
    with self.as_user():
      real = self.dir("source")
      moved = real.with_name("elsewhere")
      real.rename(moved)
      real.symlink_to(moved)
      items, errors = N.generation_items(self.T, self.root)
      self.assertIn("source_uki", errors)
      self.assertIn("module_stack", errors)
      with self.assertRaises(ValueError): N._baseline(self.T, self.root)

  def test_group_writable_artifact_directory_or_file_is_refused(self):
    for target in ("dir", "file"):
      with self.subTest(target), self.as_user():
        path = self.dir("restore") if target == "dir" else self.dir("restore") / "mba-t2-hibernation-candidate.efi"
        original = path.stat().st_mode
        self.addCleanup(path.chmod, original)
        path.chmod(original | 0o020)
        items, errors = N.generation_items(self.T, self.root)
        self.assertIn("restore_uki", errors)
        self.assertNotIn("source_uki", errors)

  def test_artifact_file_owned_by_another_account_than_its_directory_is_refused(self):
    with self.as_user(file_uid=USER_UID + 1):
      items, errors = N.generation_items(self.T, self.root)
      self.assertIn("source_uki", errors)

  def test_root_owned_strictness_is_unchanged_for_the_production_image(self):
    with self.as_user():
      real_lstat = Path.lstat
      def foreign(path, *a, **k):
        info = real_lstat(path, *a, **k)
        if str(path).endswith("/boot/EFI/Linux") or "/boot/EFI/Linux" in str(path):
          return SimpleNamespace(**{**{n: getattr(info, n) for n in dir(info) if n.startswith("st_")}, "st_uid": USER_UID})
        return info
      with patch.object(Path, "lstat", foreign):
        items, errors = N.generation_items(self.T, self.root)
      self.assertIn("production_uki", errors)


class Assess(AssessFixture):
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
    cases = self.mutation_cases()
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

  RUN_DROPIN = "run/systemd/system/bluetooth-after-wifi.service.d/10-source.conf"

  def test_volatile_run_state_never_changes_the_class_in_either_direction(self):
    absent = self.fresh()
    self.assertEqual(absent.assess()["class"], "unchanged")
    absent.write(self.RUN_DROPIN, b"[Unit]\nAfter=x\n")
    self.assertEqual(absent.assess()["class"], "unchanged")
    absent.write(self.RUN_DROPIN, b"different")
    self.assertEqual(absent.assess()["class"], "unchanged")
    self.assertNotIn("run/systemd/system/bluetooth-after-wifi.service.d", absent.T.read_baseline(absent.root, (absent.root / absent.T.MAINTENANCE).read_bytes())["control_inventory"]["directories"])
    present = Assess("test_unchanged_generation_reports_every_item_equal")
    present.setUp()
    self.addCleanup(present.doCleanups)
    present.write(self.RUN_DROPIN, b"[Unit]\nAfter=x\n")
    present.published()
    (present.root / self.RUN_DROPIN).unlink()
    (present.root / self.RUN_DROPIN).parent.rmdir()
    self.assertEqual(present.assess()["class"], "unchanged")

  def test_old_format_baseline_with_run_entries_is_unchanged_after_reboot(self):
    other = Assess("test_unchanged_generation_reports_every_item_equal")
    other.setUp()
    self.addCleanup(other.doCleanups)
    other.write(self.RUN_DROPIN, b"[Unit]\nAfter=x\n")
    def old_capture(root):  # what the published live baseline recorded: default-mode scan including /run
      return CONTROL.capture(root, baseline=False)
    with patch.object(N, "_control_capture", old_capture): other.published()
    baseline = other.T.read_baseline(other.root, (other.root / other.T.MAINTENANCE).read_bytes())["control_inventory"]
    self.assertIn("run/systemd/system/bluetooth-after-wifi.service.d", baseline["directories"])
    (other.root / self.RUN_DROPIN).unlink()
    (other.root / self.RUN_DROPIN).parent.rmdir()  # reboot: per-boot state gone
    self.assertEqual(other.assess()["class"], "unchanged")
    other.write("etc/systemd/system/bluetooth-after-wifi.service.d/x.conf", b"changed")
    report = other.assess()
    self.assertEqual((report["class"], report["changed_items"]), ("requalification-required", ["control_inventory"]))

  def test_persistent_unit_changes_still_require_requalification(self):
    for relative in ("etc/systemd/system/bluetooth-after-wifi.service.d/x.conf", "usr/lib/systemd/system/systemd-hibernate.service.d/x.conf"):
      other = self.fresh()
      other.write(relative, b"changed")
      report = other.assess()
      self.assertEqual((report["class"], report["changed_items"]), ("requalification-required", ["control_inventory"]), relative)

  def test_unreadable_items_are_unknown_and_never_unchanged(self):
    other = self.fresh()
    for name in list((other.root / "usr/lib/firmware/brcm").iterdir()): name.unlink()
    report = other.assess()
    self.assertEqual(report["class"], "unknown")
    self.assertEqual(report["unknown_items"], ["firmware"])  # the module item survives a firmware failure
    self.assertEqual(report["items"]["driver_modules"], {"state": "equal"})
    self.assertEqual(report["items"]["control_inventory"], {"state": "equal"})
    self.assertIn("firmware", report["items"]["firmware"]["reason"])
    # A definite change outranks an unreadable item.
    other.coherent_kernel_update()
    report = other.assess()
    self.assertEqual((report["class"], report["changed_items"], report["unknown_items"]), ("requalification-required", ["production_uki"], ["firmware"]))
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

  def test_assess_releases_the_physical_lock_before_any_hashing(self):
    other = self.fresh()
    events = []
    real_physical, real_generation = other.T.G._physical, N.generation_items
    def physical(root, owner):
      fd, identity = real_physical(root, owner)
      events.append("probe")
      return fd, identity
    def generation(engine, root):
      probe = os.open(other.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
      try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)  # a concurrent guard hook must be admitted while hashing
      finally: os.close(probe)
      events.append("hash")
      return real_generation(engine, root)
    with patch.object(other.T.G, "_physical", side_effect=physical), patch.object(N, "generation_items", side_effect=generation):
      report = other.assess()
    self.assertEqual(events, ["probe", "hash"])
    self.assertEqual(report["class"], "unchanged")

  def test_assess_reports_unknown_when_a_transaction_starts_while_hashing(self):
    other = self.fresh()
    real_generation = N.generation_items
    lock = other.root / self.T.DB_LOCK
    def generation(engine, root):
      lock.write_bytes(b"pacman")  # pacman begins after the lock-free probe
      return real_generation(engine, root)
    with patch.object(N, "generation_items", side_effect=generation):
      report = other.assess()
    self.assertEqual(report["class"], "unknown")
    self.assertTrue(report["busy"])
    self.assertIn("started during assessment", report["reason"])
    self.assertEqual(lock.read_bytes(), b"pacman")
    lock.unlink()

  def test_baseline_publication_and_assessment_accept_hardlinked_firmware_and_out_of_scope_control_links(self):
    other = Assess("test_unchanged_generation_reports_every_item_equal")
    other.setUp()
    self.addCleanup(other.doCleanups)
    brcm = other.root / "usr/lib/firmware/brcm"
    for suffix in DRIVER.SUFFIXES:
      os.link(brcm / (DRIVER.FORMOSA + suffix), brcm / ("brcmfmac4377b3-pcie.apple,fiji" + suffix))
    hook = other.root / "etc/boot/hooks/pre.d"
    hook.mkdir(parents=True)
    (hook / "10-limine-reset-enroll").symlink_to("/usr/bin/limine-reset-enroll")
    other.published()
    baseline = other.T.read_baseline(other.root)
    for name in ("driver_modules", "firmware", "control_inventory"): self.assertNotIn("unavailable", baseline[name], name)
    self.assertEqual(other.assess()["class"], "unchanged")

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


class Crash(BaseException):
  """A simulated process death: not an Exception, so no recovery code in the engine may swallow it."""


class Reactivation(AssessFixture):
  """`reactivate` on a disposable root: the real engine and the real lock-free assess core, fixture product/gate seams."""
  STAGES = ("none", "pre", "W3", "W4", "W5", "W7", "W8", "done")
  unavailable_control = False
  trace = None

  def setUp(self):
    super().setUp()
    if self.unavailable_control:
      with patch.object(N, "_control_capture", side_effect=ValueError("control unreadable at publication")): self.published()
    else: self.published()
    self.pinned, self.derived_manifest, self.inspect_config, self.fault = {}, None, {}, None
    self.review = (self.root / self.T.REVIEW).read_bytes()
    self.entry = json.loads(self.review)["source_entry_id"]
    self.f.write(self.T.P.LIMINE, F.with_snapshots((self.root / self.T.P.LIMINE).read_bytes(), [1, 2]))
    self.original = (self.root / self.T.P.LIMINE).read_bytes()

  # --- seams -----------------------------------------------------------------------------------
  def assess_core(self, evidence, marker): return N._assess_core(self.T, self.root, evidence, marker)

  def inspect(self, evidence):
    config = {**json.loads((self.root / STATE_DIR / "config.json").read_bytes()), **self.inspect_config}
    return {"config": config, "manifest": config["manifest"] if self.derived_manifest is None else self.derived_manifest}

  def postchecks(self, root, baseline):
    if self.fault is not None: raise self.fault
    F.F.PRODUCT.TRIAL._verify_deployment(root, self.f.config, self.f.report, source_default=True)
    items, errors = N.generation_items(self.T, root)
    if errors or items != {name: baseline[name] for name in self.T.BASELINE_ITEMS}: raise ValueError("generation differs from the baseline")

  def reactivate(self, **changes):
    arguments = {"guard": lambda: None, "gate": self.fx.gate, "assess": self.assess_core, "inspect": self.inspect, "postchecks": self.postchecks, "pinned": self.pinned}
    return self.T._reactivate(self.root, **{**arguments, **changes})

  def new(self, **attributes):
    other = Reactivation("runTest")
    for name, value in attributes.items(): setattr(other, name, value)
    other.setUp()
    self.addCleanup(other.doCleanups)
    return other

  def guards(self):
    """Stage seen by every guard() of one complete run (cached: the sequence is deterministic)."""
    if Reactivation.trace is None:
      probe = self.new()
      guard, calls = probe.guard_at(None)
      probe.reactivate(guard=guard)
      Reactivation.trace = calls
    return Reactivation.trace

  def to_stage(self, name):
    other = self.new()
    other.crashed(self.guards().index(name) + 1)
    self.assertEqual(other.stage(), name)
    return other

  def own_archive(self):
    return next(item for item in (self.root / self.T.HISTORY).iterdir() if (item / "intent.json").exists() and json.loads((item / "intent.json").read_bytes()).get("action") == "reactivation")

  # --- observation -----------------------------------------------------------------------------
  def path(self, relative): return self.root / relative

  def pending(self): return self.path(self.T.PENDINGS["activation"])

  def limine(self): return self.path(self.T.P.LIMINE).read_bytes()

  def flags(self):
    archives = [item for item in (self.root / self.T.HISTORY).iterdir() if (item / "intent.json").exists() and json.loads((item / "intent.json").read_bytes()).get("action") == "reactivation"]
    completion = any((item / "completion.json").exists() for item in archives)
    return {"pending": self.pending().exists(), "marker": self.path(self.T.MAINTENANCE).exists(), "policy": self.path(self.T.P.POLICY).exists(),
            "switched": (b"default_entry: " + self.entry.encode() + b"\n") in self.limine(), "optin": self.path(self.T.OPT_IN).exists(), "completion": completion}

  def stage(self):
    f = self.flags()
    if not f["pending"]: return "none" if f["marker"] else "done"
    if f["completion"]: return "W7" if f["marker"] else "W8"
    if f["optin"]: return "W5"
    if f["switched"]: return "W4"
    return "W3" if f["policy"] else "pre"

  def tree(self):
    state = {}
    for path in sorted(self.root.rglob("*")):
      if path == self.root / self.T.DB_LOCK: continue
      info = path.lstat()
      state[str(path.relative_to(self.root))] = (stat.S_IMODE(info.st_mode), stat.S_ISDIR(info.st_mode),
        os.readlink(path) if stat.S_ISLNK(info.st_mode) else (path.read_bytes() if stat.S_ISREG(info.st_mode) else None))
    return state

  def refuses(self, pattern, *, exception=ValueError, **changes):
    before = self.tree()
    with self.assertRaisesRegex(exception, pattern): self.reactivate(**changes)
    self.assertEqual(self.tree(), before)
    self.assertFalse(self.pending().exists())
    self.assertTrue(self.path(self.T.MAINTENANCE).exists())

  def assert_vetoed(self):
    """Every route that could sleep or update is refused while an activation pending exists."""
    with self.assertRaises(ValueError): F.SLEEP.reject_pending(self.root)
    with self.assertRaises(ValueError): F.F.PRODUCT.verify_deployment(self.root, self.f.config, self.f.report)
    with self.assertRaises(ValueError): self.T.G.check(self.root)
    if self.path(self.T.MAINTENANCE).exists():
      with self.assertRaises(ValueError): self.T.G._maintenance(self.root)  # the native guard route: marker present, so the pending vetoes it

  def assert_active(self):
    f = self.flags()
    self.assertEqual((f["pending"], f["marker"], f["policy"], f["switched"], f["optin"]), (False, False, True, True, True))
    self.assertEqual(self.path(self.T.P.POLICY).read_bytes(), self.review)
    self.assertEqual(self.path(self.T.OPT_IN).read_bytes(), b"")
    self.assertEqual(stat.S_IMODE(self.path(self.T.OPT_IN).stat().st_mode), 0o644)
    self.assertTrue(self.T.P.verify(self.root, self.T.P.digest((self.root / self.T.P.RECEIPT).read_bytes())))
    self.assertFalse((self.root / self.T.DB_LOCK).exists())
    with self.assertRaises(ValueError): self.T.G.check(self.root)  # blanket guard: boot-policy.json and the opt-in

  def assert_rolled_back(self, original):
    f = self.flags()
    self.assertEqual((f["pending"], f["marker"], f["policy"], f["switched"], f["optin"]), (False, True, False, False, False))
    self.assertEqual(self.limine(), original)
    self.assertEqual(list(self.path("boot").glob("limine.conf.source-default-*")), [])
    self.T.G._maintenance(self.root)  # inactive maintenance is valid again: updates are allowed
    self.assertFalse((self.root / self.T.DB_LOCK).exists())

  def expected(self, current, entry=None):
    return current.replace(b"default_entry: 2\n", b"default_entry: " + (entry or self.entry).encode() + b"\n", 1)

  # --- happy path and bytes --------------------------------------------------------------------
  def test_happy_path_applies_exactly_one_line_to_current_bytes_and_becomes_active(self):
    marker = (self.root / self.T.MAINTENANCE).read_bytes()
    with patch.object(self.T, "_transition", side_effect=AssertionError("no _transition")), \
         patch.object(self.T, "_verify_existing_maintenance", side_effect=AssertionError("no re-entry")), \
         patch.object(self.T.PRODUCT, "check", side_effect=AssertionError("no product.check")), \
         patch.object(self.T.PRODUCT, "verify_deployment", side_effect=AssertionError("no verify_deployment")), \
         patch.object(self.T.PRODUCT, "_admission_state", side_effect=AssertionError("no admission")), \
         patch.object(N, "_precheck", side_effect=AssertionError("no precheck")), patch.object(N, "assess", side_effect=AssertionError("no assess wrapper")), \
         patch.object(N, "check_maintenance", create=True, side_effect=AssertionError("no check_maintenance")):
      result = self.reactivate()
    self.assertTrue(result["reactivated"] and result["requalification_required"] is False)
    self.assertFalse(result["live_execution"] or result["qualification_issued"])
    self.assertEqual(result["maintenance_transition_id"], self.result["transition_id"])
    self.assertEqual(self.limine(), self.expected(self.original))
    self.assertIn(b"limine-snapper-sync", self.limine())  # the snapshot region survived the swap
    self.assert_active()
    self.assertEqual((self.root / self.T.P.BACKUP).read_bytes(), self.f.before)
    archive = self.root / self.T.HISTORY / result["transition_id"]
    self.assertEqual(sorted(item.name for item in archive.iterdir()), ["comparison.json", "completion.json", "intent.json", "opt-in", "policy.json"])
    self.assertEqual((archive / "policy.json").read_bytes(), self.review)
    self.assertEqual(json.loads((archive / "comparison.json").read_bytes())["assessment"]["class"], "unchanged")
    self.assertEqual(json.loads((archive / "completion.json").read_bytes())["configuration_canonical_sha256"], self.T.P.digest(self.T.P.limine_canonical(self.expected(self.original))))
    self.assertEqual(marker, (self.root / self.T.HISTORY / self.result["transition_id"] / "maintenance-intent.json").read_bytes())  # old evidence untouched
    self.assertEqual(json.loads(json.dumps(result, sort_keys=True)), result)
    self.assertFalse((self.root / self.T.PENDINGS["deactivation"]).exists())

  def test_snapshot_order_and_count_vary_and_only_default_entry_changes(self):
    for numbers, reverse in (([], False), ([1], False), ([1, 2], False), ([2, 3, 4], True), ([7, 8, 9, 10, 11], False)):
      with self.subTest(numbers=numbers, reverse=reverse):
        other = self.new()
        other.f.write(other.T.P.LIMINE, F.with_snapshots(other.original, numbers, reverse))
        current = other.limine()
        result = other.reactivate()
        self.assertTrue(result["reactivated"])
        self.assertEqual(other.limine(), other.expected(current))
        proposal = other.T.P.prepare(other.f.before, other.f.raw)["after"]
        self.assertEqual(other.T.P.limine_canonical(other.limine()), other.T.P.limine_canonical(proposal))
        other.assert_active()

  def test_active_state_tolerates_further_snapshot_churn_and_deactivates_again(self):
    self.reactivate()
    self.f.write(self.T.P.LIMINE, F.with_snapshots(self.limine(), [3, 4, 5], True))  # one more snapper sync
    self.assertTrue(self.T.P.verify(self.root, self.T.P.digest((self.root / self.T.P.RECEIPT).read_bytes())))
    result = self.publish()  # active again means the ordinary deactivation/maintenance round trip works
    self.assertTrue((self.root / self.T.MAINTENANCE).exists())
    self.assertNotEqual(result["transition_id"], self.result["transition_id"])
    self.assertEqual(self.assess()["class"], "unchanged")
    self.assertTrue(self.reactivate()["reactivated"])  # and the reactivation is repeatable

  def test_unrelated_limine_drift_and_non_stock_bytes_refuse_with_zero_writes(self):
    cases = {"extra global option": (lambda raw: b"timeout: 9\n" + raw, "Unrelated Limine drift"),
             "remembered selection": (lambda raw: raw.replace(b"default_entry: 2\n", b"default_entry: 2\nremember_last_entry: yes\n", 1), "Remembered"),
             "altered pair block": (lambda raw: raw.replace(b"# END", b"# tampered\n# END", 1), "Unrelated Limine drift"),
             "second default": (lambda raw: raw + b"default_entry: 3\n", "canonical stock default"),
             "snapshot promoted to default": (lambda raw: raw.replace(b"default_entry: 2\n", b"default_entry: 5\n", 1), "canonical stock default")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        other.f.write(other.T.P.LIMINE, mutate(other.limine()))
        other.refuses(pattern)

  # --- refusals with zero writes -----------------------------------------------------------------
  def test_class_b_refuses_per_item_with_zero_writes_and_keeps_the_marker(self):
    for label, (mutate, expected) in self.mutation_cases().items():
      with self.subTest(label):
        other = self.new()
        mutate(other)
        before = other.tree()
        with self.assertRaises(ValueError) as caught: other.reactivate()
        self.assertRegex(str(caught.exception), "requalification required: ")
        if expected is not None: self.assertIn(", ".join(expected), str(caught.exception))
        else: self.assertIn(label, str(caught.exception))
        self.assertEqual(other.tree(), before)
        self.assertTrue(other.path(other.T.MAINTENANCE).exists())
        self.assertFalse(other.pending().exists())

  def test_the_running_kernel_alone_refuses_as_requalification(self):
    other = self.new()
    other.running = "7.3.0-new"
    other.refuses("requalification required: kernel")

  def test_class_c_unknown_refuses_with_zero_writes(self):
    other = self.new()
    path = other.archive() / self.T.BASELINE_NAME
    good = path.read_bytes()
    document = json.loads(good)
    path.unlink()
    other.refuses("compatibility unknown: Generation baseline is missing")
    forged = {"garbage": b"{", "not canonical": good + b"\n", "other transition": self.T._encoded({**document, "transition_id": str(uuid.uuid4())}),
              "unbound": self.T._encoded({**document, "old_policy_sha256": "1" * 64}), "extra item": self.T._encoded({**document, "items": {**document["items"], "extra": {}}})}
    for label, raw in forged.items():
      with self.subTest(label):
        path.write_bytes(raw)
        path.chmod(0o600)
        other.refuses("compatibility unknown: Generation baseline is invalid")
    path.write_bytes(good)
    for item in list((other.root / "usr/lib/firmware/brcm").iterdir()): item.unlink()
    other.refuses("compatibility unknown: .*firmware|compatibility unknown: unknown items: firmware")

  def test_unavailable_baseline_item_refuses_as_unknown(self):
    other = self.new(unavailable_control=True)
    other.refuses("compatibility unknown: unknown items: control_inventory")

  def test_busy_locks_refuse_and_are_preserved(self):
    before = self.tree()
    db = self.root / self.T.DB_LOCK
    db.write_bytes(b"existing transaction")
    with self.assertRaises(FileExistsError): self.reactivate()
    self.assertEqual(db.read_bytes(), b"existing transaction")
    db.unlink()
    held = os.open(self.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with self.assertRaises(BlockingIOError): self.reactivate()
    finally: os.close(held)
    self.assertFalse(db.exists())
    self.assertEqual(self.tree(), before)

  def test_existing_policy_optin_pending_and_runtime_or_deactivation_state_refuse_with_zero_writes(self):
    T = self.T
    def foreign(relative, raw=b"foreign"):
      return lambda other: other.f.write(relative, raw)
    barrier = self.T._encoded({"protocol": "omarchy-t2-runtime-upgrade-intent-v2", "transaction_id": str(uuid.uuid4()), "approval_id": str(uuid.uuid4())})
    cases = {"policy": (foreign(T.P.POLICY), "Existing source-default"), "opt-in": (lambda other: other.f.write(T.OPT_IN, b"").chmod(0o644), "Existing source-default"),
             "runtime upgrade pending": (foreign(T.P.STATE / T.D.UPGRADE_PENDING), "Runtime deployment/upgrade pending"),
             "runtime pending": (foreign(T.P.STATE / T.D.PENDING), "Runtime deployment/upgrade pending"),
             "deactivation pending": (foreign(T.PENDINGS["deactivation"]), "re-enter `maintenance`"),
             "runtime barrier under the shared filename": (foreign(T.PENDINGS["activation"], barrier), "not a reactivation intent")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        mutate(other)
        before = other.tree()
        with self.assertRaisesRegex(ValueError, pattern): other.reactivate()
        self.assertEqual(other.tree(), before)
        self.assertTrue(other.path(T.MAINTENANCE).exists())
        self.assertFalse(other.T.reactivation_pending(other.root))  # the barrier is never mistaken for ours
    other = self.new()
    other.f.write(other.T.MAINTENANCE, b"junk")
    with self.assertRaises(ValueError): other.reactivate()
    other = self.new()
    other.path(other.T.MAINTENANCE).unlink()
    with self.assertRaisesRegex(ValueError, "marker required"): other.reactivate()

  def test_efi_override_saved_image_and_runtime_drift_refuse_with_zero_writes(self):
    other = self.new()
    other.f.write(other.T.G.EFI / other.T.PRODUCT.HOST.CT.SOURCE_VARIABLE, b"stage")
    other.refuses("EFI overrides")
    other = self.new()
    other.f.write(other.T.G.EFI / ("LoaderEntryOneShot-" + other.T.G.LOADER_GUID), b"one shot")
    other.refuses("EFI overrides|Active or incomplete source state")
    other = self.new()
    other.fx.image = True
    other.refuses("saved image present")
    other = self.new()
    next((other.root / other.T.P.STATE / "runtime").rglob("fixture.py")).write_bytes(b"drifted reviewed code\n")
    other.refuses("")
    other = self.new()
    other.fx.fail["retained"] = True
    other.refuses("injected retained")

  def test_qualified_configuration_and_evidence_mismatches_refuse_with_zero_writes(self):
    other = self.new()
    other.derived_manifest = {**other.config["manifest"], "source_sha256": "f" * 64}
    other.refuses("manifest differs")
    other = self.new()
    other.inspect_config = {"staged_receipt_sha256": "e" * 64}
    other.refuses("receipt digests differ")
    other = self.new()
    def differs(evidence): raise ValueError("Derived resume target differs")
    other.refuses("resume", inspect=differs)
    other = self.new()
    other.f.write(other.T.REVIEW, json.dumps(json.loads(other.review), indent=2).encode())  # same policy, different bytes
    other.refuses("Reviewed policy differs")
    other = self.new()
    (other.archive() / "policy.json").write_bytes(b"{}")
    other.refuses("policy")
    other = self.new()
    other.f.write(other.T.P.BACKUP, other.f.before + b"# tampered\n")
    other.refuses("Before bytes differ")

  # --- crash injection ---------------------------------------------------------------------------
  def guard_at(self, limit):
    calls = []
    def guard():
      calls.append(self.stage() if self.pending().exists() or self.path(self.T.P.POLICY).exists() else "none")
      if limit is not None and len(calls) == limit: raise Crash()
    return guard, calls

  def crashed(self, limit):
    guard, calls = self.guard_at(limit)
    try: self.reactivate(guard=guard)
    except Crash: pass
    else: self.fail("no crash at guard " + str(limit))
    return calls

  def test_a_crash_before_every_write_keeps_sleep_and_updates_vetoed_and_recovery_finishes_correctly(self):
    total = len(self.guards())
    self.assertGreaterEqual(total, 14)
    seen, outcomes = set(), {}
    for limit in range(1, total + 1):
      with self.subTest(guard=limit):
        other = self.new()
        other.crashed(limit)
        stage = other.stage()
        seen.add(stage)
        self.assertFalse((other.root / other.T.DB_LOCK).exists())
        if stage == "done":
          other.assert_active()
        elif stage == "none":
          self.assertFalse(other.pending().exists())
          self.assertEqual(other.limine(), other.original)
          self.assertTrue(other.reactivate()["reactivated"])
          other.assert_active()
        else:
          other.assert_vetoed()
          self.assertTrue(other.T.reactivation_pending(other.root))
          result = other.reactivate()
          if stage in ("pre", "W3", "W4", "W5"):
            self.assertEqual((result.get("rolled_back"), result["reactivated"]), (True, False))
            other.assert_rolled_back(other.original)
            self.assertTrue((other.root / other.T.HISTORY / result["transition_id"] / other.T.ROLLBACK_NAME).exists())
            self.assertTrue(other.reactivate()["reactivated"])  # a fresh attempt is then allowed
          else: self.assertEqual(result["recovered"], "finished-retirement" if stage == "W7" else "retired-pending")
          other.assert_active()
        outcomes[limit] = stage
    # A process death between the pending unlink and the lock release cannot be simulated in-process: the engine
    # reinstates the pending on any BaseException there, so that instant shows up as W8 again.
    self.assertEqual(seen, set(self.STAGES) - {"done"})
    order = [self.STAGES.index(outcomes[limit]) for limit in range(1, total + 1)]
    self.assertEqual(order, sorted(order))  # the writes advance monotonically through W1..W9

  def test_a_crash_between_stage_and_swap_leaves_a_stray_temporary_that_recovery_removes(self):
    calls = self.guards()
    inner = next(index + 2 for index, name in enumerate(calls) if name == "W3" and calls[index + 1] == "W3")  # the guard inside _replace, after the temporary exists
    other = self.new()
    other.crashed(inner)
    self.assertTrue(list(other.path("boot").glob("limine.conf.source-default-*")))
    self.assertEqual(other.stage(), "W3")
    self.assertEqual(other.limine(), other.original)
    self.assertTrue(other.reactivate()["rolled_back"])
    other.assert_rolled_back(other.original)

  def test_fault_after_the_boot_write_and_inside_postchecks_roll_back_on_rerun(self):
    original_new = self.T._new
    def fail_optin(path, *args, **kwargs):
      if path.name == "t2-hibernate-product.enabled": raise OSError("opt-in publication fault")
      return original_new(path, *args, **kwargs)
    other = self.new()
    with patch.object(other.T, "_new", side_effect=fail_optin):
      with self.assertRaises(OSError): other.reactivate()
    self.assertEqual(other.stage(), "W4")
    other.assert_vetoed()
    self.assertTrue(other.reactivate()["rolled_back"])
    other.assert_rolled_back(other.original)
    other = self.new()
    other.fault = ValueError("postcheck failure inside W6")
    with self.assertRaisesRegex(ValueError, "inside W6"): other.reactivate()
    self.assertEqual(other.stage(), "W5")
    other.assert_vetoed()
    other.fault = None
    result = other.reactivate()
    self.assertEqual((result["rolled_back"], result["reactivated"]), (True, False))  # never retried forward past the boot write
    other.assert_rolled_back(other.original)

  def test_a_snapshot_sync_during_the_swap_aborts_and_rolls_back_without_dropping_snapshots(self):
    other = self.new()
    original_replace = other.T._replace
    def racing(root, expected, replacement, identifier, *, guard=lambda: None):
      other.f.write(other.T.P.LIMINE, F.with_snapshots(other.limine(), [8, 9]))  # snapper-sync rewrote the region before the swap
      return original_replace(root, expected, replacement, identifier, guard=guard)
    with patch.object(other.T, "_replace", side_effect=racing):
      with self.assertRaisesRegex(ValueError, "Configuration changed before replacement"): other.reactivate()
    churned = other.limine()
    self.assertEqual(other.stage(), "W3")
    result = other.reactivate()
    self.assertTrue(result["rolled_back"])
    other.assert_rolled_back(churned)  # the new snapshots are still there
    self.assertIn(b"///9 ", other.limine())
    self.assertTrue(other.reactivate()["reactivated"])
    self.assertIn(b"///9 ", other.limine())

  def test_snapshot_churn_after_the_boot_write_is_tolerated_by_recovery_and_rollback(self):
    other = self.to_stage("W4")
    other.f.write(other.T.P.LIMINE, F.with_snapshots(other.limine(), [5, 6], True))
    churned = other.limine()
    self.assertTrue(other.reactivate()["rolled_back"])
    self.assertEqual(other.limine(), churned.replace(b"default_entry: " + other.entry.encode() + b"\n", b"default_entry: 2\n", 1))
    self.assertIn(b"///6 ", other.limine())  # the new snapshots were never dropped
    self.assertFalse(other.flags()["switched"])
    other.T.G._maintenance(other.root)

  def test_rollback_is_resumable_after_a_crash_at_every_step(self):
    for name in ("W4", "W5"):
      probe = self.to_stage(name)
      guard, calls = probe.guard_at(None)
      probe.reactivate(guard=guard)
      steps = len(calls)
      self.assertGreaterEqual(steps, 8)
      for limit in range(1, steps + 1):
        with self.subTest(stage=name, guard=limit):
          other = self.to_stage(name)
          guard, _ = other.guard_at(limit)
          try: other.reactivate(guard=guard)
          except Crash: pass
          if other.pending().exists():
            other.assert_vetoed()
            self.assertTrue(other.reactivate()["rolled_back"])
          other.assert_rolled_back(other.original)

  def test_post_completion_recovery_re_checks_and_rolls_back_when_the_checks_fail(self):
    other = self.to_stage("W7")
    other.fault = ValueError("state no longer verifies")
    result = other.reactivate()
    self.assertEqual((result["rolled_back"], result["reactivated"]), (True, False))
    other.fault = None
    other.assert_rolled_back(other.original)
    # a torn (non-matching) completion is never trusted either
    other = self.to_stage("W7")
    (other.own_archive() / "completion.json").write_bytes(b'{"torn":')
    self.assertTrue(other.reactivate()["rolled_back"])
    other.assert_rolled_back(other.original)

  def test_recovery_refuses_a_forged_or_mismatched_pending_without_touching_anything(self):
    def rewrite(other, **changes):
      other.pending().write_bytes(other.T._encoded({**json.loads(other.pending().read_bytes()), **changes}))
    cases = {"other marker": lambda other: rewrite(other, marker_sha256="0" * 64), "other baseline": lambda other: rewrite(other, baseline_sha256="0" * 64),
             "other policy": lambda other: rewrite(other, policy_sha256="0" * 64), "other action": lambda other: rewrite(other, action="activation"),
             "other maintenance": lambda other: rewrite(other, maintenance_transition_id=str(uuid.uuid4())),
             "other limine": lambda other: rewrite(other, limine={**json.loads(other.pending().read_bytes())["limine"], "to_canonical_sha256": "1" * 64}),
             "not canonical": lambda other: other.pending().write_bytes(other.pending().read_bytes() + b"\n"),
             "torn": lambda other: other.pending().write_bytes(other.pending().read_bytes()[:20]),
             "runtime barrier": lambda other: other.pending().write_bytes(other.T._encoded({"protocol": "omarchy-t2-runtime-upgrade-intent-v2", "transaction_id": str(uuid.uuid4())})),
             "archive differs": lambda other: (other.own_archive() / "intent.json").write_bytes(b"{}"),
             "comparison differs": lambda other: (other.own_archive() / "comparison.json").write_bytes(b"{}")}
    for label, mutate in cases.items():
      with self.subTest(label):
        other = self.to_stage("W5")
        mutate(other)
        before = other.tree()
        with self.assertRaises(ValueError): other.reactivate()
        self.assertEqual(other.tree(), before)
    other = self.to_stage("W5")
    other.f.write(other.T.P.LIMINE, other.limine() + b"# unrelated drift\n")
    before = other.tree()
    with self.assertRaisesRegex(ValueError, "Unrelated Limine drift"): other.reactivate()
    self.assertEqual(other.tree(), before)

  # --- mutual exclusion --------------------------------------------------------------------------
  def test_the_two_commands_exclude_each_other_and_the_runtime_upgrade_barrier(self):
    other = self.to_stage("W4")
    self.assertTrue(other.T.reactivation_pending(other.root))
    gate = other.fx.gate
    with self.assertRaises((ValueError, OSError)):
      other.T._transition(other.root, "maintenance", precheck=other.fx.fixture.check, guard=lambda: None, maintenance_gate=gate, maintenance_resume=lambda: dict(F.RESUME))
    with self.assertRaises((ValueError, OSError)): other.T._verify_existing_maintenance(other.root, guard=lambda: None, gate=gate)
    with self.assertRaises((ValueError, OSError)): other.T._complete_interrupted_maintenance(other.root, guard=lambda: None, gate=gate)
    with self.assertRaises((ValueError, OSError)): other.T._transition(other.root, "activation", precheck=other.fx.fixture.check, guard=lambda: None)
    # and the deactivation pending the maintenance publisher leaves is never adopted by reactivate
    third = self.new()
    third.f.write(third.T.PENDINGS["deactivation"], b"interrupted maintenance publication")
    third.refuses("re-enter `maintenance`")
    self.assertEqual((third.root / third.T.PENDINGS["deactivation"]).read_bytes(), b"interrupted maintenance publication")

  def test_neither_side_can_adopt_the_others_pending_under_the_shared_filename(self):
    RU = load("upgrade_native_for_exclusion", HERE / "hibernate/runtime_upgrade_native.py")
    crashed = self.to_stage("W4")
    ours = crashed.pending().read_bytes()
    self.assertEqual(json.loads(ours)["protocol"], self.T.REACTIVATION_SCHEMA)
    self.assertNotEqual(self.T.REACTIVATION_SCHEMA, "omarchy-t2-runtime-upgrade-intent-v2")
    self.assertNotEqual(self.T.REACTIVATION_SCHEMA, "omarchy-t2-runtime-upgrade-intent-v1")
    approval = {"approval_id": str(uuid.uuid4()), "expected": {name: "0" * 64 for name in ("old_review", "new_review", "old_config", "new_config")}}
    with self.assertRaisesRegex(ValueError, "invalid intent"): RU._intent(self.T.D, approval, ours)  # the upgrade's recovery compares protocol and exact fields
    document = json.loads(ours)
    self.assertNotEqual(set(document), {"protocol", "transaction_id", "approval_id", "old_review_sha256", "new_review_sha256", "old_config_sha256", "new_config_sha256"})
    # the upgrade start refuses while our pending holds the barrier name, without altering it
    expected = {name: "0" * 64 for name in ("old_review", "old_bootstrap", "old_config", "new_review", "new_bootstrap", "new_config")}
    with self.assertRaisesRegex(ValueError, "Existing or partial runtime upgrade"):
      self.T.D.upgrade_snapshot(crashed.root, root=crashed.root, expected=expected, guard=lambda: None, precheck=lambda: None, postcheck=lambda: None)
    self.assertEqual(crashed.pending().read_bytes(), ours)
    # conversely a runtime-upgrade barrier is never taken for a reactivation intent
    other = self.new()
    barrier = self.T._encoded({"protocol": "omarchy-t2-runtime-upgrade-intent-v2", "transaction_id": str(uuid.uuid4())})
    other.f.write(other.T.PENDINGS["activation"], barrier)
    self.assertFalse(other.T.reactivation_pending(other.root))
    with self.assertRaisesRegex(ValueError, "not a reactivation intent"): other.reactivate()
    self.assertEqual(other.pending().read_bytes(), barrier)

  def test_assess_core_never_probes_locks_while_the_wrapper_reports_unknown_under_them(self):
    with self.T._locks(self.root):
      self.assertEqual(self.assess()["class"], "unknown")  # the wrapper sees our own db.lck
      evidence = self.T.G._maintenance(self.root)
      marker = (self.root / self.T.MAINTENANCE).read_bytes()
      with patch.object(self.T.G, "_physical", side_effect=AssertionError("no physical probe")):
        self.assertEqual(N._assess_core(self.T, self.root, evidence, marker)["class"], "unchanged")


class ReactivationNative(unittest.TestCase):
  """The native adapter wiring for `reactivate`; every host query and reviewed byte source is mocked."""

  def dispatch(self, pending=False):
    from contextlib import contextmanager
    seen = {}
    @contextmanager
    def exclusion(action):
      seen["action"] = action
      yield lambda: None
    engine = Mock()
    engine.reactivation_pending.return_value = pending
    engine._reactivate.return_value = {"reactivated": True, "requalification_required": False, "qualification_issued": False}
    with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_exclusion", side_effect=exclusion):
      return engine, seen, N.native("reactivate")

  def test_dispatch_supplies_only_fixed_root_capability_and_callbacks(self):
    engine, seen, result = self.dispatch()
    self.assertEqual(seen["action"], "reactivate")
    arguments = engine._reactivate.call_args
    self.assertEqual(arguments.args, (Path("/"),))
    self.assertIs(arguments.kwargs["native"], engine._NATIVE_MAINTENANCE)
    self.assertEqual(set(arguments.kwargs), {"guard", "gate", "native", "pinned", "assess", "inspect", "postchecks"})
    self.assertTrue(result["live_execution"] and result["power_operation"] is False and result["reactivated"] and result["requalification_required"] is False)
    engine._transition.assert_not_called()
    with patch.object(N, "_maintenance_gate") as gate:
      arguments.kwargs["gate"](Path("/"), "retained")
    gate.assert_called_once_with(engine, Path("/"), "retained", arguments.kwargs["pinned"])
    with patch.object(N, "_assess_core", return_value={"class": "unchanged"}) as core:
      self.assertEqual(arguments.kwargs["assess"]({"evidence": 1}, b"marker"), {"class": "unchanged"})
    core.assert_called_once_with(engine, Path("/"), {"evidence": 1}, b"marker")
    with patch.object(N, "_reactivation_inspect", return_value={"config": {}}) as inspect:
      arguments.kwargs["inspect"]({"evidence": 1})
    inspect.assert_called_once_with(engine, {"evidence": 1})
    with patch.object(N, "_reactivation_postchecks") as postchecks:
      arguments.kwargs["postchecks"](Path("/"), {"kernel": {}})
    postchecks.assert_called_once_with(engine, Path("/"), {"kernel": {}})

  def test_the_inhibitor_command_and_parent_identity_use_the_reactivate_action(self):
    self.assertEqual(N._inhibit_command("reactivate")[-1], "reactivate")
    with patch.object(N.os, "execve", side_effect=AssertionError("exec")), patch.object(N, "_command", side_effect=AssertionError("no host queries")):
      with self.assertRaises(ValueError): N.native("reactivate")  # workspace/nonroot invocation refuses first

  def test_maintenance_refuses_naming_reactivate_while_a_reactivation_is_pending(self):
    from contextlib import contextmanager
    @contextmanager
    def exclusion(action):
      yield lambda: None
    engine = Mock()
    engine.reactivation_pending.return_value = True
    with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), patch.object(N, "_exclusion", side_effect=exclusion):
      with self.assertRaisesRegex(ValueError, "reactivate"): N.native("maintenance")
    engine._transition.assert_not_called()
    engine._verify_existing_maintenance.assert_not_called()
    engine._complete_interrupted_maintenance.assert_not_called()

  def test_inspect_requires_the_pinned_resume_and_product_validation(self):
    engine = Mock()
    report = {"manifest": {"m": 1}, "audited_details": {"restore_protocol": {"resume": {"offset": 1}}}}
    engine.PRODUCT.TRIAL._private_json.side_effect = [{"source_directory": "s", "restore_directory": "r", "production_uki": "p"}, {"q": 1}]
    engine.PRODUCT.ARTIFACTS.derive_artifacts.return_value = report
    info = N._reactivation_inspect(engine, {"resume": {"offset": 1}})
    self.assertEqual(info["manifest"], {"m": 1})
    engine.PRODUCT.validate.assert_called_once()
    engine.PRODUCT.TRIAL._private_json.side_effect = [{"source_directory": "s", "restore_directory": "r", "production_uki": "p"}, {"q": 1}]
    with self.assertRaisesRegex(ValueError, "resume"): N._reactivation_inspect(engine, {"resume": {"offset": 2}})

  def test_postchecks_verify_source_default_deployment_no_image_and_generation_equality(self):
    engine = Mock()
    engine.BASELINE_ITEMS = ("kernel", "config")
    report = {"manifest": {}, "audited_details": {"restore_protocol": {"resume": {"offset": 1}}}}
    engine.PRODUCT.TRIAL._private_json.side_effect = lambda path: {"source_directory": "s", "restore_directory": "r", "production_uki": "p"}
    engine.PRODUCT.ARTIFACTS.derive_artifacts.return_value = report
    with patch.object(N, "generation_items", return_value=({"kernel": {"a": 1}, "config": {"b": 2}}, {})):
      N._reactivation_postchecks(engine, Path("/"), {"kernel": {"a": 1}, "config": {"b": 2}, "limine": {}})
    engine.PRODUCT.TRIAL._verify_deployment.assert_called_once()
    self.assertIs(engine.PRODUCT.TRIAL._verify_deployment.call_args.kwargs["source_default"], True)
    engine.IMAGE_STATE.require_no_image.assert_called_once_with(Path("/"), {"offset": 1})
    for items, errors in (({"kernel": {"a": 2}, "config": {"b": 2}}, {}), ({"kernel": {"a": 1}, "config": {"b": 2}}, {"config": "unreadable"})):
      with patch.object(N, "generation_items", return_value=(items, errors)), self.assertRaisesRegex(ValueError, "differ from the baseline"):
        N._reactivation_postchecks(engine, Path("/"), {"kernel": {"a": 1}, "config": {"b": 2}, "limine": {}})

  def test_retained_gate_uses_the_pinned_resume_without_the_guards_derivation(self):
    engine = Mock()
    engine.GATE_PHASES = ("before", "after", "final", "retained")
    with patch.object(N, "_hibernate_route"), patch.object(N, "_maintenance_vetoes"):
      N._maintenance_gate(engine, Path("/"), "retained", {"resume": {"offset": 5}})
    engine.IMAGE_STATE.require_no_image.assert_called_once_with(Path("/"), {"offset": 5})
    engine._pinned_resume.assert_not_called()
    engine.IMAGE_STATE.require_no_image.reset_mock()
    engine._pinned_resume.return_value = {"offset": 6}
    with patch.object(N, "_hibernate_route"), patch.object(N, "_maintenance_vetoes"):
      N._maintenance_gate(engine, Path("/"), "retained", {})
    engine.IMAGE_STATE.require_no_image.assert_called_once_with(Path("/"), {"offset": 6})


if __name__ == "__main__": unittest.main()
