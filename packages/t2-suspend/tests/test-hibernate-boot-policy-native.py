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
      for args in ([], ["check"], ["maintenance"], ["activation", "--root", "/tmp"], ["deactivation", "--force"], ["activation", "--approve"]):
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


if __name__ == "__main__": unittest.main()
