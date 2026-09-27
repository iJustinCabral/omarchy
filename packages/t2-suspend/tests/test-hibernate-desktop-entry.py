"""Synthetic route/freeze/hooks tests; never invoke host sleep commands."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[3]
def load(name):
  spec = importlib.util.spec_from_file_location(name, REPO / "packages/t2-suspend/hibernate" / (name + ".py"))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module
ENTRY, SLEEP = load("sleep_entry"), load("desktop_sleep")


class DesktopEntry(unittest.TestCase):
  def test_absent_marker_executes_exact_stock_without_importing_product(self):
    with patch.object(ENTRY.os, "geteuid", return_value=0), patch.object(ENTRY, "opted_in", return_value=False), \
         patch.object(ENTRY, "reject_pending"), \
         patch.object(ENTRY.os, "execve", side_effect=RuntimeError("exec intercepted")) as execute, \
         patch.object(ENTRY.importlib.util, "spec_from_file_location") as imported:
      with self.assertRaisesRegex(RuntimeError, "intercepted"): ENTRY.main([])
      self.assertEqual(execute.call_args.args[:2], (ENTRY.STOCK, [ENTRY.STOCK, "hibernate"]))
      imported.assert_not_called()

  def test_invalid_marker_or_wrong_host_never_selects_stock(self):
    marker = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=0o100644, st_uid=0, st_gid=0, st_size=0))
    model = SimpleNamespace(read_text=lambda: "MacBookAir9,1\n")
    self.assertTrue(ENTRY.opted_in(marker, model, query=lambda: "Apple 106b:1802"))
    with self.assertRaises(ValueError): ENTRY.opted_in(marker, model, query=lambda: "no T2")
    model.read_text = lambda: "MacBookPro16,1"
    with self.assertRaises(ValueError): ENTRY.opted_in(marker, model, query=lambda: "106b:1801")
    marker.lstat = lambda: SimpleNamespace(st_mode=0o120777, st_uid=0, st_gid=0, st_size=0)
    with self.assertRaises(ValueError): ENTRY.opted_in(marker, model, query=lambda: "106b:1801")

  def test_no_arguments_or_nonroot_entry(self):
    with self.assertRaises(ValueError): ENTRY.main(["--force"])
    with patch.object(ENTRY.os, "geteuid", return_value=1000):
      with self.assertRaises(ValueError): ENTRY.main([])

  def test_opted_product_failure_has_no_stock_fallback(self):
    def product_main(argv):
      self.assertEqual(argv, ["hibernate", "--desktop"])
      raise RuntimeError("product failed")
    product = SimpleNamespace(main=product_main)
    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
    def metadata(path):
      return SimpleNamespace(st_uid=0, st_mode=0o100600 if path == ENTRY.PRODUCT else 0o40755, st_nlink=1)
    with patch.object(ENTRY.os, "geteuid", return_value=0), patch.object(ENTRY, "opted_in", return_value=True), \
         patch.object(ENTRY, "reject_pending"), \
         patch.object(Path, "lstat", metadata), patch.object(Path, "is_symlink", return_value=False), \
         patch.object(ENTRY.importlib.util, "spec_from_file_location", return_value=spec), \
         patch.object(ENTRY.importlib.util, "module_from_spec", return_value=product), \
         patch.object(ENTRY.os, "execve") as stock:
      with self.assertRaisesRegex(RuntimeError, "product failed"): ENTRY.main([])
      stock.assert_not_called()

  def test_pending_veto_precedes_opt_in_choice_for_both_routes(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      state = root / ENTRY.STATE
      state.mkdir(parents=True, mode=0o700)
      fixture_uid = os.geteuid()
      for name in ENTRY.PENDING:
        path = state / name
        for dangling in (False, True):
          if dangling: path.symlink_to(state / "missing")
          else: path.write_text("incomplete")
          for opted in (False, True):
            with self.subTest(name=name, dangling=dangling, opted=opted):
              real_check = ENTRY.reject_pending
              def pending_check():
                with patch.object(ENTRY.os, "geteuid", return_value=fixture_uid): real_check(root)
              with patch.object(ENTRY.os, "geteuid", return_value=0), \
                   patch.object(ENTRY, "reject_pending", side_effect=pending_check), \
                   patch.object(ENTRY, "opted_in", return_value=opted) as route, \
                   patch.object(ENTRY.os, "execve") as stock, \
                   patch.object(ENTRY.importlib.util, "spec_from_file_location") as product:
                with self.assertRaisesRegex(ValueError, "Incomplete source-default"): ENTRY.main([])
                route.assert_not_called()
                stock.assert_not_called()
                product.assert_not_called()
          path.unlink()

  def test_no_pending_allows_absent_state_and_rejects_unsafe_ancestors(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      ENTRY.reject_pending(root)
      state = root / ENTRY.STATE
      state.parent.mkdir(parents=True)
      state.symlink_to(state.with_name("missing"))
      with self.assertRaises(ValueError): ENTRY.reject_pending(root)
      state.unlink()
      state.mkdir(mode=0o700)
      ENTRY.reject_pending(root)
      state.chmod(0o777)
      with self.assertRaises(ValueError): ENTRY.reject_pending(root)
      state.chmod(0o700)
      with self.assertRaises(ValueError): ENTRY.reject_pending(root / "..")


class DesktopWindow(unittest.TestCase):
  def window(self, failure=None, initial="running", homed="inactive", root="/fixture"):
    calls, state = [], [initial]
    hooks = [Path("/fixture/keyboard-backlight"), Path("/fixture/unmount-fuse")]
    def runner(argv):
      calls.append(argv)
      if "show" in argv:
        return SimpleNamespace(stdout=(homed() if callable(homed) else homed) if "systemd-homed.service" in argv else state[0])
      if "freeze" in argv: state[0] = "frozen"
      if "thaw" in argv: state[0] = "running"
      if failure and failure in argv: raise RuntimeError(failure)
      return SimpleNamespace(stdout="")
    return SLEEP.window(root, runner=runner, hook_inventory=lambda root: hooks), calls, state

  def test_freeze_pre_power_post_thaw_order(self):
    window, calls, state = self.window()
    with window:
      self.assertEqual(state[0], "frozen")
      calls.append(["power"])
    self.assertEqual(state[0], "running")
    power = calls.index(["power"])
    self.assertTrue(all(calls.index(call) < power for call in calls if "pre" in call))
    self.assertTrue(all(calls.index(call) > power for call in calls if "post" in call))
    self.assertTrue(next(i for i, call in enumerate(calls) if "thaw" in call) > max(i for i, call in enumerate(calls) if "post" in call))

  def test_pre_power_and_post_failure_always_thaw(self):
    for phase in ("freeze", "pre", "power"):
      with self.subTest(phase=phase):
        window, calls, state = self.window(None if phase == "power" else phase)
        with self.assertRaises(RuntimeError):
          with window:
            if phase == "power": raise RuntimeError("power")
        self.assertEqual(state[0], "running")
        self.assertTrue(any("thaw" in call for call in calls))

  def test_post_failure_retained_without_suppressing_raw_capture(self):
    window, calls, state = self.window("post")
    with self.assertRaises(RuntimeError):
      with window:
        calls.append(["power"])
        calls.append(["capture"])
    self.assertEqual(state[0], "running")
    self.assertTrue(all(calls.index(["capture"]) < calls.index(call) for call in calls if "post" in call))

  def test_existing_frozen_state_and_live_injections_refused(self):
    window, calls, state = self.window(initial="frozen")
    with self.assertRaises(ValueError):
      with window: self.fail("cannot write power")
    self.assertEqual(len(calls), 2)
    with self.assertRaises(ValueError):
      with SLEEP.window("/", runner=lambda argv: None): self.fail("cannot write power")
    for alias in (".", "/tmp/..", "/tmp/../tmp"):
      with self.assertRaises(ValueError):
        with SLEEP.window(alias, runner=lambda argv: None): self.fail("alias cannot inject live operations")
    with tempfile.TemporaryDirectory() as directory:
      alias = Path(directory) / "alias"
      alias.symlink_to("/")
      with self.assertRaises(ValueError):
        with SLEEP.window(alias, runner=lambda argv: None): self.fail("symlink cannot inject live operations")

  def test_homed_or_managed_home_state_refused_before_freeze(self):
    for homed in ("active", "activating", "failed", ""):
      window, calls, state = self.window(homed=homed)
      with self.assertRaises(ValueError):
        with window: self.fail("homed cannot reach power")
      self.assertFalse(any("freeze" in call for call in calls))

  def test_homed_activation_after_hooks_prevents_power_and_thaws(self):
    states = iter(("inactive", "active"))
    window, calls, state = self.window(homed=lambda: next(states))
    with self.assertRaises(ValueError):
      with window: self.fail("changed homed cannot reach power")
    self.assertEqual(state[0], "running")
    self.assertTrue(any("thaw" in call for call in calls))
    with tempfile.TemporaryDirectory() as directory:
      homes = Path(directory) / "var/lib/systemd/home"
      homes.mkdir(parents=True)
      (homes / "user.identity").write_text("managed home")
      window, calls, state = self.window(root=directory)
      with self.assertRaises(ValueError):
        with window: self.fail("managed home cannot reach power")
      self.assertFalse(any("freeze" in call for call in calls))

  def test_exact_hook_inventory_rejects_unknown_changed_or_symlink(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      hooks = root / "usr/lib/systemd/system-sleep"
      hooks.mkdir(parents=True)
      for name in SLEEP.HOOKS:
        shutil.copyfile(REPO / "default/systemd/system-sleep" / name, hooks / name)
        (hooks / name).chmod(0o755)
      original = Path.lstat
      # Simulate root ownership only on temporary fixture metadata.
      def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0, st_size=info.st_size, st_nlink=info.st_nlink)
      with patch.object(Path, "lstat", metadata):
        self.assertEqual(len(SLEEP.inventory(root)), 2)
        (hooks / "unknown").write_text("unknown")
        with self.assertRaises(ValueError): SLEEP.inventory(root)
        (hooks / "unknown").unlink()
        (hooks / "unmount-fuse").write_text("changed")
        with self.assertRaises(ValueError): SLEEP.inventory(root)
        (hooks / "unmount-fuse").unlink()
        (hooks / "unmount-fuse").symlink_to(hooks / "keyboard-backlight")
        with self.assertRaises(ValueError): SLEEP.inventory(root)


if __name__ == "__main__": unittest.main()
