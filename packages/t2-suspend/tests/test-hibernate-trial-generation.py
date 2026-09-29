"""Per-generation one-use trial state roots: tempdirs and mocks only; no host, EFI or power operation."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


T = load("trial_generation_module", HERE / "hibernate/trial.py")
TX = T.TX


def manifest(tag):
  return {"protocol": TX.PROTOCOL, "model": "MacBookAir9,1", **{name: hashlib.sha256((tag + name).encode()).hexdigest() for name in TX.PINS}}


def authorization(value, boot):
  identity = str(uuid.uuid4())
  return {"protocol": TX.TRIAL_PROTOCOL, "qualified": False, "manifest_sha256": TX.digest(value), "audited_details_sha256": "a" * 64,
          "original_boot_id": boot, "authorization_id": identity,
          "marker_pin": {"sha256": "b" * 64, "srcversion": "SRC", "vermagic": "VER", "variable_version": "v3"},
          "physical_acceptance": {"boot_id": boot, "authorization_id": identity, "accepted": True, "method": "operator-attended-cold-power"}}


class Generation(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.base = Path(self.temp.name) / "trial"
    self.old_manifest, self.new_manifest = manifest("old"), manifest("new")
    self.identity = T.TX.digest(self.new_manifest)[:12]
    self.old_identity = T.TX.digest(self.old_manifest)[:12]
    self.legacy = self.make_root(self.base)
    self.guard_bytes = json.dumps({"protocol": TX.TRIAL_PROTOCOL, "authorization_sha256": "a" * 64, "cycle": {"manifest": self.old_manifest}}).encode()
    (self.legacy / "config.json").write_text(json.dumps({"manifest": self.old_manifest, "source_directory": "/s", "restore_directory": "/r", "production_uki": "/p"}))
    (self.legacy / "guards/trial-consumed.json").write_bytes(self.guard_bytes)
    (self.legacy / "guards/trial-consumed.json").chmod(0o600)
    (self.legacy / "physical-cycle.lock").write_bytes(b"")
    self.generations = self.base / "generations"
    self.generations.mkdir(mode=0o700)
    self.root = self.make_root(self.generations / self.identity)
    self.patches = [patch.object(T, "STATE", self.base), patch.object(T, "GENERATIONS", self.generations), patch.object(T, "_private_directory", self.private_directory),
                    patch.object(T, "_private_json", self.private_json)]
    for item in self.patches:
      item.start()
      self.addCleanup(item.stop)
    self.report = {"manifest": self.new_manifest}
    self.calls = []

  def make_root(self, directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("guards", "ledger", "archives"): (directory / name).mkdir(mode=0o700, exist_ok=True)
    for name in ("config.json", "authorization.json"):
      (directory / name).write_text("{}")
      (directory / name).chmod(0o600)
    return directory

  def private_directory(self, directory):
    info = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
      raise ValueError("Fixed existing root-private trial state directories required")

  def private_json(self, path):
    if Path(path) in (self.legacy / "config.json", self.legacy / "guards/trial-consumed.json"): return json.loads(Path(path).read_bytes())
    return {"source_directory": "/s", "restore_directory": "/r", "production_uki": "/p", "path": str(path)}

  def snapshot(self, directory):
    return {str(path.relative_to(directory)): path.read_bytes() for path in sorted(Path(directory).rglob("*")) if path.is_file()}

  def dispatch(self, action, generation=None, report=None):
    """_dispatch with the host-facing checks replaced by recorders; execute() reports the state paths it was given."""
    def execute(config, authorization_, report_, **kwargs):
      self.calls.append({"config": config["path"], "ledger": kwargs["ledger"].directory, "guard": kwargs["guard_directory"], "archive": kwargs["archive_directory"]})
      return {"classification": "one-use-product-trial-not-usable-qualification", "cycle": {"cycle_id": "c", "state": "s"}}
    with patch.object(T.ARTIFACTS, "derive_artifacts", return_value=self.report if report is None else report), patch.object(T, "validate"), \
         patch.object(T, "verify_deployment"), patch.object(T, "verify_readiness"), patch.object(T, "execute", side_effect=execute), \
         contextlib.redirect_stdout(io.StringIO()) as output:
      status = T._dispatch(action, generation=generation)
    return status, output.getvalue()

  # --- naming --------------------------------------------------------------------------------------
  def test_generation_root_is_derived_from_the_manifest_digest_and_is_distinct(self):
    self.assertEqual(T.generation_root(self.new_manifest), self.generations / self.identity)
    self.assertEqual(T.generation_root(self.identity), self.generations / self.identity)
    self.assertNotEqual(T.generation_root(self.old_manifest), T.generation_root(self.new_manifest))
    self.assertNotIn(self.base, (T.generation_root(self.new_manifest), T.generation_root(self.old_manifest)))
    self.assertEqual(T.generation_root(self.new_manifest).parent.parent, self.base)

  def test_malformed_generation_names_and_manifests_are_refused(self):
    for bad in ("", "ABCDEF012345", "0123456789a", "0123456789abc", "../0123456789", "0123456789/a", "g" * 12, "0123456789ab\n"):
      with self.subTest(bad=bad), self.assertRaises(ValueError): T.generation_root(bad)
    with self.assertRaises(ValueError): T.generation_root({**self.new_manifest, "model": "Other"})
    with self.assertRaises(ValueError): T.generation_root({"protocol": TX.PROTOCOL})

  # --- the historical root is untouched and still refuses ----------------------------------------------
  def test_the_original_root_keeps_its_consumed_guard_and_still_refuses(self):
    before = self.snapshot(self.legacy)
    with self.assertRaisesRegex(ValueError, "permanently consumed"): self.dispatch("execute", report={"manifest": self.old_manifest})
    self.assertEqual(self.calls, [])
    self.assertEqual(self.snapshot(self.legacy), before)
    with self.assertRaisesRegex(ValueError, "permanently consumed"): self.dispatch("inspect", report={"manifest": self.old_manifest})  # historical behavior: every action refuses
    self.assertEqual(self.calls, [])
    self.assertEqual(self.snapshot(self.legacy), before)

  def test_the_historical_constructor_repair_is_still_bound_to_the_original_root(self):
    with patch.object(T, "repair_constructor", side_effect=AssertionError("original repair must not run here")), patch.object(T.ARTIFACTS, "derive_artifacts", return_value=self.report), \
         patch.object(T, "validate"), patch.object(T, "verify_deployment"), patch.object(T, "verify_readiness"):
      with self.assertRaises(AssertionError): T._dispatch("repair-constructor")
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()): T.main(["repair-constructor", "--generation", self.identity])

  # --- a generation root is fresh, separate and one-use in its own right -------------------------------------
  def test_execute_in_a_generation_uses_only_that_roots_ledger_guards_and_archives(self):
    before = self.snapshot(self.legacy)
    status, output = self.dispatch("execute", generation=self.identity)
    self.assertEqual(status, 0)
    self.assertEqual(json.loads(output)["classification"], "one-use-product-trial-not-usable-qualification")
    self.assertEqual(self.calls, [{"config": str(self.root / "config.json"), "ledger": self.root / "ledger", "guard": self.root / "guards", "archive": self.root / "archives"}])
    self.assertEqual(self.snapshot(self.legacy), before)  # the original state, its consumed guard and its ledger are never touched

  def test_the_generation_guard_is_its_own_one_shot_and_the_original_guard_is_not_consulted(self):
    (self.root / "guards/trial-consumed.json").write_bytes(b"generation guard")
    (self.root / "guards/trial-consumed.json").chmod(0o600)
    with self.assertRaisesRegex(ValueError, "permanently consumed"): self.dispatch("execute", generation=self.identity)
    self.assertEqual(self.calls, [])
    (self.root / "guards/trial-consumed.json").unlink()
    (self.legacy / "guards/trial-consumed.json").write_bytes(self.guard_bytes)
    self.assertEqual(self.dispatch("execute", generation=self.identity)[0], 0)  # an unconsumed generation is not blocked by the historical guard

  def test_inspect_and_check_in_a_generation_never_execute(self):
    for action in ("inspect", "check"):
      status, output = self.dispatch(action, generation=self.identity)
      self.assertEqual(status, 0)
      self.assertEqual(json.loads(output)["manifest_sha256"], TX.digest(self.new_manifest))
    self.assertEqual(self.calls, [])

  def test_a_generation_root_cannot_re_run_the_original_trials_manifest_under_any_name(self):
    self.make_root(self.generations / self.old_identity)  # a freshly provisioned alias of the consumed trial
    with self.assertRaisesRegex(ValueError, "original one-use trial manifest"): self.dispatch("execute", generation=self.old_identity, report={"manifest": self.old_manifest})
    (self.legacy / "guards/trial-consumed.json").unlink()  # the config alone still names it
    with self.assertRaisesRegex(ValueError, "original one-use trial manifest"): self.dispatch("execute", generation=self.old_identity, report={"manifest": self.old_manifest})
    (self.legacy / "guards/trial-consumed.json").write_bytes(self.guard_bytes)
    (self.legacy / "config.json").unlink()  # and so does the consumed guard alone
    with self.assertRaisesRegex(ValueError, "original one-use trial manifest"): self.dispatch("execute", generation=self.old_identity, report={"manifest": self.old_manifest})
    self.assertEqual(self.calls, [])
    (self.legacy / "guards/trial-consumed.json").write_bytes(b"not json")  # an unreadable consumed guard fails closed
    with self.assertRaises(ValueError): self.dispatch("execute", generation=self.identity)
    (self.legacy / "guards/trial-consumed.json").write_bytes(json.dumps({"cycle": {}}).encode())
    with self.assertRaisesRegex(ValueError, "unreadable"): self.dispatch("execute", generation=self.identity)
    self.assertEqual(self.calls, [])

  def test_the_generation_root_must_bind_the_audited_manifest(self):
    other = manifest("another")
    with self.assertRaisesRegex(ValueError, "binds the audited manifest"): self.dispatch("execute", generation=self.identity, report={"manifest": other})
    self.assertEqual(self.calls, [])

  def test_missing_or_unsafe_generation_state_refuses_before_any_action(self):
    with self.assertRaises((OSError, ValueError)): self.dispatch("execute", generation="0" * 12)
    (self.root / "ledger").chmod(0o755)
    with self.assertRaisesRegex(ValueError, "root-private"): self.dispatch("execute", generation=self.identity)
    (self.root / "ledger").chmod(0o700)
    self.root.chmod(0o755)
    with self.assertRaisesRegex(ValueError, "root-private"): self.dispatch("execute", generation=self.identity)
    self.root.chmod(0o700)
    self.generations.chmod(0o755)
    with self.assertRaisesRegex(ValueError, "root-private"): self.dispatch("execute", generation=self.identity)
    self.generations.chmod(0o700)
    self.assertEqual(self.calls, [])

  def test_a_symlinked_generation_root_is_refused(self):
    link = self.generations / ("0" * 12)
    link.symlink_to(self.root)
    with self.assertRaisesRegex(ValueError, "root-private|binds"): self.dispatch("execute", generation="0" * 12)
    self.assertEqual(self.calls, [])

  # --- the CLI ---------------------------------------------------------------------------------------
  def main(self, argv):
    with patch.object(T, "_dispatch", return_value=0) as dispatch, patch.object(T, "_global_lock", contextlib.nullcontext), patch.object(T.os, "geteuid", return_value=0):
      status = T.main(argv)
    return status, dispatch

  def test_cli_accepts_only_a_twelve_hex_generation_and_keeps_the_original_form(self):
    status, dispatch = self.main(["execute"])
    dispatch.assert_called_once_with("execute")
    status, dispatch = self.main(["execute", "--generation", self.identity])
    dispatch.assert_called_once_with("execute", generation=self.identity)
    status, dispatch = self.main(["--generation", self.identity])
    dispatch.assert_called_once_with("inspect", generation=self.identity)
    for argv in (["execute", "--generation", "ABCDEF012345"], ["execute", "--generation", "short"], ["execute", "--generation", "../../etc"], ["execute", "--generation"],
                 ["execute", "--state", "/tmp/x"], ["execute", "--root", "/tmp/x"], ["repair-constructor", "--generation", self.identity]):
      with self.subTest(argv=argv), patch.object(T, "_dispatch", side_effect=AssertionError("must refuse first")), contextlib.redirect_stderr(io.StringIO()):
        with self.assertRaises(SystemExit): T.main(argv)

  def test_execute_still_requires_explicit_root(self):
    with patch.object(T.os, "geteuid", return_value=1000), patch.object(T, "_dispatch", side_effect=AssertionError("must refuse first")), contextlib.redirect_stderr(io.StringIO()):
      with self.assertRaises(SystemExit): T.main(["execute", "--generation", self.identity])

  def test_the_physical_cycle_lock_stays_global(self):
    self.assertEqual(T.STATE / "physical-cycle.lock", self.base / "physical-cycle.lock")
    with patch.object(T.os, "open", side_effect=RuntimeError("stop")) as opened, self.assertRaises(RuntimeError):
      with T._global_lock(): pass
    self.assertEqual(opened.call_args.args[0], self.base / "physical-cycle.lock")
    self.assertFalse((self.generations / "physical-cycle.lock").exists() or (self.root / "physical-cycle.lock").exists())

  # --- ledger-level: each generation can consume its own one-use trial exactly once -----------------------------
  def test_generations_consume_independent_one_use_guards_and_the_historical_one_still_blocks_its_ledger(self):
    boot = str(uuid.uuid4())
    legacy_ledger = TX.Ledger(self.legacy / "ledger")
    legacy_ledger.configure(self.old_manifest)
    with self.assertRaisesRegex(ValueError, "already consumed"): legacy_ledger.authorize_trial(authorization(self.old_manifest, boot), self.legacy / "guards")
    ledger = TX.Ledger(self.root / "ledger")
    ledger.configure(self.new_manifest)
    ledger.authorize_trial(authorization(self.new_manifest, boot), self.root / "guards")
    cycle = ledger.begin(boot)
    self.assertEqual(cycle["manifest"], self.new_manifest)
    guard = json.loads((self.root / "guards/trial-consumed.json").read_text())
    self.assertEqual(guard["cycle"]["cycle_id"], cycle["cycle_id"])
    self.assertEqual((self.legacy / "guards/trial-consumed.json").read_bytes(), self.guard_bytes)
    with self.assertRaisesRegex(ValueError, "already consumed"): ledger.authorize_trial(authorization(self.new_manifest, boot), self.root / "guards")
    second = manifest("newer")
    other = self.make_root(self.generations / T.TX.digest(second)[:12])
    newer = TX.Ledger(other / "ledger")
    newer.configure(second)
    newer.authorize_trial(authorization(second, boot), other / "guards")  # a later generation is again fresh
    newer.begin(boot)
    self.assertEqual(json.loads((self.root / "guards/trial-consumed.json").read_text())["cycle"]["cycle_id"], cycle["cycle_id"])


if __name__ == "__main__": unittest.main()
