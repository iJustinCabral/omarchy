"""Runtime upgrade under package maintenance: tempdirs and mocks only; no lock, inhibitor, EFI or power operation."""
import hashlib
import importlib.util
import signal
import json
import os
from pathlib import Path
from types import SimpleNamespace
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


DT = load("maintenance_upgrade_deployment_tests", Path(__file__).with_name("test-hibernate-product-runtime-deployment.py"))
D = DT.D
N = load("maintenance_upgrade_native", HERE / "hibernate/runtime_upgrade_native.py")


def sha(raw): return hashlib.sha256(raw).hexdigest()


def rewrite(path, raw):
  path.write_bytes(raw)
  path.chmod(0o600)


class Fixture(unittest.TestCase):
  """A runtime-only v2 upgrade fixture plus a synthetic marker, archive and generation baseline bound to the old review."""

  def setUp(self):
    self.case = DT.Deployment(methodName="runTest")
    self.case.setUp()
    self.addCleanup(self.case.tearDown)
    self.state = self.case.state
    self.expected, self.config = self.case.runtime_only_fixture()
    (self.state / "boot-policy.json").unlink()  # the fixture's ACTIVE-state files do not exist under maintenance
    (self.case.root / "etc/omarchy/t2-hibernate-product.enabled").unlink()
    self.identifier = str(uuid.uuid4())
    self.fields = {"protocol": D.MAINTENANCE_SCHEMA, "transition_id": self.identifier, "old_policy_sha256": "1" * 64,
                   "runtime_review_sha256": self.expected["old_review"], "staged_receipt_sha256": "2" * 64,
                   "fallback_limine_sha256": "3" * 64, "deactivation_completion_sha256": "4" * 64}
    self.marker = D._encoded(self.fields)
    self.baseline_fields = {"protocol": D.BASELINE_SCHEMA, "transition_id": self.identifier, "maintenance_intent_sha256": sha(self.marker),
                            "items": {"kernel": {"running_release": "7.2.7"}, "limine": {"exact_sha256": "5" * 64}},
                            "old_policy_sha256": "1" * 64, "staged_receipt_sha256": "2" * 64, "deactivation_completion_sha256": "4" * 64}
    self.baseline = D._encoded(self.baseline_fields)
    self.archive = self.state / D.HISTORY / self.identifier
    self.archive.mkdir(parents=True, mode=0o700)
    (self.state / D.HISTORY).chmod(0o700)
    for path, raw in ((self.archive / "maintenance-intent.json", self.marker), (self.archive / D.BASELINE_NAME, self.baseline), (self.state / D.MAINTENANCE_PENDING, self.marker)):
      rewrite(path, raw)
    self.new_marker, self.new_baseline = D._maintenance_binding(self.marker, self.baseline, self.expected["old_review"], self.expected["new_review"])
    self.events = []

  def upgrade(self, *, maintenance=True, **changes):
    def precheck(): self.events.append("precheck")
    def postcheck():
      self.events.append("postcheck")
      self.assertTrue((self.state / D.COMPATIBLE_BARRIER).exists() and (self.state / D.UPGRADE_PENDING).exists())  # both vetoes still held
      self.assertEqual(self.triple(), (self.new_baseline, self.new_marker, self.new_marker))
    arguments = {"expected": self.expected, "approval_id": self.case.approval_id, "guard": lambda: None, "precheck": precheck, "postcheck": postcheck, "maintenance": maintenance}
    return D.upgrade_snapshot(self.case.source, root=self.case.root, **{**arguments, **changes})

  def triple(self):
    return ((self.archive / D.BASELINE_NAME).read_bytes(), (self.archive / "maintenance-intent.json").read_bytes(), (self.state / D.MAINTENANCE_PENDING).read_bytes())

  def old_triple(self): return (self.baseline, self.marker, self.marker)

  def new_triple(self): return (self.new_baseline, self.new_marker, self.new_marker)

  def tree(self):
    return {str(path.relative_to(self.case.root)): (path.stat().st_mode, path.read_bytes() if path.is_file() else None) for path in sorted(self.case.root.rglob("*"))}

  def review_digest(self): return sha((self.state / D.REVIEW.name).read_bytes())

  def record(self): return json.loads((self.state / D.UPGRADE_PENDING).read_bytes())


class Core(Fixture):
  """runtime_deployment._upgrade_snapshot(maintenance=True)."""

  # --- the ordinary path keeps its refusal ---------------------------------------------------------
  def test_the_ordinary_path_still_refuses_under_a_marker_and_touches_nothing(self):
    before = self.tree()
    with self.assertRaisesRegex(ValueError, "automatic retry"): self.upgrade(maintenance=False, postcheck=lambda: self.fail("no admission under a marker"))
    with self.assertRaisesRegex(ValueError, "automatic retry"):
      D.upgrade_snapshot(self.case.source, root=self.case.root, expected=self.expected, approval_id=self.case.approval_id, guard=lambda: None, precheck=lambda: None, postcheck=lambda: None)
    self.assertEqual(self.tree(), before)

  def test_maintenance_mode_is_explicit_and_boolean(self):
    for value in ("yes", 1, None):
      with self.subTest(value=value), self.assertRaisesRegex(ValueError, "boolean maintenance"): self.upgrade(maintenance=value)

  # --- the maintenance path ------------------------------------------------------------------------
  def test_maintenance_upgrade_rewrites_marker_archived_intent_and_baseline_together(self):
    result = self.upgrade()
    self.assertEqual(result["review_sha256"], self.expected["new_review"])
    self.assertEqual(self.events, ["precheck", "postcheck"])
    self.assertEqual(self.triple(), self.new_triple())
    fields = json.loads(self.new_marker)
    self.assertEqual(fields["runtime_review_sha256"], self.expected["new_review"])
    self.assertEqual({key: value for key, value in fields.items() if key != "runtime_review_sha256"}, {key: value for key, value in self.fields.items() if key != "runtime_review_sha256"})
    baseline = json.loads(self.new_baseline)
    self.assertEqual(baseline["maintenance_intent_sha256"], sha(self.new_marker))
    self.assertEqual({key: value for key, value in baseline.items() if key != "maintenance_intent_sha256"}, {key: value for key, value in self.baseline_fields.items() if key != "maintenance_intent_sha256"})
    old_marker, old_baseline, record = D._binding_names(self.expected["new_review"])
    self.assertEqual((self.archive / old_marker).read_bytes(), self.marker)
    self.assertEqual((self.archive / old_baseline).read_bytes(), self.baseline)
    rebind = json.loads((self.archive / record).read_bytes())
    self.assertEqual((rebind["protocol"], rebind["approval_id"], rebind["old_marker_sha256"], rebind["new_marker_sha256"]), (D.REBIND_RECORD_SCHEMA, self.case.approval_id, sha(self.marker), sha(self.new_marker)))
    for path in (self.archive / old_marker, self.archive / old_baseline, self.archive / record, self.state / D.MAINTENANCE_PENDING, self.archive / D.BASELINE_NAME):
      self.assertEqual(path.stat().st_mode & 0o777, 0o600)
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists() or (self.state / D.UPGRADE_PENDING).exists())
    self.assertEqual((self.state / D.CONFIG).read_bytes(), self.config)  # runtime-only: exact configuration bytes
    completed = json.loads((self.state / "runtime-upgrade-completed-bbbbbbbbbbbb.json").read_bytes())
    consumed = json.loads((self.state / ("runtime-upgrade-approval-consumed-" + self.case.approval_id + ".json")).read_bytes())
    self.assertEqual((completed["protocol"], consumed["protocol"]), (D.COMPLETED_MAINTENANCE, D.INTENT_MAINTENANCE))
    self.assertEqual(completed["intent"], consumed)
    self.assertEqual(consumed["marker_sha256"], sha(self.marker))
    self.assertEqual(self.review_digest(), self.expected["new_review"])
    self.assertEqual(self.case.historical.read_bytes(), b"consumed v1-to-v2 evidence")

  def test_the_approval_is_consumed_and_a_second_upgrade_refuses(self):
    self.upgrade()
    with self.assertRaisesRegex(ValueError, "automatic retry|pin differs"): self.upgrade()  # the consumed approval and the old pins are both spent

  def test_missing_reused_or_malformed_approval_and_pins_refuse_before_the_barrier(self):
    before = self.tree()
    for identity in (None, "not-an-id", "306521e4-998e-1477-b603-31b93144d101"):
      with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "UUID4"): self.upgrade(approval_id=identity)
    with self.assertRaisesRegex(ValueError, "Exact old/new"): self.upgrade(expected={**self.expected, "extra": "0" * 64})
    with self.assertRaisesRegex(ValueError, "Invalid exact upgrade pin"): self.upgrade(expected={**self.expected, "old_review": "nope"})
    with self.assertRaisesRegex(ValueError, "Exact upgrade pin differs"): self.upgrade(expected={**self.expected, "old_review": "0" * 64})
    self.assertEqual(self.tree(), before)

  def test_changed_configuration_and_the_historical_v1_upgrade_refuse_in_maintenance(self):
    rewrite(self.state / D.CANDIDATE_CONFIG, self.config + b"\n")
    with self.assertRaisesRegex(ValueError, "exact configuration bytes"): self.upgrade(expected={**self.expected, "new_config": sha(self.config + b"\n")})
    case = DT.Deployment(methodName="runTest")
    case.setUp()
    self.addCleanup(case.tearDown)
    expected = case.upgrade_fixture()[0]  # v1 -> v2 configuration upgrade, not runtime-only
    with self.assertRaisesRegex(ValueError, "runtime-only"):
      D.upgrade_snapshot(case.source, root=case.root, expected=expected, guard=lambda: None, precheck=lambda: None, postcheck=lambda: None, maintenance=True)
    self.assertFalse((case.state / D.COMPATIBLE_BARRIER).exists())

  def test_every_marker_archive_and_baseline_defect_refuses_before_any_write(self):
    def both(case, raw):
      rewrite(case.state / D.MAINTENANCE_PENDING, raw)
      rewrite(case.archive / "maintenance-intent.json", raw)
    def defective(case, **changes): return D._encoded({**case.fields, **changes})
    def baseline(case, **changes): rewrite(case.archive / D.BASELINE_NAME, D._encoded({**case.baseline_fields, **changes}))
    cases = {
      "no marker": (lambda c: (c.state / D.MAINTENANCE_PENDING).unlink(), "requires the package maintenance marker"),
      "marker bound to another runtime": (lambda c: both(c, defective(c, runtime_review_sha256="9" * 64)), "not bound to the old runtime review"),
      "marker not canonical": (lambda c: both(c, c.marker + b"\n"), "canonical maintenance intent"),
      "marker extra field": (lambda c: both(c, defective(c, x=1)), "canonical maintenance intent"),
      "marker other protocol": (lambda c: both(c, defective(c, protocol="x")), "canonical maintenance intent"),
      "marker transition not a uuid": (lambda c: both(c, defective(c, transition_id="x")), "UUID"),
      "archive intent differs": (lambda c: rewrite(c.archive / "maintenance-intent.json", defective(c, runtime_review_sha256="9" * 64)), "differs from its archived intent"),
      "archive intent missing": (lambda c: (c.archive / "maintenance-intent.json").unlink(), ""),
      "baseline missing": (lambda c: (c.archive / D.BASELINE_NAME).unlink(), ""),
      "baseline not bound to the marker": (lambda c: baseline(c, maintenance_intent_sha256="6" * 64), "generation baseline bound"),
      "baseline other transition": (lambda c: baseline(c, transition_id=str(uuid.uuid4())), "generation baseline bound"),
      "baseline other protocol": (lambda c: baseline(c, protocol="x"), "generation baseline bound"),
      "baseline not canonical": (lambda c: rewrite(c.archive / D.BASELINE_NAME, c.baseline + b"\n"), "generation baseline bound|Extra data"),
      "archive directory not private": (lambda c: c.archive.chmod(0o755), "private maintenance evidence directory"),
      "history directory not private": (lambda c: (c.state / D.HISTORY).chmod(0o755), "private maintenance evidence directory"),
      "prior rebind evidence": (lambda c: rewrite(c.archive / D._binding_names(c.expected["new_review"])[2], b"{}"), "refuses automatic retry"),
      "stray marker temporary": (lambda c: rewrite(c.state / (D.MAINTENANCE_PENDING + ".runtime-rebind-tmp"), b"x"), "refuses automatic retry"),
      "deactivation pending": (lambda c: rewrite(c.state / D.DEACTIVATION_PENDING, b"x"), "automatic retry"),
      "existing barrier": (lambda c: rewrite(c.state / D.COMPATIBLE_BARRIER, b"x"), "automatic retry"),
    }
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        case = Fixture("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        mutate(case)
        before = case.tree()
        with self.assertRaisesRegex((ValueError, OSError), pattern):
          case.upgrade(postcheck=lambda: self.fail("no admission"), precheck=lambda: self.fail("no precheck"))
        after = case.tree()
        self.assertEqual({name: value for name, value in after.items() if not name.endswith("runtime-deployment.lock")}, {name: value for name, value in before.items() if not name.endswith("runtime-deployment.lock")})
        self.assertFalse((case.state / D.UPGRADE_PENDING).exists())

  def test_a_stray_archive_temporary_is_replaced_not_trusted(self):
    rewrite(self.archive / (D.BASELINE_NAME + ".runtime-rebind-tmp"), b"stray")
    self.upgrade()
    self.assertEqual(self.triple(), self.new_triple())
    self.assertFalse((self.archive / (D.BASELINE_NAME + ".runtime-rebind-tmp")).exists())

  def test_pre_and_post_check_failures_keep_the_barrier_and_the_consistent_marker_binding(self):
    def refuse(): raise ValueError("no saved image proof")
    with self.assertRaisesRegex(ValueError, "no saved image proof"): self.upgrade(precheck=refuse)
    self.assertFalse((self.state / D.COMPATIBLE_BARRIER).exists())  # a precheck failure precedes every write
    self.assertEqual(self.triple(), self.old_triple())
    self.assertEqual(self.review_digest(), self.expected["old_review"])
    case = Fixture("runTest")
    case.setUp()
    self.addCleanup(case.doCleanups)
    with self.assertRaisesRegex(ValueError, "guard refused"): case.upgrade(postcheck=lambda: (_ for _ in ()).throw(ValueError("guard refused")))
    self.assertTrue((case.state / D.COMPATIBLE_BARRIER).exists() and (case.state / D.UPGRADE_PENDING).exists())  # the veto stays
    self.assertEqual(case.triple(), case.new_triple())  # the rewrite completed atomically with the new runtime
    with self.assertRaisesRegex(ValueError, "automatic retry"): case.upgrade()

  # --- every rewrite step can fail; settling converges to the installed runtime -----------------------
  def test_a_fault_at_every_rewrite_write_leaves_a_veto_and_settles_to_the_installed_runtime(self):
    calls = []
    original = D._write_private
    def trace(path, raw, *, replace):
      calls.append((Path(path).name, replace))
      return original(path, raw, replace=replace)
    with patch.object(D, "_write_private", side_effect=trace): self.upgrade()
    self.assertEqual(len(calls), 6)  # three exclusive copies/records and three replacements
    for number in range(1, len(calls) + 1):
      with self.subTest(fault_at=number):
        case = Fixture("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        seen = []
        def fail(path, raw, *, replace, case=case, number=number, seen=seen):
          seen.append(path)
          if len(seen) == number: raise OSError("simulated storage fault at write " + str(number))
          return original(path, raw, replace=replace)
        with patch.object(D, "_write_private", side_effect=fail), self.assertRaisesRegex(OSError, "simulated storage fault"): case.upgrade()
        self.assertTrue((case.state / D.COMPATIBLE_BARRIER).exists() and (case.state / D.UPGRADE_PENDING).exists())  # sleep and updates stay vetoed
        self.assertEqual(case.review_digest(), case.expected["new_review"])  # the new runtime is what is installed
        record = case.record()
        old_marker, old_baseline, _ = D._binding_names(case.expected["new_review"])
        for name, expected in ((old_marker, case.marker), (old_baseline, case.baseline)):  # a retained copy is never torn under its name
          if (case.archive / name).exists(): self.assertEqual((case.archive / name).read_bytes(), expected)
        self.assertEqual(D.settle_maintenance_binding(case.state, record, case.review_digest()), "new")
        self.assertEqual(case.triple(), case.new_triple())
        self.assertEqual(D.settle_maintenance_binding(case.state, record, case.review_digest()), "new")  # idempotent
        self.assertEqual(case.triple(), case.new_triple())

  def test_a_storage_fault_while_writing_a_retained_copy_leaves_no_torn_file_under_its_name(self):
    old_marker, old_baseline, record = D._binding_names(self.expected["new_review"])
    real_fsync = D.os.fsync
    state = {"armed": False}
    def fsync(fd):
      if state["armed"]: raise OSError("storage fault after the bytes were written")
      return real_fsync(fd)
    real = D._write_private
    def arm(path, raw, *, replace):
      state["armed"] = Path(path).name == old_baseline
      try: return real(path, raw, replace=replace)
      finally: state["armed"] = False
    with patch.object(D, "_write_private", side_effect=arm), patch.object(D.os, "fsync", side_effect=fsync), self.assertRaisesRegex(OSError, "storage fault"): self.upgrade()
    self.assertFalse((self.archive / old_baseline).exists())  # only a stray temporary may hold the bytes
    self.assertEqual((self.archive / old_marker).read_bytes(), self.marker)
    self.assertEqual(D.settle_maintenance_binding(self.state, self.record(), self.review_digest()), "new")
    self.assertEqual(self.triple(), self.new_triple())
    self.assertEqual((self.archive / old_baseline).read_bytes(), self.baseline)

  def test_settling_to_the_old_runtime_restores_the_exact_old_bytes_from_every_partial_state(self):
    original = D._write_private
    for number in range(1, 7):
      with self.subTest(fault_at=number):
        case = Fixture("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        seen = []
        def fail(path, raw, *, replace, number=number, seen=seen):
          seen.append(path)
          if len(seen) == number: raise OSError("simulated storage fault")
          return original(path, raw, replace=replace)
        with patch.object(D, "_write_private", side_effect=fail), self.assertRaises(OSError): case.upgrade()
        self.assertEqual(D.settle_maintenance_binding(case.state, case.record(), case.expected["old_review"]), "old")  # the operator restored the old runtime
        self.assertEqual(case.triple(), case.old_triple())

  def test_settling_refuses_foreign_bytes_and_unknown_runtimes_without_touching_anything(self):
    with patch.object(D, "_write_private", side_effect=OSError("stop")), self.assertRaises(OSError): self.upgrade()
    record = self.record()
    before = self.triple()
    with self.assertRaisesRegex(ValueError, "neither the old nor the new one"): D.settle_maintenance_binding(self.state, record, "0" * 64)
    self.assertEqual(self.triple(), before)
    for name, path in (("baseline", self.archive / D.BASELINE_NAME), ("archived intent", self.archive / "maintenance-intent.json"), ("marker", self.state / D.MAINTENANCE_PENDING)):
      with self.subTest(name):
        original = path.read_bytes()
        rewrite(path, original + b" ")
        held = tuple(item.read_bytes() for item in (self.archive / D.BASELINE_NAME, self.archive / "maintenance-intent.json", self.state / D.MAINTENANCE_PENDING))
        with self.assertRaises(ValueError): D.settle_maintenance_binding(self.state, record, self.expected["new_review"])
        self.assertEqual(tuple(item.read_bytes() for item in (self.archive / D.BASELINE_NAME, self.archive / "maintenance-intent.json", self.state / D.MAINTENANCE_PENDING)), held)
        rewrite(path, original)
    with self.assertRaisesRegex(ValueError, "not the one the upgrade pinned"): D.settle_maintenance_binding(self.state, {**record, "marker_sha256": "0" * 64}, self.expected["new_review"])

  def test_binding_is_pure_and_only_moves_the_runtime_review_and_the_bound_digest(self):
    marker, baseline = D._maintenance_binding(self.marker, self.baseline, self.expected["old_review"], "7" * 64)
    self.assertEqual(json.loads(marker), {**self.fields, "runtime_review_sha256": "7" * 64})
    self.assertEqual(json.loads(baseline), {**self.baseline_fields, "maintenance_intent_sha256": sha(marker)})
    self.assertEqual(D._maintenance_binding(marker, baseline, "7" * 64, self.expected["old_review"]), (self.marker, self.baseline))  # and it round-trips
    with self.assertRaisesRegex(ValueError, "not bound to the old runtime review"): D._maintenance_binding(self.marker, self.baseline, "8" * 64, "7" * 64)


class Adapter(unittest.TestCase):
  """The installed adapter's maintenance mode: approval parsing, host pins, guard-based checks and recovery."""

  def approval(self, maintenance=True):
    return {"protocol": N.MAINTENANCE_PROTOCOL if maintenance else N.ORDINARY_PROTOCOL, "approved": True,
            "approval_id": "306521e4-998e-4477-b603-31b93144d101", "current_boot_id": "0f909934-0ecf-4407-863d-6822c81cb2df",
            "source_directory": "/reviewed/source", "reviewed_commit": "a" * 40, "adapter_sha256": sha(b"adapter"),
            "expected": {name: "c" * 64 for name in N.HASHES},
            "unchanged": {name: "d" * 64 for name in (N.UNCHANGED_MAINTENANCE if maintenance else N.UNCHANGED)}}

  def parse(self, approval): return N._parse_approval(json.dumps(approval).encode(), b"adapter")

  def test_maintenance_approval_uses_the_v2_pins_and_its_own_host_pins(self):
    parsed = self.parse(self.approval())
    self.assertIs(parsed["maintenance"], True)
    self.assertIs(self.parse(self.approval(False))["maintenance"], False)
    self.assertEqual(set(N.UNCHANGED_MAINTENANCE), {"qualification", "hook", "marker"})
    cases = {"the ordinary host pins": lambda a: a.update(unchanged={name: "d" * 64 for name in N.UNCHANGED}),
             "a missing marker pin": lambda a: a["unchanged"].pop("marker"), "an extra pin": lambda a: a["unchanged"].update(limine="d" * 64),
             "a missing old config pin": lambda a: a["expected"].pop("old_config"), "a changed config pin": lambda a: a["expected"].update(new_config="e" * 64),
             "no new image-state pin": lambda a: a["expected"].pop("new_image_state"), "a short pin": lambda a: a["unchanged"].update(marker="d" * 63),
             "another adapter": lambda a: a.update(adapter_sha256=sha(b"other")), "unapproved": lambda a: a.update(approved=False),
             "another protocol": lambda a: a.update(protocol="omarchy-t2-runtime-upgrade-maintenance-approval-v2"),
             "a reused-format id": lambda a: a.update(approval_id="306521e4-998e-1477-b603-31b93144d101"), "a relative source": lambda a: a.update(source_directory="relative")}
    for label, mutate in cases.items():
      with self.subTest(label):
        approval = self.approval()
        mutate(approval)
        with self.assertRaises(ValueError): self.parse(approval)
    ordinary = self.approval(False)
    ordinary["unchanged"] = {name: "d" * 64 for name in N.UNCHANGED_MAINTENANCE}
    with self.assertRaisesRegex(ValueError, "unchanged host"): self.parse(ordinary)  # the ordinary protocol keeps its own pin set

  def unchanged(self, *, boot=None, contents=None, present=()):
    approval = {**self.parse(self.approval()), "current_boot_id": "b"}
    contents = contents or {name: b"same" for name in N.UNCHANGED_MAINTENANCE}
    pins = {name: sha(raw) for name, raw in contents.items()}
    approval["unchanged"] = {name: pins[name] for name in N.UNCHANGED_MAINTENANCE}
    by_path = {path: contents[name] for name, (path, mode) in N.UNCHANGED_MAINTENANCE.items()}
    def private(path, mode=None):
      if str(path) == "/proc/sys/kernel/random/boot_id": return ((boot or "b") + "\n").encode()
      return by_path[path]
    with patch.object(N, "_private_bytes", side_effect=private), patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)), \
         patch.object(Path, "is_symlink", return_value=False), patch.object(N.os.path, "lexists", side_effect=lambda path: Path(path) in present):
      return N._unchanged(approval)

  def test_maintenance_host_pins_are_exact_and_active_state_must_be_absent(self):
    self.unchanged()
    with self.assertRaisesRegex(ValueError, "boot changed"): self.unchanged(boot="other")
    for name in N.UNCHANGED_MAINTENANCE:
      with self.subTest(name), patch.object(N, "_private_bytes", side_effect=lambda path, mode=None, name=name: (b"b\n" if str(path).endswith("boot_id") else (b"x" if Path(path) == N.UNCHANGED_MAINTENANCE[name][0] else b"same"))), \
           patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)), patch.object(Path, "is_symlink", return_value=False), \
           patch.object(N.os.path, "lexists", return_value=False):
        approval = {**self.parse(self.approval()), "current_boot_id": "b", "unchanged": {item: sha(b"same") for item in N.UNCHANGED_MAINTENANCE}}
        with self.assertRaisesRegex(ValueError, "differs: " + name): N._unchanged(approval)
    for path in N.ABSENT_IN_MAINTENANCE:
      with self.subTest(present=path.name), self.assertRaisesRegex(ValueError, "Active source-default state"): self.unchanged(present=(path,))
    self.assertIn(Path("/etc/omarchy/t2-hibernate-product.enabled"), N.ABSENT_IN_MAINTENANCE)
    self.assertIn(N.STATE / "boot-policy.json", N.ABSENT_IN_MAINTENANCE)

  def test_the_maintenance_check_uses_the_guards_validator_with_exactly_the_two_vetoes_ignored(self):
    guard = Mock()
    guard.STATE = Path("var/lib/omarchy/t2-hibernate-product")
    resume = {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 10}
    guard._maintenance.return_value = {"resume": resume, "transition_id": "t"}
    image_state = Mock()
    image_state.require_no_image.return_value = {"classification": "no-image-at-qualified-resume-page"}
    self.assertEqual(N._maintenance_check(guard, barrier=False, image_state=image_state)["resume"], resume)
    guard._maintenance.assert_called_once_with(N.ROOT, ignore=())
    image_state.require_no_image.assert_called_once_with(N.ROOT, resume)
    guard._maintenance.reset_mock()
    N._maintenance_check(guard, barrier=True, image_state=image_state)
    guard._maintenance.assert_called_once_with(N.ROOT, ignore=(guard.STATE / "source-default-activation.pending", guard.STATE / "runtime-upgrade.pending"))
    for bad in ({"classification": "image"}, None, "no-image-at-qualified-resume-page"):
      image_state.require_no_image.return_value = bad
      with self.assertRaisesRegex(ValueError, "absence of a saved hibernation image"): N._maintenance_check(guard, barrier=False, image_state=image_state)
    image_state.require_no_image.side_effect = ValueError("image present")
    with self.assertRaisesRegex(ValueError, "image present"): N._maintenance_check(guard, barrier=False, image_state=image_state)
    guard._maintenance.side_effect = ValueError("chain broken")
    with self.assertRaisesRegex(ValueError, "chain broken"): N._maintenance_check(guard, barrier=True, image_state=image_state)
    # the installed image_state module is used after the barrier, never anything from the workspace
    guard._maintenance.side_effect = None
    installed = Mock()
    installed.require_no_image.return_value = {"classification": "no-image-at-qualified-resume-page"}
    with patch.object(N, "_load", return_value=installed) as load: N._maintenance_check(guard, barrier=False)
    load.assert_called_once_with("reviewed_upgrade_image_state", N.STATE / "runtime/packages/t2-suspend/hibernate/image_state.py")

  def test_maintenance_postcheck_loads_the_new_reviewed_guard_only_after_the_whole_tree_verifies(self):
    core = Mock()
    approval = {**self.parse(self.approval()), "reviewed_commit": "a" * 40}
    review = {"protocol": "omarchy-t2-product-runtime-snapshot-v1", "approved": True, "reviewed_commit": "a" * 40, "files": {}}
    raw = json.dumps(review).encode()
    approval["expected"] = {**approval["expected"], "new_review": sha(raw)}
    guard = Mock()
    with patch.object(N, "_private_bytes", return_value=raw), patch.object(N, "_load_new_guard", return_value=guard), patch.object(N, "_maintenance_check") as check:
      N._postcheck(core, approval)
    core._verify_tree.assert_called_once()
    check.assert_called_once_with(guard, barrier=True)
    # the ordinary approval never reaches the guard-based check
    ordinary = {**approval, "maintenance": False}
    product = Mock()
    with patch.object(N, "_private_bytes", return_value=raw), patch.object(N, "_load", return_value=product), patch.object(N, "_product_check") as product_check, patch.object(N, "_maintenance_check") as check:
      N._postcheck(core, ordinary)
    check.assert_not_called()
    product_check.assert_called_once_with(product, barrier=True)

  def test_signals_become_systemexit_and_previous_handlers_are_restored(self):
    before = {number: signal.getsignal(number) for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)}
    for number in before:
      with self.subTest(signal=number), self.assertRaises(SystemExit) as caught:
        with N._signals_raise(): os.kill(os.getpid(), number)
      self.assertEqual(caught.exception.code, 128 + number)
      self.assertEqual({n: signal.getsignal(n) for n in before}, before)

  def intent(self, approval, **changes):
    expected = approval["expected"]
    record = {"protocol": D.INTENT_MAINTENANCE, "transaction_id": "706521e4-998e-4477-b603-31b93144d102", "approval_id": approval["approval_id"],
              "old_review_sha256": expected["old_review"], "new_review_sha256": expected["new_review"], "old_config_sha256": expected["old_config"],
              "new_config_sha256": expected["new_config"], "marker_sha256": "e" * 64}
    return {**record, **changes}

  def test_recovery_intents_are_mode_specific(self):
    maintenance = {**self.parse(self.approval()), "maintenance": True}
    ordinary = {**self.parse(self.approval(False)), "maintenance": False}
    raw = D._encoded(self.intent(maintenance))
    self.assertEqual(N._intent(D, maintenance, raw), raw)
    with self.assertRaisesRegex(ValueError, "invalid intent"): N._intent(D, ordinary, raw)  # a maintenance intent is never an ordinary recovery intent
    plain = {key: value for key, value in self.intent(maintenance, protocol="omarchy-t2-runtime-upgrade-intent-v2").items() if key != "marker_sha256"}
    with self.assertRaisesRegex(ValueError, "invalid intent"): N._intent(D, maintenance, D._encoded(plain))
    self.assertEqual(N._intent(D, ordinary, D._encoded(plain)), D._encoded(plain))
    for changes in ({"approval_id": "306521e4-998e-4477-b603-31b93144d103"}, {"new_review_sha256": "0" * 64}, {"protocol": "x"}):
      with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "invalid intent"): N._intent(D, maintenance, D._encoded(self.intent(maintenance, **changes)))

  def test_maintenance_recovery_restores_the_veto_then_settles_the_marker_binding(self):
    approval = {**self.parse(self.approval()), "maintenance": True}
    intent = self.intent(approval)
    with tempfile.TemporaryDirectory() as directory:
      state = Path(directory)
      state.chmod(0o700)
      raw = D._encoded(intent)
      consumed = state / ("runtime-upgrade-approval-consumed-" + approval["approval_id"] + ".json")
      rewrite(consumed, raw)
      settle = Mock(return_value="new")
      core = SimpleNamespace(**{name: getattr(D, name) for name in dir(D) if not name.startswith("__")})
      core.settle_maintenance_binding = settle
      installed = b"installed review"
      rewrite(state / "runtime-deployment-review.json", installed)
      with patch.object(N, "STATE", state), patch.object(N, "_private_bytes", side_effect=lambda path, mode=0o600: Path(path).read_bytes()):
        N._restore_veto(core, approval)
        self.assertEqual((state / D.COMPATIBLE_BARRIER).read_bytes(), raw)  # the durable veto is restored first
        settle.assert_called_once()
        self.assertEqual(settle.call_args.args, (state, intent, sha(installed)))
        settle.reset_mock()
        # an ordinary approval never settles a marker
        ordinary = {**approval, "maintenance": False}
        with self.assertRaises(ValueError): N._restore_veto(core, ordinary)
        settle.assert_not_called()
        # a failing settle propagates so the recovery retries with the veto retained
        settle.side_effect = ValueError("foreign marker bytes preserved")
        with self.assertRaisesRegex(ValueError, "foreign marker bytes"): N._restore_veto(core, approval)
        self.assertTrue((state / D.COMPATIBLE_BARRIER).exists())


class LiveGuard(Fixture):
  """The REAL adapter guard (`N._guard`, `N._unchanged`) driving the REAL core, in the live call order.

  The earlier fixtures gave the core `guard=lambda: None` and tested `_unchanged` against mocked files, so nothing ever
  called the real guard after the core had written its own barrier or rebound the marker. Only the fixed host paths, the
  root-ownership requirement, the ancestry walk and the inhibitor-parent probe are redirected to the tempdir; the guard's
  decisions are the installed ones.
  """

  def setUp(self):
    super().setUp()
    root = self.case.root
    self.qualification = self.state / "qualification.json"
    rewrite(self.qualification, b"qualification bytes")
    self.hook = root / D.HOOK
    self.barrier, self.pending = self.state / D.COMPATIBLE_BARRIER, self.state / D.UPGRADE_PENDING
    marker = self.state / D.MAINTENANCE_PENDING
    patches = {"STATE": self.state, "BARRIER": self.barrier, "UPGRADE_PENDING": self.pending, "OWNERS": (0, os.geteuid()),
               # the adapter's own list, re-rooted: whatever it names as active state is what the fixture checks
               "ABSENT_IN_MAINTENANCE": tuple(self.state / path.name if path.parent == N.STATE else root / path.relative_to("/") for path in N.ABSENT_IN_MAINTENANCE),
               "UNCHANGED_MAINTENANCE": {"qualification": (self.qualification, 0o600), "hook": (self.hook, 0o644), "marker": (marker, 0o600)},
               "_ancestry": lambda path, name: None, "_parent_identity": lambda pid: "identity"}
    for name, value in patches.items():
      patcher = patch.object(N, name, value)
      patcher.start()
      self.addCleanup(patcher.stop)
    self.approval = self.make_approval()
    self.guard_fd, self.check = N._guard(SimpleNamespace(_power_idle=lambda pid: None), self.approval)
    self.addCleanup(os.close, self.guard_fd)

  def make_approval(self, **changes):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    expected = {**self.expected, "new_image_state": "c" * 64}
    approval = {"protocol": N.MAINTENANCE_PROTOCOL, "approved": True, "approval_id": self.case.approval_id, "current_boot_id": boot,
                "source_directory": "/reviewed/source", "reviewed_commit": "b" * 40, "adapter_sha256": sha(b"adapter"), "expected": expected,
                "unchanged": {"qualification": sha(self.qualification.read_bytes()), "hook": sha(self.hook.read_bytes()), "marker": sha(self.marker)}}
    return N._parse_approval(json.dumps({**approval, **changes}).encode(), b"adapter")

  def core_pins(self): return {name: self.approval["expected"][name] for name in N.CORE_HASHES}

  def upgrade_live(self, **changes):
    arguments = {"expected": self.core_pins(), "approval_id": self.case.approval_id, "guard": self.check,
                 "precheck": lambda: self.events.append("precheck"), "postcheck": lambda: self.events.append("postcheck"), "maintenance": True}
    return D.upgrade_snapshot(self.case.source, root=self.case.root, **{**arguments, **changes})

  def own_intent(self, **changes):
    record = {"protocol": N.INTENT_MAINTENANCE, "transaction_id": str(uuid.uuid4()), "approval_id": self.case.approval_id,
              "old_review_sha256": self.expected["old_review"], "new_review_sha256": self.expected["new_review"],
              "old_config_sha256": self.expected["old_config"], "new_config_sha256": self.expected["new_config"], "marker_sha256": sha(self.marker)}
    return {**record, **changes}

  def write_barrier(self, raw, path=None):
    rewrite(path or self.barrier, raw)


class LiveGuardCore(LiveGuard):
  def test_the_maintenance_upgrade_completes_with_the_real_guard_after_the_barrier_and_the_marker_rebind(self):
    # Live failure 2026-09-29 (approval c6051717): the first guard() after the core wrote its own source-default-activation.pending
    # raised "Active source-default state is present under a maintenance upgrade". The guard after the marker rebind would have
    # raised "Unchanged host artifact differs: marker" next.
    result = self.upgrade_live()
    self.assertEqual(result["review_sha256"], self.expected["new_review"])
    self.assertEqual(self.events, ["precheck", "postcheck"])
    self.assertEqual(self.triple(), self.new_triple())
    self.assertFalse(self.barrier.exists() or self.pending.exists())
    self.check()  # and the guard admits the finished state, marker in its new form

  def test_the_guard_sees_the_barrier_the_pending_and_the_rebound_marker_at_the_right_moments(self):
    seen = []
    def watching():
      seen.append((self.barrier.exists(), self.pending.exists(), (self.state / D.MAINTENANCE_PENDING).read_bytes() == self.new_marker))
      self.check()
    self.upgrade_live(guard=watching)
    self.assertIn((True, False, False), seen)  # barrier alone: the very call that failed live
    self.assertIn((True, True, False), seen)
    self.assertIn((True, True, True), seen)   # marker rebound, both vetoes still held

  def test_a_failure_after_the_barrier_keeps_the_veto_and_the_recovery_intent_is_what_the_guard_accepts(self):
    def failing():
      self.check()
      if self.pending.exists(): raise ValueError("stop after both vetoes")
    with self.assertRaisesRegex(ValueError, "stop after both vetoes"): self.upgrade_live(guard=failing)
    self.assertTrue(self.barrier.exists() and self.pending.exists())
    self.check()  # the retained veto is the approval's own exact intent, so the adapter's recovery guard still admits it
    intent = json.loads(self.barrier.read_bytes())
    self.assertEqual((intent["protocol"], intent["approval_id"], intent["marker_sha256"]), (N.INTENT_MAINTENANCE, self.case.approval_id, sha(self.marker)))


class LiveGuardRefusals(LiveGuard):
  def refuses(self, message="Active source-default state"):
    with self.assertRaisesRegex((ValueError, OSError), message + "|symbolic links"): N._unchanged(self.approval)

  def test_only_this_approvals_exact_private_intent_is_admitted(self):
    N._unchanged(self.approval)  # nothing present
    good = D._encoded(self.own_intent())
    self.write_barrier(good)
    N._unchanged(self.approval)
    rewrite(self.pending, good)
    N._unchanged(self.approval)
    rewrite(self.pending, good + b" ")
    self.refuses("differs from the compatible barrier")
    self.pending.unlink()
    for label, raw in {
      "another approval": D._encoded(self.own_intent(approval_id="306521e4-998e-4477-b603-31b93144d999")),
      "another marker": D._encoded(self.own_intent(marker_sha256="0" * 64)),
      "another old review": D._encoded(self.own_intent(old_review_sha256="0" * 64)),
      "another new review": D._encoded(self.own_intent(new_review_sha256="0" * 64)),
      "another old config": D._encoded(self.own_intent(old_config_sha256="0" * 64)),
      "another protocol": D._encoded(self.own_intent(protocol="omarchy-t2-runtime-upgrade-intent-v2")),
      "a transaction that is not a uuid4": D._encoded(self.own_intent(transaction_id="not-a-uuid")),
      "an extra field": D._encoded({**self.own_intent(), "extra": 1}),
      "a missing field": D._encoded({key: value for key, value in self.own_intent().items() if key != "marker_sha256"}),
      "not canonical": good + b"\n", "not json": b"policy", "empty": b"", "not an object": b"[]",
      "the rebind intent": D._encoded({"protocol": "omarchy-t2-package-rebind-intent-v1"}),
    }.items():
      with self.subTest(label):
        self.write_barrier(raw)
        self.refuses()
    self.write_barrier(good)
    self.barrier.chmod(0o644)
    with self.subTest("mode"): self.refuses()
    self.barrier.chmod(0o600)
    other = self.state / "other"
    rewrite(other, good)
    self.barrier.unlink()
    os.link(other, self.barrier)
    with self.subTest("hard link"): self.refuses()
    self.barrier.unlink()
    other.unlink()
    rewrite(other, good)
    os.symlink(other, self.barrier)
    with self.subTest("symlink"): self.refuses()
    self.barrier.unlink()
    with self.subTest("pending without a barrier"):
      rewrite(self.pending, good)
      self.refuses("without its compatible barrier")

  def test_the_other_active_state_stays_refused_and_a_barrier_never_excuses_it(self):
    self.write_barrier(D._encoded(self.own_intent()))
    for path in N.ABSENT_IN_MAINTENANCE:
      with self.subTest(path.name):
        rewrite(path, b"x")
        self.refuses("Active source-default state")
        path.unlink()

  def test_the_rebound_marker_is_only_the_pinned_marker_with_the_review_moved(self):
    marker = self.state / D.MAINTENANCE_PENDING
    N._unchanged(self.approval)
    rewrite(marker, self.new_marker)
    N._unchanged(self.approval)
    fields = json.loads(self.new_marker)
    for label, raw in {
      "another review": D._encoded({**fields, "runtime_review_sha256": "0" * 64}),
      "another field": D._encoded({**fields, "old_policy_sha256": "0" * 64}),
      "an extra field": D._encoded({**fields, "extra": 1}),
      "not canonical": self.new_marker + b"\n",
      "not json": b"x", "the old review is not restorable": D._encoded({**fields, "transition_id": str(uuid.uuid4())}),
    }.items():
      with self.subTest(label):
        rewrite(marker, raw)
        self.refuses("Unchanged host artifact differs: marker")

  def test_the_ordinary_protocol_never_reaches_the_maintenance_barrier_check_and_cannot_adopt(self):
    ordinary = {**self.make_approval(), "maintenance": False}
    ordinary["unchanged"] = {name: "d" * 64 for name in N.UNCHANGED}
    with patch.object(N, "_maintenance_barrier") as barrier, patch.object(N, "_private_bytes", return_value=(ordinary["current_boot_id"] + "\n").encode()), patch.object(N, "UNCHANGED", {}):
      N._unchanged(ordinary)
    barrier.assert_not_called()
    body = {"protocol": N.ORDINARY_PROTOCOL, "approved": True, "approval_id": self.case.approval_id, "current_boot_id": "0f909934-0ecf-4407-863d-6822c81cb2df",
            "source_directory": "/reviewed/source", "reviewed_commit": "b" * 40, "adapter_sha256": sha(b"adapter"),
            "expected": {name: "c" * 64 for name in N.HASHES}, "unchanged": {name: "d" * 64 for name in N.UNCHANGED},
            "leftover": {"approval_id": "306521e4-998e-4477-b603-31b93144d999", "intent_sha256": "e" * 64}}
    with self.assertRaisesRegex(ValueError, "earlier approval"): N._parse_approval(json.dumps(body).encode(), b"adapter")

  def test_the_leftover_pin_is_strict(self):
    def parse(**leftover):
      body = {"protocol": N.MAINTENANCE_PROTOCOL, "approved": True, "approval_id": self.case.approval_id, "current_boot_id": "0f909934-0ecf-4407-863d-6822c81cb2df",
              "source_directory": "/reviewed/source", "reviewed_commit": "b" * 40, "adapter_sha256": sha(b"adapter"),
              "expected": {name: "c" * 64 for name in N.HASHES}, "unchanged": {name: "d" * 64 for name in N.UNCHANGED_MAINTENANCE}, "leftover": leftover}
      return N._parse_approval(json.dumps(body).encode(), b"adapter")
    good = {"approval_id": "306521e4-998e-4477-b603-31b93144d999", "intent_sha256": "e" * 64}
    self.assertEqual(parse(**good)["leftover"], good)
    for label, bad in {"same id": {**good, "approval_id": self.case.approval_id}, "not a uuid4": {**good, "approval_id": "306521e4-998e-1477-b603-31b93144d999"},
                       "short pin": {**good, "intent_sha256": "e" * 63}, "extra": {**good, "x": 1}, "missing": {"approval_id": good["approval_id"]}}.items():
      with self.subTest(label), self.assertRaises(ValueError): parse(**bad)


class Adoption(LiveGuard):
  """A leftover from an earlier, unconsumed maintenance approval, adopted by this approval's adapter."""

  OLD = "306521e4-998e-4477-b603-31b93144d999"

  def setUp(self):
    super().setUp()
    self.old_new_review = "9" * 64
    self.leftover = D._encoded({"protocol": N.INTENT_MAINTENANCE, "transaction_id": str(uuid.uuid4()), "approval_id": self.OLD,
                                "old_review_sha256": self.expected["old_review"], "new_review_sha256": self.old_new_review,
                                "old_config_sha256": self.expected["old_config"], "new_config_sha256": self.expected["new_config"], "marker_sha256": sha(self.marker)})
    self.write_barrier(self.leftover)
    rewrite(self.case.historical, D._encoded({"review_sha256": "7" * 64}))  # a real completion record of an older generation
    self.settle_old()
    self.approval = self.make_approval(leftover={"approval_id": self.OLD, "intent_sha256": sha(self.leftover)})
    self.guard_fd2, self.check = N._guard(SimpleNamespace(_power_idle=lambda pid: None), self.approval)
    self.addCleanup(os.close, self.guard_fd2)
    self.consumed = self.state / ("runtime-upgrade-approval-consumed-" + self.OLD + ".json")
    self.abandoned = self.state / ("runtime-upgrade-abandoned-intent-" + self.OLD + ".json")

  def settle_old(self):
    """What the earlier adapter's own recovery left: old-form retained copies and a rebind record under its review's tag."""
    self.assertEqual(D.settle_maintenance_binding(self.state, json.loads(self.leftover), self.expected["old_review"]), "old")
    self.assertTrue((self.archive / D._binding_names(self.old_new_review)[2]).exists())

  def adopt(self, guard=None): return N._adopt_leftover(D, self.approval, guard or self.check)

  def snapshot(self):
    return {name: value for name, value in self.tree().items() if not name.endswith("runtime-deployment.lock")}

  def refuses_unchanged(self, pattern, mutate):
    mutate()
    before = self.snapshot()
    with self.assertRaisesRegex((ValueError, OSError), pattern): self.adopt()
    self.assertEqual(self.snapshot(), before)  # nothing was written, archived or removed
    self.assertTrue(self.barrier.exists() and not self.consumed.exists() and not self.abandoned.exists())

  def test_the_guard_admits_the_pinned_leftover_only_with_the_approval_that_names_it(self):
    N._unchanged(self.approval)
    without = self.make_approval()
    with self.assertRaisesRegex(ValueError, "Active source-default state"): N._unchanged(without)
    wrong_pin = self.make_approval(leftover={"approval_id": self.OLD, "intent_sha256": "0" * 64})
    with self.assertRaisesRegex(ValueError, "Active source-default state"): N._unchanged(wrong_pin)
    wrong_id = self.make_approval(leftover={"approval_id": "306521e4-998e-4477-b603-31b93144d998", "intent_sha256": sha(self.leftover)})
    with self.assertRaisesRegex(ValueError, "Active source-default state"): N._unchanged(wrong_id)
    rewrite(self.pending, self.leftover)  # an earlier intent never coexists with an upgrade pending
    with self.assertRaisesRegex(ValueError, "Active source-default state"): N._unchanged(self.approval)

  def test_adoption_archives_the_intent_consumes_the_old_approval_and_returns_to_inactive_maintenance(self):
    self.assertTrue(self.adopt())
    self.assertFalse(self.barrier.exists())
    self.assertEqual(self.consumed.read_bytes(), self.leftover)   # the old approval can never be replayed
    self.assertEqual(self.abandoned.read_bytes(), self.leftover)  # evidence archived, not deleted
    self.assertEqual(self.triple(), self.old_triple())
    self.assertEqual(self.review_digest(), self.expected["old_review"])
    for path in (self.consumed, self.abandoned): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
    self.check()
    self.assertTrue(self.adopt())  # idempotent

  def test_adoption_without_the_earlier_recovery_evidence_is_equally_accepted(self):
    for name in D._binding_names(self.old_new_review): (self.archive / name).unlink()
    self.assertTrue(self.adopt())
    self.assertFalse(self.barrier.exists())

  def test_no_leftover_named_means_no_adoption(self):
    approval = self.make_approval()
    self.assertFalse(N._adopt_leftover(D, approval, self.check))
    self.assertTrue(self.barrier.exists())

  def test_adoption_then_the_new_upgrade_completes_and_keeps_both_generations_of_evidence(self):
    self.adopt()
    result = self.upgrade_live()
    self.assertEqual(result["review_sha256"], self.expected["new_review"])
    self.assertEqual(self.triple(), self.new_triple())
    old_marker, old_baseline, record = D._binding_names(self.old_new_review)
    for name in (old_marker, old_baseline, record): self.assertTrue((self.archive / name).exists())  # earlier evidence never deleted
    for name in D._binding_names(self.expected["new_review"]): self.assertTrue((self.archive / name).exists())
    self.assertEqual(self.abandoned.read_bytes(), self.leftover)
    self.assertTrue((self.state / ("runtime-upgrade-approval-consumed-" + self.case.approval_id + ".json")).exists())
    self.assertFalse(self.barrier.exists() or self.pending.exists())
    self.check()

  def test_a_failing_new_upgrade_after_adoption_is_a_clean_old_state_when_it_stops_before_its_barrier(self):
    def refuse(): raise ValueError("no saved image proof")
    self.adopt()
    with self.assertRaisesRegex(ValueError, "no saved image proof"): self.upgrade_live(precheck=refuse)
    self.assertFalse(self.barrier.exists() or self.pending.exists())
    self.assertEqual(self.triple(), self.old_triple())
    self.assertEqual(self.review_digest(), self.expected["old_review"])

  def test_a_crash_at_every_adoption_step_is_resumed_or_refused_never_half_adopted(self):
    steps = []
    def counting():
      steps.append(1)
      self.check()
    self.adopt(counting)
    total = len(steps)
    self.assertEqual(total, 3)
    for number in range(1, total + 1):
      with self.subTest(crash_at_guard=number):
        case = Adoption("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        seen = []
        def crash(case=case, number=number, seen=seen):
          seen.append(1)
          case.check()
          if len(seen) == number: raise OSError("simulated crash")
        with self.assertRaisesRegex(OSError, "simulated crash"): case.adopt(crash)
        self.assertTrue(case.barrier.exists() != case.abandoned.exists())  # exactly one of: still vetoed, or archived
        case.check()
        self.assertTrue(case.adopt())  # the same approval resumes
        self.assertFalse(case.barrier.exists())
        self.assertEqual((case.consumed.read_bytes(), case.abandoned.read_bytes()), (case.leftover, case.leftover))
        self.assertTrue(case.adopt())
        self.assertEqual(case.triple(), case.old_triple())

  def test_a_crash_that_left_the_barrier_removed_but_the_archive_torn_is_refused(self):
    self.adopt()
    self.abandoned.write_bytes(b"other")
    with self.assertRaisesRegex(ValueError, "neither in place nor archived"): self.adopt()
    self.abandoned.write_bytes(self.leftover)
    self.consumed.unlink()
    with self.assertRaisesRegex(ValueError, "neither in place nor archived"): self.adopt()

  # --- anything moved refuses, with zero writes -------------------------------------------------------
  def test_a_moved_runtime_authority_config_or_review_refuses(self):
    def first_runtime_file(c): return next(iter(sorted((c.state / "runtime").rglob("*.py"))))
    cases = {
      "runtime tree file": (lambda c: rewrite(first_runtime_file(c), first_runtime_file(c).read_bytes() + b"#"), "differs"),
      "review": (lambda c: rewrite(c.state / D.REVIEW.name, (c.state / D.REVIEW.name).read_bytes() + b" "), "moved authority: runtime-deployment-review"),
      "bootstrap": (lambda c: rewrite(c.state / D.BOOTSTRAP, b"other"), "moved authority: runtime-deployment-bootstrap"),
      "config": (lambda c: rewrite(c.state / D.CONFIG, c.config + b" "), "moved authority: config"),
      "receipt": (lambda c: rewrite(c.state / "runtime" / D.MANIFEST, b"{}"), "receipt"),
    }
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        case = Adoption("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.refuses_unchanged(pattern, lambda case=case, mutate=mutate: mutate(case))

  def test_a_moved_marker_archive_or_baseline_refuses(self):
    marker = lambda case: case.state / D.MAINTENANCE_PENDING
    cases = {
      "marker in the new form": (lambda c: (rewrite(marker(c), c.new_marker), rewrite(c.archive / "maintenance-intent.json", c.new_marker), rewrite(c.archive / D.BASELINE_NAME, c.new_baseline)), "not the pinned old marker"),
      "marker only changed": (lambda c: rewrite(marker(c), c.new_marker), "not the pinned old marker"),
      "archived intent differs": (lambda c: rewrite(c.archive / "maintenance-intent.json", c.new_marker), "archived intent"),
      "baseline in the new form": (lambda c: rewrite(c.archive / D.BASELINE_NAME, c.new_baseline), "generation baseline"),
      "baseline foreign": (lambda c: rewrite(c.archive / D.BASELINE_NAME, c.baseline + b" "), "generation baseline|Extra data"),
      "marker missing": (lambda c: marker(c).unlink(), "No such file|FileNotFound"),
      "retained old marker tampered": (lambda c: rewrite(c.archive / D._binding_names(c.old_new_review)[0], b"x"), "Retained old evidence differs"),
      "retained old baseline tampered": (lambda c: rewrite(c.archive / D._binding_names(c.old_new_review)[1], b"x"), "Retained old evidence differs"),
      "rebind record tampered": (lambda c: rewrite(c.archive / D._binding_names(c.old_new_review)[2], b"{}"), "not the old-form record"),
      "rebind record without its copies": (lambda c: (c.archive / D._binding_names(c.old_new_review)[0]).unlink(), "not the old-form record"),
      "rebind evidence for this approval's review": (lambda c: rewrite(c.archive / D._binding_names(c.expected["new_review"])[2], b"{}"), "already exists"),
      "rebind temporary": (lambda c: rewrite(c.state / (D.MAINTENANCE_PENDING + ".runtime-rebind-tmp"), b"x"), "temporary exists"),
      "archive temporary": (lambda c: rewrite(c.archive / (D.BASELINE_NAME + ".runtime-rebind-tmp"), b"x"), "temporary exists"),
    }
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        case = Adoption("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.refuses_unchanged(pattern, lambda case=case, mutate=mutate: mutate(case))

  def test_publication_or_consumption_evidence_refuses(self):
    cases = {
      "this approval already consumed": (lambda c: rewrite(c.state / ("runtime-upgrade-approval-consumed-" + c.case.approval_id + ".json"), b"x"), "Publication evidence"),
      "upgrade pending": (lambda c: rewrite(c.pending, c.leftover), "inconsistent|Active source-default"),
      "runtime pending": (lambda c: (c.state / D.PENDING).mkdir(mode=0o700), "Publication evidence"),
      "retained runtime": (lambda c: rewrite(c.state / ("runtime-review-retained-" + "a" * 12 + "-before-" + "b" * 12 + ".json"), b"x"), "Retained publication evidence"),
      "retained config": (lambda c: rewrite(c.state / ("config-retained-" + "a" * 12 + "-before-" + "9" * 12 + ".json"), b"x"), "Retained publication evidence"),
      "completion for the earlier review": (lambda c: rewrite(c.state / "runtime-upgrade-completed-999999999999.json", D._encoded({"review_sha256": c.old_new_review})), "Completion evidence"),
      "completion for this review": (lambda c: rewrite(c.state / ("runtime-upgrade-completed-" + "b" * 12 + ".json"), b"{}"), "Publication evidence"),
      "unreadable completion": (lambda c: rewrite(c.state / "runtime-upgrade-completed-888888888888.json", b"not json"), "Unreadable"),
      "earlier consumed record differs": (lambda c: rewrite(c.consumed, b"other"), "inconsistent"),
      "earlier archive already present": (lambda c: rewrite(c.abandoned, c.leftover), "inconsistent"),
    }
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        case = Adoption("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        before_barrier = case.barrier.read_bytes()
        mutate(case)
        before = case.snapshot()
        with self.assertRaisesRegex((ValueError, OSError), pattern): case.adopt()
        self.assertEqual(case.snapshot(), before)
        self.assertEqual(case.barrier.read_bytes(), before_barrier)

  def test_a_foreign_or_tampered_leftover_is_never_adopted(self):
    cases = {
      "another approval": D._encoded({**json.loads(self.leftover), "approval_id": "306521e4-998e-4477-b603-31b93144d998"}),
      "another marker": D._encoded({**json.loads(self.leftover), "marker_sha256": "0" * 64}),
      "the same review as this approval": D._encoded({**json.loads(self.leftover), "new_review_sha256": self.expected["new_review"]}),
      "another old review": D._encoded({**json.loads(self.leftover), "old_review_sha256": "0" * 64}),
      "extra field": D._encoded({**json.loads(self.leftover), "x": 1}),
      "not canonical": self.leftover + b"\n",
      "bytes not matching the pin": D._encoded({**json.loads(self.leftover), "transaction_id": str(uuid.uuid4())}),
    }
    for label, raw in cases.items():
      with self.subTest(label):
        case = Adoption("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        rewrite(case.barrier, raw)
        before = case.snapshot()
        with self.assertRaises(ValueError): case.adopt()
        self.assertEqual(case.snapshot(), before)
        with self.assertRaisesRegex(ValueError, "Active source-default state"): N._unchanged(case.approval)

  def test_recovery_recognises_the_leftover_as_the_veto_and_preserves_everything(self):
    with patch.object(N, "_private_bytes", side_effect=lambda path, mode=0o600: Path(path).read_bytes()):
      N._restore_veto(D, self.approval)  # old authority proven, durable veto is the leftover itself
      self.assertEqual(self.barrier.read_bytes(), self.leftover)
      rewrite(self.state / D.CONFIG, self.config + b" ")
      with self.assertRaisesRegex(ValueError, "Prepublication old authority changed"): N._restore_veto(D, self.approval)
      self.assertEqual(self.barrier.read_bytes(), self.leftover)
      rewrite(self.state / D.CONFIG, self.config)
      rewrite(self.barrier, D._encoded({**json.loads(self.leftover), "marker_sha256": "0" * 64}))
      with self.assertRaises(ValueError): N._restore_veto(D, self.approval)


if __name__ == "__main__": unittest.main()
