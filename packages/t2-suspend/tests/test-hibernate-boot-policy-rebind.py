"""New-generation rebind on a disposable root: the real engine, the real lock-free assess core and fixture product/gate seams.

Nothing here touches the host: no inhibitor, package lock, EFI, boot, module or power operation.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
import uuid
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


NT = load("rebind_native_tests", Path(__file__).with_name("test-hibernate-boot-policy-native.py"))
N, F = NT.N, NT.F
POLICY_FIXTURE = F.F
PAIR = POLICY_FIXTURE.PAIR
STATE_DIR = NT.STATE_DIR
Crash = NT.Crash


def blake2(raw): return hashlib.blake2b(raw).hexdigest()


class Rebind(NT.AssessFixture):
  """Maintenance published for generation 1; the old pair retired; a new pair staged and qualified for generation 2."""
  STAGES = ("none", "pre", "W3", "W4", "W5", "W6", "W8", "W9", "done")
  trace = None
  fault = None
  inspect_fault = None

  def setUp(self):
    super().setUp()
    # Make generation 1 self-consistent as on the host: the receipt's image hashes ARE the manifest's pins.
    P = self.T.P
    for role in ("source", "restore"): self.write(STATE_DIR + "/artifacts/" + role + "/mba-t2-hibernation-candidate.efi", role.encode())
    self.config["manifest"] = {**self.config["manifest"], "source_sha256": P.digest(b"source"), "restore_sha256": P.digest(b"restore")}
    self.write_config()
    self.published()
    self.pinned = {}
    self.marker = (self.root / self.T.MAINTENANCE).read_bytes()
    self.stage_new_generation()
    self.history0 = {item.name for item in (self.root / self.T.HISTORY).iterdir()}
    self.before = self.tree()

  # --- the new generation ----------------------------------------------------------------------
  def stage_new_generation(self):
    T, P = self.T, self.T.P
    old_manifest = self.config["manifest"]
    # 1. The stager retires the old pair: receipt, images and backup go; custody of the receipt bytes and a record remain.
    self.old_receipt_raw = self.f.raw
    self.write(T.RETIRED_RECEIPT, self.old_receipt_raw)
    self.retirement = {"protocol": T.RETIREMENT_SCHEMA, "retired_receipt_sha256": P.digest(self.old_receipt_raw),
                       "source_sha256": old_manifest["source_sha256"], "restore_sha256": old_manifest["restore_sha256"]}
    self.write(T.RETIREMENT, json.dumps(self.retirement).encode())
    (self.root / P.RECEIPT).unlink()
    (self.root / PAIR.BACKUP).unlink()
    for role in ("source", "restore"): (self.root / PAIR.IMAGES[role]).unlink()
    # 2. The kernel update rewrote the production UKI and the Limine hash that binds it.
    old_production = (self.root / T.PRODUCTION).read_bytes()
    self.new_production = b"production image of the new kernel"
    (self.root / T.PRODUCTION).write_bytes(self.new_production)
    text = (self.root / P.LIMINE).read_bytes().decode().replace(blake2(old_production), blake2(self.new_production))
    # 3. A new pair is staged: new images, new receipt, new pair backup and Limine block.
    ukis = {role: (role + " uki v2").encode() for role in ("source", "restore")}
    images = {role: {"entry_id": PAIR.entry_id(role, P.digest(raw)), "sha256": P.digest(raw), "blake2": blake2(raw), "provenance_sha256": "f" * 64}
              for role, raw in ukis.items()}
    for role, raw in ukis.items(): self.write(PAIR.IMAGES[role], raw)
    begin, end = text.index(PAIR.BEGIN), text.index(PAIR.END) + len(PAIR.END) + 1
    block = PAIR.BEGIN + "\n" + "".join("/" + images[role]["entry_id"] + "\npath: boot():/EFI/Linux/" + PAIR.IMAGES[role].name + "#" + images[role]["blake2"] + "\n" for role in images) + PAIR.END + "\n"
    staged, donor = (text[:begin] + block + text[end:]).encode(), (text[:begin] + text[end:]).encode()
    self.staged_limine, self.donor = staged, donor
    self.receipt = {"kernel_policy": "production-linux-unchanged", "images": images, "original_limine_sha256": P.digest(donor),
                    "staged_limine_sha256": P.digest(staged), "production_uki_sha256": P.digest(self.new_production)}
    self.receipt_raw = json.dumps(self.receipt).encode()
    self.write(P.RECEIPT, self.receipt_raw)
    self.write(PAIR.BACKUP, donor)
    self.write(PAIR.SINGLE.ENTRIES, b"\x06\0\0\0" + ("\0".join(item["entry_id"] for item in images.values()) + "\0").encode("utf-16-le"))
    self.f.write(P.LIMINE, F.with_snapshots(staged, [3, 4, 5]))  # snapper churned after staging
    self.original = (self.root / P.LIMINE).read_bytes()
    for role in ("source", "restore"):
      base = STATE_DIR + "/artifacts2/" + role
      self.write(base + "/provenance.json", json.dumps({"kernel_release": self.RELEASE, "modules": {"t2bce_core": {"sha256": role + " v2"}}}).encode())
      self.write(base + "/mba-t2-hibernation-candidate.efi", ukis[role])
      self.write(base + "/mba-t2-hibernation-candidate.initrd", (role + " initrd v2").encode())
    self.manifest = {"protocol": "fixture", "runtime_sha256": "9" * 64, "source_sha256": P.digest(ukis["source"]), "restore_sha256": P.digest(ukis["restore"])}
    self.new_config = {**self.config, "source_directory": NT.ARTIFACTS + "2/source", "restore_directory": NT.ARTIFACTS + "2/restore",
                       "audited_details_sha256": "e" * 64, "staged_receipt_sha256": P.digest(self.receipt_raw), "manifest": self.manifest}
    self.new_qualification = {"protocol": "omarchy-t2-product-cycle-v1", "manifest_sha256": T.PRODUCT.TX.digest(self.manifest), "evidence_sha256": "1" * 64, "qualified": True}
    self.new_policy = {**P.prepare(staged, self.receipt_raw)["policy"], "approved": True}
    self.staged_raw = {"config": json.dumps(self.new_config).encode(), "qualification": json.dumps(self.new_qualification).encode(),
                       "review": json.dumps(self.new_policy).encode()}
    for name, raw in self.staged_raw.items(): self.write(T.STAGED[name], raw)
    self.deployment_config = {"staged_receipt_sha256": P.digest(self.receipt_raw)}
    self.deployment_report = {"manifest": {role + "_sha256": images[role]["sha256"] for role in images},
                              "audited_details": {"production_uki_sha256": P.digest(self.new_production), "provenance_sha256": {role: "f" * 64 for role in images}}}

  # --- seams -----------------------------------------------------------------------------------
  def assess_core(self, evidence, marker): return N._assess_core(self.T, self.root, evidence, marker)

  def inspect(self, evidence, staged):
    if self.inspect_fault is not None: raise self.inspect_fault
    items, errors = N.generation_items(self.T, self.root, config_name="rebind-config.json", qualification_name="rebind-qualification.json")
    self.assertEqual(errors, {})
    return {"manifest": staged["config"]["manifest"], "baseline": items}

  def postchecks(self, root, fresh):
    if self.fault is not None: raise self.fault
    POLICY_FIXTURE.PRODUCT.TRIAL._verify_deployment(root, self.deployment_config, self.deployment_report, source_default=True)
    items, errors = N.generation_items(self.T, root)
    if errors or items != {name: fresh[name] for name in self.T.BASELINE_ITEMS}: raise ValueError("generation differs from the fresh baseline")

  def rebind(self, **changes):
    arguments = {"guard": lambda: None, "gate": self.fx.gate, "assess": self.assess_core, "inspect": self.inspect, "postchecks": self.postchecks, "pinned": self.pinned}
    return self.T._rebind(self.root, **{**arguments, **changes})

  def new(self, **attributes):
    other = Rebind("runTest")
    for name, value in attributes.items(): setattr(other, name, value)
    other.setUp()
    self.addCleanup(other.doCleanups)
    return other

  # --- observation -----------------------------------------------------------------------------
  def path(self, relative): return self.root / relative

  def pending(self): return self.path(self.T.PENDINGS["activation"])

  def limine(self): return self.path(self.T.P.LIMINE).read_bytes()

  def archives(self):
    directory = self.root / self.T.HISTORY
    return [item for item in directory.iterdir() if (item / "intent.json").exists() and json.loads((item / "intent.json").read_bytes()).get("action") == "rebind"]

  def own_archive(self): return self.archives()[0]

  def flags(self):
    entry = self.receipt["images"]["source"]["entry_id"]
    return {"pending": self.pending().exists(), "marker": self.path(self.T.MAINTENANCE).exists(), "policy": self.path(self.T.P.POLICY).exists(),
            "switched": (b"default_entry: " + entry.encode() + b"\n") in self.limine(), "optin": self.path(self.T.OPT_IN).exists(),
            "config": self.path(self.T.CONFIG).read_bytes() == self.staged_raw["config"], "completion": any((item / "completion.json").exists() for item in self.archives())}

  def stage(self):
    f = self.flags()
    if not f["pending"]: return "none" if f["marker"] else "done"
    if f["completion"]: return "W8" if f["marker"] else "W9"
    if f["optin"]: return "W6"
    if f["switched"]: return "W5"
    if f["policy"]: return "W4"
    return "W3" if f["config"] else "pre"

  def tree(self):
    # Archives of the rebind itself are its own evidence (a torn one is only noise); everything else must be byte-exact.
    skip = [self.T.HISTORY / item.name for item in (self.root / self.T.HISTORY).iterdir() if item.name not in self.history0] if hasattr(self, "history0") else []
    state = {}
    for path in sorted(self.root.rglob("*")):
      relative = path.relative_to(self.root)
      if path == self.root / self.T.DB_LOCK or any(relative == item or item in relative.parents for item in skip): continue
      info = path.lstat()
      state[str(relative)] = (stat.S_IMODE(info.st_mode), stat.S_ISDIR(info.st_mode),
        os.readlink(path) if stat.S_ISLNK(info.st_mode) else (path.read_bytes() if stat.S_ISREG(info.st_mode) else None))
    return state

  def refuses(self, pattern, *, exception=ValueError, **changes):
    before = self.tree()
    with self.assertRaisesRegex(exception, pattern): self.rebind(**changes)
    self.assertEqual(self.tree(), before)
    self.assertFalse(self.pending().exists())
    self.assertTrue(self.path(self.T.MAINTENANCE).exists())

  def assert_vetoed(self):
    """Every route that could sleep or update is refused while a rebind pending exists."""
    with self.assertRaises(ValueError): F.SLEEP.reject_pending(self.root)
    with self.assertRaises(ValueError): POLICY_FIXTURE.PRODUCT.verify_deployment(self.root, self.deployment_config, self.deployment_report)
    with self.assertRaises(ValueError): self.T.G.check(self.root)
    if self.path(self.T.MAINTENANCE).exists():
      with self.assertRaises(ValueError): self.T.G._maintenance(self.root)

  def assert_active(self, result=None):
    T, P = self.T, self.T.P
    f = self.flags()
    self.assertEqual((f["pending"], f["marker"], f["policy"], f["switched"], f["optin"]), (False, False, True, True, True))
    for name, relative in (("config", T.CONFIG), ("qualification", T.QUALIFICATION), ("review", T.REVIEW), ("review", P.POLICY)):
      self.assertEqual(self.path(relative).read_bytes(), self.staged_raw[name])
    self.assertEqual(self.path(P.BACKUP).read_bytes(), self.staged_limine)
    self.assertEqual(self.path(T.OPT_IN).read_bytes(), b"")
    self.assertEqual(stat.S_IMODE(self.path(T.OPT_IN).stat().st_mode), 0o644)
    self.assertTrue(P.verify(self.root, P.digest(self.receipt_raw)))
    self.assertFalse((self.root / T.DB_LOCK).exists())
    for relative in (T.CONFIG, T.QUALIFICATION, T.REVIEW, P.POLICY, P.BACKUP): self.assertEqual(stat.S_IMODE(self.path(relative).stat().st_mode), 0o600)
    self.assertEqual(list(self.path(T.P.STATE).glob("*.rebind-*")), [])
    self.assertEqual(list(self.path("boot").glob("limine.conf.source-default-*")), [])
    with self.assertRaises(ValueError): T.G.check(self.root)  # blanket guard: boot-policy.json and the opt-in
    if result is not None: self.assertTrue(result["rebound"] and result["requalification_required"] is False)

  def assert_rolled_back(self):
    self.assertEqual(self.tree(), self.before)  # every byte and mode of the prior maintenance state
    f = self.flags()
    self.assertEqual((f["pending"], f["marker"], f["policy"], f["switched"], f["optin"]), (False, True, False, False, False))
    self.T.G._maintenance(self.root)  # inactive maintenance is valid again: updates are allowed

  # --- happy path --------------------------------------------------------------------------------
  def test_happy_path_installs_new_authority_activates_and_retires_the_marker(self):
    T, P = self.T, self.T.P
    old = {name: self.path(relative).read_bytes() for name, relative in T.AUTHORITY}
    with patch.object(T, "_transition", side_effect=AssertionError("no _transition")), patch.object(T.PRODUCT, "check", side_effect=AssertionError("no product.check")), \
         patch.object(T.PRODUCT, "_admission_state", side_effect=AssertionError("no admission")), patch.object(N, "_precheck", side_effect=AssertionError("no precheck")):
      result = self.rebind()
    self.assert_active(result)
    self.assertFalse(result["live_execution"] or result["qualification_issued"])
    self.assertEqual(result["maintenance_transition_id"], self.result["transition_id"])
    current = self.limine()
    self.assertEqual(current, self.original.replace(b"default_entry: 2\n", b"default_entry: " + self.receipt["images"]["source"]["entry_id"].encode() + b"\n", 1))
    self.assertIn(b"limine-snapper-sync", current)  # the churned snapshot region survived the swap
    archive = self.root / T.HISTORY / result["transition_id"]
    self.assertEqual(sorted(item.name for item in archive.iterdir()), sorted(["intent.json", "comparison.json", "completion.json", "new-baseline.json", "retirement.json",
      "retired-receipt.json", "new-receipt.json", "opt-in", "old-config.json", "old-qualification.json", "old-policy.json", "old-backup",
      "policy.json", "new-config.json", "new-qualification.json", "new-backup"]))
    for name, archived in T.REBIND_ARCHIVE["old"].items(): self.assertEqual((archive / archived).read_bytes(), old[name])
    for name, archived in T.REBIND_ARCHIVE["new"].items(): self.assertEqual((archive / archived).read_bytes(), self.staged_raw[name] if name != "backup" else self.staged_limine)
    self.assertEqual((archive / "retired-receipt.json").read_bytes(), self.old_receipt_raw)
    self.assertEqual(json.loads((archive / "comparison.json").read_bytes())["assessment"]["class"], "requalification-required")
    self.assertEqual(self.marker, (self.root / T.HISTORY / self.result["transition_id"] / "maintenance-intent.json").read_bytes())  # old evidence untouched
    self.assertEqual(json.loads(json.dumps(result, sort_keys=True)), result)
    self.assertEqual(json.loads((archive / "new-baseline.json").read_bytes())["protocol"], T.REBIND_BASELINE)
    self.assertFalse(self.pending().exists())
    self.assertEqual((self.root / T.RETIRED_RECEIPT).read_bytes(), self.old_receipt_raw)  # the stager's evidence is never consumed

  def test_snapshot_churn_after_staging_changes_only_the_default_entry_line(self):
    for numbers, reverse in (([], False), ([1], False), ([2, 3, 4], True), ([7, 8, 9, 10, 11], False)):
      with self.subTest(numbers=numbers):
        other = self.new()
        other.f.write(other.T.P.LIMINE, F.with_snapshots(other.original, numbers, reverse))
        current = other.limine()
        self.assertTrue(other.rebind()["rebound"])
        self.assertEqual(other.limine(), current.replace(b"default_entry: 2\n", b"default_entry: " + other.receipt["images"]["source"]["entry_id"].encode() + b"\n", 1))
        other.assert_active()

  def test_active_state_round_trips_through_maintenance_and_rebinds_again(self):
    self.rebind()
    self.f.config, self.f.report = self.deployment_config, self.deployment_report  # the fixture's product view of the NEW generation
    self.f.write(self.T.P.LIMINE, F.with_snapshots(self.limine(), [3, 4, 5], True))  # one more snapper sync
    self.assertTrue(self.T.P.verify(self.root, self.T.P.digest(self.receipt_raw)))
    result = self.publish()  # the rebound generation is an ordinary qualified generation again
    self.assertTrue((self.root / self.T.MAINTENANCE).exists())
    self.assertNotEqual(result["transition_id"], self.result["transition_id"])
    self.assertEqual(self.assess()["class"], "unchanged")

  # --- preconditions: every refusal writes nothing -------------------------------------------------
  def test_no_marker_and_wrong_or_missing_assessment_refuse(self):
    other = self.new()
    other.path(other.T.MAINTENANCE).unlink()
    with self.assertRaisesRegex(ValueError, "Inactive package maintenance marker required"): other.rebind()
    for label, result, pattern in (("unchanged", {"class": "unchanged"}, "use `reactivate`"), ("unknown", {"class": "unknown", "reason": "baseline missing"}, "compatibility unknown: baseline missing"),
                                   ("unknown items", {"class": "unknown", "unknown_items": ["kernel"]}, "unknown items: kernel"), ("malformed", {"class": "fine"}, "malformed assessment"),
                                   ("not a dict", "requalification-required", "malformed assessment")):
      with self.subTest(label): self.new().refuses(pattern, assess=lambda evidence, marker, result=result: result)

  def test_real_unknown_assessment_refuses_without_an_override(self):
    other = self.new()
    (other.archive() / self.T.BASELINE_NAME).unlink()
    other.refuses("compatibility unknown: Generation baseline is missing")
    other = self.new()
    other.assess_core = lambda evidence, marker: {**N._assess_report(), "class": "unknown", "unknown_items": ["driver_modules"]}
    other.refuses("rebind needs a definite requalification-required")

  def test_unchanged_generation_real_assessment_points_at_reactivate(self):
    other = self.new()
    other.assess_core = lambda evidence, marker: {**N._assess_report(), "class": "unchanged"}
    other.refuses("use `reactivate`")

  def test_old_pair_must_be_retired_and_the_new_pair_staged(self):
    other = self.new()
    other.f.write(other.T.P.RECEIPT, other.old_receipt_raw)
    other.refuses("old pair is still staged")
    other = self.new()
    (other.root / other.T.P.RECEIPT).unlink()
    other.refuses("Staged replacement pair receipt required")

  def test_retirement_record_must_exist_be_exact_and_chain_to_the_marker(self):
    T = self.T
    record = self.retirement
    cases = {"missing record": (lambda o: (o.root / T.RETIREMENT).unlink(), "Pair retirement record required"),
             "missing retained receipt": (lambda o: (o.root / T.RETIRED_RECEIPT).unlink(), "Retained retired receipt required"),
             "not json": (lambda o: o.write(T.RETIREMENT, b"{"), None),
             "extra key": (lambda o: o.write(T.RETIREMENT, json.dumps({**record, "extra": 1}).encode()), "Exact pair retirement record"),
             "wrong protocol": (lambda o: o.write(T.RETIREMENT, json.dumps({**record, "protocol": "other"}).encode()), "Exact pair retirement record"),
             "other receipt": (lambda o: o.write(T.RETIREMENT, json.dumps({**record, "retired_receipt_sha256": "1" * 64}).encode()), "does not chain"),
             "bad digest": (lambda o: o.write(T.RETIREMENT, json.dumps({**record, "source_sha256": "zz"}).encode()), "Invalid pair retirement hash"),
             "altered retained receipt": (lambda o: o.write(T.RETIRED_RECEIPT, o.old_receipt_raw + b" "), "differs from the maintenance receipt")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        mutate(other)
        before = other.tree()
        with self.assertRaisesRegex(ValueError, pattern or ""): other.rebind()
        self.assertEqual(other.tree(), before)
        self.assertFalse(other.pending().exists())

  def test_retirement_record_must_name_the_retired_images_and_the_new_images_must_differ(self):
    T = self.T
    other = self.new()
    other.write(T.RETIREMENT, json.dumps({**other.retirement, "source_sha256": "1" * 64}).encode())
    other.refuses("does not name the retired source image")
    other = self.new()
    other.write(T.RETIREMENT, json.dumps({**other.retirement, "restore_sha256": "1" * 64}).encode())
    other.refuses("does not name the retired restore image")
    other = self.new()
    receipt = json.loads(other.receipt_raw)
    receipt["images"]["restore"]["sha256"] = other.retirement["restore_sha256"]
    other.f.write(T.P.RECEIPT, json.dumps(receipt).encode())
    other.refuses("staged restore image is the retired one")

  def test_staged_authority_files_are_required_and_bound_to_the_new_pair(self):
    T = self.T
    for name in T.STAGED:
      with self.subTest(missing=name):
        other = self.new()
        (other.root / T.STAGED[name]).unlink()
        other.refuses("Staged replacement authority required")
    def config(**changes): return lambda o: o.write(T.STAGED["config"], json.dumps({**o.new_config, **changes}).encode())
    def qualification(**changes): return lambda o: o.write(T.STAGED["qualification"], json.dumps({**o.new_qualification, **changes}).encode())
    cases = {"receipt digest not bound": (config(staged_receipt_sha256="1" * 64), "does not bind the staged pair receipt"),
             "no manifest": (config(manifest=None), "lacks a manifest"),
             "manifest of the retired generation": (lambda o: (o.write(T.STAGED["config"], json.dumps({**o.new_config, "manifest": o.config["manifest"]}).encode()),
                                                              o.write(T.STAGED["qualification"], json.dumps({**o.new_qualification, "manifest_sha256": T.PRODUCT.TX.digest(o.config["manifest"])}).encode())), "equals the retired generation"),
             "manifest not pinning the image": (lambda o: (o.write(T.STAGED["config"], json.dumps({**o.new_config, "manifest": {**o.manifest, "source_sha256": "1" * 64}}).encode()),
                                                          o.write(T.STAGED["qualification"], json.dumps({**o.new_qualification, "manifest_sha256": T.PRODUCT.TX.digest({**o.manifest, "source_sha256": "1" * 64})}).encode())), "does not pin the staged source image"),
             "qualification for another manifest": (qualification(manifest_sha256="1" * 64), "not bound to this product manifest"),
             "qualification not qualified": (qualification(qualified=False), "not bound to this product manifest"),
             "qualification other protocol": (qualification(protocol="omarchy-t2-product-one-use-trial-v1"), "not bound to this product manifest"),
             "qualification extra field": (qualification(extra=1), "Qualification receipt fields differ"),
             "qualification bad evidence": (qualification(evidence_sha256="nope"), "Invalid SHA-256")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        mutate(other)
        other.refuses(pattern)

  def test_product_level_validation_failure_and_a_derived_manifest_mismatch_refuse(self):
    other = self.new(inspect_fault=ValueError("product validation refused"))
    other.refuses("product validation refused")
    other = self.new()
    def wrong(evidence, staged): return {"manifest": {**staged["config"]["manifest"], "protocol": "other"}, "baseline": {}}
    other.refuses("Derived manifest differs", inspect=wrong)
    other = self.new()
    def malformed(evidence, staged): return {"manifest": staged["config"]["manifest"], "baseline": {"kernel": {}}}
    other.refuses("Exact generation baseline item set", inspect=malformed)

  def test_the_fresh_capture_must_have_read_exactly_the_staged_bytes(self):
    for name in ("config", "qualification"):
      with self.subTest(name):
        other = self.new()
        def swapped(evidence, staged, other=other, name=name):
          info = other.inspect(evidence, staged)
          info["baseline"][name] = {**info["baseline"][name], "sha256": "1" * 64}
          return info
        other.refuses("read different " + name + " bytes", inspect=swapped)

  def test_review_policy_must_be_the_approved_proposal_for_the_new_pair(self):
    T = self.T
    cases = {"unapproved": {**self.new_policy, "approved": False}, "other receipt": {**self.new_policy, "staged_receipt_sha256": "1" * 64},
             "other entry": {**self.new_policy, "source_entry_id": "MBA-T2-hibernation-source-0000000000000000"}}
    for label, policy in cases.items():
      with self.subTest(label):
        other = self.new()
        other.write(T.STAGED["review"], json.dumps(policy).encode())
        other.refuses("")

  def test_pair_backup_and_limine_drift_since_staging_refuse(self):
    T = self.T
    other = self.new()
    (other.root / PAIR.BACKUP).unlink()
    other.refuses("Staged pair Limine backup required")
    other = self.new()
    other.write(PAIR.BACKUP, other.donor + b"# tampered\n")
    other.refuses("Pair Limine backup differs")
    cases = {"extra global option": (lambda raw: b"timeout: 9\n" + raw, "Unrelated Limine drift"),
             "altered pair block": (lambda raw: raw.replace(b"# END", b"# tampered\n# END", 1), "Unrelated Limine drift"),
             "remembered selection": (lambda raw: raw.replace(b"default_entry: 2\n", b"default_entry: 2\nremember_last_entry: yes\n", 1), "Remembered"),
             "second default": (lambda raw: raw + b"default_entry: 3\n", "canonical stock default"),
             "already source default": (lambda raw: raw.replace(b"default_entry: 2\n", b"default_entry: 5\n", 1), "canonical stock default"),
             "production hash drift": (lambda raw: raw.replace(blake2(self.new_production).encode(), blake2(b"another update").encode()), "does not bind actual production UKI|Unrelated Limine drift")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        other.f.write(T.P.LIMINE, mutate(other.limine()))
        other.refuses(pattern)

  def test_the_current_configuration_cannot_be_restaged_as_the_replacement(self):
    T = self.T
    other = self.new()
    current = other.path(T.CONFIG).read_bytes()
    other.write(T.STAGED["config"], current)
    # the current configuration binds the retired receipt, so it cannot also bind the new one
    other.refuses("does not bind the staged pair receipt")

  def test_runtime_gate_and_maintenance_chain_failures_refuse(self):
    other = self.new()
    with patch.object(other.T, "_runtime", return_value="0" * 64): other.refuses("Reviewed runtime differs")
    other = self.new()
    def closed(root, phase): raise ValueError("gate closed at " + phase)
    other.refuses("gate closed at retained", gate=closed)
    other = self.new()
    path = other.archive() / "policy.json"
    path.write_bytes(b"{}")
    other.refuses("policy")

  def test_existing_policy_optin_pending_and_runtime_or_deactivation_state_refuse(self):
    T = self.T
    def foreign(relative, raw=b"foreign"): return lambda other: other.f.write(relative, raw)
    barrier = T._encoded({"protocol": "omarchy-t2-runtime-upgrade-intent-v2", "transaction_id": str(uuid.uuid4()), "approval_id": str(uuid.uuid4())})
    cases = {"policy": (foreign(T.P.POLICY), "Existing source-default"), "opt-in": (lambda other: other.f.write(T.OPT_IN, b"").chmod(0o644), "Existing source-default"),
             "runtime upgrade pending": (foreign(T.P.STATE / T.D.UPGRADE_PENDING), "Runtime deployment/upgrade pending"),
             "runtime pending": (foreign(T.P.STATE / T.D.PENDING), "Runtime deployment/upgrade pending"),
             "deactivation pending": (foreign(T.PENDINGS["deactivation"]), "re-enter `maintenance`"),
             "runtime barrier under the shared filename": (foreign(T.PENDINGS["activation"], barrier), "not a rebind intent")}
    for label, (mutate, pattern) in cases.items():
      with self.subTest(label):
        other = self.new()
        mutate(other)
        before = other.tree()
        with self.assertRaisesRegex(ValueError, pattern): other.rebind()
        self.assertEqual(other.tree(), before)
        if label == "runtime barrier under the shared filename":
          self.assertFalse(other.T.rebind_pending(other.root))  # the barrier is never mistaken for ours
          self.assertFalse(other.T.reactivation_pending(other.root))

  def test_busy_locks_refuse_and_are_preserved(self):
    before = self.tree()
    db = self.root / self.T.DB_LOCK
    db.write_bytes(b"existing transaction")
    with self.assertRaises(FileExistsError): self.rebind()
    self.assertEqual(db.read_bytes(), b"existing transaction")
    db.unlink()
    held = os.open(self.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with self.assertRaises(BlockingIOError): self.rebind()
    finally: os.close(held)
    self.assertFalse(db.exists())
    self.assertEqual(self.tree(), before)

  def test_canonical_root_and_live_root_refusals(self):
    with self.assertRaisesRegex(ValueError, "Canonical root"): self.T._rebind(Path("relative"), guard=lambda: None, gate=self.fx.gate, assess=self.assess_core, inspect=self.inspect, postchecks=self.postchecks)
    with self.assertRaisesRegex(ValueError, "native coordinator"): self.T._rebind(Path("/"), guard=lambda: None, gate=self.fx.gate, assess=self.assess_core, inspect=self.inspect, postchecks=self.postchecks)
    with self.assertRaisesRegex(ValueError, "callbacks"): self.T._rebind(self.root, guard=lambda: None, gate=self.fx.gate, assess=None, inspect=self.inspect, postchecks=self.postchecks)

  def test_rebind_pending_recognizes_only_its_own_protocol(self):
    T = self.T
    self.assertFalse(T.rebind_pending(self.root))
    for raw, expected in ((b"garbage", False), (T._encoded({"protocol": T.REACTIVATION_SCHEMA}), False), (T._encoded({"protocol": "omarchy-t2-runtime-upgrade-intent-v2"}), False),
                          (T._encoded({"protocol": T.REBIND_SCHEMA}), True)):
      self.f.write(T.PENDINGS["activation"], raw)
      self.assertIs(T.rebind_pending(self.root), expected)
    self.assertFalse(T.reactivation_pending(self.root))

  def test_reactivate_refuses_to_adopt_a_rebind_pending_and_maintenance_never_deletes_it(self):
    self.crashed(self.guards().index("W3") + 1)
    self.assertTrue(self.T.rebind_pending(self.root))
    before = self.tree()
    with self.assertRaisesRegex(ValueError, "not a reactivation intent"):
      self.T._reactivate(self.root, guard=lambda: None, gate=self.fx.gate, assess=self.assess_core, inspect=lambda evidence: {}, postchecks=lambda root, baseline: None, pinned={})
    self.assertEqual(self.tree(), before)
    self.assertTrue(self.pending().exists())

  # --- failures roll back to the exact prior maintenance state --------------------------------------
  def test_postcheck_failure_rolls_back_exactly_and_a_fresh_attempt_then_succeeds(self):
    other = self.new(fault=ValueError("inside W7"))
    with self.assertRaisesRegex(ValueError, "inside W7"): other.rebind()
    self.assertTrue(other.pending().exists())
    other.assert_vetoed()
    other.fault = None
    result = other.rebind()
    self.assertEqual((result["rolled_back"], result["rebound"]), (True, False))  # never retried forward past the boot write
    other.assert_rolled_back()
    self.assertTrue((other.own_archive() / other.T.ROLLBACK_NAME).exists())
    self.assertTrue(other.rebind()["rebound"])
    other.assert_active()

  def test_a_torn_policy_write_never_leaves_partial_bytes_under_the_policy_name(self):
    other = self.new()
    real = other.T._new
    def torn(path, raw, mode=0o600):
      if path.name.startswith(other.T.P.POLICY.name + ".rebind-tmp-"):
        path.write_bytes(raw[:len(raw) // 2])
        raise Crash()
      return real(path, raw, mode)
    with patch.object(other.T, "_new", side_effect=torn), self.assertRaises(Crash): other.rebind()
    self.assertFalse(other.path(other.T.P.POLICY).exists())  # only a stray temporary holds the torn bytes
    self.assertTrue(other.pending().exists())
    other.assert_vetoed()
    self.assertTrue(other.rebind()["rolled_back"])  # recovery removes the stray and restores the exact prior state
    other.assert_rolled_back()
    self.assertTrue(other.rebind()["rebound"])
    other.assert_active()

  def test_a_torn_pending_write_leaves_no_pending_and_the_next_run_proceeds(self):
    other = self.new()
    real = other.T._new
    def torn(path, raw, mode=0o600):
      if path.name.startswith(other.T.PENDINGS["activation"].name + ".rebind-tmp-"):
        path.write_bytes(raw[:len(raw) // 2])
        raise Crash()
      return real(path, raw, mode)
    with patch.object(other.T, "_new", side_effect=torn), self.assertRaises(Crash): other.rebind()
    self.assertFalse(other.pending().exists())  # nothing else was written yet, so the machine is still plain maintenance
    other.T.G._maintenance(other.root)
    self.assertTrue(other.rebind()["rebound"])
    other.assert_active()

  def test_a_persistent_fault_keeps_the_veto_and_the_recorded_state(self):
    other = self.new(fault=ValueError("inside W7"))
    with self.assertRaises(ValueError): other.rebind()
    with self.assertRaisesRegex(ValueError, "gate closed"):
      other.rebind(gate=lambda root, phase: (_ for _ in ()).throw(ValueError("gate closed")))
    self.assertTrue(other.pending().exists())  # a failed rollback preserves the pending: sleep and updates stay vetoed
    other.assert_vetoed()
    self.assertTrue(other.rebind()["rolled_back"])
    other.assert_rolled_back()

  def test_recovery_rollback_refuses_foreign_bytes_without_touching_anything(self):
    T = self.T
    cases = {"config": lambda o: o.write(T.CONFIG, b"{}"), "qualification": lambda o: o.write(T.QUALIFICATION, b"{}"), "review": lambda o: o.write(T.REVIEW, b"{}"),
             "backup": lambda o: o.write(T.P.BACKUP, b"foreign"), "policy": lambda o: o.write(T.P.POLICY, b"foreign"),
             "limine": lambda o: o.f.write(T.P.LIMINE, b"timeout: 9\n" + o.limine())}
    for label, mutate in cases.items():
      with self.subTest(label):
        other = self.new()
        other.crashed(other.guards().index("W5") + 1)
        mutate(other)
        before = other.tree()
        with self.assertRaises(ValueError): other.rebind()
        self.assertEqual(other.tree(), before)
        self.assertTrue(other.pending().exists())

  def test_recovery_refuses_a_missing_or_altered_archive_while_state_is_changed(self):
    for label, name in (("old config", "old-config.json"), ("new backup", "new-backup"), ("baseline", "new-baseline.json"), ("comparison", "comparison.json"), ("new receipt", "new-receipt.json"),
                        ("retirement record", "retirement.json"), ("retired receipt", "retired-receipt.json")):
      with self.subTest(label):
        other = self.new()
        other.crashed(other.guards().index("W3") + 1)
        archive = other.own_archive()
        (archive / name).write_bytes(b"altered")
        before = other.tree()
        with self.assertRaises(ValueError): other.rebind()
        self.assertEqual(other.tree(), before)
        self.assertTrue(other.pending().exists())

  def test_a_torn_completion_is_never_trusted_forward(self):
    other = self.to_stage("W8")
    (other.own_archive() / "completion.json").write_bytes(b"{}")
    result = other.rebind()
    self.assertEqual((result["rolled_back"], result["rebound"]), (True, False))
    other.assert_rolled_back()

  def test_foreign_pending_and_marker_mismatch_are_preserved(self):
    other = self.to_stage("W3")
    other.f.write(other.T.PENDINGS["activation"], other.T._encoded({**json.loads(other.pending().read_bytes()), "marker_sha256": "1" * 64}))
    before = other.tree()
    with self.assertRaisesRegex(ValueError, "marker is not the one"): other.rebind()
    self.assertEqual(other.tree(), before)

  # --- crash injection ---------------------------------------------------------------------------
  def guard_at(self, limit):
    calls = []
    def guard():
      calls.append(self.stage() if self.pending().exists() or self.path(self.T.P.POLICY).exists() else "none")
      if limit is not None and len(calls) == limit: raise Crash()
    return guard, calls

  def crashed(self, limit):
    guard, calls = self.guard_at(limit)
    try: self.rebind(guard=guard)
    except Crash: pass
    else: self.fail("no crash at guard " + str(limit))
    return calls

  def guards(self):
    """Stage seen by every guard() of one complete run (cached: the sequence is deterministic)."""
    if Rebind.trace is None:
      probe = self.new()
      guard, calls = probe.guard_at(None)
      probe.rebind(guard=guard)
      Rebind.trace = calls
    return Rebind.trace

  def to_stage(self, name):
    other = self.new()
    other.crashed(self.guards().index(name) + 1)
    self.assertEqual(other.stage(), name)
    return other

  def test_a_crash_before_every_write_keeps_sleep_and_updates_vetoed_and_recovery_finishes_correctly(self):
    total = len(self.guards())
    self.assertGreaterEqual(total, 30)
    seen = set()
    for limit in range(1, total + 1):
      with self.subTest(guard=limit):
        other = self.new()
        other.crashed(limit)
        stage = other.stage()
        seen.add(stage)
        self.assertFalse((other.root / other.T.DB_LOCK).exists())
        if stage == "done": other.assert_active()
        elif stage == "none":
          self.assertFalse(other.pending().exists())
          self.assertEqual(other.tree(), other.before)
          self.assertTrue(other.rebind()["rebound"])
          other.assert_active()
        else:
          other.assert_vetoed()
          self.assertTrue(other.T.rebind_pending(other.root))
          result = other.rebind()
          if stage in ("pre", "W3", "W4", "W5", "W6"):
            self.assertEqual((result.get("rolled_back"), result["rebound"]), (True, False))
            other.assert_rolled_back()
            self.assertTrue((other.root / other.T.HISTORY / result["transition_id"] / other.T.ROLLBACK_NAME).exists())
            self.assertTrue(other.rebind()["rebound"])  # a fresh attempt is then allowed
          else: self.assertEqual(result["recovered"], "finished-retirement" if stage == "W8" else "retired-pending")
          other.assert_active()
    # A process death between the pending unlink and the lock release cannot be simulated in-process: the engine
    # reinstates the pending on any BaseException there, so that instant shows up as W9 again.
    self.assertEqual(seen, set(self.STAGES) - {"done"})

  def test_repeated_crashes_during_recovery_still_converge_to_the_exact_prior_state(self):
    total = len(self.guards())
    for start in (self.guards().index("W5") + 1, self.guards().index("W6") + 1):
      other = self.new()
      other.crashed(start)
      for attempt in range(1, 60):
        guard, calls = other.guard_at(attempt)
        try: result = other.rebind(guard=guard)
        except Crash: continue
        break
      else: self.fail("recovery never completed")
      self.assertTrue(result["rolled_back"])
      other.assert_rolled_back()

  def test_a_failure_releasing_the_package_lock_reinstates_the_pending(self):
    other = self.new()
    real = other.T._locks
    @contextlib.contextmanager
    def locks(root):
      with real(root) as release:
        def failing(*, verify_only=False):
          if not verify_only: raise OSError("release fault")
          return release(verify_only=True)
        failing.check_physical = release.check_physical
        yield failing
        release()
    with patch.object(other.T, "_locks", side_effect=locks):
      with self.assertRaises(OSError): other.rebind()
    self.assertTrue(other.pending().exists())  # sleep and updates stay vetoed
    self.assertEqual(other.stage(), "W9")  # the marker is already retired; only the pending remains
    self.assertFalse((other.root / other.T.DB_LOCK).exists())
    self.assertEqual(other.rebind()["recovered"], "retired-pending")
    other.assert_active()

  def test_a_new_marker_for_the_new_generation_publishes_and_validates_normally(self):
    self.rebind()
    self.f.config, self.f.report = self.deployment_config, self.deployment_report
    published = self.publish()
    evidence = self.T.G._maintenance(self.root)
    self.assertEqual(evidence["transition_id"], published["transition_id"])
    self.assertNotEqual(evidence["transition_id"], self.result["transition_id"])


class AssessAfterRetirement(NT.AssessFixture):
  """The maintenance chain must stay valid (updates allowed, assess meaningful) between retirement and rebind."""

  def setUp(self):
    super().setUp()
    self.published()
    self.receipt_raw = self.f.raw
    self.receipt_sha = self.T.P.digest(self.receipt_raw)

  def retire(self, record=True):
    T, P = self.T, self.T.P
    self.write(T.RETIRED_RECEIPT, self.receipt_raw)
    self.write(T.RETIREMENT, json.dumps({"protocol": T.RETIREMENT_SCHEMA, "retired_receipt_sha256": self.receipt_sha, "source_sha256": self.T.P.digest(b"source"), "restore_sha256": self.T.P.digest(b"restore")}).encode())
    (self.root / P.RECEIPT).unlink()

  def test_marker_receipt_resolves_the_live_or_the_retained_copy_only_when_chained(self):
    T = self.T
    intent = json.loads((self.root / T.MAINTENANCE).read_bytes())
    self.assertEqual(T.marker_receipt(self.root, intent), self.receipt_raw)
    self.retire()
    self.assertEqual(T.marker_receipt(self.root, intent), self.receipt_raw)
    self.f.write(T.P.RECEIPT, b'{"a": "new pair receipt"}')  # a NEW receipt at the fixed path never satisfies the OLD marker on its own
    self.assertEqual(T.marker_receipt(self.root, intent), self.receipt_raw)
    (self.root / T.RETIREMENT).unlink()
    with self.assertRaisesRegex(ValueError, "Pair retirement record required"): T.marker_receipt(self.root, intent)

  def test_update_guard_and_assess_stay_valid_after_the_old_pair_was_retired(self):
    self.T.G._maintenance(self.root)
    self.retire()
    evidence = self.T.G._maintenance(self.root)
    self.assertEqual(evidence["transition_id"], self.result["transition_id"])
    self.f.write(self.T.P.RECEIPT, b'{"a": "new pair receipt"}')
    self.T.G._maintenance(self.root)
    self.assertIn(self.assess()["class"], ("unchanged", "requalification-required", "unknown"))
    self.assertNotIn("Maintenance evidence not validated", self.assess().get("reason", ""))

  def test_the_guard_cross_checks_the_record_images_against_the_retained_receipt(self):
    T = self.T
    self.retire()
    self.T.G._maintenance(self.root)
    for role in ("source", "restore"):
      record = json.loads((self.root / T.RETIREMENT).read_bytes())
      record[role + "_sha256"] = "1" * 64
      self.write(T.RETIREMENT, json.dumps(record).encode())
      with self.assertRaisesRegex(ValueError, "does not name the retired " + role + " image"): T.G._maintenance(self.root)
      record[role + "_sha256"] = T.P.digest(role.encode())
      self.write(T.RETIREMENT, json.dumps(record).encode())
    T.G._maintenance(self.root)

  def test_without_the_retirement_evidence_a_missing_or_foreign_receipt_still_blocks_the_guard(self):
    T = self.T
    (self.root / T.P.RECEIPT).unlink()
    with self.assertRaises(ValueError): T.G._maintenance(self.root)
    self.f.write(T.P.RECEIPT, b'{"a": "foreign"}')
    with self.assertRaises(ValueError): T.G._maintenance(self.root)
    self.assertTrue(self.assess()["class"] == "unknown" and "Maintenance evidence not validated" in self.assess()["reason"])


class RebindNative(unittest.TestCase):
  """The native adapter wiring for `rebind`; every host query and reviewed byte source is mocked."""

  def dispatch(self, pending=False):
    seen = {}
    @contextlib.contextmanager
    def exclusion(action):
      seen["action"] = action
      yield lambda: None
    engine = Mock()
    engine.reactivation_pending.return_value = False
    engine.rebind_pending.return_value = pending
    engine._rebind.return_value = {"rebound": True, "requalification_required": False, "qualification_issued": False}
    with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), \
         patch.object(N, "_exclusion", side_effect=exclusion):
      return engine, seen, N.native("rebind")

  def test_dispatch_supplies_only_fixed_root_capability_and_callbacks(self):
    engine, seen, result = self.dispatch()
    self.assertEqual(seen["action"], "rebind")
    arguments = engine._rebind.call_args
    self.assertEqual(arguments.args, (Path("/"),))
    self.assertIs(arguments.kwargs["native"], engine._NATIVE_MAINTENANCE)
    self.assertEqual(set(arguments.kwargs), {"guard", "gate", "native", "pinned", "assess", "inspect", "postchecks"})
    self.assertTrue(result["live_execution"] and result["power_operation"] is False and result["rebound"] and result["requalification_required"] is False)
    engine._transition.assert_not_called()
    engine._reactivate.assert_not_called()
    with patch.object(N, "_maintenance_gate") as gate: arguments.kwargs["gate"](Path("/"), "retained")
    gate.assert_called_once_with(engine, Path("/"), "retained", arguments.kwargs["pinned"])
    with patch.object(N, "_assess_core", return_value={"class": "requalification-required"}) as core:
      self.assertEqual(arguments.kwargs["assess"]({"evidence": 1}, b"marker"), {"class": "requalification-required"})
    core.assert_called_once_with(engine, Path("/"), {"evidence": 1}, b"marker")
    with patch.object(N, "_rebind_inspect", return_value={"manifest": {}}) as inspect: arguments.kwargs["inspect"]({"evidence": 1}, {"config": {}})
    inspect.assert_called_once_with(engine, {"evidence": 1}, {"config": {}})
    with patch.object(N, "_rebind_postchecks") as postchecks: arguments.kwargs["postchecks"](Path("/"), {"kernel": {}})
    postchecks.assert_called_once_with(engine, Path("/"), {"kernel": {}})

  def test_the_live_7_2_7_assessment_shape_is_accepted(self):
    """Changed items win over unknown ones: the 2026-09-29 live report (kernel, production_uki, control_inventory changed; driver items unknown)."""
    live = {"class": "requalification-required", "changed_items": ["control_inventory", "kernel", "production_uki"], "unknown_items": ["driver_modules", "firmware"],
            "baseline": "valid", "limine": {"exact_equal": False, "state": "equal", "stock_projection_equal": True}}
    F.T._rebind_refuse_assessment(live)
    for bad in ({**live, "class": "unknown"}, {**live, "class": "unchanged"}):
      with self.assertRaises(ValueError): F.T._rebind_refuse_assessment(bad)

  def test_the_action_is_fixed_and_the_cli_takes_no_paths_or_force(self):
    self.assertIn("rebind", N.ACTIONS)
    self.assertEqual(N._inhibit_command("rebind")[-1], "rebind")
    with patch.object(N, "native", return_value={"rebound": True}) as native:
      self.assertEqual(N.main(["rebind"]), 0)
      for args in (["rebind", "--root", "/tmp"], ["rebind", "--force"], ["rebind", "--config", "/tmp/x"], ["rebind", "maintenance"]):
        with self.assertRaises(SystemExit): N.main(args)
    self.assertEqual([call.args for call in native.call_args_list], [("rebind",)])
    with patch.object(N.os, "execve", side_effect=AssertionError("exec")), patch.object(N, "_command", side_effect=AssertionError("no host queries")):
      with self.assertRaises(ValueError): N.native("rebind")  # workspace/nonroot invocation refuses first

  def test_maintenance_and_activation_refuse_naming_rebind_while_one_is_pending(self):
    for action in ("maintenance",):
      with self.assertRaisesRegex(ValueError, "re-run `rebind`"):
        engine = Mock()
        engine.reactivation_pending.return_value = False
        engine.rebind_pending.return_value = True
        @contextlib.contextmanager
        def exclusion(name):
          yield lambda: None
        with patch.object(N, "_installed", return_value=engine), patch.object(Path, "readlink", return_value=Path("/usr/bin/systemd-inhibit")), patch.object(N, "_exclusion", side_effect=exclusion):
          N.native(action)
      engine._transition.assert_not_called()

  def report(self, resume=None):
    return {"manifest": {"m": 1}, "audited_details": {"restore_protocol": {"resume": {"offset": 1} if resume is None else resume}}}

  def test_inspect_requires_the_pinned_resume_product_validation_staged_deployment_and_fresh_capture(self):
    engine = Mock()
    engine.PRODUCT.ARTIFACTS.derive_artifacts.return_value = self.report()
    config = {"source_directory": "s", "restore_directory": "r", "production_uki": "p"}
    with patch.object(N, "generation_items", return_value=({"kernel": {}}, {})) as items:
      info = N._rebind_inspect(engine, {"resume": {"offset": 1}}, {"config": config, "qualification": {"q": 1}})
    self.assertEqual(info, {"manifest": {"m": 1}, "baseline": {"kernel": {}}})
    engine.PRODUCT.validate.assert_called_once()
    self.assertIs(engine.PRODUCT.TRIAL._verify_deployment.call_args.kwargs["source_default"], False)
    engine.IMAGE_STATE.require_no_image.assert_called_once_with(Path("/"), {"offset": 1})
    items.assert_called_once_with(engine, Path("/"), config_name="rebind-config.json", qualification_name="rebind-qualification.json")
    with patch.object(N, "generation_items", return_value=({}, {})), self.assertRaisesRegex(ValueError, "resume"):
      N._rebind_inspect(engine, {"resume": {"offset": 2}}, {"config": config, "qualification": {}})
    with patch.object(N, "generation_items", return_value=({}, {"production_uki": "unreadable", "firmware": "x"})), self.assertRaisesRegex(ValueError, "production_uki"):
      N._rebind_inspect(engine, {"resume": {"offset": 1}}, {"config": config, "qualification": {}})
    with patch.object(N, "generation_items", return_value=({}, {"firmware": "tolerated"})):
      N._rebind_inspect(engine, {"resume": {"offset": 1}}, {"config": config, "qualification": {}})

  def test_postchecks_verify_source_default_deployment_no_image_and_the_fresh_baseline(self):
    engine = Mock()
    engine.BASELINE_ITEMS = ("kernel", "firmware")
    engine.PRODUCT.TRIAL._private_json.side_effect = lambda path: {"source_directory": "s", "restore_directory": "r", "production_uki": "p"}
    engine.PRODUCT.ARTIFACTS.derive_artifacts.return_value = self.report()
    fresh = {"kernel": {"a": 1}, "firmware": {"b": 2}, "limine": {}}
    with patch.object(N, "generation_items", return_value=({"kernel": {"a": 1}, "firmware": {"b": 2}}, {})):
      N._rebind_postchecks(engine, Path("/"), fresh)
    self.assertIs(engine.PRODUCT.TRIAL._verify_deployment.call_args.kwargs["source_default"], True)
    engine.IMAGE_STATE.require_no_image.assert_called_once_with(Path("/"), {"offset": 1})
    for items, errors, pattern in (({"kernel": {"a": 2}, "firmware": {"b": 2}}, {}, "kernel"), ({"kernel": {"a": 1}, "firmware": {"b": 3}}, {}, "firmware"),
                                   ({"kernel": {"a": 1}, "firmware": {"b": 2}}, {"kernel": "unreadable"}, "kernel")):
      with patch.object(N, "generation_items", return_value=(items, errors)), self.assertRaisesRegex(ValueError, pattern):
        N._rebind_postchecks(engine, Path("/"), fresh)
    with patch.object(N, "generation_items", return_value=({"kernel": {"a": 1}, "firmware": {"unavailable": "x"}}, {"firmware": "x"})):
      N._rebind_postchecks(engine, Path("/"), fresh)  # a tolerated item unreadable on one side is not a difference


if __name__ == "__main__": unittest.main()
