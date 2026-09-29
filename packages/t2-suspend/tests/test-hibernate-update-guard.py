"""Offline update admission fixtures; never run pacman, power or boot tools."""
import configparser
import fcntl
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("update_guard", HERE / "hibernate/update_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Updates(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name) / "root"
    self.root.mkdir(mode=0o700)
    (self.root / guard.EFI).mkdir(parents=True, mode=0o700)
    self.stock = ("timeout: 3\ndefault_entry: 2\n/+Omarchy\n  //linux-t2\n  comment: Kernel version: 7.1.1-test\n"
                  "  comment: kernel-id=linux-t2\n  protocol: efi\n  path: " + guard.PRODUCTION + "#" + "a" * 128 + "\n")
    self.write(guard.LIMINE, self.stock)

  def write(self, relative, raw):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
      if parent == self.root.parent: break
      parent.chmod(0o700)
    path.write_text(raw)
    path.chmod(0o600)
    return path

  def test_inactive_stock_and_updated_production_hash_are_read_only(self):
    self.write(guard.STATE / "history/boot-policy.json", '{"approved":true}')
    self.write(guard.STATE / "limine.conf.before-source-default", "retained immutable evidence")
    self.write(guard.STATE / "ledger/consumed-guard.json", "retained consumed guard")
    before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
    self.assertEqual(guard.check(self.root)["default_entry"], 2)
    self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
    self.write(guard.LIMINE, self.stock.replace("a" * 128, "b" * 128).replace("7.1.1-test", "7.2.0-test"))
    self.assertEqual(guard.check(self.root)["classification"], "inactive-stock-update-admitted")

  def test_all_active_artifacts_block_even_invalid_empty_or_dangling(self):
    self.assertIn(guard.STATE / "package-maintenance.pending", guard.ACTIVE)
    for relative in guard.ACTIVE:
      for content in ("", "malformed", '{"approved":false}'):
        with self.subTest(relative=relative, content=content):
          path = self.write(relative, content)
          with self.assertRaises(ValueError): guard.check(self.root)
          path.unlink()
      path = self.root / relative
      path.symlink_to(path.with_name("missing"))
      with self.assertRaises(ValueError): guard.check(self.root)
      path.unlink()

  def test_partial_deactivation_does_not_release_until_all_active_artifacts_absent(self):
    paths = [self.write(relative, "pending") for relative in guard.ACTIVE]
    for path in paths:
      with self.assertRaises(ValueError): guard.check(self.root)
      path.unlink()
    self.assertEqual(guard.check(self.root)["default_entry"], 2)

  def test_source_foreign_or_ambiguous_defaults_block_without_policy(self):
    for text in (
      self.stock.replace("default_entry: 2", "default_entry: MBA-T2-hibernation-source-c5e6f0c9"),
      self.stock.replace("default_entry: 2", "default_entry: 3"),
      "default_entry: 2\n" + self.stock,
      "remember_last_entry: yes\n" + self.stock,
      self.stock.replace("//linux-t2", "//MBA-T2-hibernation-source-c5e6f0c9"),
      self.stock.replace("/+Omarchy", "/+Foreign"),
      self.stock.replace(guard.PRODUCTION, "boot():/EFI/Linux/mba-t2-source.efi"),
      self.stock.replace("protocol: efi", "protocol: linux"),
      self.stock.replace("a" * 128, "bad-hash"),
      self.stock + "  protocol: efi\n",
      self.stock + "  protocol : efi\n",
      self.stock + "  image_path: boot():/alternate\n",
      self.stock + "  kernel_path: boot():/alternate\n",
    ):
      with self.subTest(text=text[:80]):
        self.write(guard.LIMINE, text)
        with self.assertRaises(ValueError): guard.check(self.root)

  def test_missing_writable_symlinked_and_oversized_configuration_fail_closed(self):
    path = self.root / guard.LIMINE
    path.chmod(0o666)
    with self.assertRaises(ValueError): guard.check(self.root)
    path.unlink()
    with self.assertRaises(FileNotFoundError): guard.check(self.root)
    path.symlink_to("missing")
    with self.assertRaises(ValueError): guard.check(self.root)
    path.unlink()
    self.write(guard.LIMINE, "x" * (guard.MAX_BYTES + 1))
    with self.assertRaises(ValueError): guard.check(self.root)

  def test_fifo_configuration_rejected_before_open_can_block(self):
    path = self.root / guard.LIMINE
    path.unlink()
    os.mkfifo(path, mode=0o600)
    with patch.object(guard.os, "open", side_effect=AssertionError("FIFO must not be opened")):
      with self.assertRaises(ValueError): guard.check(self.root)

  def test_dangling_symlink_and_writable_active_state_ancestors_fail_closed(self):
    state = self.root / guard.STATE
    state.parent.mkdir(parents=True)
    state.symlink_to(state.with_name("missing"))
    with self.assertRaises(ValueError): guard.check(self.root)
    state.unlink()
    state.mkdir(mode=0o777)
    state.chmod(0o777)
    with self.assertRaises(ValueError): guard.check(self.root)
    state.chmod(0o700)
    self.assertEqual(guard.check(self.root)["default_entry"], 2)
    omarchy = self.root / "etc/omarchy"
    omarchy.parent.mkdir()
    omarchy.symlink_to(omarchy.with_name("missing"))
    with self.assertRaises(ValueError): guard.check(self.root)

  def test_unavailable_efi_view_cannot_prove_absent_overrides(self):
    (self.root / guard.EFI).rmdir()
    with self.assertRaises(FileNotFoundError): guard.check(self.root)

  def test_cli_fixed_root_no_arguments_no_environment_bypass(self):
    bypasses = {"OMARCHY_UPDATE_PACMAN": "1", "OMARCHY_ALLOW_DIRECT_PACMAN": "1", "OMARCHY_T2_UPDATE_FORCE": "1"}
    with patch.dict(os.environ, bypasses), patch.object(guard.os, "geteuid", return_value=0), patch.object(guard, "_marker_present", return_value=False):
      with patch.object(guard, "check", side_effect=ValueError("fixture active policy")) as checked:
        with self.assertRaises(ValueError): guard.main([])
        checked.assert_called_once_with(Path("/"))
      with patch.object(guard, "check", side_effect=AssertionError("no root reads")):
        for arguments in (["--root", "/tmp"], ["--force"], ["--help"]):
          with self.assertRaises(ValueError): guard.main(arguments)
    with patch.object(guard.os, "geteuid", return_value=1000), patch.object(guard, "check") as checked:
      with self.assertRaises(ValueError): guard.main([])
      checked.assert_not_called()
    with self.assertRaises(ValueError): guard.check(Path("relative"))
    with self.assertRaises(ValueError): guard.check(self.root / "..")

  def test_hook_scope_ordering_fixed_snapshot_and_fail_closed_contract(self):
    filename = HERE / "hibernate/00-omarchy-t2-hibernate-guard.hook"
    parser = configparser.ConfigParser(allow_no_value=True)
    # ALPM permits repeated Operation fields; inspect their exact set separately.
    text = filename.read_text()
    operations = [line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("Operation =")]
    parser.read_string("\n".join(line for line in text.splitlines() if not line.startswith("Operation =")))
    self.assertEqual(set(operations), {"Install", "Upgrade", "Remove"})
    self.assertEqual(parser["Trigger"]["Type"], "Package")
    self.assertEqual(parser["Trigger"]["Target"], "*")
    self.assertEqual(parser["Action"]["When"], "PreTransaction")
    self.assertIn("AbortOnFail", parser["Action"])
    self.assertEqual(parser["Action"]["Exec"], "/usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py")
    self.assertNotIn("NeedsTargets", parser["Action"])
    self.assertLess(filename.name, "10-linux-modules-pre.hook")
    self.assertLess(filename.name, "11-glibc-remove-ldconfig-cache.hook")


class MaintenanceEvidence(unittest.TestCase):
  def setUp(self):
    spec = importlib.util.spec_from_file_location("guard_transition_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))
    self.fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(self.fixture_module)
    self.fixture = self.fixture_module.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.f, self.T = self.fixture.root, self.fixture.f, self.fixture_module.T
    self.fixture.run_action()
    self.fixture.run_action("maintenance")
    self.marker = self.root / self.T.MAINTENANCE
    self.raw = self.marker.read_bytes()
    self.intent = json.loads(self.raw)
    self.archive = self.T.HISTORY / self.intent["transition_id"]

  def check(self): return guard.check_inactive_maintenance(self.root)

  def test_real_seeded_chain_is_read_only_and_native_guard_still_refuses(self):
    before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
    result = self.check()
    self.assertEqual(result["classification"], "fixture-inactive-maintenance-verified")
    self.assertFalse(result["qualification_issued"])
    self.assertFalse(result["reactivation_evaluated"])
    self.assertEqual(result["maintenance_intent_sha256"], hashlib.sha256(self.raw).hexdigest())
    self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
    with self.assertRaises(ValueError): guard.check(self.root)

  def test_coherent_updated_production_is_evidence_not_old_generation_reuse(self):
    image = b"updated synthetic production UKI"
    path = Path("boot/EFI/Linux/omarchy_linux-t2.efi")
    old_hash = hashlib.blake2b((self.root / path).read_bytes()).hexdigest()
    self.f.write(path, image)
    config = (self.root / guard.LIMINE).read_bytes().replace(old_hash.encode(), hashlib.blake2b(image).hexdigest().encode())
    self.f.write(guard.LIMINE, config)
    result = self.check()
    self.assertEqual(result["fallback"]["production"]["sha256"], hashlib.sha256(image).hexdigest())
    self.assertFalse(result["reactivation_evaluated"])
    self.assertEqual(self.marker.read_bytes(), self.raw)

  def test_live_root_aliases_refuse_before_import_or_open(self):
    alias = self.root.parent / "live-alias"
    alias.symlink_to("/")
    with patch.object(guard.importlib.util, "spec_from_file_location", side_effect=AssertionError("No live import")):
      for root in ("/", "/tmp/..", alias, "relative", self.root / ".."):
        with self.assertRaises(ValueError): guard.check_inactive_maintenance(root)

  def test_malformed_empty_noncanonical_and_foreign_marker_refuse(self):
    for raw in (b"", b"malformed", b"{}", json.dumps(self.intent).encode(), self.T._encoded({**self.intent, "transition_id": "../foreign"}), self.T._encoded({**self.intent, "runtime_review_sha256": "bad"})):
      self.f.write(self.T.MAINTENANCE, raw)
      with self.assertRaises((ValueError, KeyError)): self.check()
    self.marker.unlink()
    self.marker.symlink_to(self.root / self.archive / "maintenance-intent.json")
    with self.assertRaises((OSError, ValueError)): self.check()

  def test_private_metadata_and_missing_archive_refuse(self):
    self.marker.chmod(0o644)
    with self.assertRaises(ValueError): self.check()
    self.marker.chmod(0o600)
    archive = self.root / self.archive
    archive.chmod(0o755)
    with self.assertRaises(ValueError): self.check()
    archive.chmod(0o700)
    (archive / "completion.json").unlink()
    with self.assertRaises(FileNotFoundError): self.check()

  def test_symlink_archive_and_hardlinked_marker_refuse(self):
    archive = self.root / self.archive
    retained = archive.with_name("foreign-archive")
    archive.rename(retained)
    archive.symlink_to(retained, target_is_directory=True)
    with self.assertRaises(ValueError): self.check()
    archive.unlink()
    retained.rename(archive)
    os.link(self.marker, self.marker.with_name("marker-hardlink"))
    with self.assertRaises(ValueError): self.check()

  def test_repeated_hashes_do_not_make_false_completion_valid(self):
    completion_path = self.archive / "completion.json"
    original = json.loads((self.root / completion_path).read_bytes())
    for changed in ({**original, "action": "activation"}, {**original, "extra": "claim"}, {**original, "configuration_sha256": "f" * 64}):
      raw = self.T._encoded(changed)
      self.f.write(completion_path, raw)
      marker = self.T._encoded({**self.intent, "deactivation_completion_sha256": hashlib.sha256(raw).hexdigest()})
      self.f.write(self.T.MAINTENANCE, marker)
      self.f.write(self.archive / "maintenance-intent.json", marker)
      with self.assertRaises(ValueError): self.check()

  def test_old_policy_receipt_runtime_and_optin_drift_refuse(self):
    relatives = (self.archive / "policy.json", self.T.P.RECEIPT,
                 self.T.P.STATE / "runtime-deployment-review.json", self.archive / "opt-in")
    for relative in relatives:
      path = self.root / relative
      raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
      self.f.write(relative, b"changed")
      if relative.name == "opt-in": path.chmod(0o644)
      with self.assertRaises((ValueError, KeyError)): self.check()
      self.f.write(relative, raw).chmod(mode)

  def test_active_markers_and_reusable_efi_refuse(self):
    for relative in (*[item for item in guard.ACTIVE if item != self.T.MAINTENANCE],
                     guard.EFI / self.T.PRODUCT.HOST.CT.SOURCE_VARIABLE):
      path = self.f.write(relative, b"")
      with self.assertRaises(ValueError): self.check()
      path.unlink()

  def test_unresolved_ledger_and_missing_efi_view_refuse(self):
    unresolved = self.f.write(self.T.P.STATE / "ledger/slot-retirement-001-unresolved.json", b"unresolved")
    with self.assertRaises(ValueError): self.check()
    unresolved.unlink()
    efi = self.root / guard.EFI
    retained = efi.with_name("unavailable-efivars")
    efi.rename(retained)
    with self.assertRaises(FileNotFoundError): self.check()

  def during_fallback(self, mutation):
    original_spec = guard.importlib.util.spec_from_file_location
    def load(name, path):
      spec = original_spec(name, path)
      if name == "guard_maintenance_evidence":
        execute = spec.loader.exec_module
        def loaded(module):
          execute(module)
          fallback = module._fallback
          def changed(root):
            result = fallback(root)
            mutation()
            return result
          module._fallback = changed
        spec.loader.exec_module = loaded
      return spec
    with patch.object(guard.importlib.util, "spec_from_file_location", side_effect=load):
      with self.assertRaises(ValueError): self.check()

  def test_marker_drift_after_fallback_hashing_refuses(self):
    self.during_fallback(lambda: self.f.write(self.T.MAINTENANCE, b"changed after hashing"))

  def test_private_directory_and_archived_optin_mode_drift_refuses(self):
    for relative, changed, original in ((self.archive, 0o755, 0o700),
                                        (self.T.HISTORY, 0o755, 0o700),
                                        (self.T.P.STATE / "ledger", 0o755, 0o700),
                                        (self.archive / "opt-in", 0o600, 0o644)):
      with self.subTest(relative=relative):
        path = self.root / relative
        try: self.during_fallback(lambda: path.chmod(changed))
        finally: path.chmod(original)

  def test_actual_image_or_stock_hash_drift_refuse_but_foreign_db_is_preserved(self):
    lock = self.f.write(self.T.DB_LOCK, b"existing actual pacman lock fixture")
    self.check()  # read-only pre-hooks do not own/remove pacman's lock
    self.assertEqual(lock.read_bytes(), b"existing actual pacman lock fixture")
    self.f.write("boot/EFI/Linux/omarchy_linux-t2.efi", b"unbound replacement")
    with self.assertRaises(ValueError): self.check()
    self.assertEqual(lock.read_bytes(), b"existing actual pacman lock fixture")


class NativeAdmission(unittest.TestCase):
  """Native ALPM admission over the real seeded maintenance chain; temp roots only."""
  def setUp(self):
    spec = importlib.util.spec_from_file_location("guard_native_fixture", Path(__file__).with_name("test-hibernate-boot-policy-transition.py"))
    self.fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(self.fixture_module)
    self.T = self.fixture_module.T
    original = self.T.D.inventory
    def inventory(source):
      # The reviewed runtime must carry the pinned stdlib verifier the guard loads first.
      (Path(source) / self.T.D.TREES[0] / "runtime_deployment.py").write_bytes((HERE / "hibernate/runtime_deployment.py").read_bytes())
      return original(source)
    self.fixture = self.fixture_module.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
    with patch.object(self.T.D, "inventory", inventory): self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.f = self.fixture.root, self.fixture.f
    self.fixture.run_action()
    self.fixture.run_action("maintenance")
    self.marker = self.root / self.T.MAINTENANCE
    self.raw = self.marker.read_bytes()
    self.script = self.root / guard.RUNTIME / "packages/t2-suspend/hibernate/update_guard.py"
    self.intent = json.loads(self.raw)

  def admit(self, **overrides):
    arguments = {"root": self.root, "owner": os.geteuid(), "isolated": True, "script": self.script}
    return guard._admit(**{**arguments, **overrides})

  def snapshot(self): return {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}

  def test_valid_inactive_evidence_admits_repeatedly_and_retains_marker(self):
    before = self.snapshot()
    for _ in range(3):
      result = self.admit()
      self.assertEqual(result["classification"], "inactive-maintenance-update-admitted")
      self.assertFalse(result["qualification_issued"])
      self.assertFalse(result["reactivation_evaluated"])
    self.assertEqual(before, self.snapshot())
    self.assertEqual(self.marker.read_bytes(), self.raw)
    held = os.open(self.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try: fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released after each admission
    finally: os.close(held)

  def test_existing_pacman_db_lock_is_neither_required_absent_nor_removed(self):
    lock = self.f.write(self.T.DB_LOCK, b"pacman owns this during hooks")
    self.admit()
    self.assertEqual(lock.read_bytes(), b"pacman owns this during hooks")
    lock.unlink()
    self.admit()

  def test_missing_marker_blocks(self):
    self.assertTrue(guard._marker_present(self.root))
    self.marker.unlink()
    self.assertFalse(guard._marker_present(self.root))
    with self.assertRaises((ValueError, FileNotFoundError)): self.admit()

  def test_forged_foreign_or_partial_markers_block(self):
    T = self.T
    for raw in (b"", b"malformed", b"{}", json.dumps(self.intent).encode(),
                T._encoded({**self.intent, "transition_id": "../foreign"}),
                T._encoded({**self.intent, "runtime_review_sha256": "0" * 64}),
                T._encoded({**self.intent, "transition_id": "00000000-0000-4000-8000-000000000000"})):
      self.f.write(T.MAINTENANCE, raw)
      with self.assertRaises((ValueError, KeyError, OSError)): self.admit()
    self.marker.unlink()
    self.marker.symlink_to(self.root / T.HISTORY / self.intent["transition_id"] / "maintenance-intent.json")
    with self.assertRaises((ValueError, OSError)): self.admit()
    self.marker.unlink()
    self.f.write(T.MAINTENANCE, self.raw)
    self.admit()
    (self.root / T.HISTORY / self.intent["transition_id"] / "completion.json").unlink()  # partial archive
    with self.assertRaises((ValueError, OSError)): self.admit()

  def test_active_policy_optin_pending_or_efi_state_blocks(self):
    self.assertIn(guard.STATE / "runtime-upgrade.pending", guard.ACTIVE)
    for relative in (*[item for item in guard.ACTIVE if item != guard.MAINTENANCE], guard.EFI / self.T.PRODUCT.HOST.CT.SOURCE_VARIABLE):
      with self.subTest(relative=relative):
        path = self.f.write(relative, b"")
        with self.assertRaises(ValueError): self.admit()
        path.unlink()
    self.admit()

  def test_stock_drift_and_unresolved_ledger_block(self):
    ledger = self.f.write(self.T.P.STATE / "ledger/slot-retirement-001-unresolved.json", b"unresolved")
    with self.assertRaises(ValueError): self.admit()
    ledger.unlink()
    self.f.write("boot/EFI/Linux/omarchy_linux-t2.efi", b"unbound replacement")
    with self.assertRaises(ValueError): self.admit()

  def test_concurrent_hibernation_cycle_holding_physical_lock_blocks(self):
    held = os.open(self.root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
      with patch.object(guard, "_maintenance", side_effect=AssertionError("must not validate while a cycle runs")):
        with self.assertRaisesRegex(ValueError, "physical lock"): self.admit()
    finally: os.close(held)
    self.admit()

  def test_missing_or_unsafe_physical_lock_blocks(self):
    path = self.root / self.T.PHYSICAL_LOCK
    path.chmod(0o644)
    with self.assertRaises(ValueError): self.admit()
    path.chmod(0o600)
    path.unlink()
    with self.assertRaises(FileNotFoundError): self.admit()

  def test_authentication_precedes_every_lazy_import(self):
    rejected = ({"script": HERE / "hibernate/update_guard.py"}, {"isolated": False}, {"isolated": 0},
                {"owner": os.geteuid() + 1}, {"script": self.script.with_name("elsewhere.py")})
    for override in rejected:
      with self.subTest(override=override):
        with patch.object(guard.importlib.util, "spec_from_file_location", side_effect=AssertionError("import before authentication")):
          with self.assertRaises((ValueError, FileNotFoundError, OSError)): self.admit(**override)

  def test_unreviewed_or_unprivate_runtime_refuses_before_imports(self):
    target = self.script.with_name("runtime_deployment.py")
    raw = target.read_bytes()
    review = self.root / guard.REVIEW
    review_raw = review.read_bytes()
    with patch.object(guard.importlib.util, "spec_from_file_location", side_effect=AssertionError("import before authentication")):
      target.write_bytes(raw + b"# tampered\n")
      with self.assertRaises(ValueError): self.admit()
      target.write_bytes(raw)
      self.script.chmod(0o644)
      with self.assertRaises(ValueError): self.admit()
      self.script.chmod(0o600)
      review.write_bytes(review_raw.replace(b"true", b"false"))
      with self.assertRaises(ValueError): self.admit()
      review.write_bytes(review_raw)

  def test_extra_unreviewed_runtime_file_refuses(self):
    extra = self.script.parent / "unreviewed.py"
    extra.write_text("x = 1\n")
    extra.chmod(0o600)
    with self.assertRaises(ValueError): self.admit()

  def test_live_entry_is_fixed_and_refuses_workspace_copy_or_nonroot(self):
    with patch.object(guard, "_admit", side_effect=AssertionError("no admission")):
      with patch.object(guard.os, "geteuid", return_value=1000):
        with self.assertRaises(ValueError): guard.native()
      with patch.object(guard.os, "geteuid", return_value=0):
        with self.assertRaises(ValueError): guard.native()  # this workspace file is not the installed path

  def test_fixture_wrapper_still_refuses_live_root_and_aliases_and_takes_no_lock(self):
    alias = self.root.parent / "live-alias"
    alias.symlink_to("/")
    with patch.object(guard, "_authenticate", side_effect=AssertionError("wrapper is not native")), patch.object(guard, "_physical", side_effect=AssertionError("no lock")):
      for root in ("/", "/tmp/..", alias, "relative"):
        with self.assertRaises(ValueError): guard.check_inactive_maintenance(root)
      self.assertEqual(guard.check_inactive_maintenance(self.root)["classification"], "fixture-inactive-maintenance-verified")

  def test_cli_routes_marker_to_native_and_absent_marker_to_blanket_check(self):
    with patch.object(guard.os, "geteuid", return_value=0):
      with patch.object(guard, "_marker_present", return_value=True), patch.object(guard, "native", return_value={}) as native, patch.object(guard, "check", side_effect=AssertionError("no blanket fallback")):
        self.assertEqual(guard.main([]), 0)
        native.assert_called_once_with()
      with patch.object(guard, "_marker_present", return_value=True), patch.object(guard, "native", side_effect=ValueError("blocked")), patch.object(guard, "check", side_effect=AssertionError("no fallback after failure")):
        with self.assertRaises(ValueError): guard.main([])
      with patch.object(guard, "_marker_present", return_value=False), patch.object(guard, "native", side_effect=AssertionError("no native")), patch.object(guard, "check", return_value={}) as check:
        self.assertEqual(guard.main([]), 0)
        check.assert_called_once_with(Path("/"))


if __name__ == "__main__": unittest.main()
