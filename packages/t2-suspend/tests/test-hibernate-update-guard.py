"""Offline update admission fixtures; never run pacman, power or boot tools."""
import configparser
import contextlib
import fcntl
import importlib.util
import importlib._bootstrap_external
import shutil
import stat
import subprocess
import sys
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

  def test_refusal_text_names_the_update_command_and_the_fixed_maintenance_command(self):
    text = guard.refusal(ValueError("fixture active policy"))
    self.assertTrue(text.startswith("T2 hibernation update guard: fixture active policy\n"))
    self.assertIn("  omarchy update\n", text)
    self.assertIn("sudo /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py maintenance", text)
    self.assertIn("MAINTENANCE-RUNBOOK.md", text)

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
    with patch.object(guard, "_load", side_effect=AssertionError("No live import")), patch.object(guard, "_execute", side_effect=AssertionError("No live import")):
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
    original = guard._load
    def load(name, path, expected=None):
      module = original(name, path, expected)
      if name == "guard_maintenance_evidence":
        fallback = module._fallback
        def changed(root):
          result = fallback(root)
          mutation()
          return result
        module._fallback = changed
      return module
    with patch.object(guard, "_load", side_effect=load):
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
      for name in ("runtime_deployment.py", "image_state.py"):  # the guard also loads the reviewed image_state
        (Path(source) / self.T.D.TREES[0] / name).write_bytes((HERE / "hibernate" / name).read_bytes())
      parser = Path(source) / self.T.D.TREES[1] / "audit-hibernation-swap-header.py"  # image_state's reviewed header parser
      parser.parent.mkdir(parents=True, exist_ok=True)
      parser.write_bytes((HERE / "experiments/audit-hibernation-swap-header.py").read_bytes())
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
    self.image_state = guard._load("test_image_state", HERE / "hibernate/image_state.py")
    self.offset, self.devnum = 7, "254:0"
    for directory in ("dev", "dev/mapper", "sys/power"): (self.root / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
    os.symlink("../dm-0", self.root / "dev/mapper/root")
    self.f.write("sys/power/resume", (self.devnum + "\n").encode())
    self.f.write("sys/power/resume_offset", (str(self.offset) + "\n").encode())
    self.device = self.root / "dev/dm-0"
    self.set_page(self.clean_page())
    self.calls, self.resumes = [], []

  def clean_page(self):
    page = bytearray(4096)
    page[1024:1028] = b"\x01\0\0\0"
    page[-10:] = b"SWAPSPACE2"
    return bytes(page)

  def set_page(self, page):
    data = bytearray((self.offset + 1) * 4096)
    data[self.offset * 4096:] = page
    self.device.write_bytes(bytes(data))
    self.device.chmod(0o600)

  def query(self, argv):
    if argv[0] == "/usr/bin/btrfs": return str(self.offset)
    return "/dev/mapper/root[/@swap] btrfs"

  def image(self, root, inventory, resume):
    self.calls.append("image")
    self.resumes.append(resume)
    held = os.open(root / self.T.PHYSICAL_LOCK, os.O_RDONLY)
    try:
      with self.assertRaises(BlockingIOError): fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # checked under our lock
    finally: os.close(held)
    # The real guard code path: reviewed image_state loaded from the runtime, pinned tuple from evidence.
    return guard._live_image(root, inventory, resume, query=self.query, fixture_identity=lambda fd: (254, 0))

  def admit(self, **overrides):
    arguments = {"root": self.root, "owner": os.geteuid(), "isolated": True, "script": self.script, "image": self.image}
    return guard._admit(**{**arguments, **overrides})

  def test_saved_image_unknown_or_unreadable_header_blocks_under_lock(self):
    self.assertEqual(self.admit()["image"], "no-image-at-qualified-resume-page")
    self.assertEqual(self.calls, ["image"])
    swsusp = bytearray(self.clean_page())
    swsusp[-10:] = b"S1SUSPEND\0"
    for page in (bytes(swsusp), bytes(4096), b"S" * 4096, self.clean_page()[:-10] + b"SWAP-SPACE"):
      self.set_page(page)
      with self.assertRaises(ValueError): self.admit()
    self.device.write_bytes(b"short")  # truncated: header page unreadable
    with self.assertRaises(ValueError): self.admit()
    self.set_page(self.clean_page())
    (self.root / "sys/power/resume_offset").write_text("8\n")  # kernel target differs
    with self.assertRaises(ValueError): self.admit()
    (self.root / "sys/power/resume_offset").write_text(str(self.offset) + "\n")
    (self.root / "dev/mapper/root").unlink()
    with self.assertRaises(OSError): self.admit()

  def test_image_check_failure_or_bad_result_blocks_and_synthetic_roots_need_a_check(self):
    with self.assertRaises(ValueError): self.admit(image=lambda root, inventory, resume: {"classification": "unknown"})
    with self.assertRaises(ValueError): self.admit(image=lambda root, inventory, resume: None)
    with self.assertRaises(ValueError): guard._admit(self.root, os.geteuid(), True, self.script)  # no seam supplied
    with self.assertRaises(ValueError): guard._admit(Path("/"), 0, True, self.script, image=self.image)  # live root refuses seam

  def test_planted_bytecode_and_reopened_paths_are_never_executed(self):
    package = self.root.parent / "package-copy"
    copy = package / "hibernate"
    shutil.copytree(HERE / "hibernate", copy, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(HERE / "experiments", package / "experiments", ignore=shutil.ignore_patterns("__pycache__"))
    target = copy / "package_maintenance.py"
    evil = compile("raise RuntimeError('stale pyc executed')", str(target), "exec")
    info = target.stat()
    cache = Path(importlib.util.cache_from_source(str(target)))
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(evil, int(info.st_mtime), info.st_size))
    spec = importlib.util.spec_from_file_location("guard_copy", copy / "update_guard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    before = sys.dont_write_bytecode, sys.pycache_prefix
    result = module._admit(self.root, os.geteuid(), True, self.script, image=self.image)
    self.assertEqual(result["classification"], "inactive-maintenance-update-admitted")
    self.assertEqual(before, (sys.dont_write_bytecode, sys.pycache_prefix))  # process settings restored
    normal = importlib.util.spec_from_file_location("normal_import", target)
    with self.assertRaises(RuntimeError):  # sanity: an ordinary import WOULD run the planted cache
      normal.loader.exec_module(importlib.util.module_from_spec(normal))

  def test_reviewed_bytes_pin_is_enforced_by_loader(self):
    target = HERE / "hibernate/update_guard.py"
    raw = target.read_bytes()
    good = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    self.assertTrue(hasattr(guard._load("pinned", target, good), "check"))
    with self.assertRaises(ValueError): guard._load("pinned", target, {**good, "size": good["size"] + 1})
    with self.assertRaises(ValueError): guard._load("pinned", target, {**good, "sha256": "0" * 64})

  def snapshot(self): return {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}

  def test_admit_and_native_route_never_pass_ignore(self):
    real = guard._maintenance
    seen = []
    def spy(*args, **kwargs):
      seen.append(kwargs)
      return real(*args, **kwargs)
    with patch.object(guard, "_maintenance", spy):
      self.admit()
    self.assertEqual(seen, [{}])
    seen.clear()
    with patch.object(guard.os, "geteuid", return_value=0), patch.object(guard, "_marker_present", return_value=True), \
         patch.object(guard, "_admit", side_effect=lambda *a, **k: seen.append(k) or {}):
      with patch.object(guard, "SCRIPT", Path(guard.__file__).absolute()): guard.main([])
    self.assertNotIn("ignore", seen[0])

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
        with patch.object(guard, "_load", side_effect=AssertionError("import before authentication")), patch.object(guard, "_execute", side_effect=AssertionError("import before authentication")):
          with self.assertRaises((ValueError, FileNotFoundError, OSError)): self.admit(**override)

  def test_unreviewed_or_unprivate_runtime_refuses_before_imports(self):
    target = self.script.with_name("runtime_deployment.py")
    raw = target.read_bytes()
    review = self.root / guard.REVIEW
    review_raw = review.read_bytes()
    with patch.object(guard, "_load", side_effect=AssertionError("import before authentication")), patch.object(guard, "_execute", side_effect=AssertionError("import before authentication")):
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

  def test_ignore_is_strict_and_only_relaxes_the_named_known_pending(self):
    deactivation = self.T.PENDINGS["deactivation"]
    self.assertEqual(guard._maintenance(self.root, ignore=())["transition_id"], self.intent["transition_id"])
    for bad in (self.T.MAINTENANCE, Path("etc/passwd"), self.T.PENDINGS["deactivation"].parent, str(deactivation), [deactivation], (str(deactivation),), (deactivation, self.T.MAINTENANCE), deactivation):
      with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "Ignore must name"): guard._maintenance(self.root, ignore=bad)
    before = guard.ACTIVE
    pending = self.f.write(deactivation, b"pending")
    with self.assertRaisesRegex(ValueError, "Active or incomplete"): guard._maintenance(self.root)
    with self.assertRaisesRegex(ValueError, "Active or incomplete"): guard._maintenance(self.root, ignore=())
    self.assertEqual(guard._maintenance(self.root, ignore=(deactivation,))["transition_id"], self.intent["transition_id"])
    self.assertIs(guard.ACTIVE, before)
    for other, mode in ((self.T.PENDINGS["activation"], 0o600), (self.T.RUNTIME_PENDINGS[0], 0o600), (self.T.RUNTIME_PENDINGS[1], 0o600), (self.T.P.POLICY, 0o600), (self.T.OPT_IN, 0o644)):
      with self.subTest(other=other.name):
        extra = self.f.write(other, b"x")
        extra.chmod(mode)
        with self.assertRaisesRegex(ValueError, "Active or incomplete"): guard._maintenance(self.root, ignore=(deactivation,))
        # ignoring one path never excuses a different one
        with self.assertRaisesRegex(ValueError, "Active or incomplete"): guard._maintenance(self.root, ignore=(other,))
        extra.unlink()
    pending.unlink()
    self.assertEqual(guard._maintenance(self.root)["transition_id"], self.intent["transition_id"])

  def test_ignore_also_relaxes_the_final_appeared_during_verification_scan(self):
    deactivation = self.T.PENDINGS["deactivation"]
    self.f.write(deactivation, b"pending")
    other = self.T.PENDINGS["activation"]
    real = self.T._idle
    calls = []  # counts _idle calls made by the validator itself
    def appear(root):
      real(root)
      calls.append(1)
      if len(calls) == 2 and not (root / other).exists(): self.f.write(other, b"late")
    loader = guard._load
    def load(*args):
      module = loader(*args)
      module.T._idle = appear  # the module instance _maintenance actually validates with
      return module
    with patch.object(guard, "_load", load), self.assertRaisesRegex(ValueError, "appeared during"):
      guard._maintenance(self.root, ignore=(deactivation,))
    self.assertTrue((self.root / other).exists())

  def test_public_wrapper_and_admission_paths_never_pass_ignore(self):
    import ast, inspect
    self.assertEqual(list(inspect.signature(guard.check_inactive_maintenance).parameters), ["root"])
    with self.assertRaises(TypeError): guard.check_inactive_maintenance(self.root, ignore=(self.T.PENDINGS["deactivation"],))
    tree = ast.parse(Path(guard.__file__).read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_maintenance"]
    self.assertTrue(calls)
    for node in calls: self.assertFalse([keyword for keyword in node.keywords if keyword.arg == "ignore" or keyword.arg is None], ast.dump(node))
    self.f.write(self.T.PENDINGS["deactivation"], b"pending")
    with self.assertRaises(ValueError): guard.check_inactive_maintenance(self.root)

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

  # ---- pinned resume evidence (the guard never derives qualified artifacts) ----
  def resume_path(self): return self.root / self.T.HISTORY / self.intent["transition_id"] / guard.RESUME_NAME

  def rewrite_resume(self, raw):
    path = self.resume_path()
    path.write_bytes(raw)
    path.chmod(0o600)

  def resume_bytes(self, resume, **overrides):
    document = json.loads(self.resume_path().read_bytes())
    document.update(resume=resume, **overrides)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

  def booby_traps(self):
    """Any qualified-artifact audit, tool run or product/artifacts load fails the test."""
    def load(name, path, expected=None):
      if Path(path).name not in ("package_maintenance.py", "image_state.py"): raise AssertionError("guard loaded unexpected module " + str(path))
      return original(name, path, expected)
    original = guard._load
    trap = AssertionError("guard consulted qualified artifacts or ran a tool")
    stack = contextlib.ExitStack()
    stack.enter_context(patch.object(guard, "_load", load))
    for name in ("run", "Popen", "check_output", "check_call"): stack.enter_context(patch.object(subprocess, name, side_effect=trap))
    return stack

  def test_publisher_archives_the_exact_resume_tuple_and_guard_admits_it(self):
    expected = {"device": "/dev/mapper/root", "devnum": self.devnum, "offset": self.offset}
    self.assertEqual(expected, self.fixture_module.RESUME)
    raw = self.resume_path().read_bytes()
    document = json.loads(raw)
    self.assertEqual(document["resume"], expected)
    self.assertEqual(raw, guard._resume_document(self.intent["transition_id"], expected, self.intent))
    self.assertEqual(stat.S_IMODE(self.resume_path().stat().st_mode), 0o600)
    result = self.admit()
    self.assertEqual((result["resume"], self.resumes), (expected, [expected]))  # the seam saw the evidence tuple

  def update_kernel(self, image):
    """Coherent OS update: new production UKI bytes and the stock entry's hash."""
    path = "boot/EFI/Linux/omarchy_linux-t2.efi"
    old_hash = hashlib.blake2b((self.root / path).read_bytes()).hexdigest()
    self.f.write(path, image)
    config = (self.root / guard.LIMINE).read_bytes().replace(old_hash.encode(), hashlib.blake2b(image).hexdigest().encode())
    self.f.write(guard.LIMINE, config)

  def test_kernel_update_between_transactions_never_blocks_and_derives_nothing(self):
    for generation in range(3):
      image = ("updated synthetic production UKI %d" % generation).encode()
      self.update_kernel(image)
      with self.booby_traps():
        result = self.admit()
        self.assertEqual(result["classification"], "inactive-maintenance-update-admitted")
        self.assertEqual(result["fallback"]["production"]["sha256"], hashlib.sha256(image).hexdigest())
    self.assertEqual(self.marker.read_bytes(), self.raw)
    self.assertEqual(self.calls, ["image"] * 3)

  def test_snapshot_churn_between_transactions_never_blocks_and_snapshot_default_does(self):
    snapshots = self.fixture_module.with_snapshots
    def rewrite(numbers, reverse=False, kernel=None):
      config = snapshots((self.root / guard.LIMINE).read_bytes(), numbers, reverse)
      if kernel is not None:
        path = "boot/EFI/Linux/omarchy_linux-t2.efi"
        config = config.replace(hashlib.blake2b((self.root / path).read_bytes()).hexdigest().encode(), hashlib.blake2b(kernel).hexdigest().encode())
        self.f.write(path, kernel)
      self.f.write(guard.LIMINE, config)
    with self.booby_traps():
      for label, change in (("first snapshot", lambda: rewrite([1])), ("second snapshot added", lambda: rewrite([1, 2])),
                            ("old snapshot cleaned up", lambda: rewrite([2])), ("reordered block", lambda: rewrite([2, 3, 4], reverse=True)),
                            ("kernel update plus churn", lambda: rewrite([5], kernel=b"kernel update with snapshot churn")), ("snapshots removed", lambda: rewrite([]))):
        with self.subTest(label):
          change()
          self.assertEqual(self.admit()["classification"], "inactive-maintenance-update-admitted")
      rewrite([1, 2])
      good = (self.root / guard.LIMINE).read_bytes()
      for label, text in (("snapshot promoted to default", good.replace(b"default_entry: 2", b"default_entry: 5")),
                          ("default inside the region", good.replace(b"comment: 4.0.2-1", b"default_entry: 5", 1))):
        with self.subTest(label):
          self.f.write(guard.LIMINE, text)
          with self.assertRaisesRegex(ValueError, "canonical stock default 2"): self.admit()
      self.f.write(guard.LIMINE, good)
      self.assertEqual(self.admit()["classification"], "inactive-maintenance-update-admitted")
    self.assertEqual(self.marker.read_bytes(), self.raw)

  def test_missing_or_prefix_marker_without_resume_evidence_is_refused(self):
    self.resume_path().unlink()  # what a pre-fix publisher produced (no deployed markers exist; no migration)
    with self.assertRaises(FileNotFoundError): self.admit()
    self.assertEqual(self.calls, [])

  def test_malformed_resume_evidence_blocks_before_any_image_read(self):
    good = {"device": "/dev/mapper/root", "devnum": self.devnum, "offset": self.offset}
    document = json.loads(self.resume_path().read_bytes())
    encoded = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    cases = [b"", b"{}", b"[]", b"malformed", json.dumps(document).encode(),  # noncanonical spacing
             encoded({**document, "extra": 1}), encoded({key: value for key, value in document.items() if key != "resume"}),
             encoded({**document, "transition_id": "00000000-0000-4000-8000-000000000000"}),
             encoded({**document, "deactivation_completion_sha256": "0" * 64}),
             encoded({**document, "old_policy_sha256": "0" * 64}), encoded({**document, "staged_receipt_sha256": "0" * 64}),
             encoded({**document, "protocol": "other"})]
    for resume in ({}, {"device": good["device"], "devnum": good["devnum"]}, {**good, "extra": 1}, {**good, "device": "/dev/sda1"},
                   {**good, "devnum": 254}, {**good, "devnum": "254"}, {**good, "devnum": "254:0\n"}, {**good, "devnum": "a:b"},
                   {**good, "offset": str(self.offset)}, {**good, "offset": True}, {**good, "offset": 0}, {**good, "offset": -7},
                   {**good, "offset": self.offset + 0.5}, {**good, "offset": 2**63}, None, "254:0", [good]):
      cases.append(encoded({**document, "resume": resume}))
    for raw in cases:
      with self.subTest(raw=raw[:100]):
        self.rewrite_resume(raw)
        with self.assertRaises((ValueError, KeyError, TypeError)): self.admit()
    self.assertEqual(self.calls, [])
    self.rewrite_resume(encoded(document))
    self.assertEqual(self.admit()["image"], "no-image-at-qualified-resume-page")

  def test_resume_evidence_metadata_and_symlink_are_private_and_exact(self):
    path = self.resume_path()
    path.chmod(0o644)
    with self.assertRaises(ValueError): self.admit()
    path.chmod(0o600)
    saved = path.read_bytes()
    path.unlink()
    (path.parent / "elsewhere").write_bytes(saved)
    path.symlink_to("elsewhere")
    with self.assertRaises((ValueError, OSError)): self.admit()
    path.unlink()
    self.rewrite_resume(saved)
    self.admit()

  def test_stale_pinned_resume_fails_closed_against_live_topology(self):
    other = self.resume_bytes({"device": "/dev/mapper/root", "devnum": self.devnum, "offset": self.offset + 1})
    self.rewrite_resume(other)  # canonical and well-formed, but no longer the active swap location
    with self.assertRaises(ValueError): self.admit()
    self.rewrite_resume(self.resume_bytes({"device": "/dev/mapper/root", "devnum": "254:1", "offset": self.offset}))
    with self.assertRaises(ValueError): self.admit()
    self.rewrite_resume(self.resume_bytes({"device": "/dev/mapper/root", "devnum": self.devnum, "offset": self.offset}))
    self.assertEqual(self.admit()["image"], "no-image-at-qualified-resume-page")

  def test_saved_image_at_pinned_page_blocks_after_kernel_update(self):
    self.update_kernel(b"kernel updated")
    self.admit()
    page = bytearray(self.clean_page())
    page[-10:] = b"S1SUSPEND\0"
    self.set_page(bytes(page))
    with self.assertRaises(ValueError): self.admit()

  def test_live_image_loads_only_reviewed_image_state_and_no_product(self):
    source = (HERE / "hibernate/update_guard.py").read_text()
    body = source[source.index("def _live_image"):source.index("def _admit")]
    for forbidden in ("product.py", "derive_artifacts", "config.json", "production_uki", "source_directory"):
      self.assertNotIn(forbidden, body)
    seen = []
    original = guard._load
    def spy(name, path, expected=None):
      seen.append(Path(path).name)
      return original(name, path, expected)
    with patch.object(guard, "_load", spy): self.admit()
    self.assertEqual(sorted(set(seen)), ["image_state.py", "package_maintenance.py"])


if __name__ == "__main__": unittest.main()
