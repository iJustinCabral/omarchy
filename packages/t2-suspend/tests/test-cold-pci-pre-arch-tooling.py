#!/usr/bin/python3
"""Combined two-module bundle and exact read-only witness fault fixtures."""
import copy
import importlib.util
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent / "experiments"


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


images = load("pci_image_fixtures", HERE / "test-cold-pre-cpu-uki.py")
returns = load("pci_return_fixtures", HERE / "test-cold-pre-cpu-return.py")
builder, auditor = images.builder, images.auditor
dedicated = load("pci_dedicated_return", EXPERIMENTS / "audit-cold-pci-pre-arch-return.py")
reader = dedicated.reader
PCI = builder.PCI


class CombinedToolingTests(unittest.TestCase):
  # Reuse fixture setup only; historical tests run separately unchanged.
  def setUp(self):
    images.ColdPreCpuImageTests.setUp(self)
    self.guard = self.root / "guard.ko"
    self.guard.write_bytes(b"offline synthetic separate PCI guard module")
    self.guard.chmod(0o600)
    self.guard_identity = {"sha256": builder.digest(self.guard), "srcversion": "DEF456",
                           "vermagic": self.identity["vermagic"]}

  def metadata(self, command, **kwargs):
    filename = Path(command[-1]).name
    guard = filename == "guard.ko"
    values = {"name": PCI.PROFILE["guard_module"] if guard else PCI.PROFILE["module"],
              "mba_cold_boundary": "pre-arch-v1", "mba_cold_permanent": "v1",
              **(self.guard_identity if guard else self.identity)}
    return SimpleNamespace(stdout=values[command[2]] + "\n")

  def prepare_combined(self, **changes):
    args = {
      "work": self.root, "module": self.module, "module_sha256": builder.digest(self.module),
      "srcversion": self.identity["srcversion"], "helper": self.helper,
      "helper_sha256": builder.digest(self.helper), "guard": self.guard,
      "guard_sha256": builder.digest(self.guard), "guard_srcversion": self.guard_identity["srcversion"],
      "release": self.release, "restore_marker": self.marker,
    }
    args.update(changes)
    def identity(path):
      return self.guard_identity if path == self.guard else self.identity
    with mock.patch.object(builder, "validate_cold_private_file"), mock.patch.object(builder, "module_metadata", side_effect=identity), mock.patch.object(builder, "run", side_effect=self.metadata):
      return builder.prepare_cold_pci_pre_arch(**args)

  def combined_tree(self):
    prepared = self.prepare_combined()
    tree = self.root / "combined-extracted"
    directory = tree / PCI.PROFILE["directory"]
    directory.mkdir(parents=True)
    for path in prepared["bundle"].iterdir():
      shutil.copyfile(path, directory / path.name)
      (directory / path.name).chmod(path.stat().st_mode & 0o777)
    (tree / "hooks").mkdir()
    for hook in PCI.hooks(PCI.KEY):
      shutil.copyfile(PCI.PROFILE["source"] / "hooks" / hook, tree / "hooks" / hook)
    hook = PCI.PROFILE["hook"]
    (tree / "config").write_text('HOOKS="udev encrypt ' + hook + ' omarchy-t2-restore-marker resume ' + hook + '-return"\n'
                                 'EARLYHOOKS="udev"\nLATEHOOKS="omarchy-t2-candidate-modules"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS=""\n')
    report = {PCI.KEY: prepared["provenance"], "kernel_release": self.release,
              "experiment_id": PCI.PROFILE["version"],
              "restore_marker": {"version": "v2", "efi_variable": prepared["provenance"]["restore_variable"]}}
    return tree, report

  def verify_combined(self, tree, report):
    with mock.patch.object(PCI.subprocess, "run", side_effect=self.metadata):
      auditor.verify_cold_pre_cpu_tree(tree, report)

  def test_combined_exact_two_module_bundle_and_historical_manifests(self):
    for key in builder.COLD.PROFILES:
      self.assertEqual(PCI.sources(key), builder.COLD.sources(key))
      self.assertEqual({name: builder.digest(path) for name, path in PCI.sources(key).items()},
                       {name: builder.digest(path) for name, path in builder.COLD.sources(key).items()})
    tree, report = self.combined_tree()
    self.verify_combined(tree, report)
    self.assertEqual(PCI.select(report), PCI.KEY)
    self.assertEqual(PCI.PROFILE["magic"], b"MBPG")
    self.assertIn("install/bundle", report[PCI.KEY]["source_sha256"])
    self.assertNotIn(builder.COLD.COMMON_DIRECTORY + "functions", report[PCI.KEY]["files_sha256"])

  def test_combined_partial_inputs_marker_and_both_abis_fail_closed(self):
    for missing in ("module", "module_sha256", "srcversion", "helper", "helper_sha256", "guard", "guard_sha256", "guard_srcversion", "restore_marker"):
      with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "together"):
        self.prepare_combined(**{missing: None})
    with self.assertRaisesRegex(ValueError, "V2"):
      self.prepare_combined(restore_marker={"version": "v1"})
    with self.assertRaisesRegex(ValueError, "source version"):
      self.prepare_combined(guard_srcversion="ABC456")
    self.guard_identity["vermagic"] = self.release + " different_flags"
    with self.assertRaisesRegex(ValueError, "identical production ABI"):
      self.prepare_combined()

  def test_combined_source_file_and_metadata_tampering(self):
    tree, report = self.combined_tree()
    for name in report[PCI.KEY]["source_sha256"]:
      bad = copy.deepcopy(report)
      bad[PCI.KEY]["source_sha256"][name] = "0" * 64
      with self.subTest(source=name), self.assertRaises(ValueError):
        self.verify_combined(tree, bad)
    for name in ("guard.ko", "guard.sha256", "guard.srcversion", "abort.ko", "functions", "resume.offset"):
      path = tree / PCI.PROFILE["directory"] / name
      original = path.read_bytes()
      path.write_bytes(b"tampered")
      with self.subTest(file=name), self.assertRaises(ValueError):
        self.verify_combined(tree, report)
      path.write_bytes(original)
    for section, key, value in (("guard_observations", "gate_failed", "Y"), ("guard_observations", "gates", True),
                                 ("boundary_observations", "observed_online_cpus", True)):
      bad = copy.deepcopy(report)
      bad[PCI.KEY][section][key] = value
      with self.subTest(section=section, key=key), self.assertRaisesRegex(ValueError, "observation"):
        self.verify_combined(tree, bad)
    original = self.metadata
    def wrong_name(command, **kwargs):
      if command[2] == "name" and Path(command[-1]).name == "guard.ko":
        return SimpleNamespace(stdout="wrong_guard\n")
      return original(command, **kwargs)
    with mock.patch.object(PCI.subprocess, "run", side_effect=wrong_name), self.assertRaisesRegex(ValueError, "guard.ko:name"):
      auditor.verify_cold_pre_cpu_tree(tree, report)

  def test_combined_module_placement_symlink_mixed_profiles_and_hook_phases(self):
    tree, report = self.combined_tree()
    for key in builder.COLD.PROFILES:
      bad = copy.deepcopy(report)
      bad[key] = {}
      with self.subTest(key=key), self.assertRaisesRegex(ValueError, "mutually exclusive"):
        self.verify_combined(tree, bad)
    with self.assertRaisesRegex(ValueError, "Source image"):
      auditor.audit(report, {})
    with self.assertRaisesRegex(ValueError, "Unannounced"):
      auditor.verify_no_unannounced_cold_tree(tree)
    duplicate = tree / "usr/lib/modules/test/mba_hibernate_cold_pci_guard.ko"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_bytes(self.guard.read_bytes())
    with self.assertRaisesRegex(ValueError, "pending-only"):
      self.verify_combined(tree, report)
    duplicate.unlink()
    directory = tree / PCI.PROFILE["directory"]
    original_dir = directory.with_name(directory.name + "-original")
    directory.rename(original_dir)
    directory.symlink_to(original_dir)
    with self.assertRaisesRegex(ValueError, "symlinked"):
      self.verify_combined(tree, report)
    directory.unlink()
    original_dir.rename(directory)
    config = (tree / "config").read_text()
    for field in ("EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
      changed = config.replace(field + '="', field + '="' + PCI.PROFILE["hook"] + ' ')
      (tree / "config").write_text(changed)
      with self.subTest(field=field), self.assertRaisesRegex(ValueError, "outside synchronous"):
        self.verify_combined(tree, report)
    (tree / "config").write_text(config)

  def test_combined_cli_rejects_incomplete_and_mixed_before_output(self):
    base = ["python3", str(EXPERIMENTS / "build-hibernation-candidate-uki.py"), "--candidate-source", str(self.root),
            "--output", str(self.root / "never-created"), "--cold-pci-pre-arch-guard-module", str(self.guard)]
    for extra in ([], ["--cold-pre-arch-module", str(self.module)]):
      result = subprocess.run(base + extra, capture_output=True, text=True)
      self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
      self.assertFalse((self.root / "never-created").exists())

  def test_combined_actual_config_and_install_use_isolated_bundle(self):
    prepared = self.prepare_combined()
    base = self.root / "base.conf"
    base.write_text("HOOKS=(udev encrypt omarchy-t2-restore-marker resume)\n")
    script = builder.cold_pre_cpu_config(base, PCI.KEY) + '\nprintf "%s\\n" "${HOOKS[*]}"\n'
    configured = subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True)
    self.assertEqual(configured.stdout.strip(), "udev encrypt " + PCI.PROFILE["hook"] +
                     " omarchy-t2-restore-marker resume " + PCI.PROFILE["hook"] + "-return")
    for source in ("omarchy-t2-cold-pre-arch", PCI.PROFILE["hook"]):
      base.write_text("HOOKS=(encrypt " + source + " omarchy-t2-restore-marker resume)\n")
      refused = subprocess.run(["bash", "-c", builder.cold_pre_cpu_config(base, PCI.KEY)], capture_output=True)
      self.assertEqual(refused.returncode, 1)
    script = r'''
add_file() { printf '%s\n' "$2"; }
add_binary() { printf '%s\n' "$2"; }
add_runscript() { :; }
. "$1"
build
'''
    installed = subprocess.run(["bash", "-c", script, "bash", str(PCI.PROFILE["source"] / "install" / PCI.PROFILE["hook"])],
                               check=True, capture_output=True, text=True,
                               env={"OMARCHY_T2_COLD_PCI_ABORT_BUNDLE": str(prepared["bundle"])})
    self.assertEqual(set(installed.stdout.splitlines()), {"/" + PCI.PROFILE["directory"] + name for name in PCI.BUNDLE_FILES})

  def test_combined_exact_return_witness_and_cross_profile_refusals(self):
    _, image_report = self.combined_tree()
    fixture = returns.ReturnAuditTests()
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    fixture.pair.pop("cold_pre_cpu")
    fixture.pair.update(image_report)
    fixture.pair["restore_marker"].update(sha256="1" * 64, srcversion="ABC123")
    fixture.images["restore"]["experiment_id"] = PCI.PROFILE["version"]
    fixture.receipt["images"]["restore"]["experiment_id"] = PCI.PROFILE["version"]
    fixture.write_json(reader.PAIR.RECEIPT, fixture.receipt)
    fixture.attempted(returned=False)
    witness = reader.EFI / (PCI.PROFILE["returned"] + fixture.vector[:24] + "-" + reader.GUID)
    fixture.write(witness, reader.ATTRIBUTES + b"MBPG" + fixture.vector[:24].encode() + b"\1")
    def inspect():
      return reader.inspect(fixture.root, self.root / "source", self.root / "restore", fixture.vector,
                            pair_loader=lambda *_: (copy.deepcopy(fixture.pair), copy.deepcopy(fixture.images), {}),
                            staged_verifier=lambda *_: None, required_protocol=PCI.KEY)
    before = fixture.state()
    report = inspect()
    self.assertEqual(fixture.state(), before)
    self.assertEqual(report["classification"], "controlled-abort-return")
    self.assertEqual(report["witness_attested_guard_observations"], PCI.PROFILE["guard_observations"])
    self.assertFalse(report["hibernate_success"])
    self.assertFalse(report["physical_dma_inactivity_proven"])
    for key, profile in builder.COLD.PROFILES.items():
      conflicting = reader.EFI / (profile["returned"] + fixture.vector[:24] + "-" + reader.GUID)
      fixture.write(conflicting, reader.ATTRIBUTES + profile["magic"] + fixture.vector[:24].encode() + b"\1")
      with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Cross-protocol"):
        inspect()
      (fixture.root / conflicting).unlink()
    fixture.pair[PCI.KEY]["guard_observations"]["gate_failed"] = "Y"
    with self.assertRaisesRegex(ValueError, "Guard observation"):
      inspect()


if __name__ == "__main__":
  unittest.main()
