#!/usr/bin/python3
"""Three closed cold protocols; actual shell dispatch and read-only evidence."""
import copy
import itertools
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import runpy
from types import SimpleNamespace

import importlib.util

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cold_closed_integration", HERE / "test-cold-pre-syscore-integration.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
builder, auditor, reader = integration.builder, integration.auditor, integration.reader
PROFILES = builder.COLD.PROFILES


class PreArchIntegrationTests(unittest.TestCase):
  # Reuse helpers without rerunning the existing tests; their actual BusyBox
  # ordinary/refusal/sysctl and permanent-attestation loops cover all profiles.
  image_fixture = integration.SyscoreIntegrationTests.image_fixture
  return_fixture = integration.SyscoreIntegrationTests.return_fixture
  inspect_return = integration.SyscoreIntegrationTests.inspect_return
  runtime_dispatch = integration.SyscoreIntegrationTests.runtime_dispatch
  def test_exact_pre_arch_contract(self):
    profile = PROFILES["cold_pre_arch"]
    self.assertEqual((profile["version"], profile["target"], profile["module"], profile["boundary"], profile["magic"], profile["returned"]),
                     ("cold-pre-arch-abort-v1", "swsusp_arch_resume", "mba_hibernate_cold_pre_arch", "pre-arch-v1", b"MBAR", "OmarchyT2ColdPreArchReturned"))
    self.assertEqual(profile["observations"], {"observed_irqs_disabled": "Y", "observed_online_cpus": 1, "observed_boundary_valid": "Y"})
    fixture = self.image_fixture()
    tree, report = fixture.extracted("cold_pre_arch")
    fixture.verify(tree, report)
    self.assertEqual(builder.COLD.select(report), "cold_pre_arch")
    self.assertEqual(report["cold_pre_arch"]["target"], "swsusp_arch_resume")
    for source, pin in report["cold_pre_arch"]["source_sha256"].items():
      bad = copy.deepcopy(report)
      bad["cold_pre_arch"]["source_sha256"][source] = "0" * 64
      with self.subTest(source=source), self.assertRaises(ValueError):
        fixture.verify(tree, bad)

  def test_every_pair_of_profiles_rejects_mixed_metadata_cli_and_bundle(self):
    for selected, other in itertools.permutations(PROFILES, 2):
      with self.subTest(selected=selected, other=other):
        fixture = self.image_fixture()
        tree, report = fixture.extracted(selected)
        bad = copy.deepcopy(report)
        bad[other] = copy.deepcopy(report[selected])
        with self.assertRaises(ValueError):
          fixture.verify(tree, bad)
        base = ["python3", str(integration.EXPERIMENTS / "build-hibernation-candidate-uki.py"), "--candidate-source", str(fixture.root),
                "--output", str(fixture.root / "never-created")]
        selected_flag = "--" + selected.replace("_", "-") + "-module"
        other_flag = "--" + other.replace("_", "-") + "-module"
        for flags in ([selected_flag, str(fixture.module)], [selected_flag, str(fixture.module), other_flag, str(fixture.module)]):
          result = subprocess.run(base + flags, capture_output=True, text=True)
          self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
          self.assertFalse((fixture.root / "never-created").exists())
        profile = PROFILES[other]
        for relative in ("hooks/" + profile["hook"], profile["directory"] + "functions",
                         "usr/lib/modules/test/" + profile["module"] + ".ko.zst"):
          path = tree / relative
          path.parent.mkdir(parents=True, exist_ok=True)
          path.write_bytes(b"unannounced")
          with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "Unannounced"):
            fixture.verify(tree, report)
          path.unlink()
          if relative == profile["directory"] + "functions":
            path.parent.rmdir()

  def protocol_return_fixture(self, protocol):
    fixture = self.return_fixture()
    profile = PROFILES[protocol]
    fixture.pair[protocol] = fixture.pair.pop("cold_pre_syscore")
    fixture.pair[protocol].update(version=profile["version"], target=profile["target"])
    if profile["observations"]:
      fixture.pair[protocol]["boundary_observations"] = profile["observations"].copy()
    else:
      fixture.pair[protocol].pop("boundary_observations", None)
    fixture.images["restore"]["experiment_id"] = profile["version"]
    fixture.receipt["images"]["restore"]["experiment_id"] = profile["version"]
    fixture.write_json(reader.PAIR.RECEIPT, fixture.receipt)
    fixture.attempted(returned=False)
    path = reader.EFI / (profile["returned"] + fixture.vector[:24] + "-" + reader.GUID)
    fixture.write(path, reader.ATTRIBUTES + profile["magic"] + fixture.vector[:24].encode() + b"\1")
    return fixture, path

  def test_all_return_protocol_pairs_reject_conflicting_witnesses(self):
    for selected, other in itertools.permutations(PROFILES, 2):
      with self.subTest(selected=selected, other=other):
        fixture, _ = self.protocol_return_fixture(selected)
        report = self.inspect_return(fixture, selected)
        self.assertFalse(report["hibernate_success"])
        self.assertFalse(report["restored_userspace"])
        self.assertFalse(report["hardware_qualified"])
        self.assertEqual(report["boundary"], PROFILES[selected]["target"])
        profile = PROFILES[other]
        fixture.write(reader.EFI / (profile["returned"] + fixture.vector[:24] + "-" + reader.GUID),
                      reader.ATTRIBUTES + profile["magic"] + fixture.vector[:24].encode() + b"\1")
        with self.assertRaisesRegex(ValueError, "Cross-protocol"):
          self.inspect_return(fixture, selected)

  def test_dedicated_pre_arch_reader_requires_its_own_protocol(self):
    dedicated = integration.load("pre_arch_return_reader", integration.EXPERIMENTS / "audit-cold-pre-arch-return.py")
    fixture, path = self.protocol_return_fixture("cold_pre_arch")
    report = self.inspect_return(fixture, "cold_pre_arch")
    self.assertEqual(report["classification"], "controlled-abort-return")
    self.assertEqual(report["witness_attested_observations"], PROFILES["cold_pre_arch"]["observations"])
    self.assertIn("not restored source userspace or completion of target body", report["controlled_return_semantics"])
    with mock.patch.object(dedicated.reader, "main") as main:
      # Execute the adapter's actual __main__ block while substituting its
      # shared reader: this cannot reach any host evidence or PM interface.
      fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
      with mock.patch.object(importlib.util, "spec_from_file_location", return_value=fake_spec), mock.patch.object(importlib.util, "module_from_spec", return_value=dedicated.reader):
        runpy.run_path(dedicated.__file__, run_name="__main__")
      main.assert_called_once_with(required_protocol="cold_pre_arch")
    raw = (fixture.root / path).read_bytes()
    fixture.write(path, raw[:4] + b"MBSC" + raw[8:])
    with self.assertRaisesRegex(ValueError, "Malformed EFI"):
      self.inspect_return(fixture, "cold_pre_arch")

  def test_actual_quiet_runtime_rejects_both_opposite_profiles(self):
    for selected in PROFILES:
      for other in PROFILES:
        if selected != other:
          with self.subTest(selected=selected, other=other):
            self.runtime_dispatch(PROFILES[selected], PROFILES[other])

  def test_actual_busybox_rejects_every_loaded_module_and_hook_phase_conflict(self):
    import tempfile
    import os
    for selected, other in itertools.permutations(PROFILES, 2):
      profile, opposite = PROFILES[selected], PROFILES[other]
      for fault in ("module", "HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
        with self.subTest(selected=selected, other=other, fault=fault), tempfile.TemporaryDirectory(prefix="cold-cross-phase-") as temporary:
          root = Path(temporary)
          selector = root / builder.COLD.COMMON_DIRECTORY / "protocol"
          selector.parent.mkdir(parents=True)
          selector.write_text(profile["version"] + "\n")
          if fault == "module":
            (root / "sys/module" / opposite["module"]).mkdir(parents=True)
          env = {"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root),
                 "HOOKS": "encrypt " + profile["hook"] + " omarchy-t2-restore-marker resume " + profile["hook"] + "-return"}
          if fault != "module":
            env[fault] = opposite["hook"] + " " + env.get(fault, "")
          script = '. "$1"\ncold_select_protocol && cold_hook_order\n'
          result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-c", script, "ash", str(builder.COLD.COMMON / "functions")],
                                  capture_output=True, text=True, env=env)
          self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
  unittest.main()
