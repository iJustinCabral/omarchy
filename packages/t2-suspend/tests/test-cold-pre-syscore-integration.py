#!/usr/bin/python3
"""Exact two-protocol image/runtime/returned-proof fixtures; no host PM."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
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


images = load("syscore_image_fixtures", HERE / "test-cold-pre-cpu-uki.py")
returns = load("syscore_return_fixtures", HERE / "test-cold-pre-cpu-return.py")
builder, auditor, reader = images.builder, images.auditor, returns.audit
PROFILE = builder.COLD.PROFILES["cold_pre_syscore"]


class SyscoreIntegrationTests(unittest.TestCase):
  def test_busybox_ordinary_gate_reports_fixed_refusal_reasons_for_both_protocols(self):
    busybox = "/usr/lib/initcpio/busybox"
    self.assertTrue(Path(busybox).is_file())
    cases = {
      "normal": None,
      "selector-missing": "protocol-selector",
      "variable-missing": "restore-variable-file",
      "variable-wrong": "restore-variable-identity",
      "ftrace-missing": "ftrace-read",
      "ftrace-empty": "ftrace-read",
      "ftrace-disabled": "ftrace-disabled",
      "bad-order": "hook-order",
      "offset-missing": "resume-offset-read",
      "offset-wrong": "resume-offset-mismatch",
      "cmdline-missing": "commandline-read",
      "cmdline-wrong": "commandline-resume",
      "reader-fails": "header-reader-execution",
      "reader-hash-wrong": "header-reader-hash",
      "reader-unknown": "header-reader-result",
      "pending-no-marker": "ordinary-header",
      "ordinary-residue": "ordinary-residue",
    }
    script = r'''
err() { printf '%s\n' "$*"; }
plymouth() { return 0; }
launch_interactive_shell() { exit 81; }
insmod() { printf 'UNEXPECTED INSMOD\n'; exit 90; }
. "$OMARCHY_T2_COLD_PRE_CPU_ROOT/config"
. "$1"
run_hook
'''
    for protocol, profile in builder.COLD.PROFILES.items():
      for mode, expected in cases.items():
        with self.subTest(protocol=protocol, mode=mode), tempfile.TemporaryDirectory(prefix="cold-gate-reason-") as temporary:
          root = Path(temporary)
          common = root / builder.COLD.COMMON_DIRECTORY
          directory = root / profile["directory"]
          common.mkdir(parents=True)
          directory.mkdir(parents=True)
          (common / "functions").write_bytes((EXPERIMENTS / "hibernate-cold-common/functions").read_bytes())
          (common / "protocol").write_text(profile["version"] + "\n")
          (directory / "functions").write_bytes((profile["source"] / "functions").read_bytes())
          (directory / "restore.variable").write_text("OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27\n")
          for name, value in (("resume.device", "/dev/mapper/root"), ("resume.offset", "1923214"), ("resume.devnum", "253:0")):
            (directory / name).write_text(value + "\n")
          (root / "proc/sys/kernel").mkdir(parents=True)
          (root / "proc/sys/kernel/ftrace_enabled").write_text("1\n")
          (root / "proc/cmdline").write_text("quiet resume=/dev/mapper/root resume_offset=1923214\n")
          (root / "sys/power").mkdir(parents=True)
          (root / "sys/power/resume_offset").write_text("1923214\n")
          (root / "run").mkdir()
          hook = profile["hook"]
          # Exact resolved arrays from the published ordinary v10 image.
          (root / "config").write_text('HOOKS="udev keymap consolefont encrypt ' + hook + ' omarchy-t2-restore-marker resume ' + hook + '-return"\nEARLYHOOKS="udev"\nLATEHOOKS="btrfs-overlayfs omarchy-t2-candidate-modules"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS=""\n')
          reader = directory / "header-reader"
          reader.write_text("#!/bin/sh\nprintf 'NORMAL\\n'\n")
          if mode == "reader-fails":
            reader.write_text("#!/bin/sh\nexit 3\n")
          elif mode in ("reader-unknown", "pending-no-marker"):
            reader.write_text("#!/bin/sh\nprintf '" + ("UNKNOWN" if mode == "reader-unknown" else "PENDING") + "\\n'\n")
          reader.chmod(0o700)
          (directory / "header-reader.sha256").write_text(hashlib.sha256(reader.read_bytes()).hexdigest() + "\n")
          if mode == "selector-missing":
            (common / "protocol").unlink()
          elif mode == "variable-missing":
            (directory / "restore.variable").unlink()
          elif mode == "variable-wrong":
            (directory / "restore.variable").write_text("wrong\n")
          elif mode == "ftrace-missing":
            (root / "proc/sys/kernel/ftrace_enabled").unlink()
          elif mode == "ftrace-empty":
            (root / "proc/sys/kernel/ftrace_enabled").write_text("")
          elif mode == "ftrace-disabled":
            (root / "proc/sys/kernel/ftrace_enabled").write_text("0\n")
          elif mode == "bad-order":
            (root / "config").write_text('HOOKS="encrypt resume"\n')
          elif mode == "offset-missing":
            (root / "sys/power/resume_offset").unlink()
          elif mode == "offset-wrong":
            (root / "sys/power/resume_offset").write_text("0\n")
          elif mode == "cmdline-missing":
            (root / "proc/cmdline").unlink()
          elif mode == "cmdline-wrong":
            (root / "proc/cmdline").write_text("quiet resume=/dev/other resume_offset=1923214\n")
          elif mode == "ordinary-residue":
            (root / "run" / (hook + ".intent")).write_text("private-value-never-printed\n")
          elif mode == "reader-hash-wrong":
            (directory / "header-reader.sha256").write_text("0" * 64 + "\n")
          result = subprocess.run([busybox, "ash", "-c", script, "ash", str(profile["source"] / "hooks" / hook)],
                                  capture_output=True, text=True,
                                  env={"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root)})
          if expected is None:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
          else:
            self.assertEqual(result.returncode, 81, result.stdout + result.stderr)
            self.assertIn("(" + expected + ")", result.stdout)
          self.assertNotIn("UNEXPECTED INSMOD", result.stdout)
          self.assertNotIn("private-value-never-printed", result.stdout + result.stderr)

  def image_fixture(self):
    fixture = images.ColdPreCpuImageTests()
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    return fixture

  def test_exact_syscore_image_and_module_boundary_are_audited(self):
    fixture = self.image_fixture()
    tree, report = fixture.extracted("cold_pre_syscore")
    fixture.verify(tree, report)
    self.assertEqual(report["cold_pre_syscore"]["target"], "syscore_suspend")
    self.assertEqual(report["cold_pre_syscore"]["boundary_observations"], PROFILE["observations"])
    with mock.patch.object(auditor.subprocess, "run", return_value=SimpleNamespace(stdout="wrong\n")):
      with self.assertRaisesRegex(ValueError, "module metadata"):
        auditor.verify_cold_pre_cpu_tree(tree, report)
    with mock.patch.object(builder, "validate_cold_private_file"), mock.patch.object(builder, "module_metadata", return_value=fixture.identity):
      def wrong_tag(command, **kwargs):
        value = {"name": PROFILE["module"], "mba_cold_permanent": "v1", "mba_cold_boundary": "wrong"}[command[2]]
        return SimpleNamespace(stdout=value + "\n")
      with mock.patch.object(builder, "run", side_effect=wrong_tag), self.assertRaisesRegex(ValueError, "boundary metadata"):
        builder.prepare_cold_pre_cpu(fixture.root, fixture.module, builder.digest(fixture.module), "ABC123", fixture.helper,
                                    builder.digest(fixture.helper), fixture.release, fixture.marker, protocol="cold_pre_syscore")

  def test_both_compiled_modules_require_permanent_attestation(self):
    for protocol, profile in builder.COLD.PROFILES.items():
      with self.subTest(protocol=protocol):
        fixture = self.image_fixture()
        tree, report = fixture.extracted(protocol)
        def old_binary(command, **kwargs):
          values = {"name": profile["module"], "mba_cold_boundary": profile["boundary"], "mba_cold_permanent": "", **fixture.identity}
          return SimpleNamespace(stdout=values[command[2]] + "\n")
        with mock.patch.object(auditor.subprocess, "run", side_effect=old_binary), self.assertRaisesRegex(ValueError, "mba_cold_permanent"):
          auditor.verify_cold_pre_cpu_tree(tree, report)
        with mock.patch.object(builder, "validate_cold_private_file"), mock.patch.object(builder, "module_metadata", return_value=fixture.identity), mock.patch.object(builder, "run", side_effect=old_binary):
          with self.assertRaisesRegex(ValueError, "permanent-ftrace attestation"):
            builder.prepare_cold_pre_cpu(fixture.root, fixture.module, builder.digest(fixture.module), "ABC123", fixture.helper,
                                        builder.digest(fixture.helper), fixture.release, fixture.marker, protocol=protocol)

  def test_dual_protocol_wrong_experiment_target_observations_and_common_pins_refused(self):
    fixture = self.image_fixture()
    tree, report = fixture.extracted("cold_pre_syscore")
    faults = [copy.deepcopy(report) for _ in range(5)]
    faults[0]["cold_pre_cpu"] = copy.deepcopy(report["cold_pre_syscore"])
    faults[1]["experiment_id"] = "cold-pre-cpu-abort-v1"
    faults[2]["cold_pre_syscore"]["target"] = "hibernate_resume_nonboot_cpu_disable"
    faults[3]["cold_pre_syscore"]["boundary_observations"]["observed_online_cpus"] = 2
    faults[4]["cold_pre_syscore"]["source_sha256"]["common/functions"] = "0" * 64
    for fault in faults:
      with self.subTest(fault=fault), self.assertRaises(ValueError):
        fixture.verify(tree, fault)
    for relative in (builder.COLD.COMMON_DIRECTORY + "protocol", builder.COLD.COMMON_DIRECTORY + "functions", "hooks/resume"):
      path = tree / relative
      original = path.read_bytes()
      path.write_bytes(b"changed")
      with self.subTest(relative=relative), self.assertRaises(ValueError):
        fixture.verify(tree, report)
      path.write_bytes(original)
    with self.assertRaisesRegex(ValueError, "Source image"):
      auditor.audit(report, {})
    for malformed in (None, [], "wrong"):
      with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, "metadata"):
        auditor.validate_cold_pre_cpu_metadata({**report, "cold_pre_syscore": malformed})
    bad = copy.deepcopy(report)
    bad["cold_pre_syscore"]["boundary_observations"]["observed_online_cpus"] = True
    with self.assertRaisesRegex(ValueError, "observation"):
      fixture.verify(tree, bad)

  def test_actual_mkinitcpio_runscript_uses_adapter_caller_not_shared_helper(self):
    actual = re.search(r"add_runscript\(\) \{\n.*?\n\}", Path("/usr/lib/initcpio/functions").read_text(), re.S).group(0)
    for protocol in builder.COLD.PROFILES:
      with self.subTest(protocol=protocol):
        fixture = self.image_fixture()
        tree, _ = fixture.extracted(protocol)
        prepared_bundle = next(fixture.root.glob("*-bundle"))
        profile = builder.COLD.PROFILES[protocol]
        for path in (tree / "hooks").iterdir():
          path.chmod(0o700)
        script = r'''
declare -A _runhooks
add_file() { printf 'file %s\n' "$2"; }
add_binary() { printf 'binary %s\n' "$2"; }
funcgrep() { printf 'run_hook\n'; }
error() { printf 'ERROR %s\n' "$*"; return 1; }
'''
        script += actual + '\n. "$1"\nbuild\nprintf "hooks %s\\n" "${_runhooks[hooks]}"\n'
        result = subprocess.run(["bash", "-e", "-c", script, "bash", str(profile["source"] / "install" / profile["hook"])],
                                capture_output=True, text=True,
                                env={"PATH": os.environ["PATH"], "_d_hooks": str(tree / "hooks"), "OMARCHY_T2_COLD_ABORT_BUNDLE": str(prepared_bundle)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("binary /hooks/" + profile["hook"], result.stdout)
        self.assertIn("hooks  " + profile["hook"], result.stdout)
        self.assertNotIn("/hooks/bundle", result.stdout)

  def test_other_protocol_tree_and_hooks_are_forbidden(self):
    fixture = self.image_fixture()
    tree, report = fixture.extracted("cold_pre_syscore")
    for relative in ("hooks/omarchy-t2-cold-pre-cpu", "usr/lib/omarchy-t2-cold-pre-cpu/functions",
                     "usr/lib/modules/test/mba_hibernate_cold_pre_cpu.ko.zst"):
      path = tree / relative
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(b"unannounced")
      with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "Unannounced"):
        fixture.verify(tree, report)
      path.unlink()
      if "cold-pre-cpu/functions" in relative:
        path.parent.rmdir()
    config = (tree / "config").read_text()
    for field in ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
      (tree / "config").write_text(config.replace(field + '="', field + '="omarchy-t2-cold-pre-cpu ', 1))
      with self.subTest(field=field), self.assertRaises(ValueError):
        fixture.verify(tree, report)
    (tree / "config").write_text(config)

  def test_partial_or_dual_cli_is_refused_without_build(self):
    fixture = self.image_fixture()
    base = ["python3", str(EXPERIMENTS / "build-hibernation-candidate-uki.py"), "--candidate-source", str(fixture.root),
            "--output", str(fixture.root / "never-created")]
    for flags in (["--cold-pre-syscore-module", str(fixture.module)],
                  ["--cold-pre-syscore-module", str(fixture.module), "--cold-pre-cpu-module", str(fixture.module)]):
      result = subprocess.run(base + flags, capture_output=True, text=True)
      self.assertEqual(result.returncode, 2)
      self.assertFalse((fixture.root / "never-created").exists())

  def return_fixture(self):
    fixture = returns.ReturnAuditTests()
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    fixture.pair["cold_pre_syscore"] = fixture.pair.pop("cold_pre_cpu")
    fixture.pair["cold_pre_syscore"].update(version=PROFILE["version"], target=PROFILE["target"], boundary_observations=PROFILE["observations"].copy())
    fixture.images["restore"]["experiment_id"] = PROFILE["version"]
    fixture.receipt["images"]["restore"]["experiment_id"] = PROFILE["version"]
    fixture.write_json(reader.PAIR.RECEIPT, fixture.receipt)
    return fixture

  def returned(self, fixture):
    fixture.attempted()
    old = fixture.root / fixture.marker_path("returned")
    raw = old.read_bytes()
    old.unlink()
    path = reader.EFI / (PROFILE["returned"] + fixture.vector[:24] + "-" + reader.GUID)
    fixture.write(path, raw[:4] + PROFILE["magic"] + raw[8:])
    return path

  def inspect_return(self, fixture, protocol="cold_pre_syscore"):
    before = fixture.state()
    try:
      return reader.inspect(fixture.root, fixture.root, fixture.root, fixture.vector,
                            pair_loader=lambda *_: (copy.deepcopy(fixture.pair), copy.deepcopy(fixture.images), {}),
                            staged_verifier=lambda *_: None, required_protocol=protocol)
    finally:
      self.assertEqual(fixture.state(), before)

  def test_distinct_syscore_reader_proof_is_not_syscore_or_atomic_completion(self):
    fixture = self.return_fixture()
    self.returned(fixture)
    report = self.inspect_return(fixture)
    self.assertEqual(report["classification"], "controlled-abort-return")
    self.assertEqual(report["protocol"], PROFILE["version"])
    self.assertEqual(report["boundary"], "syscore_suspend")
    self.assertEqual(report["witness_attested_observations"], PROFILE["observations"])
    self.assertFalse(report["hibernate_success"])
    self.assertFalse(report["restored_userspace"])
    self.assertIn("not restored source userspace or completion of target body", report["controlled_return_semantics"])
    with self.assertRaisesRegex(ValueError, "requested cold abort protocol"):
      self.inspect_return(fixture, "cold_pre_cpu")

  def test_return_missing_cross_protocol_and_wrong_magic_are_distinct(self):
    fixture = self.return_fixture()
    path = self.returned(fixture)
    raw = (fixture.root / path).read_bytes()
    (fixture.root / path).unlink()
    self.assertEqual(self.inspect_return(fixture)["classification"], "return-witness-missing")
    fixture.write_marker("returned")
    with self.assertRaisesRegex(ValueError, "Cross-protocol"):
      self.inspect_return(fixture)
    (fixture.root / fixture.marker_path("returned")).unlink()
    fixture.write(path, raw[:4] + b"MBCP" + raw[8:])
    with self.assertRaisesRegex(ValueError, "Malformed EFI"):
      self.inspect_return(fixture)

  def test_all_new_and_existing_runtime_files_parse_in_actual_busybox(self):
    paths = [builder.COLD.COMMON / "functions", builder.COLD.COMMON / "hooks/resume"]
    for profile in builder.COLD.PROFILES.values():
      paths.extend([profile["source"] / "functions", profile["source"] / "hooks" / profile["hook"],
                    profile["source"] / "hooks" / (profile["hook"] + "-return")])
    for path in paths:
      result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-n", str(path)], capture_output=True, text=True)
      self.assertEqual(result.returncode, 0, str(path) + result.stderr)

  def test_actual_quiet_dispatch_stock_resume_and_syscore_observations(self):
    # Source the real dispatcher/stock resume; only absolute paths are
    # relocated. Module insertion and the sysfs trigger are explicit mocks.
    dispatch = re.search(r"run_hookfunctions\(\) \{\n.*?\n\}", Path("/usr/lib/initcpio/init_functions").read_text(), re.S).group(0)
    dispatch = dispatch.replace('"/hooks/$hook"', '"$MOCK_HOOKS/$hook"')
    stock = Path("/usr/lib/initcpio/hooks/resume").read_text().replace("/sys/power/resume", "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/power/resume").replace(
      "/usr/lib/systemd/systemd-hibernate-resume", "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/systemd/systemd-hibernate-resume")
    driver = r'''
. /usr/lib/initcpio/init_functions
getarg() { case $1 in quiet) command printf 'y\n' ;; resume) command printf '/dev/mapper/root\n' ;; esac; return 0; }
err() { command printf 'ERROR: %s\n' "$*"; }
plymouth() { return 0; }
launch_interactive_shell() { command printf 'STOP\n'; exit 81; }
resolve_device() { [[ $1 == "/dev/mapper/root" ]] || exit 91; command printf '%s/dev/mapper/root\n' "$OMARCHY_T2_COLD_PRE_CPU_ROOT"; }
stat() { [[ "$1" == "-Lc" && "$2" == "0x%t 0x%T" ]] || exit 92; command printf '0xfd 0x0\n'; }
insmod() {
  local module
  case $1 in
    "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/omarchy-t2-cold-pre-syscore/abort.ko")
      module=$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/mba_hibernate_cold_pre_syscore
      mkdir -p "$module/parameters"
      command printf 'SRC\n' > "$module/srcversion"
      command printf '0\n' > "$module/parameters/arm_prefix"
      command printf 'N\n' > "$module/parameters/arm_consumed"
      command printf '0\n' > "$module/parameters/interceptions"
      command printf 'N\n' > "$module/parameters/observed_irqs_disabled"
      command printf '0\n' > "$module/parameters/observed_online_cpus"
      command printf 'N\n' > "$module/parameters/observed_boundary_valid"
      cold_write_arm() {
        command printf '1\n' > "$cold_sys/parameters/arm_prefix"
        command printf 'Y\n' > "$cold_sys/parameters/arm_consumed"
        command printf '%s\n' "$cold_prefix" > "$cold_sys/parameters/vector_prefix"
      }
      ;;
    "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/omarchy-t2-restore-marker/marker.ko")
      module=$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/mba_hibernate_efi_restore_marker
      mkdir -p "$module/parameters"
      command printf 'SRC\n' > "$module/srcversion"
      command printf '0\n' > "$module/parameters/arm_prefix"
      command printf '0\n' > "$module/parameters/stage"
      write_restore_arm_prefix() { command printf '1\n' > "$2"; }
      ;;
    *) exit 93 ;;
  esac
}
printf() {
  if [[ $1 == "%d:%d" ]]; then
    [[ "$2" == "0xfd" && "$3" == "0x0" ]] || exit 94
    command printf 'RESUME\n' >> "$cold_root/order"
    if [[ -e $cold_intent ]]; then
      command printf '0\n' > "$cold_sys/parameters/arm_prefix"
      command printf '1\n' > "$cold_sys/parameters/interceptions"
      command printf 'Y\n' > "$cold_sys/parameters/observed_irqs_disabled"
      command printf '1\n' > "$cold_sys/parameters/observed_online_cpus"
      command printf 'Y\n' > "$cold_sys/parameters/observed_boundary_valid"
      command printf '\007\000\000\000MBRS\001\043\105\147\211\253\315\357\001\043\105\147\007' > "$cold_marker"
      case $MOCK in
        irq-enabled) command printf 'N\n' > "$cold_sys/parameters/observed_irqs_disabled" ;;
        multi-cpu) command printf '2\n' > "$cold_sys/parameters/observed_online_cpus" ;;
        invalid-boundary) command printf 'N\n' > "$cold_sys/parameters/observed_boundary_valid" ;;
        missing-observation) rm "$cold_sys/parameters/observed_online_cpus" ;;
        no-interception) command printf '0\n' > "$cold_sys/parameters/interceptions" ;;
        ftrace-lost) command printf '0\n' > "$cold_root/proc/sys/kernel/ftrace_enabled" ;;
        cross-return) command printf '\007\000\000\000MBCP%s\001' "$cold_prefix" > "$cold_vars/OmarchyT2ColdPreCpuReturned${cold_prefix}-$cold_guid" ;;
      esac
    fi
    command printf 'NORMAL\n' > "$cold_root/header-state"
    [[ $MOCK != "pending-after-return" ]] || command printf 'PENDING\n' > "$cold_root/header-state"
  fi
  command printf "$@"
}
'''
    driver += dispatch + '\nrun_hookfunctions run_hook hook $HOOKS\n'
    modes = ("success", "ordinary", "irq-enabled", "multi-cpu", "invalid-boundary", "missing-observation",
             "no-interception", "pending-after-return", "ftrace-disabled", "ftrace-lost", "other-module", "cross-return", "other-hook")
    with tempfile.TemporaryDirectory(prefix="syscore-runtime-test-") as temporary:
      for mode in modes:
        with self.subTest(mode=mode):
          root = Path(temporary) / mode
          def write(name, value, executable=False):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else value.encode())
            if executable:
              path.chmod(0o700)
            return path
          common = builder.COLD.COMMON_DIRECTORY
          directory = PROFILE["directory"]
          write(common + "functions", (builder.COLD.COMMON / "functions").read_bytes())
          write(common + "protocol", PROFILE["version"] + "\n")
          write(directory + "functions", (PROFILE["source"] / "functions").read_bytes())
          write(directory + "abort.ko", b"explicit synthetic module")
          write(directory + "abort.sha256", hashlib.sha256(b"explicit synthetic module").hexdigest() + "\n")
          write(directory + "abort.srcversion", "SRC\n")
          write(directory + "restore.variable", reader.RESTORE_VARIABLE + "\n")
          for name, value in (("resume.device", "/dev/mapper/root"), ("resume.offset", "1923214"), ("resume.devnum", "253:0")):
            write(directory + name, value + "\n")
          helper = write(directory + "header-reader", '#!/bin/bash\nread -r value < "$OMARCHY_T2_COLD_PRE_CPU_ROOT/header-state"\nprintf "%s\\n" "$value"\n', True)
          write(directory + "header-reader.sha256", hashlib.sha256(helper.read_bytes()).hexdigest() + "\n")
          write(directory + "stock-resume", stock)
          write(directory + "stock-resume.sha256", hashlib.sha256(stock.encode()).hexdigest() + "\n")
          write("proc/cmdline", "quiet resume=/dev/mapper/root resume_offset=1923214\n")
          write("proc/sys/kernel/ftrace_enabled", "0\n" if mode == "ftrace-disabled" else "1\n")
          write("sys/power/resume_offset", "1923214\n")
          write("sys/power/resume", "0:0\n")
          write("dev/mapper/root", b"fixture not a real block device")
          write("header-state", "NORMAL\n" if mode == "ordinary" else "PENDING\n")
          (root / "run").mkdir()
          (root / reader.EFI).mkdir(parents=True)
          if mode != "ordinary":
            write(str(reader.EFI / reader.RESTORE_VARIABLE), reader.ATTRIBUTES + b"MBRS" + bytes.fromhex("0123456789abcdef01234567") + b"\0")
          marker_dir = "usr/lib/omarchy-t2-restore-marker/"
          write(marker_dir + "marker.ko", b"synthetic restore marker")
          write(marker_dir + "marker.sha256", hashlib.sha256(b"synthetic restore marker").hexdigest() + "\n")
          write(marker_dir + "marker.srcversion", "SRC\n")
          write(marker_dir + "marker.version", "v2\n")
          for hook in builder.COLD.hooks("cold_pre_syscore"):
            source = builder.COLD.COMMON if hook == "resume" else PROFILE["source"]
            write("hooks/" + hook, (source / "hooks" / hook).read_bytes(), True)
          write("hooks/omarchy-t2-restore-marker", (EXPERIMENTS / "hibernate-candidate-initcpio/hooks/omarchy-t2-restore-marker").read_bytes(), True)
          if mode == "other-module":
            (root / "sys/module/mba_hibernate_cold_pre_cpu").mkdir(parents=True)
          chain = "encrypt " + PROFILE["hook"] + " omarchy-t2-restore-marker resume " + PROFILE["hook"] + "-return"
          if mode == "other-hook":
            chain = "omarchy-t2-cold-pre-cpu " + chain
          result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-c", driver, "ash"], capture_output=True, text=True,
                                  env={"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root), "OMARCHY_T2_RESTORE_MARKER_ROOT": str(root),
                                       "MOCK_HOOKS": str(root / "hooks"),
                                       "MOCK": mode, "HOOKS": chain})
          witness = root / reader.EFI / (PROFILE["returned"] + "0123456789abcdef01234567-" + reader.GUID)
          if mode == "ordinary":
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(witness.exists())
          else:
            self.assertEqual(result.returncode, 81, result.stdout + result.stderr)
            self.assertIn("STOP", result.stdout)
            if mode == "success":
              self.assertTrue(witness.exists(), result.stdout + result.stderr)
              self.assertEqual(witness.read_bytes(), reader.ATTRIBUTES + b"MBSC0123456789abcdef01234567\1")
              self.assertEqual(result.stderr, "")
              self.assertIn("controlled abort returned and EFI witness verified", result.stdout)
            else:
              self.assertFalse(witness.exists(), result.stdout + result.stderr)


if __name__ == "__main__":
  unittest.main()
