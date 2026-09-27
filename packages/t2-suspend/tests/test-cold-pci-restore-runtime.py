#!/usr/bin/python3
"""Actual BusyBox hook dispatch over fake sysfs/EFI; no host PM or PCI access."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

EXPERIMENT = Path(__file__).resolve().parents[1] / "experiments/hibernate-cold-pci-restore"
BUSYBOX = Path("/usr/lib/initcpio/busybox")
PREFIX = "9c973c61402167014599b656"
GUID = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"


class RuntimeTests(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.bundle = self.root / "usr/lib/omarchy-t2-cold-pci-restore"
    self.bundle.mkdir(parents=True)
    self.vars = self.root / "sys/firmware/efi/efivars"
    self.vars.mkdir(parents=True)
    (self.root / "run").mkdir()
    for name in ("guard",):
      self.put(self.bundle / (name + ".ko"), name + " binary")
      self.put(self.bundle / (name + ".sha256"), hashlib.sha256((name + " binary").encode()).hexdigest() + "\n")
      self.put(self.bundle / (name + ".srcversion"), name.upper() + "\n")
    self.put(self.bundle / "restore.variable", "OmarchyT2RestoreStageV2-" + GUID + "\n")
    for name, value in (("device", "/dev/mapper/root"), ("offset", "1923214"), ("devnum", "253:0")):
      self.put(self.bundle / ("resume." + name), value + "\n")
    reader = '#!/bin/sh\ncat "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/header-mode"\n'
    self.put(self.bundle / "header-reader", reader)
    (self.bundle / "header-reader").chmod(0o700)
    self.put(self.bundle / "header-reader.sha256", hashlib.sha256(reader.encode()).hexdigest() + "\n")
    stock = 'run_hook() { printf "resume\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"; }\n'
    self.put(self.bundle / "stock-resume", stock)
    self.put(self.bundle / "stock-resume.sha256", hashlib.sha256(stock.encode()).hexdigest() + "\n")
    shutil.copyfile(EXPERIMENT / "functions", self.bundle / "functions")
    self.put(self.root / "header-mode", "NORMAL\n")
    self.put(self.root / "proc/sys/kernel/ftrace_enabled", "1\n")
    self.put(self.root / "proc/cmdline", "resume=/dev/mapper/root resume_offset=1923214\n")
    self.put(self.root / "sys/power/resume_offset", "1923214\n")
    for function, identity in enumerate(("0x2005", "0x1801", "0x1802", "0x1803")):
      path = self.root / ("sys/bus/pci/devices/0000:74:00." + str(function))
      self.put(path / "vendor", "0x106b\n")
      self.put(path / "device", identity + "\n")
    driver = self.root / "sys/bus/pci/drivers/nvme"
    driver.mkdir(parents=True)
    (self.root / "sys/bus/pci/devices/0000:74:00.0/driver").symlink_to(driver)
    guard_driver = self.root / "sys/bus/pci/drivers/mba_hibernate_cold_pci_guard"
    guard_driver.mkdir()
    (guard_driver / "module").symlink_to(self.root / "sys/module/mba_hibernate_cold_pci_guard")
    for name in ("guard",):
      params = {"arm_prefix": "0", "arm_consumed": "N", "vector_prefix": ""}
      params.update(gates="0", gate_active="N", gate_failed="N")
      for key, value in params.items():
        self.put(self.root / "templates" / name / "parameters" / key, value + "\n")
      self.put(self.root / "templates" / name / "srcversion", name.upper() + "\n")

  def put(self, path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else value.encode())

  def marker(self, stage):
    self.put(self.vars / ("OmarchyT2RestoreStageV2-" + GUID), b"\x07\0\0\0MBRS" + bytes.fromhex(PREFIX) + bytes([stage]))

  def hooks(self):
    for kind, stage in (("Entered", 1), ("Armed", 2)):
      self.put(self.vars / ("OmarchyT2RestoreHook" + kind + PREFIX + "-" + GUID), b"\x07\0\0\0MBRH" + PREFIX.encode() + bytes([stage]))

  def pending(self):
    self.put(self.root / "header-mode", "PENDING\n")
    self.marker(0)

  def run_shell(self, body, fault=""):
    # Only sysfs side effects are mocked; all runtime validation and dispatch is real ash.
    setup = r'''
HOOKS="base encrypt omarchy-t2-cold-pci-restore omarchy-t2-restore-marker resume omarchy-t2-cold-pci-restore-stop filesystems"
LATEHOOKS="omarchy-t2-candidate-modules"
EARLYHOOKS= CLEANUPHOOKS= EMERGENCYHOOKS=
hexdump() { /usr/lib/initcpio/busybox hexdump "$@"; }
err() { printf '%s\n' "$*" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"; }
launch_interactive_shell() { printf 'STOP\n' >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"; }
insmod() {
  name=${1##*/}; name=${name%.ko}
  printf 'load-%s\n' "$name" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"
  [[ $name == "guard" ]] || return 1
  module=mba_hibernate_cold_pci_guard
  [[ "$FAULT" != "insert-$name" ]] || return 1
  mkdir -p "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/module"
  cp -r "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/templates/$name" "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/module/$module"
  if [[ "$FAULT" == "missing-$name" ]]; then rm "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/module/$module/parameters/arm_consumed"; fi
  if [[ "$FAULT" == "srcversion-$name" ]]; then printf 'wrong\n' > "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/module/$module/srcversion"; fi
  if [[ $name == "guard" && "$FAULT" != "no-bind" ]]; then
    ln -s "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/bus/pci/drivers/mba_hibernate_cold_pci_guard" "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/sys/bus/pci/devices/0000:74:00.1/driver"
  fi
}
'''
    arm = r'''
fr_write_arm() {
  name=guard
  printf 'arm-%s\n' "$name" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"
  [[ "$FAULT" != "arm-$name" ]] || return 1
  printf '1\n' > "$1/parameters/arm_prefix"
  printf 'Y\n' > "$1/parameters/arm_consumed"
  printf '%s\n' "$fr_prefix" > "$1/parameters/vector_prefix"
  if [[ "$FAULT" == "partial-$name" ]]; then printf 'N\n' > "$1/parameters/arm_consumed"; fi
}
'''
    script = setup + '. "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/usr/lib/omarchy-t2-cold-pci-restore/functions"\n' + arm + body
    result = subprocess.run([str(BUSYBOX), "ash", "-c", script], env={"PATH": "/usr/bin:/bin", "OMARCHY_T2_COLD_PCI_RESTORE_ROOT": str(self.root), "FAULT": fault}, capture_output=True, text=True)
    return result

  def events(self):
    path = self.root / "events"
    return path.read_text() if path.exists() else ""

  def armed(self):
    self.pending()
    result = self.run_shell("fr_prepare")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.hooks()
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix", "1\n")
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/stage", "0\n")

  def dispatch(self, name):
    return '. "' + str(EXPERIMENT / "hooks" / name) + '"\nrun_hook\n'

  def repin_stock(self, stock):
    self.put(self.bundle / "stock-resume", stock)
    self.put(self.bundle / "stock-resume.sha256", hashlib.sha256(stock.encode()).hexdigest() + "\n")

  def test_normal_actual_dispatch_allows_late_without_module_load(self):
    body = "".join(self.dispatch(name) for name in ("omarchy-t2-cold-pci-restore", "resume", "omarchy-t2-cold-pci-restore-stop"))
    result = self.run_shell(body + 'printf "late\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"')
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(self.events(), "resume\nlate\n")

  def test_pending_loads_and_arms_only_guard_then_requires_marker_hook_evidence(self):
    self.pending()
    self.assertEqual(self.run_shell("fr_prepare").returncode, 0)
    self.assertEqual(self.events(), "load-guard\narm-guard\n")
    self.assertNotEqual(self.run_shell("fr_before_resume").returncode, 0)
    self.hooks()
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix", "1\n")
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/stage", "0\n")
    self.assertEqual(self.run_shell("fr_before_resume").returncode, 0)
    self.assertFalse((self.root / "sys/module/mba_hibernate_cold_pre_arch").exists())

  def test_any_pending_stock_return_stops_and_never_writes_success(self):
    for status in (0, 1, 77):
      with self.subTest(status=status):
        self.setUp()
        self.repin_stock('run_hook() { printf "resume\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"; return ' + str(status) + '; }\n')
        self.armed()
        before = {p.name: p.read_bytes() for p in self.vars.iterdir()}
        result = self.run_shell(self.dispatch("resume") + 'printf "late\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resume\n", self.events())
        self.assertIn("pending stock resume returned", self.events())
        self.assertIn("STOP\n", self.events())
        self.assertNotIn("late", self.events())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.vars.iterdir()})
        self.assertTrue((self.root / "sys/module/mba_hibernate_cold_pci_guard").exists())

  def test_pending_return_latch_survives_intent_deletion_and_consumed_header(self):
    self.repin_stock('run_hook() { rm "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/run/omarchy-t2-cold-pci-restore.intent"; printf "NORMAL\\n" > "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/header-mode"; }\n')
    self.armed()
    result = self.run_shell(self.dispatch("resume") + 'printf "late\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"')
    self.assertNotEqual(result.returncode, 0)
    self.assertIn("pending stock resume returned", self.events())
    self.assertNotIn("late", self.events())

  def test_stop_hook_refuses_pending_continuation_and_exits_if_shell_returns(self):
    self.armed()
    result = self.run_shell(self.dispatch("omarchy-t2-cold-pci-restore-stop") + 'printf "late\\n" >> "$OMARCHY_T2_COLD_PCI_RESTORE_ROOT/events"')
    self.assertNotEqual(result.returncode, 0)
    self.assertIn("STOP", self.events())
    self.assertNotIn("late", self.events())

  def test_partial_setup_actual_hook_stops_without_resume(self):
    for fault in ("no-bind", "insert-guard", "arm-guard", "partial-guard", "missing-guard", "srcversion-guard"):
      with self.subTest(fault=fault):
        self.setUp()
        self.pending()
        result = self.run_shell(self.dispatch("omarchy-t2-cold-pci-restore") + self.dispatch("resume"), fault)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STOP", self.events())
        self.assertNotIn("resume\n", self.events())
        self.assertNotIn("load-abort", self.events())
        self.assertNotIn("arm-abort", self.events())

  def test_pristine_and_before_gate_fail_closed_for_every_guard_parameter(self):
    fields = {"arm_prefix": "1", "arm_consumed": "Y", "vector_prefix": "a" * 24, "gates": "1", "gate_active": "Y", "gate_failed": "Y"}
    for phase in ("initial", "before"):
      for key in fields:
        with self.subTest(phase=phase, key=key):
          self.setUp()
          if phase == "initial":
            self.pending()
            self.put(self.root / "templates/guard/parameters" / key, fields[key] + "\n")
            result = self.run_shell("fr_prepare")
          else:
            self.armed()
            self.put(self.root / "sys/module/mba_hibernate_cold_pci_guard/parameters" / key, "bad\n")
            result = self.run_shell(self.dispatch("resume"))
            self.assertIn("STOP", self.events())
            self.assertNotIn("resume\n", self.events())
          self.assertNotEqual(result.returncode, 0)

  def test_loaded_abort_or_bce_modules_rejected_in_normal_and_pending(self):
    for module in ("mba_hibernate_cold_pre_arch", "mba_hibernate_cold_pre_cpu", "mba_hibernate_cold_pre_syscore", "mba_hibernate_cold_pre_relocate", "t2bce_core", "t2bce_audio", "t2bce_vhci", "t2bce_ave"):
      for pending in (False, True):
        with self.subTest(module=module, pending=pending):
          self.setUp()
          if pending: self.pending()
          (self.root / "sys/module" / module).mkdir(parents=True)
          self.assertNotEqual(self.run_shell("fr_prepare").returncode, 0)
          self.assertEqual(self.events(), "")

  def test_immediate_resume_rechecks_exact_artifacts_pci_and_hook_witnesses(self):
    for mutation in ("guard-hash", "guard-source", "stock-hash", "no-bind", "ans", "sep", "audio", "pci-id", "entered", "marker-stage", "marker-arm", "systemd", "intent"):
      with self.subTest(mutation=mutation):
        self.setUp()
        self.armed()
        if mutation == "guard-hash": self.put(self.bundle / "guard.ko", "wrong")
        elif mutation == "guard-source": self.put(self.root / "sys/module/mba_hibernate_cold_pci_guard/srcversion", "wrong\n")
        elif mutation == "stock-hash": self.put(self.bundle / "stock-resume", "wrong")
        elif mutation == "no-bind": (self.root / "sys/bus/pci/devices/0000:74:00.1/driver").unlink()
        elif mutation in ("ans", "sep", "audio"):
          function = {"ans": 0, "sep": 2, "audio": 3}[mutation]
          path = self.root / ("sys/bus/pci/devices/0000:74:00." + str(function) + "/driver")
          if path.is_symlink(): path.unlink()
          path.symlink_to(self.root / "sys/bus/pci/drivers/wrong")
        elif mutation == "pci-id": self.put(self.root / "sys/bus/pci/devices/0000:74:00.0/device", "0x2006\n")
        elif mutation == "entered": (self.vars / ("OmarchyT2RestoreHookEntered" + PREFIX + "-" + GUID)).unlink()
        elif mutation == "marker-stage": self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/stage", "7\n")
        elif mutation == "marker-arm": self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix", "0\n")
        elif mutation == "systemd":
          self.put(self.root / "usr/lib/systemd/systemd-hibernate-resume", "fake")
          (self.root / "usr/lib/systemd/systemd-hibernate-resume").chmod(0o700)
        else: self.put(self.root / "run/omarchy-t2-cold-pci-restore.intent", "a" * 24 + "\n")
        result = self.run_shell(self.dispatch("resume"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STOP", self.events())
        self.assertNotIn("resume\n", self.events())

  def test_missing_or_symlinked_bundle_pins_refuse_pending_resume(self):
    for name in ("guard.ko", "guard.sha256", "guard.srcversion", "stock-resume", "stock-resume.sha256", "header-reader.sha256", "restore.variable"):
      for symlink in (False, True):
        with self.subTest(name=name, symlink=symlink):
          self.setUp()
          self.pending()
          path = self.bundle / name
          saved = path.read_bytes()
          path.unlink()
          if symlink:
            target = self.root / "replacement"
            self.put(target, saved)
            path.symlink_to(target)
          result = self.run_shell(self.dispatch("omarchy-t2-cold-pci-restore") + self.dispatch("resume"))
          self.assertNotEqual(result.returncode, 0)
          self.assertIn("STOP", self.events())
          self.assertNotIn("resume\n", self.events())

  def test_cross_protocol_witness_rejected_before_load_and_resume(self):
    for name in ("OmarchyT2ColdPciPreArchReturned", "OmarchyT2ColdPreArchReturned", "OmarchyT2ColdPreSyscoreReturned", "OmarchyT2ColdPreCpuReturned"):
      for phase in ("prepare", "before"):
        with self.subTest(name=name, phase=phase):
          self.setUp()
          if phase == "before": self.armed()
          else: self.pending()
          self.put(self.vars / (name + PREFIX + "-" + GUID), b"occupied")
          self.assertNotEqual(self.run_shell("fr_prepare" if phase == "prepare" else "fr_before_resume").returncode, 0)

  def test_header_marker_hook_order_and_symlink_faults_refuse_before_load(self):
    for mutation in ("normal-marker", "pending-no-marker", "bad-marker", "intent", "guard", "device", "offset", "ftrace", "order", "late", "symlink"):
      with self.subTest(mutation=mutation):
        self.setUp()
        self.pending()
        prefix = ""
        if mutation == "normal-marker": self.put(self.root / "header-mode", "NORMAL\n")
        elif mutation == "pending-no-marker": (self.vars / ("OmarchyT2RestoreStageV2-" + GUID)).unlink()
        elif mutation == "bad-marker": self.marker(7)
        elif mutation == "intent": self.put(self.root / "run/omarchy-t2-cold-pci-restore.intent", PREFIX + "\n")
        elif mutation == "guard": (self.root / "sys/module/mba_hibernate_cold_pci_guard").mkdir(parents=True)
        elif mutation == "device": self.put(self.bundle / "resume.device", "/dev/wrong\n")
        elif mutation == "offset": self.put(self.root / "sys/power/resume_offset", "1\n")
        elif mutation == "ftrace": self.put(self.root / "proc/sys/kernel/ftrace_enabled", "0\n")
        elif mutation == "order": prefix = 'HOOKS="encrypt omarchy-t2-cold-pci-restore resume omarchy-t2-restore-marker omarchy-t2-cold-pci-restore-stop"\n'
        elif mutation == "late": prefix = 'LATEHOOKS="omarchy-t2-cold-pci-restore"\n'
        else:
          (self.bundle / "guard.ko").unlink()
          (self.bundle / "guard.ko").symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_shell(prefix + "fr_prepare").returncode, 0)
        self.assertEqual(self.events(), "")


if __name__ == "__main__":
  unittest.main()
