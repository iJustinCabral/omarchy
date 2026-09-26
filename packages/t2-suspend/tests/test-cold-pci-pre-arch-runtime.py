#!/usr/bin/python3
"""Actual BusyBox hook dispatch over fake sysfs/EFI; no host PM or PCI access."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

EXPERIMENT = Path(__file__).resolve().parents[1] / "experiments/hibernate-cold-pci-pre-arch"
BUSYBOX = Path("/usr/lib/initcpio/busybox")
PREFIX = "9c973c61402167014599b656"
GUID = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"


class RuntimeTests(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.bundle = self.root / "usr/lib/omarchy-t2-cold-pci-pre-arch"
    self.bundle.mkdir(parents=True)
    self.vars = self.root / "sys/firmware/efi/efivars"
    self.vars.mkdir(parents=True)
    (self.root / "run").mkdir()
    for name in ("abort", "guard"):
      self.put(self.bundle / (name + ".ko"), name + " binary")
      self.put(self.bundle / (name + ".sha256"), hashlib.sha256((name + " binary").encode()).hexdigest() + "\n")
      self.put(self.bundle / (name + ".srcversion"), name.upper() + "\n")
    self.put(self.bundle / "restore.variable", "OmarchyT2RestoreStageV2-" + GUID + "\n")
    for name, value in (("device", "/dev/mapper/root"), ("offset", "1923214"), ("devnum", "253:0")):
      self.put(self.bundle / ("resume." + name), value + "\n")
    reader = '#!/bin/sh\ncat "$OMARCHY_T2_COLD_PRE_CPU_ROOT/header-mode"\n'
    self.put(self.bundle / "header-reader", reader)
    (self.bundle / "header-reader").chmod(0o700)
    self.put(self.bundle / "header-reader.sha256", hashlib.sha256(reader.encode()).hexdigest() + "\n")
    stock = 'run_hook() { printf "resume\\n" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"; }\n'
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
    for name in ("abort", "guard"):
      params = {"arm_prefix": "0", "arm_consumed": "N", "vector_prefix": ""}
      if name == "abort":
        params.update(interceptions="0", observed_irqs_disabled="N", observed_online_cpus="0", observed_boundary_valid="N")
      else:
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

  def returned(self):
    self.marker(7)
    self.hooks()
    self.put(self.root / "run/omarchy-t2-cold-pci-pre-arch.intent", PREFIX + "\n")
    for name, module in (("abort", "mba_hibernate_cold_pre_arch"), ("guard", "mba_hibernate_cold_pci_guard")):
      target = self.root / "sys/module" / module
      shutil.copytree(self.root / "templates" / name, target)
      for key, value in {"arm_prefix": "0", "arm_consumed": "Y", "vector_prefix": PREFIX}.items():
        self.put(target / "parameters" / key, value + "\n")
      extra = {"interceptions": "1", "observed_irqs_disabled": "Y", "observed_online_cpus": "1", "observed_boundary_valid": "Y"} if name == "abort" else {"gates": "1"}
      for key, value in extra.items():
        self.put(target / "parameters" / key, value + "\n")
    (self.root / "sys/bus/pci/devices/0000:74:00.1/driver").symlink_to(self.root / "sys/bus/pci/drivers/mba_hibernate_cold_pci_guard")

  def run_shell(self, body, fault=""):
    # Only sysfs side effects are mocked; all runtime validation and dispatch is real ash.
    setup = r'''
HOOKS="base encrypt omarchy-t2-cold-pci-pre-arch omarchy-t2-restore-marker resume omarchy-t2-cold-pci-pre-arch-return filesystems"
LATEHOOKS="omarchy-t2-candidate-modules"
EARLYHOOKS= CLEANUPHOOKS= EMERGENCYHOOKS=
hexdump() { /usr/lib/initcpio/busybox hexdump "$@"; }
err() { printf '%s\n' "$*" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"; }
launch_interactive_shell() { printf 'STOP\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"; }
insmod() {
  name=${1##*/}; name=${name%.ko}
  printf 'load-%s\n' "$name" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"
  if [[ $name == "guard" ]]; then module=mba_hibernate_cold_pci_guard; else module=mba_hibernate_cold_pre_arch; fi
  [[ "$FAULT" != "insert-$name" ]] || return 1
  mkdir -p "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module"
  cp -r "$OMARCHY_T2_COLD_PRE_CPU_ROOT/templates/$name" "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/$module"
  if [[ "$FAULT" == "missing-$name" ]]; then rm "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/$module/parameters/arm_consumed"; fi
  if [[ "$FAULT" == "srcversion-$name" ]]; then printf 'wrong\n' > "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/$module/srcversion"; fi
  if [[ $name == "guard" && "$FAULT" != "no-bind" ]]; then
    ln -s "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/bus/pci/drivers/mba_hibernate_cold_pci_guard" "$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/bus/pci/devices/0000:74:00.1/driver"
  fi
}
'''
    arm = r'''
pg_write_arm() {
  if [[ $1 == "$pg_guard" ]]; then name=guard; else name=abort; fi
  printf 'arm-%s\n' "$name" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"
  [[ "$FAULT" != "arm-$name" ]] || return 1
  printf '1\n' > "$1/parameters/arm_prefix"
  printf 'Y\n' > "$1/parameters/arm_consumed"
  printf '%s\n' "$pg_prefix" > "$1/parameters/vector_prefix"
  if [[ "$FAULT" == "partial-$name" ]]; then printf 'N\n' > "$1/parameters/arm_consumed"; fi
}
'''
    script = setup + '. "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/omarchy-t2-cold-pci-pre-arch/functions"\n' + arm + body
    result = subprocess.run([str(BUSYBOX), "ash", "-c", script], env={"PATH": "/usr/bin:/bin", "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(self.root), "FAULT": fault}, capture_output=True, text=True)
    return result

  def witness(self):
    return self.vars / ("OmarchyT2ColdPciPreArchReturned" + PREFIX + "-" + GUID)

  def test_ordinary_actual_hooks_allow_late_payload_without_loads(self):
    script = ""
    for name in ("omarchy-t2-cold-pci-pre-arch", "resume", "omarchy-t2-cold-pci-pre-arch-return"):
      script += '. "' + str(EXPERIMENT / "hooks" / name) + '"\nrun_hook || exit 1\n'
    script += 'printf "late\\n" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"\n'
    result = self.run_shell(script)
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual((self.root / "events").read_text(), "resume\nlate\n")

  def test_pending_success_arms_then_before_gate_requires_hook_witnesses(self):
    self.pending()
    result = self.run_shell("pg_prepare")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual((self.root / "events").read_text(), "load-guard\nload-abort\narm-guard\narm-abort\n")
    result = self.run_shell("pg_before_resume")
    self.assertNotEqual(result.returncode, 0)
    self.hooks()
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix", "1\n")
    self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/stage", "0\n")
    self.assertEqual(self.run_shell("pg_before_resume").returncode, 0)

  def test_partial_preparation_never_resume_or_witness(self):
    for fault in ("no-bind", "insert-guard", "insert-abort", "arm-guard", "arm-abort", "partial-guard", "partial-abort", "missing-guard", "missing-abort", "srcversion-guard", "srcversion-abort"):
      with self.subTest(fault=fault):
        self.setUp()
        self.pending()
        result = self.run_shell('if pg_prepare; then printf "late\\n" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"; else exit 1; fi', fault)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("late", (self.root / "events").read_text())
        self.assertFalse(self.witness().exists())
        self.assertTrue((self.root / "run/omarchy-t2-cold-pci-pre-arch.intent").exists())

  def test_return_hook_witnesses_and_stops_before_late_payload(self):
    self.returned()
    result = self.run_shell('. "' + str(EXPERIMENT / "hooks/omarchy-t2-cold-pci-pre-arch-return") + '"\nif run_hook; then printf "late\\n" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"; else exit 1; fi')
    self.assertNotEqual(result.returncode, 0)
    self.assertEqual(self.witness().read_bytes(), b"\x07\0\0\0MBPG" + PREFIX.encode() + b"\1")
    self.assertIn("STOP", (self.root / "events").read_text())
    self.assertNotIn("late", (self.root / "events").read_text())
    self.assertTrue((self.root / "sys/module/mba_hibernate_cold_pci_guard").exists())

  def test_return_rejects_every_incomplete_gate_or_abort_observation(self):
    cases = (("guard", "gate_failed", "Y"), ("guard", "gate_active", "Y"), ("guard", "gates", "0"),
             ("guard", "gates", "2"), ("guard", "arm_prefix", "1"), ("guard", "arm_consumed", "N"),
             ("guard", "vector_prefix", "a" * 24), ("abort", "interceptions", "0"),
             ("abort", "observed_irqs_disabled", "N"), ("abort", "observed_online_cpus", "2"), ("abort", "observed_boundary_valid", "N"))
    for name, key, value in cases:
      with self.subTest(name=name, key=key):
        self.setUp()
        self.returned()
        module = "mba_hibernate_cold_pci_guard" if name == "guard" else "mba_hibernate_cold_pre_arch"
        self.put(self.root / "sys/module" / module / "parameters" / key, value + "\n")
        self.assertNotEqual(self.run_shell("pg_capture_return").returncode, 0)
        self.assertFalse(self.witness().exists())

  def test_conflicts_replaced_modules_missing_fields_and_cross_protocols(self):
    for mutation in ("bce", "sep", "audio", "replace-guard", "replace-abort", "srcversion-guard", "srcversion-abort", "missing-gate", "missing-entered", "wrong-armed", "cross-arch", "cross-cpu", "cross-syscore"):
      with self.subTest(mutation=mutation):
        self.setUp()
        self.returned()
        if mutation in ("bce", "sep", "audio"):
          function = {"bce": 1, "sep": 2, "audio": 3}[mutation]
          link = self.root / ("sys/bus/pci/devices/0000:74:00." + str(function) + "/driver")
          if link.is_symlink(): link.unlink()
          link.symlink_to(self.root / "sys/bus/pci/drivers/nvme")
        elif mutation.startswith("replace-"):
          name = mutation.split("-")[1]
          self.put(self.bundle / (name + ".ko"), "replacement")
        elif mutation.startswith("srcversion-"):
          name = mutation.split("-")[1]
          module = "mba_hibernate_cold_pci_guard" if name == "guard" else "mba_hibernate_cold_pre_arch"
          self.put(self.root / "sys/module" / module / "srcversion", "replacement\n")
        elif mutation == "missing-gate":
          (self.root / "sys/module/mba_hibernate_cold_pci_guard/parameters/gate_active").unlink()
        elif mutation == "missing-entered":
          (self.vars / ("OmarchyT2RestoreHookEntered" + PREFIX + "-" + GUID)).unlink()
        elif mutation == "wrong-armed":
          self.put(self.vars / ("OmarchyT2RestoreHookArmed" + PREFIX + "-" + GUID), b"bad")
        else:
          name = {"cross-arch": "Arch", "cross-cpu": "Cpu", "cross-syscore": "Syscore"}[mutation]
          self.put(self.vars / ("OmarchyT2ColdPre" + name + "Returned" + PREFIX + "-" + GUID), b"occupied")
        self.assertNotEqual(self.run_shell("pg_capture_return").returncode, 0)
        self.assertFalse(self.witness().exists())

  def test_ordinary_residue_and_wrong_hook_phase_refuse(self):
    for body in ('mkdir -p "$pg_guard"; pg_prepare', 'LATEHOOKS="omarchy-t2-cold-pci-pre-arch-return"; pg_prepare', 'HOOKS="encrypt omarchy-t2-cold-pci-pre-arch resume omarchy-t2-restore-marker omarchy-t2-cold-pci-pre-arch-return"; pg_prepare'):
      with self.subTest(body=body):
        self.setUp()
        result = self.run_shell("pg_paths\n" + body)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "events").exists())

  def test_cross_protocol_witnesses_refuse_preparation_and_immediate_resume(self):
    for phase in ("prepare", "before"):
      for name in ("Arch", "Cpu", "Syscore"):
        with self.subTest(phase=phase, name=name):
          self.setUp()
          self.pending()
          if phase == "before":
            self.assertEqual(self.run_shell("pg_prepare").returncode, 0)
            self.hooks()
            self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix", "1\n")
            self.put(self.root / "sys/module/mba_hibernate_efi_restore_marker/parameters/stage", "0\n")
          self.put(self.vars / ("OmarchyT2ColdPre" + name + "Returned" + PREFIX + "-" + GUID), b"occupied")
          if phase == "prepare":
            self.assertNotEqual(self.run_shell("pg_prepare").returncode, 0)
            self.assertFalse((self.root / "events").exists())
          else:
            result = self.run_shell('. "' + str(EXPERIMENT / "hooks/resume") + '"\nrun_hook')
            self.assertNotEqual(result.returncode, 0)
            events = (self.root / "events").read_text().splitlines()
            self.assertNotIn("resume", events)
            self.assertIn("STOP", events)
          self.assertFalse(self.witness().exists())

  def test_pending_pci_conflicts_are_rejected_before_insertion(self):
    for function in (1, 2, 3):
      with self.subTest(function=function):
        self.setUp()
        self.pending()
        (self.root / ("sys/bus/pci/devices/0000:74:00." + str(function) + "/driver")).symlink_to(self.root / "sys/bus/pci/drivers/nvme")
        self.assertNotEqual(self.run_shell("pg_prepare").returncode, 0)
        self.assertFalse((self.root / "events").exists())
        self.assertFalse((self.root / "run/omarchy-t2-cold-pci-pre-arch.intent").exists())

  def test_recovery_cannot_fall_through_even_if_shell_exec_returns(self):
    self.returned()
    result = self.run_shell('. "' + str(EXPERIMENT / "hooks/omarchy-t2-cold-pci-pre-arch-return") + '"\nrun_hook\nprintf "late\\n" >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/events"')
    self.assertNotEqual(result.returncode, 0)
    self.assertNotIn("late", (self.root / "events").read_text())
    self.assertTrue(self.witness().exists())


if __name__ == "__main__":
  unittest.main()
