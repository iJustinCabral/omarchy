#!/usr/bin/python3
"""Exercise pair source boot verification against an entirely synthetic host."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/verify-hibernation-uki-pair-source.py"
spec = importlib.util.spec_from_file_location("pair_source_verifier", script)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
pair_stage = verifier.PAIR
legacy = verifier.LEGACY


def digest(data):
  return hashlib.sha256(data).hexdigest()


def write(path, data):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(data)


def efi_string(value):
  return b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le")


def efi_strings(values):
  return b"\x06\x00\x00\x00" + "".join(value + "\x00" for value in values).encode("utf-16-le")


def rejects(root, source, restore, expected, role="source"):
  try:
    verifier.inspect(root, source, restore, role)
  except ValueError as error:
    assert expected in str(error), error
  else:
    raise AssertionError("Unsafe pair source boot passed: " + expected)


def publish(directory, role, production_hash, release, cmdline):
  directory.mkdir()
  image = (role + "-uki").encode()
  initrd = (role + "-initrd").encode()
  (directory / "mba-t2-hibernation-candidate.efi").write_bytes(image)
  (directory / "mba-t2-hibernation-candidate.initrd").write_bytes(initrd)
  modules = {
    name: {
      "source": "drivers/" + name + ".ko",
      "sha256": digest(name.encode()),
      "srcversion": "SRC_" + name.replace("-", "_"),
      "vermagic": release + " SMP preempt mod_unload",
    }
    for name in pair_stage.AUDIT.S4.RUNTIME_MODULES
  }
  report = {
    "candidate": "mba-t2-hibernation-early-source" if role == "source" else "mba-t2-hibernation-module-overlay",
    "experiment_id": "pair-verifier-" + role,
    "candidate_uki_sha256": digest(image),
    "candidate_initrd_sha256": digest(initrd),
    "cmdline": cmdline,
    "kernel_release": release,
    "modules": modules,
    "production_uki_sha256": production_hash,
    "source_provenance_sha256": "b" * 64,
    "unchanged_production_sections_sha256": {
      section: digest(section.encode()) for section in pair_stage.AUDIT.S4.RUNTIME_SECTIONS
    },
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
    "production_modified": False,
  }
  if role == "source":
    report.update({
      "initrd_module_selection": {
        name: "usr/lib/modules/" + release + "/" + name + ".ko"
        for name in pair_stage.AUDIT.SOURCE_INITRD_MODULES
      },
      "pre_restore_module_policy": "early-t2-radio",
    })
  else:
    report.update({
      "initrd_module_selection": {},
      "pre_restore_module_policy": "root-only-no-t2-radio",
      "pre_restore_excluded_modules": sorted(pair_stage.AUDIT.S4.RUNTIME_MODULES),
      "post_switch_root_payload": {
        name: "usr/lib/omarchy-t2-hibernation-candidate/payload/" + name + ".ko"
        for name in pair_stage.AUDIT.S4.RUNTIME_MODULES
      },
    })
  (directory / "provenance.json").write_text(json.dumps(report))
  return report


with tempfile.TemporaryDirectory(prefix="t2-pair-source-verify-") as temporary:
  base = Path(temporary)
  root = base / "root"
  production = root / "boot/EFI/Linux/omarchy_linux-t2.efi"
  production.parent.mkdir(parents=True)
  production.write_bytes(b"healthy production uki")
  write(root / pair_stage.SINGLE.LIMINE, (
    "timeout: 3\n"
    "default_entry: 2\n"
    "/+Omarchy\n"
    "  //linux-t2\n"
    "  protocol: efi\n"
    "  path: boot():/EFI/Linux/omarchy_linux-t2.efi#"
    + hashlib.blake2b(production.read_bytes()).hexdigest() + "\n"
  ))
  selected = root / pair_stage.SINGLE.SELECTED
  selected.parent.mkdir(parents=True)
  selected.write_bytes(efi_string("Omarchy.linux-t2"))
  write(root / pair_stage.BOOT_ID, "11111111-2222-3333-4444-555555555555\n")
  release = "7.2.6-arch2-Watanare-T2-2-t2"
  cmdline = "cryptdevice=PARTUUID=test:root root=/dev/mapper/root rootflags=subvol=@ rw rootfstype=btrfs resume=/dev/mapper/root resume_offset=42 cryptkey=rootfs:/key"
  source = base / "source"
  restore = base / "restore"
  source_report = publish(source, "source", digest(production.read_bytes()), release, cmdline)
  publish(restore, "restore", digest(production.read_bytes()), release, cmdline)
  receipt = pair_stage.stage(root, source, restore)
  entries = root / pair_stage.SINGLE.ENTRIES
  entries.write_bytes(efi_strings(("Omarchy.linux-t2", receipt["images"]["source"]["entry_id"], receipt["images"]["restore"]["entry_id"])))

  def bootctl(arguments, check):
    assert arguments == ["bootctl", "set-oneshot", receipt["images"]["source"]["entry_id"]] and check
    (root / pair_stage.SINGLE.ONESHOT).write_bytes(efi_string(arguments[2]))

  pair_stage.arm_source(root, runner=bootctl, sync=lambda: None)
  rejects(root, source, restore, "not consumed")
  (root / pair_stage.SINGLE.ONESHOT).unlink()
  selected.write_bytes(efi_string(receipt["images"]["source"]["entry_id"]))
  write(root / pair_stage.BOOT_ID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
  write(root / legacy.MODEL, "MacBookAir9,1\n")
  write(root / legacy.OSRELEASE, release + "\n")
  write(root / legacy.CMDLINE, cmdline + "\n")
  write(root / verifier.MOUNTS, "/dev/mapper/root / btrfs rw,subvol=/@ 0 0\n")
  (root / "proc/mounts").symlink_to("self/mounts")
  write(root / legacy.INPUT_DEVICES, (
    'N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"\n'
    "P: Phys=usb-t2bce_vhci-5/input1\n\n"
    'N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"\n'
    "P: Phys=usb-t2bce_vhci-5/input2\n"
  ))
  write(root / legacy.ASOUND_CARDS, " 0 [AppleT2        ]: Apple T2 Audio\n")
  for name in legacy.REQUIRED_MODULES:
    write(root / "sys/module" / name.replace("-", "_") / "srcversion", source_report["modules"][name]["srcversion"] + "\n")
  for address, (vendor, device, driver) in legacy.PCI_DEVICES.items():
    path = root / "sys/bus/pci/devices" / address
    write(path / "vendor", vendor + "\n")
    write(path / "device", device + "\n")
    if driver is not None:
      (path / "driver").symlink_to("../../../drivers/" + driver)
  (root / "sys/bus/pci/devices/0000:73:00.0/net/wlp115s0f0").mkdir(parents=True)
  (root / "sys/class/bluetooth/hci0").mkdir(parents=True)

  result = verifier.inspect(root, source, restore)
  assert result["qualification"] == "pair-source-ordinary-boot-preflight-passed"
  assert result["source_uki_sha256"] == receipt["images"]["source"]["sha256"]
  assert result["restore_uki_sha256"] == receipt["images"]["restore"]["sha256"]
  assert result["primary_root"]["subvolume"] == "/@"
  assert result["physical_input_confirmed"] is False
  assert result["hibernate_attempted"] is False
  assert result["hardware_qualified"] is False

  selected.write_bytes(efi_string("Omarchy.linux-t2"))
  rejects(root, source, restore, "not the exact source entry")
  selected.write_bytes(efi_string(receipt["images"]["source"]["entry_id"]))
  module = root / "sys/module/t2bce_core/srcversion"
  module.write_text("WRONG\n")
  rejects(root, source, restore, "does not match candidate")
  module.write_text(source_report["modules"]["t2bce_core"]["srcversion"] + "\n")
  write(root / verifier.MOUNTS, "/dev/nvme0n1p4 / btrfs rw,subvol=/@ 0 0\n")
  rejects(root, source, restore, "not the primary encrypted")
  write(root / verifier.MOUNTS, "/dev/mapper/root / btrfs rw,subvol=/@ 0 0\n")
  restore_report = restore / "provenance.json"
  original = restore_report.read_text()
  changed = json.loads(original)
  changed["experiment_id"] = "tampered"
  restore_report.write_text(json.dumps(changed))
  rejects(root, source, restore, "provenance changed")
  restore_report.write_text(original)
  receipt_path = root / pair_stage.RECEIPT
  original_receipt = receipt_path.read_text()
  changed_receipt = json.loads(original_receipt)
  changed_receipt["source_armed_from_boot_id"] = "not-a-boot-id"
  receipt_path.write_text(json.dumps(changed_receipt))
  rejects(root, source, restore, "arming boot ID is missing or malformed")
  receipt_path.write_text(original_receipt)
  changed_receipt = json.loads(original_receipt)
  changed_receipt.pop("kernel_policy")
  receipt_path.write_text(json.dumps(changed_receipt))
  rejects(root, source, restore, "production-kernel boot policy")
  receipt_path.write_text(original_receipt)
  assert verifier.inspect(root, source, restore)["qualification"] == "pair-source-ordinary-boot-preflight-passed"

  runner_path = script.parent / "run-hibernation-uki-pair-s4.py"
  runner_spec = importlib.util.spec_from_file_location("pair_s4_platform_adapter", runner_path)
  pair_runner = importlib.util.module_from_spec(runner_spec)
  runner_spec.loader.exec_module(pair_runner)
  power = root / pair_runner.TEST.POWER
  write(power / "state", "freeze mem disk\n")
  write(power / "disk", "[platform] shutdown test_resume\n")
  write(power / "pm_test", "[none] core processors platform devices freezer\n")
  write(power / "pm_trace", "0\n")
  write(power / "resume", "254:0\n")
  write(power / "resume_offset", "42\n")
  write(power / "pm_async", "0\n")
  write(root / pair_runner.TEST.SWAPS, "Filename Type Size Used Priority\n/swap/swapfile file 4096 0 -2\n")
  platform = pair_runner.source_platform_preflight(root, source, restore)
  assert platform["entry_id"] == receipt["images"]["source"]["entry_id"]
  assert platform["candidate_uki_sha256"] == receipt["images"]["source"]["sha256"]
  assert platform["restore_uki_sha256"] == receipt["images"]["restore"]["sha256"]
  assert platform["resume_offset"] == 42

  rejects(root, source, restore, "restore one-shot was not armed", role="restore")

  def restore_bootctl(arguments, check):
    assert arguments == ["bootctl", "set-oneshot", receipt["images"]["restore"]["entry_id"]] and check
    (root / pair_stage.SINGLE.ONESHOT).write_bytes(efi_string(arguments[2]))

  pair_stage.arm_restore(root, runner=restore_bootctl, sync=lambda: None)
  rejects(root, source, restore, "not consumed", role="restore")
  (root / pair_stage.SINGLE.ONESHOT).unlink()
  selected.write_bytes(efi_string(receipt["images"]["restore"]["entry_id"]))
  write(root / pair_stage.BOOT_ID, "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb\n")
  restore_result = verifier.inspect(root, source, restore, role="restore")
  assert restore_result["qualification"] == "pair-restore-ordinary-boot-preflight-passed"
  assert restore_result["restore_armed_from_boot_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  assert restore_result["primary_root"]["subvolume"] == "/@"
  assert restore_result["physical_input_confirmed"] is False
  assert restore_result["hibernate_attempted"] is False
  assert restore_result["hardware_qualified"] is False
  selected.write_bytes(efi_string(receipt["images"]["source"]["entry_id"]))
  rejects(root, source, restore, "not the exact restore entry", role="restore")

print("PASS: pair boot verifier binds source and restore images, exact boots and live T2 devices without claiming PM success")
