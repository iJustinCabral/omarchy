#!/usr/bin/python3
"""Exercise the read-only dual-UKI structural audit with private fake images."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/audit-hibernation-uki-pair.py"
spec = importlib.util.spec_from_file_location("uki_pair_audit", script)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def digest(data):
  return hashlib.sha256(data).hexdigest()


def provenance(role):
  modules = {
    name: {
      "source": "drivers/" + name + ".ko",
      "sha256": digest(name.encode()),
      "srcversion": "TEST" + name,
      "vermagic": "test-kernel SMP preempt mod_unload",
    }
    for name in audit.S4.RUNTIME_MODULES
  }
  result = {
    "candidate_uki_sha256": "",
    "candidate_initrd_sha256": "",
    "cmdline": "root=/dev/mapper/root resume=/dev/mapper/root",
    "kernel_release": "test-kernel",
    "modules": modules,
    "production_uki_sha256": "a" * 64,
    "source_provenance_sha256": "b" * 64,
    "unchanged_production_sections_sha256": {
      section: digest(section.encode()) for section in audit.S4.RUNTIME_SECTIONS
    },
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
    "production_modified": False,
  }
  if role == "source":
    result["initrd_module_selection"] = {
      name: "usr/lib/modules/test-kernel/" + name + ".ko"
      for name in audit.SOURCE_INITRD_MODULES
    }
    result["pre_restore_module_policy"] = "early-t2-radio"
  else:
    result.update({
      "initrd_module_selection": {},
      "pre_restore_module_policy": "root-only-no-t2-radio",
      "pre_restore_excluded_modules": sorted(audit.S4.RUNTIME_MODULES),
      "post_switch_root_payload": {
        name: "usr/lib/omarchy-t2-hibernation-candidate/payload/" + name + ".ko"
        for name in audit.S4.RUNTIME_MODULES
      },
    })
  return result


def publish(directory, role):
  directory.mkdir()
  image = (role + "-uki").encode()
  initrd = (role + "-initrd").encode()
  (directory / "mba-t2-hibernation-candidate.efi").write_bytes(image)
  (directory / "mba-t2-hibernation-candidate.initrd").write_bytes(initrd)
  report = provenance(role)
  report["candidate_uki_sha256"] = digest(image)
  report["candidate_initrd_sha256"] = digest(initrd)
  (directory / "provenance.json").write_text(json.dumps(report))
  return report


def rejects(source, restore, message):
  try:
    audit.audit(source, restore)
  except ValueError as error:
    assert message in str(error), error
  else:
    raise AssertionError("Unsafe pair was accepted: " + message)


with tempfile.TemporaryDirectory(prefix="t2-uki-pair-") as temporary:
  root = Path(temporary)
  source_dir = root / "source"
  restore_dir = root / "restore"
  source = publish(source_dir, "source")
  restore = publish(restore_dir, "restore")
  loaded_source = audit.load_candidate(source_dir, "source")
  loaded_restore = audit.load_candidate(restore_dir, "restore")
  result = audit.audit(loaded_source, loaded_restore)
  assert result["classification"] == "structurally-matched-private-pair-not-boot-qualified"
  assert len(result["source_initrd_modules"]) == 9
  assert len(result["restore_pre_restore_excluded_modules"]) == 10

  changed = copy.deepcopy(restore)
  changed["modules"]["t2bce_core"]["sha256"] = "c" * 64
  rejects(source, changed, "different kernel/cmdline/module stack identities")

  changed = copy.deepcopy(source)
  changed["initrd_module_selection"].pop("t2bce_core")
  rejects(changed, restore, "complete T2/radio module set")

  changed = copy.deepcopy(source)
  changed["pre_restore_module_policy"] = "root-only-no-t2-radio"
  rejects(changed, restore, "unknown or isolated")

  changed = copy.deepcopy(restore)
  changed["initrd_module_selection"] = {"t2bce_core": "usr/lib/modules/test-kernel/t2bce_core.ko"}
  rejects(source, changed, "would select a T2/radio module")

  changed = copy.deepcopy(restore)
  changed["pre_restore_excluded_modules"].remove("t2bce_core")
  rejects(source, changed, "does not exclude the complete")

  (restore_dir / "mba-t2-hibernation-candidate.initrd").write_bytes(b"tampered")
  try:
    audit.load_candidate(restore_dir, "restore")
  except ValueError as error:
    assert "initramfs differs" in str(error)
  else:
    raise AssertionError("Tampered private initramfs was accepted")

  (restore_dir / "provenance.json").write_text("[]")
  try:
    audit.load_candidate(restore_dir, "restore")
  except ValueError as error:
    assert "not an object" in str(error)
  else:
    raise AssertionError("Non-object provenance was accepted")

print("PASS: dual-UKI audit binds matching stack and opposing initrd/restore module policies")
