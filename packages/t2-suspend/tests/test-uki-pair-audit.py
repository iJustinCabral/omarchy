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

  marker = {
    "sha256": digest(b"private-marker"),
    "srcversion": "ABC123",
    "efi_variable": audit.RESTORE_MARKER_VARIABLE,
    "pre_resume_hook": audit.RESTORE_MARKER_HOOK,
    "hook_sha256": audit.sha256(audit.RESTORE_MARKER_HOOK_SOURCE),
  }
  extracted = root / "marker-initrd"
  hooks = extracted / "hooks"
  hooks.mkdir(parents=True)
  (hooks / audit.RESTORE_MARKER_HOOK).write_bytes(audit.RESTORE_MARKER_HOOK_SOURCE.read_bytes())
  marker_dir = extracted / "usr/lib/omarchy-t2-restore-marker"
  marker_dir.mkdir(parents=True)
  (marker_dir / "marker.ko").write_bytes(b"private-marker")
  (marker_dir / "marker.sha256").write_text(marker["sha256"] + "\n")
  (marker_dir / "marker.srcversion").write_text(marker["srcversion"] + "\n")
  (extracted / "config").write_text('HOOKS="udev encrypt omarchy-t2-restore-marker resume"\n')
  audit.verify_restore_marker_tree(extracted, marker)
  instrumented_restore = copy.deepcopy(restore)
  instrumented_restore["restore_marker"] = marker
  assert audit.audit(source, instrumented_restore)["restore_marker"] == marker
  instrumented_source = copy.deepcopy(source)
  instrumented_source["restore_marker"] = marker
  rejects(instrumented_source, restore, "Source image must not contain")
  (extracted / "config").write_text('HOOKS="udev encrypt resume omarchy-t2-restore-marker"\n')
  try:
    audit.verify_restore_marker_tree(extracted, marker)
  except ValueError as error:
    assert "immediately before resume" in str(error), error
  else:
    raise AssertionError("Late restore marker was accepted")
  (extracted / "config").write_text('HOOKS="udev encrypt omarchy-t2-restore-marker resume"\n')
  (hooks / audit.RESTORE_MARKER_HOOK).write_text("run_hook() { :; }\n")
  try:
    audit.verify_restore_marker_tree(extracted, marker)
  except ValueError as error:
    assert "hook differs" in str(error), error
  else:
    raise AssertionError("Altered restore hook was accepted")
  (hooks / audit.RESTORE_MARKER_HOOK).write_bytes(audit.RESTORE_MARKER_HOOK_SOURCE.read_bytes())
  v2_marker = {**marker, "version": "v2", "efi_variable": audit.V2_RESTORE_MARKER_VARIABLE}
  version_file = marker_dir / "marker.version"
  version_file.write_text("v2\n")
  audit.verify_restore_marker_tree(extracted, v2_marker)
  version_file.write_text("v1\n")
  try:
    audit.verify_restore_marker_tree(extracted, v2_marker)
  except ValueError as error:
    assert "variable version differs" in str(error), error
  else:
    raise AssertionError("Mismatched restore marker version was accepted")
  version_file.unlink()
  (marker_dir / "marker.ko").write_bytes(b"wrong-marker")
  try:
    audit.verify_restore_marker_tree(extracted, marker)
  except ValueError as error:
    assert "module differs" in str(error), error
  else:
    raise AssertionError("Altered restore marker was accepted")

  marker_source = copy.deepcopy(source)
  marker_restore = copy.deepcopy(restore)
  marker_hash = digest(b"marker-enabled-kernel")
  for report in (marker_source, marker_restore):
    baseline = report["unchanged_production_sections_sha256"].pop(".linux")
    report["modified_sections_sha256"] = {".linux": marker_hash}
    report["kernel_override"] = {
      "sha256": digest(b"raw-marker-kernel"),
      "pe_section_sha256": marker_hash,
      "unpadded_size": 17,
      "baseline_linux_sha256": baseline,
      "patch_sha256": digest(b"marker-patch"),
      "kernel_release": "test-kernel",
    }
  marker_result = audit.audit(marker_source, marker_restore)
  assert marker_result["runtime_stack_sha256"] != result["runtime_stack_sha256"]
  rejects(marker_source, restore, "different kernel/cmdline/module stack identities")
  malformed = copy.deepcopy(marker_restore)
  malformed["kernel_override"]["pe_section_sha256"] = digest(b"wrong-kernel")
  rejects(marker_source, malformed, "kernel override metadata is inconsistent")
  malformed = copy.deepcopy(marker_restore)
  malformed["kernel_override"]["baseline_linux_sha256"] = digest(b"wrong-baseline")
  rejects(marker_source, malformed, "different kernel/cmdline/module stack identities")
  malformed = copy.deepcopy(marker_restore)
  malformed["unchanged_production_sections_sha256"][".linux"] = digest(b"incorrectly-unchanged")
  rejects(marker_source, malformed, "invalid kernel-only PE override")

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

  (restore_dir / "provenance.json").write_text(json.dumps(marker_restore))
  try:
    audit.load_candidate(restore_dir, "restore")
  except ValueError as error:
    assert "UKI .linux" in str(error), error
  else:
    raise AssertionError("Kernel override accepted an image without a matching PE section")
  (restore_dir / "provenance.json").write_text(json.dumps(restore))

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
