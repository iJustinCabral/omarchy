#!/usr/bin/python3
"""Synthetic offline UKI/provenance adapter faults; no real build or boot."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("product_artifacts", Path(__file__).parents[1] / "hibernate/artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class Artifacts(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.root = Path(self.temp.name)
    self.source = self.root / "source"
    self.restore = self.root / "restore"
    self.source.mkdir()
    self.restore.mkdir()
    self.production = self.root / "production.efi"
    self.production.write_bytes(b"synthetic production UKI")
    self.cmdline = b"root=/dev/mapper/root resume=/dev/mapper/root resume_offset=1923214\0"
    self.sections = {name: (self.cmdline if name == ".cmdline" else b"section " + name.encode())
                     for name in artifacts.AUDIT.S4.RUNTIME_SECTIONS}
    self.initrd = {"source": b"synthetic early-source initramfs", "restore": b"synthetic isolated fullrestore initramfs"}
    self.provenance = {}
    modules = {name: {"source": "/synthetic/" + name, "sha256": "b" * 64,
                      "srcversion": "A" * 24, "vermagic": "synthetic-t2 SMP"}
               for name in artifacts.AUDIT.S4.RUNTIME_MODULES}
    preserved = {name: artifacts._digest(raw) for name, raw in self.sections.items()}
    for role, directory in (("source", self.source), ("restore", self.restore)):
      image = b"synthetic " + role.encode() + b" UKI"
      (directory / "mba-t2-hibernation-candidate.efi").write_bytes(image)
      (directory / "mba-t2-hibernation-candidate.initrd").write_bytes(self.initrd[role])
      provenance = {"candidate": "mba-t2-hibernation-early-source" if role == "source" else "mba-t2-hibernation-candidate",
                    "candidate_uki_sha256": artifacts._digest(image), "candidate_initrd_sha256": artifacts._digest(self.initrd[role]),
                    "production_uki_sha256": artifacts._digest(self.production.read_bytes()),
                    "source_provenance_sha256": "c" * 64, "kernel_release": "synthetic-t2",
                    "cmdline": self.cmdline.replace(b"\0", b" ").decode().strip(),
                    "modules": copy.deepcopy(modules), "unchanged_production_sections_sha256": preserved.copy(),
                    "installed": False, "boot_entry_created": False, "hardware_qualified": False,
                    "production_modified": False, "experiment_id": "synthetic-source"}
      if role == "source":
        provenance.update(pre_restore_module_policy="early-t2-radio",
                          initrd_module_selection={name: "usr/lib/modules/synthetic-t2/" + name + ".ko"
                                                  for name in artifacts.AUDIT.SOURCE_INITRD_MODULES})
      else:
        provenance.update(pre_restore_module_policy="root-only-no-t2-radio", initrd_module_selection={},
                          pre_restore_excluded_modules=sorted(artifacts.AUDIT.S4.RUNTIME_MODULES),
                          post_switch_root_payload={name: "usr/lib/omarchy-t2-hibernation-candidate/payload/" + name + ".ko"
                                                    for name in artifacts.AUDIT.S4.RUNTIME_MODULES},
                          experiment_id=artifacts.FULLRESTORE,
                          minimal_restore_policy=artifacts.AUDIT.MINIMAL_RESTORE_POLICY.copy(),
                          cold_pci_restore={"version": artifacts.FULLRESTORE, "resume": artifacts.AUDIT.RESTORE.RESUME.copy(),
                                            "guard_module_sha256": artifacts.AUDIT.RESTORE.GUARD_SHA256},
                          restore_marker={"version": "v2", "sha256": "d" * 64, "srcversion": "D" * 24,
                                          "efi_variable": artifacts.AUDIT.V2_RESTORE_MARKER_VARIABLE,
                                          "pre_resume_hook": artifacts.AUDIT.RESTORE_MARKER_HOOK,
                                          "hook_sha256": artifacts.AUDIT.sha256(artifacts.AUDIT.RESTORE_MARKER_HOOK_SOURCE)})
      self.provenance[role] = provenance
    self.publish()
    # The fixture has synthetic archives, not a full actual BusyBox tree. Keep
    # the real pair metadata/layout checks; bypass only cold bundle validation,
    # normally exercised by the existing fullrestore tooling/runtime suites.
    self.cold_metadata = mock.patch.object(artifacts.AUDIT, "validate_cold_pre_cpu_metadata",
                                           side_effect=lambda provenance: provenance["cold_pci_restore"])
    self.cold_metadata.start()
    self.source_verifier = mock.Mock()

  def tearDown(self):
    self.cold_metadata.stop()
    self.temp.cleanup()

  def publish(self):
    for role, directory in (("source", self.source), ("restore", self.restore)):
      (directory / "provenance.json").write_text(json.dumps(self.provenance[role], sort_keys=True))

  def load(self, directory, role):
    return json.loads((directory / "provenance.json").read_text())

  def extract(self, image, section):
    if section == ".initrd":
      return self.initrd[image.parent.name] if image != self.production else b"production initramfs"
    return self.sections[section]

  def derive(self, **options):
    return artifacts.derive_artifacts(self.source, self.restore, self.production,
                                      section_extractor=options.pop("section_extractor", self.extract),
                                      candidate_loader=options.pop("candidate_loader", self.load),
                                      source_layout_verifier=options.pop("source_layout_verifier", self.source_verifier), **options)

  def test_actual_files_define_strict_manifest_and_separate_details(self):
    before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
    result = self.derive()
    manifest = result["manifest"]
    self.assertEqual(set(manifest), {"protocol", "model", *artifacts.TX.PINS})
    self.assertEqual(manifest["source_sha256"], self.provenance["source"]["candidate_uki_sha256"])
    self.assertEqual(manifest["linux_sha256"], artifacts._digest(self.sections[".linux"]))
    self.assertEqual(result["audited_details_sha256"], artifacts.TX.digest(result["audited_details"]))
    self.assertEqual(result["audited_details"]["restore_protocol"]["resume"], artifacts.AUDIT.RESTORE.RESUME)
    self.assertFalse(result["hardware_qualified"])
    self.assertFalse(result["usable_hibernation_qualified"])
    self.assertNotIn("qualification", result)
    self.assertTrue(result["audited_details"]["external_source_marker_pin_required"])
    self.source_verifier.assert_called_once()
    self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

  def test_uki_cmdline_and_runtime_proc_framing_are_distinct(self):
    result = self.derive()
    proc_cmdline = self.cmdline.rstrip(b"\0") + b"\n"
    self.assertNotEqual(result["manifest"]["cmdline_sha256"], hashlib.sha256(proc_cmdline).hexdigest())
    self.assertEqual(result["audited_details"]["cmdline_text"], proc_cmdline.decode().strip())

  def test_image_initrd_and_production_tampering_refuse(self):
    for path in (self.source / "mba-t2-hibernation-candidate.efi",
                 self.restore / "mba-t2-hibernation-candidate.initrd", self.production):
      original = path.read_bytes()
      path.write_bytes(b"tampered")
      with self.assertRaises(ValueError): self.derive()
      path.write_bytes(original)

  def test_actual_kernel_cmdline_and_other_preserved_sections_refuse(self):
    for section in (".linux", ".cmdline", ".text"):
      def extract(image, requested):
        raw = self.extract(image, requested)
        return raw + b"tamper" if image.parent == self.restore and requested == section else raw
      with self.subTest(section=section):
        with self.assertRaises(ValueError): self.derive(section_extractor=extract)

  def test_claimed_section_identity_does_not_replace_byte_verification(self):
    for role in self.provenance:
      self.provenance[role]["unchanged_production_sections_sha256"][".text"] = "f" * 64
    self.publish()
    with self.assertRaises(ValueError): self.derive()

  def test_embedded_initrd_must_equal_audited_external_bytes(self):
    def extract(image, section):
      raw = self.extract(image, section)
      return raw + b"embedded tamper" if image.parent == self.source and section == ".initrd" else raw
    with self.assertRaises(ValueError): self.derive(section_extractor=extract)

  def test_replacement_and_abort_profiles_refuse(self):
    original = copy.deepcopy(self.provenance)
    for role, change in (("source", {"modified_sections_sha256": {".linux": "f" * 64}}),
                         ("restore", {"kernel_override": {"sha256": "f" * 64}}),
                         ("restore", {"experiment_id": "cold-pci-guard-pre-arch-abort-v1"}),
                         ("source", {"pre_restore_module_policy": "root-only-no-t2-radio"})):
      self.provenance = copy.deepcopy(original)
      self.provenance[role].update(change)
      self.publish()
      with self.assertRaises(ValueError): self.derive()

  def test_real_pair_primitive_rejects_module_stack_mismatch(self):
    self.provenance["restore"]["modules"]["t2bce_core"]["srcversion"] = "E" * 24
    self.publish()
    with self.assertRaises(ValueError): self.derive()

  def test_source_layout_verification_cannot_be_skipped_on_failure(self):
    self.source_verifier.side_effect = ValueError("early-source actual tree mismatch")
    with self.assertRaises(ValueError): self.derive()

  def test_provenance_duplicate_fields_and_loader_disagreement_refuse(self):
    path = self.source / "provenance.json"
    original = path.read_bytes()
    path.write_bytes(original[:-1] + b',"installed":false}')
    with self.assertRaises(ValueError): self.derive()
    path.write_bytes(original)
    with self.assertRaises(ValueError):
      self.derive(candidate_loader=lambda directory, role: {**self.load(directory, role), "invented": True})

  def test_missing_or_symlinked_artifacts_refuse(self):
    path = self.restore / "mba-t2-hibernation-candidate.efi"
    original = path.read_bytes()
    path.unlink()
    with self.assertRaises(ValueError): self.derive()
    path.symlink_to(self.production)
    with self.assertRaises(ValueError): self.derive()
    path.unlink()
    path.write_bytes(original)
    linked = self.root / "linked"
    linked.symlink_to(self.source, target_is_directory=True)
    with self.assertRaises(ValueError):
      artifacts.derive_artifacts(linked, self.restore, self.production)

  def test_inputs_changed_during_extraction_refuse(self):
    def extract(image, section):
      if section == ".linux":
        self.production.write_bytes(b"changed during extraction")
      return self.extract(image, section)
    with self.assertRaises(ValueError): self.derive(section_extractor=extract)

  def test_resume_contract_and_cmdline_text_are_bound(self):
    for role in self.provenance:
      self.provenance[role]["cmdline"] = "claimed unrelated command line"
    self.publish()
    with self.assertRaises(ValueError): self.derive()
    for role in self.provenance:
      self.provenance[role]["cmdline"] = self.cmdline.replace(b"\0", b" ").decode().strip()
    self.provenance["restore"]["cold_pci_restore"]["resume"]["offset"] += 1
    self.publish()
    with self.assertRaises(ValueError): self.derive()

  def test_empty_section_and_extractor_path_instead_of_bytes_refuse(self):
    for value in (b"", Path("not-bytes")):
      with self.assertRaises(ValueError):
        self.derive(section_extractor=lambda image, section: value)

  def test_large_sparse_artifacts_use_streaming_hashes_and_section_files(self):
    size = 64 * 1024 * 1024
    paths = {"production": self.production, "source": self.source / "mba-t2-hibernation-candidate.efi",
             "restore": self.restore / "mba-t2-hibernation-candidate.efi"}
    for role, path in paths.items():
      with path.open("wb") as stream:
        stream.write(("sparse UKI " + role).encode())
        stream.truncate(size)
    section_files = {}
    for name, raw in self.sections.items():
      path = self.root / ("section" + name)
      with path.open("wb") as stream:
        stream.write(raw)
        if name == ".linux":
          stream.truncate(size)
      section_files[name] = path
    for role, directory in (("source", self.source), ("restore", self.restore)):
      initrd = directory / "mba-t2-hibernation-candidate.initrd"
      with initrd.open("wb") as stream:
        stream.write(("sparse initrd " + role).encode())
        stream.truncate(size)
      self.provenance[role]["candidate_uki_sha256"] = artifacts._file_digest(paths[role])
      self.provenance[role]["candidate_initrd_sha256"] = artifacts._file_digest(initrd)
      self.provenance[role]["production_uki_sha256"] = artifacts._file_digest(self.production)
      self.provenance[role]["unchanged_production_sections_sha256"] = {
        name: artifacts._file_digest(path) for name, path in section_files.items()}
    self.publish()
    original_read_bytes = Path.read_bytes
    def small_read_only(path):
      if path.stat().st_size > artifacts.MAX_SMALL_BYTES:
        raise AssertionError("Whole-file read of large artifact is forbidden")
      return original_read_bytes(path)
    def extract(image, section):
      if section == ".initrd":
        return image.parent / "mba-t2-hibernation-candidate.initrd" if image != self.production else section_files[".linux"]
      return section_files[section]
    with mock.patch.object(Path, "read_bytes", small_read_only):
      result = self.derive(section_extractor=extract)
    self.assertEqual(result["manifest"]["linux_sha256"], artifacts._file_digest(section_files[".linux"]))

  def test_forbidden_replacement_rejected_before_legacy_loader(self):
    self.provenance["source"]["modified_sections_sha256"] = {".linux": "f" * 64}
    self.publish()
    loader = mock.Mock(side_effect=AssertionError("Forbidden legacy loader must never run"))
    with self.assertRaises(ValueError):
      self.derive(candidate_loader=loader)
    loader.assert_not_called()

  def test_small_metadata_read_is_bounded(self):
    path = self.source / "provenance.json"
    with path.open("wb") as stream:
      stream.truncate(artifacts.MAX_SMALL_BYTES + 1)
    with self.assertRaises(ValueError): self.derive()


if __name__ == "__main__":
  unittest.main()
