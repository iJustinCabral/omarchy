#!/usr/bin/python3
"""Repack a verified private UKI pair with one offline marker-enabled kernel.

This only creates a new private pair. It does not stage, boot, install modules,
write EFI variables or enter PM. The previously booted pair is never modified.
"""

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
PATCH = HERE / "0012-hibernate-efi-stage-marker.patch"
IMAGE = "mba-t2-hibernation-candidate.efi"
INITRD = "mba-t2-hibernation-candidate.initrd"


def import_path(name, path):
  spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


AUDIT = import_path("hibernate_pair_kernel_audit", HERE / "audit-hibernation-uki-pair.py")
BASE = import_path("hibernate_pair_kernel_base_builder", HERE / "build-hibernation-candidate-uki.py")


def digest(path):
  value = hashlib.sha256()
  with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      value.update(block)
  return value.hexdigest()


def verify_linked_kernel(kernel, build_source, expected_hash):
  """Verify the completed x86 image without querying Kbuild's phony target."""
  if re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
    raise ValueError("Expected kernel image SHA-256 is malformed")
  kernel_hash = digest(kernel)
  if kernel_hash != expected_hash:
    raise ValueError("Kernel image differs from its pinned SHA-256")

  boot = build_source / "arch/x86/boot"
  setup = boot / "setup.bin"
  payload = boot / "vmlinux.bin"
  command = boot / ".bzImage.cmd"
  vmlinux = build_source / "vmlinux"
  hibernate_object = build_source / "kernel/power/hibernate.o"
  config = build_source / ".config"
  for path in (setup, payload, command, vmlinux, hibernate_object, config):
    if path.is_symlink() or not path.is_file():
      raise ValueError("Kernel build component is missing or symlinked: " + str(path))
    if path.stat().st_mtime_ns > kernel.stat().st_mtime_ns:
      raise ValueError("Kernel image predates build component: " + str(path))

  expected_command = (
    "savedcmd_arch/x86/boot/bzImage := "
    "(dd if=arch/x86/boot/setup.bin bs=4k conv=sync status=none; "
    "cat arch/x86/boot/vmlinux.bin) >arch/x86/boot/bzImage"
  )
  if command.read_text().strip() != expected_command:
    raise ValueError("Kernel build command differs from the reviewed x86 assembly")
  assembled = hashlib.sha256()
  setup_bytes = setup.read_bytes()
  assembled.update(setup_bytes)
  assembled.update(bytes(-len(setup_bytes) % 4096))
  with payload.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      assembled.update(block)
  if assembled.hexdigest() != kernel_hash:
    raise ValueError("Kernel image does not match its setup and compressed payload")
  with kernel.open("rb") as stream:
    stream.seek(0x1fe)
    if stream.read(2) != b"\x55\xaa":
      raise ValueError("Kernel image lacks the x86 boot signature")
    stream.seek(0x202)
    if stream.read(4) != b"HdrS":
      raise ValueError("Kernel image lacks the x86 setup header")
  with vmlinux.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as linked:
    if linked.find(b"t2_hibernate_efi_marker") < 0 or linked.find("OmarchyT2HibernateStage".encode("utf-16-le")) < 0:
      raise ValueError("Linked kernel lacks the opt-in EFI marker")
  return kernel_hash


def section_details(image):
  output = subprocess.run(("objdump", "-h", str(image)), check=True, text=True, capture_output=True).stdout
  details = {}
  pattern = r"^\s*\d+\s+(\.\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
  for match in re.finditer(pattern, output, re.M):
    details[match.group(1)] = {"size": int(match.group(2), 16), "vma": int(match.group(3), 16)}
  return details


def extract_section(image, section, work):
  extracted = work / (image.stem + section)
  subprocess.run(("objcopy", "-O", "binary", "--only-section=" + section, str(image), str(extracted)), check=True, capture_output=True)
  return extracted


def section_digest(image, section, work):
  return digest(extract_section(image, section, work))


def verify_base(directory, provenance, work):
  if provenance.get("modified_sections_sha256") is not None:
    raise ValueError("Input is already kernel-overridden; only the original private pair is accepted")
  image = directory / IMAGE
  sections = section_details(image)
  expected = provenance["unchanged_production_sections_sha256"]
  if set(sections) - {".initrd"} != set(expected):
    raise ValueError("Input UKI section set differs from its production provenance")
  for section, value in expected.items():
    if section_digest(image, section, work) != value:
      raise ValueError("Input UKI section differs from production provenance: " + section)
  if section_digest(image, ".initrd", work) != provenance["candidate_initrd_sha256"]:
    raise ValueError("Input UKI initramfs differs from its sidecar")
  return sections


def repack(directory, provenance, kernel, kernel_hash, patch_hash, output, work):
  original = directory / IMAGE
  sections = verify_base(directory, provenance, work)
  if sections[".linux"]["vma"] + kernel.stat().st_size > sections[".initrd"]["vma"]:
    raise ValueError("Marker kernel would overlap the original initramfs virtual address")
  output.mkdir(mode=0o700)
  image = output / IMAGE
  without_kernel = work / "without-linux.efi"
  subprocess.run(("objcopy", "--remove-section=.linux", str(original), str(without_kernel)), check=True, capture_output=True)
  subprocess.run((
    "objcopy", "--add-section", ".linux=" + str(kernel),
    "--change-section-vma", ".linux=" + hex(sections[".linux"]["vma"]),
    "--set-section-flags", ".linux=alloc,load,readonly,data",
    str(without_kernel), str(image),
  ), check=True, capture_output=True)
  actual_details = section_details(image)
  if set(actual_details) != set(sections) or any(actual_details.get(name) != value for name, value in sections.items() if name != ".linux") or actual_details[".linux"]["vma"] != sections[".linux"]["vma"]:
    changed = sorted(name for name in set(sections) | set(actual_details) if name != ".linux" and actual_details.get(name) != sections.get(name))
    raise ValueError("Repacked UKI changed a section address or size other than .linux: " + ", ".join(changed))
  linux_size = actual_details[".linux"]["size"]
  if linux_size < kernel.stat().st_size or linux_size - kernel.stat().st_size >= 4096 or actual_details[".linux"]["vma"] + linux_size > actual_details[".initrd"]["vma"]:
    raise ValueError(f"Repacked kernel section size or virtual address is unsafe: section={linux_size} raw={kernel.stat().st_size} gap={actual_details['.initrd']['vma'] - actual_details['.linux']['vma']}")
  linux_bytes = extract_section(image, ".linux", work).read_bytes()
  kernel_bytes = kernel.read_bytes()
  if linux_bytes[:len(kernel_bytes)] != kernel_bytes or any(linux_bytes[len(kernel_bytes):]):
    raise ValueError("Repacked kernel section differs from bzImage or has nonzero padding")
  pe_kernel_hash = hashlib.sha256(linux_bytes).hexdigest()
  for section in sections:
    expected = pe_kernel_hash if section == ".linux" else provenance["candidate_initrd_sha256"] if section == ".initrd" else provenance["unchanged_production_sections_sha256"][section]
    if section_digest(image, section, work) != expected:
      raise ValueError("Repacked UKI has an unexpected section: " + section)
  if subprocess.run(("bootctl", "kernel-identify", str(image)), check=True, text=True, capture_output=True).stdout.strip() != "uki":
    raise ValueError("Repacked image is not recognized as a UKI")

  shutil.copyfile(directory / INITRD, output / INITRD)
  report = dict(provenance)
  baseline = provenance["unchanged_production_sections_sha256"][".linux"]
  report["unchanged_production_sections_sha256"] = dict(provenance["unchanged_production_sections_sha256"])
  report["unchanged_production_sections_sha256"].pop(".linux")
  report["modified_sections_sha256"] = {".linux": pe_kernel_hash}
  report["kernel_override"] = {
    "sha256": kernel_hash,
    "pe_section_sha256": pe_kernel_hash,
    "unpadded_size": kernel.stat().st_size,
    "baseline_linux_sha256": baseline,
    "patch_sha256": patch_hash,
    "kernel_release": provenance["kernel_release"],
  }
  report["base_candidate_uki_sha256"] = provenance["candidate_uki_sha256"]
  report["candidate_uki_sha256"] = digest(image)
  (output / "provenance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
  return report


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source", required=True, type=Path)
  parser.add_argument("--restore", required=True, type=Path)
  parser.add_argument("--expected-source-uki-sha256", required=True)
  parser.add_argument("--expected-restore-uki-sha256", required=True)
  parser.add_argument("--kernel-image", required=True, type=Path)
  parser.add_argument("--kernel-build-source", required=True, type=Path)
  parser.add_argument("--expected-kernel-image-sha256", required=True)
  parser.add_argument("--output", required=True, type=Path, help="new private directory outside the ESP")
  args = parser.parse_args()

  source = args.source.resolve(strict=True)
  restore = args.restore.resolve(strict=True)
  kernel = args.kernel_image.resolve(strict=True)
  build_source = args.kernel_build_source.resolve(strict=True)
  output = args.output.absolute()
  if args.source.is_symlink() or args.restore.is_symlink():
    raise ValueError("Input private pair directories must not be symlinks")
  if output.exists() or output.is_symlink():
    raise ValueError("Output already exists; choose a new directory")
  if any(BASE.under(output, location) for location in (Path("/boot"), Path("/efi"), source, restore, build_source)):
    raise ValueError("Output must be new, private and outside boot/input/build locations")
  if args.kernel_image.is_symlink() or not kernel.is_file() or kernel.stat().st_size < 1024 * 1024:
    raise ValueError("Kernel image is missing or implausibly small")
  if kernel != build_source / "arch/x86/boot/bzImage":
    raise ValueError("Kernel image must be the exact bzImage from the supplied build tree")
  release = subprocess.run(("make", "-s", "kernelrelease"), cwd=build_source, check=True, text=True, capture_output=True).stdout.strip()
  source_report = AUDIT.load_candidate(source, "source")
  restore_report = AUDIT.load_candidate(restore, "restore")
  AUDIT.audit(source_report, restore_report)
  for role, expected, report in (
    ("source", args.expected_source_uki_sha256, source_report),
    ("restore", args.expected_restore_uki_sha256, restore_report),
  ):
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None or report["candidate_uki_sha256"] != expected:
      raise ValueError("Pinned baseline " + role + " UKI SHA-256 does not match")
  if release != os.uname().release or source_report["kernel_release"] != release:
    raise ValueError("Offline kernel release does not match the installed module ABI")
  if subprocess.run(("git", "apply", "--reverse", "--check", str(PATCH)), cwd=build_source, capture_output=True).returncode != 0:
    raise ValueError("Build tree does not contain the pinned EFI marker patch")
  source_text = (build_source / "kernel/power/hibernate.c").read_text()
  if "t2_hibernate_efi_marker" not in source_text or "OmarchyT2HibernateStage" not in source_text:
    raise ValueError("Build source lacks the opt-in EFI marker implementation")
  kernel_hash = verify_linked_kernel(kernel, build_source, args.expected_kernel_image_sha256)
  patch_hash = digest(PATCH)
  if source_report["unchanged_production_sections_sha256"][".linux"] != restore_report["unchanged_production_sections_sha256"][".linux"]:
    raise ValueError("Input UKIs do not contain the same baseline kernel")

  output.parent.mkdir(parents=True, exist_ok=True)
  os.umask(0o077)
  with tempfile.TemporaryDirectory(prefix=".t2-marker-pair-", dir=output.parent) as temporary:
    work = Path(temporary)
    publish = work / "publish"
    publish.mkdir(mode=0o700)
    built = {}
    for role, directory, report in (("source", source, source_report), ("restore", restore, restore_report)):
      role_work = work / (role + "-work")
      role_work.mkdir(mode=0o700)
      built[role] = repack(directory, report, kernel, kernel_hash, patch_hash, publish / role, role_work)
    if AUDIT.audit(built["source"], built["restore"])["runtime_stack_sha256"] == AUDIT.audit(source_report, restore_report)["runtime_stack_sha256"]:
      raise ValueError("Kernel override failed to create a distinct runtime stack identity")
    for role in ("source", "restore"):
      AUDIT.load_candidate(publish / role, role)
    publish.rename(output)
  for item in (output, *output.rglob("*")):
    item.chmod(0o700 if item.is_dir() else 0o600)
  print("PASS: private marker-kernel pair repacked without staging or changing the production UKI: " + str(output))


if __name__ == "__main__":
  main()
