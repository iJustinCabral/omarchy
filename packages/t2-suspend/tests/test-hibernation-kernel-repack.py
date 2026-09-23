#!/usr/bin/python3
"""Exercise kernel-only UKI repacking with disposable PE fixtures."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/repack-hibernation-uki-pair-kernel.py"
spec = importlib.util.spec_from_file_location("hibernate_kernel_repack", script)
repack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repack)
stub = Path("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")
assert stub.is_file()


def add_section(source, output, name, data, address, work):
  blob = work / (name.lstrip(".") + ".bin")
  blob.write_bytes(data)
  subprocess.run((
    "objcopy", "--add-section", name + "=" + str(blob),
    "--change-section-vma", name + "=" + hex(address),
    "--set-section-flags", name + "=alloc,load,readonly,data",
    str(source), str(output),
  ), check=True, capture_output=True)


def make_input(role, root, original_kernel):
  directory = root / role
  directory.mkdir()
  work = directory / "work"
  work.mkdir()
  image = work / "stub.efi"
  image.write_bytes(stub.read_bytes())
  initrd = (role + "-root-unlock-initrd").encode()
  for number, (name, data, address) in enumerate((
    (".uname", b"test-release\0", 0x14dfb5000),
    (".osrel", b"ID=test\n", 0x14dfb6000),
    (".cmdline", b"root=/dev/mapper/root\0", 0x14dfb7000),
    (".linux", original_kernel, 0x14dfb8000),
    (".initrd", initrd, 0x14e000000),
  )):
    next_image = work / (str(number) + ".efi")
    add_section(image, next_image, name, data, address, work)
    image = next_image
  final = directory / repack.IMAGE
  final.write_bytes(image.read_bytes())
  sidecar = directory / repack.INITRD
  sidecar.write_bytes(initrd)
  sections = repack.section_details(final)
  assert set(sections) - {".initrd"} == repack.AUDIT.S4.RUNTIME_SECTIONS
  module_metadata = {
    name: {
      "source": "drivers/" + name + ".ko",
      "sha256": hashlib.sha256(name.encode()).hexdigest(),
      "srcversion": "TEST",
      "vermagic": "test-release SMP",
    }
    for name in repack.AUDIT.S4.RUNTIME_MODULES
  }
  report = {
    "candidate_uki_sha256": repack.digest(final),
    "candidate_initrd_sha256": repack.digest(sidecar),
    "cmdline": "root=/dev/mapper/root",
    "kernel_release": "test-release",
    "modules": module_metadata,
    "production_uki_sha256": "a" * 64,
    "source_provenance_sha256": "b" * 64,
    "unchanged_production_sections_sha256": {
      section: repack.section_digest(final, section, work) for section in sections if section != ".initrd"
    },
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
    "production_modified": False,
  }
  if role == "source":
    report["initrd_module_selection"] = {
      name: "usr/lib/modules/test-release/" + name + ".ko"
      for name in repack.AUDIT.SOURCE_INITRD_MODULES
    }
    report["pre_restore_module_policy"] = "early-t2-radio"
  else:
    report["initrd_module_selection"] = {}
    report["pre_restore_module_policy"] = "root-only-no-t2-radio"
    report["pre_restore_excluded_modules"] = sorted(repack.AUDIT.S4.RUNTIME_MODULES)
    report["post_switch_root_payload"] = {
      name: "usr/lib/omarchy-t2-hibernation-candidate/payload/" + name + ".ko"
      for name in repack.AUDIT.S4.RUNTIME_MODULES
    }
  (directory / "provenance.json").write_text(json.dumps(report))
  return directory, report


with tempfile.TemporaryDirectory(prefix="t2-kernel-repack-test-") as temporary:
  root = Path(temporary)
  source, original_source = make_input("source", root, b"baseline-kernel" * 64)
  restore, original_restore = make_input("restore", root, b"baseline-kernel" * 64)
  original_identity = repack.AUDIT.audit(original_source, original_restore)["runtime_stack_sha256"]
  kernel = root / "marker-kernel"
  kernel.write_bytes(b"marker-enabled-kernel" * 64)
  outputs = {}
  for role, directory, report in (("source", source, original_source), ("restore", restore, original_restore)):
    work = root / (role + "-repack-work")
    work.mkdir()
    output = root / (role + "-repacked")
    outputs[role] = repack.repack(directory, report, kernel, repack.digest(kernel), repack.digest(repack.PATCH), output, work)
    assert repack.AUDIT.load_candidate(output, role) == outputs[role]
    assert repack.digest(output / repack.INITRD) == report["candidate_initrd_sha256"]
    assert report["unchanged_production_sections_sha256"][".linux"] != outputs[role]["modified_sections_sha256"][".linux"]
    assert outputs[role]["kernel_override"]["sha256"] == repack.digest(kernel)
  new_identity = repack.AUDIT.audit(outputs["source"], outputs["restore"])["runtime_stack_sha256"]
  assert new_identity != original_identity

with tempfile.TemporaryDirectory(prefix="t2-kernel-link-test-") as temporary:
  build = Path(temporary)
  boot = build / "arch/x86/boot"
  boot.mkdir(parents=True)
  (build / "kernel/power").mkdir(parents=True)
  setup = bytearray(1024)
  setup[0x1fe:0x200] = b"\x55\xaa"
  setup[0x202:0x206] = b"HdrS"
  (boot / "setup.bin").write_bytes(setup)
  (boot / "vmlinux.bin").write_bytes(b"compressed-kernel")
  (boot / ".bzImage.cmd").write_text(
    "savedcmd_arch/x86/boot/bzImage := "
    "(dd if=arch/x86/boot/setup.bin bs=4k conv=sync status=none; "
    "cat arch/x86/boot/vmlinux.bin) >arch/x86/boot/bzImage\n"
  )
  (build / "vmlinux").write_bytes(
    b"t2_hibernate_efi_marker" + "OmarchyT2HibernateStage".encode("utf-16-le")
  )
  (build / "kernel/power/hibernate.o").write_bytes(b"compiled marker")
  (build / ".config").write_bytes(b"CONFIG_EFI=y\n")
  kernel = boot / "bzImage"
  contents = bytes(setup) + bytes(4096 - len(setup)) + b"compressed-kernel"
  kernel.write_bytes(contents)
  expected = repack.digest(kernel)
  assert repack.verify_linked_kernel(kernel, build, expected) == expected

  try:
    repack.verify_linked_kernel(kernel, build, "0" * 64)
  except ValueError as error:
    assert "pinned SHA-256" in str(error)
  else:
    raise AssertionError("Wrong kernel hash was accepted")

  (boot / "vmlinux.bin").write_bytes(b"changed payload")
  try:
    repack.verify_linked_kernel(kernel, build, expected)
  except ValueError as error:
    assert "predates build component" in str(error)
  else:
    raise AssertionError("Kernel predating its compressed payload was accepted")

print("PASS: kernel-only PE repack preserves both initramfs images; linked-kernel provenance checks reject stale inputs")
