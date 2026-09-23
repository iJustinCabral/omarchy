#!/usr/bin/python3
"""Build a private ordinary-source UKI with candidate T2 modules in initramfs.

This image is only the source half of a proposed two-UKI design. It must never
be used as the cold restore image. The builder changes no installed boot image,
module or power setting and does not create a boot entry.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("candidate_uki_builder", HERE / "build-hibernation-candidate-uki.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

CONFIG = HERE / "hibernate-source-mkinitcpio.conf"
SOURCE_HOOKS = HERE / "hibernate-source-initcpio"
INITRD_MODULES = tuple(name for name in BASE.MODULES if name != "t2bce_ave")
REQUIRED_INITRD_FILES = (
  "hooks/omarchy-t2-source-bluetooth",
  "usr/lib/omarchy-t2-hibernation-candidate/bluetooth-after-wifi.py",
  "usr/lib/omarchy-t2-hibernation-candidate/source-experiment-id",
)


def build_initrd(work, module_root, release, expected, experiment_id):
  marker = work / "source-experiment-id"
  marker.write_text(experiment_id + "\n")
  marker.chmod(0o600)
  initrd = work / "source.initrd"
  BASE.run((
    "env",
    "MKINITCPIO_HOOKS=" + str(SOURCE_HOOKS / "hooks") + ":/etc/initcpio/hooks:/usr/lib/initcpio/hooks",
    "MKINITCPIO_INSTALL=" + str(SOURCE_HOOKS / "install") + ":/etc/initcpio/install:/usr/lib/initcpio/install",
    "OMARCHY_T2_CANDIDATE_BLUETOOTH_HELPER=" + str(BASE.CANDIDATE_BLUETOOTH_HELPER),
    "OMARCHY_T2_SOURCE_EXPERIMENT_MARKER=" + str(marker),
    "mkinitcpio",
    "--config",
    CONFIG,
    "--generate",
    initrd,
    "--kernel",
    release,
    "--moduleroot",
    module_root,
  ))

  extracted = work / "initrd-root"
  extracted.mkdir()
  BASE.run(("lsinitcpio", "--early", "--extract", initrd), cwd=extracted)
  BASE.run(("lsinitcpio", "--cpio", "--extract", initrd), cwd=extracted)
  for name in ("init", "usr/bin/cryptsetup", "usr/bin/btrfs", "etc/cryptsetup-keys.d/root.key"):
    if not (extracted / name).exists():
      raise ValueError("Source initramfs omitted boot-critical file: " + name)
  for name in REQUIRED_INITRD_FILES:
    if not (extracted / name).is_file():
      raise ValueError("Source initramfs omitted source boot policy: " + name)
  if (extracted / REQUIRED_INITRD_FILES[2]).read_text().strip() != experiment_id:
    raise ValueError("Source initramfs experiment marker mismatch")
  build_config = (extracted / "config").read_text()
  if "omarchy-t2-source-bluetooth" not in build_config or "omarchy-t2-candidate-modules" in build_config:
    raise ValueError("Source initramfs selected the wrong candidate hook")
  blacklist = (extracted / "etc/modprobe.d/t2-bluetooth-order.conf").read_text()
  if re.search(r"^\s*blacklist\s+hci_bcm4377(?:\s|$)", blacklist, re.M) is None:
    raise ValueError("Source initramfs Bluetooth blacklist is inactive")

  module_tree = extracted / "usr/lib/modules" / release
  selected = {}
  for name in INITRD_MODULES:
    matches = list(module_tree.rglob(name + ".ko"))
    if len(matches) != 1 or BASE.digest(matches[0]) != expected[name]["sha256"]:
      raise ValueError("Source initramfs module missing or mismatched: " + name)
    selected[name] = str(matches[0].relative_to(extracted))
  if list(module_tree.rglob("t2bce_ave.ko")):
    raise ValueError("Source initramfs unexpectedly includes optional AVE")

  resolution = BASE.run((
    "modprobe",
    "--config",
    extracted / "etc/modprobe.d",
    "--dirname",
    extracted,
    "--set-version",
    release,
    "--show-depends",
    "--use-blacklist",
    "hci_bcm4377",
  ), capture=True)
  if resolution.stderr.strip():
    raise ValueError("Source initramfs Bluetooth dependency resolution failed: " + resolution.stderr.strip())
  if any(Path(line.split()[1]).name == "hci_bcm4377.ko" for line in resolution.stdout.splitlines() if line.startswith("insmod ")):
    raise ValueError("Source initramfs would load Bluetooth before Wi-Fi readiness")
  return initrd, selected


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--candidate-source", type=Path, required=True)
  parser.add_argument("--production-uki", type=Path, default=Path("/boot/EFI/Linux/omarchy_linux-t2.efi"))
  parser.add_argument("--output", type=Path, required=True, help="new private directory outside the ESP")
  parser.add_argument("--kernel-release", default=os.uname().release)
  parser.add_argument("--experiment-id", required=True)
  args = parser.parse_args()

  if os.geteuid() != 0:
    raise SystemExit("Run as root so the root-unlock key retains protected handling")
  experiment_id = BASE.validate_experiment_id(args.experiment_id)
  output = args.output.absolute()
  if output.exists():
    raise ValueError("Output already exists; choose a new directory")
  if any(BASE.under(output, path) for path in (Path("/boot"), Path("/efi"))):
    raise ValueError("Offline builder refuses to publish onto an EFI or boot filesystem")
  output.parent.mkdir(parents=True, exist_ok=True)
  os.umask(0o077)

  candidate_source = args.candidate_source.resolve()
  production = args.production_uki.resolve()
  with tempfile.TemporaryDirectory(prefix=".t2-source-uki-", dir=output.parent) as directory:
    work = Path(directory)
    source_provenance, expected = BASE.validate_candidate(candidate_source, args.kernel_release)
    module_root, selected = BASE.prepare_module_root(work, candidate_source, args.kernel_release, expected)
    initrd, initrd_modules = build_initrd(work, module_root, args.kernel_release, expected, experiment_id)
    uki, cmdline, sections, production_hash = BASE.build_uki(work, production, initrd)

    publish = work / "publish"
    publish.mkdir(mode=0o700)
    shutil.copyfile(uki, publish / "mba-t2-hibernation-candidate.efi")
    shutil.copyfile(initrd, publish / "mba-t2-hibernation-candidate.initrd")
    report = {
      "candidate": "mba-t2-hibernation-early-source",
      "kernel_release": args.kernel_release,
      "production_uki": str(production),
      "production_uki_sha256": production_hash,
      "candidate_uki_sha256": BASE.digest(publish / "mba-t2-hibernation-candidate.efi"),
      "candidate_initrd_sha256": BASE.digest(publish / "mba-t2-hibernation-candidate.initrd"),
      "experiment_id": experiment_id,
      "cmdline": cmdline,
      "unchanged_production_sections_sha256": {name: value for name, value in sections.items() if name != ".initrd"},
      "source_provenance_sha256": BASE.digest(source_provenance),
      "modules": expected,
      "private_module_selection": selected,
      "initrd_module_selection": initrd_modules,
      "pre_restore_module_policy": "early-t2-radio",
      "production_modified": False,
      "installed": False,
      "boot_entry_created": False,
      "hardware_qualified": False,
    }
    (publish / "provenance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    publish.rename(output)
  BASE.secure_output(output)
  print("PASS: private early-source UKI preserves production kernel/cmdline and root-critical initramfs: " + str(output))


if __name__ == "__main__":
  main()
