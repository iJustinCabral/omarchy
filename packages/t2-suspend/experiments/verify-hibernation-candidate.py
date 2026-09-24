#!/usr/bin/env python3
"""Reproduce, test and optionally build the complete offline hibernation candidate.

This program never installs modules, modifies a boot image, or initiates a power
transition.  Published output appears only after every requested check passes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
TESTS = PACKAGE / "tests"
PATCHES = (
  "0005-t2-block-shared-dma-before-restore.patch",
  "0006-t2bce-rebuild-queues-for-hibernation.patch",
  "0007-t2-serialize-shared-pci-pm.patch",
  "0009-t2bce-ave-hibernation-idle.patch",
  "0010-t2bce-block-dma-before-queue-drop.patch",
  "0011-t2bce-wake-before-device-noirq.patch",
  "0013-t2bce-quarantine-vhci-command-timeout.patch",
  "0014-t2bce-remove-vhci-before-hibernate-queue-pause.patch",
)


def digest(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def run(arguments, cwd=None):
  command = [str(argument) for argument in arguments]
  print("+ " + " ".join(command), flush=True)
  return subprocess.run(
    command,
    cwd=cwd,
    check=True,
    text=True,
  )


def prepare_input(work, supplied_input):
  if supplied_input is not None:
    return supplied_input.resolve()
  fetched = work / "input"
  run((sys.executable, PACKAGE / "fetch-source.py", fetched))
  return fetched


def prepare_active_source(work, source_input):
  active = work / "active"
  run((
    sys.executable,
    PACKAGE / "prepare-source.py",
    "--wifi-source",
    source_input / "drivers/net/wireless/broadcom/brcm80211",
    "--bluetooth-source",
    source_input / "drivers/bluetooth/hci_bcm4377.c",
    "--t2bce-source-patch",
    source_input / "t2bce/1001-Add-t2bce-driver-stack.patch",
    "--output",
    active,
    "--profile",
    "wifi-reenable",
  ))
  return active


def reconstruct_complete_source(work, source_input, active):
  full = work / "full"
  full.mkdir()
  t2bce_patch = source_input / "t2bce/1001-Add-t2bce-driver-stack.patch"
  run(("patch", "--batch", "--fuzz=0", "-p1", "-i", t2bce_patch), cwd=full)

  candidate = work / "candidate"
  shutil.copytree(full, candidate)
  shutil.copytree(active, candidate, dirs_exist_ok=True)

  required = (
    "drivers/staging/t2bce/Kconfig",
    "drivers/staging/t2bce/Makefile",
    "drivers/staging/t2bce/t2bce_dma/queue.c",
    "drivers/staging/t2bce/t2bce_vhci/vhci.c",
    "drivers/staging/t2bce/t2bce_ave/ave.c",
  )
  for name in required:
    if not (candidate / name).is_file():
      raise ValueError("Incomplete T2 BCE source reconstruction: " + name)
  return candidate


def apply_candidate_patches(candidate):
  hashes = {}
  for name in PATCHES:
    patch = HERE / name
    hashes[name] = digest(patch)
    run(("patch", "--batch", "--fuzz=0", "-p1", "-i", patch), cwd=candidate)
  return hashes


def run_active_regressions(active):
  wifi = active / "drivers/net/wireless/broadcom/brcm80211/brcmfmac"
  bluetooth = active / "drivers/bluetooth/hci_bcm4377.c"
  t2bce = active / "drivers/staging/t2bce"
  core = t2bce / "t2bce_core/t2bce_main.c"
  audio = t2bce / "t2bce_audio/audio.c"

  commands = (
    ("test-hibernate-pm.py", wifi / "pcie.c"),
    ("test-bce-hibernate-pm.py", core),
    ("test-bce-audio-hibernate-pm.py", audio),
    ("test-bluetooth.py", bluetooth),
    ("test-create-failure.py", bluetooth),
    ("test-flr.py",),
  )
  for command in commands:
    run((sys.executable, TESTS / command[0], *command[1:]))


def run_candidate_regressions(candidate):
  bluetooth = candidate / "drivers/bluetooth/hci_bcm4377.c"
  t2bce = candidate / "drivers/staging/t2bce"
  core = t2bce / "t2bce_core/t2bce_main.c"
  header = t2bce / "t2bce_core/t2bce.h"
  audio = t2bce / "t2bce_audio/audio.c"

  commands = (
    ("test-bce-audio-hibernate-pm.py", audio),
    ("test-dma-quiesce.py", core, header, bluetooth),
    ("test-cold-s4-rebuild.py", candidate),
    ("test-syscore-early-wake.py", candidate),
    ("test-vhci-command-timeout.py", candidate),
    ("test-shared-pci-pm-serialization.py", candidate),
    ("test-ave-hibernation-idle.py", candidate),
    ("test-wifi-hibernate-isolation.py",),
  )
  for command in commands:
    run((sys.executable, TESTS / command[0], *command[1:]))


def build_modules(candidate, release, jobs):
  if not re.fullmatch(r"[a-zA-Z0-9._+-]+-t2", release):
    raise ValueError("Expected a linux-t2 kernel release")
  headers = Path("/usr/lib/modules") / release / "build"
  if not (headers / "Makefile").is_file():
    raise ValueError("Missing configured headers for " + release)

  brcmfmac = candidate / "drivers/net/wireless/broadcom/brcm80211/brcmfmac"
  bluetooth = candidate / "drivers/bluetooth"
  t2bce = candidate / "drivers/staging/t2bce"
  wifi_arguments = [
    "make", "-C", headers, f"M={brcmfmac}", "W=1", f"-j{jobs}", "modules",
  ]
  if (headers / ".config").is_file() and "CONFIG_BRCMDBG=y\n" in (headers / ".config").read_text():
    wifi_arguments.insert(-2, "KCFLAGS=-DDEBUG")
  run(wifi_arguments)
  run(("make", "-C", headers, f"M={bluetooth}", "W=1", f"-j{jobs}", "modules"))
  run((
    "make",
    "-C",
    headers,
    f"M={t2bce}",
    "CONFIG_T2BCE_DMA=m",
    "CONFIG_T2BCE_CORE=m",
    "CONFIG_T2BCE_VHCI=m",
    "CONFIG_T2BCE_AUDIO=m",
    "CONFIG_T2BCE_AVE=m",
    "W=1",
    f"-j{jobs}",
    "modules",
  ))
  modules = {
    str(path.relative_to(candidate)): digest(path)
    for path in sorted(candidate.rglob("*.ko"))
  }
  expected = {
    "brcmfmac.ko",
    "brcmfmac-bca.ko",
    "brcmfmac-cyw.ko",
    "brcmfmac-wcc.ko",
    "hci_bcm4377.ko",
    "t2bce_core.ko",
    "t2bce_dma.ko",
    "t2bce_vhci.ko",
    "t2bce_audio.ko",
    "t2bce_ave.ko",
  }
  names = {Path(name).name for name in modules}
  missing = sorted(expected - names)
  if missing:
    raise ValueError("Module build omitted: " + ", ".join(missing))
  return modules


def write_provenance(candidate, patch_hashes, release, module_hashes):
  provenance_path = candidate / "provenance.json"
  provenance = json.loads(provenance_path.read_text())
  provenance.update({
    "candidate": "t2-hibernation-offline",
    "candidate_patches": patch_hashes,
    "candidate_tests": "passed",
    "candidate_kernel_release": release,
    "candidate_module_sha256": module_hashes,
    "installed": False,
    "hardware_qualified": False,
  })
  provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--input", type=Path, help="previously fetched pinned input tree")
  parser.add_argument("--output", type=Path, help="publish the verified candidate at this new path")
  parser.add_argument("--kernel-release", help="build modules for this installed linux-t2 release")
  parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
  args = parser.parse_args()

  if args.jobs < 1:
    parser.error("--jobs must be positive")
  output = args.output.absolute() if args.output is not None else None
  if output is not None and output.exists():
    raise ValueError("Output already exists; choose a new directory")
  temp_parent = output.parent if output is not None else None
  if temp_parent is not None:
    temp_parent.mkdir(parents=True, exist_ok=True)

  with tempfile.TemporaryDirectory(prefix=".t2-hibernate-candidate-", dir=temp_parent) as directory:
    work = Path(directory)
    source_input = prepare_input(work, args.input)
    active = prepare_active_source(work, source_input)
    run_active_regressions(active)
    candidate = reconstruct_complete_source(work, source_input, active)
    patch_hashes = apply_candidate_patches(candidate)
    run_candidate_regressions(candidate)
    module_hashes = {}
    if args.kernel_release is not None:
      module_hashes = build_modules(candidate, args.kernel_release, args.jobs)
    write_provenance(candidate, patch_hashes, args.kernel_release, module_hashes)

    if output is not None:
      candidate.rename(output)
      result = output
    else:
      result = candidate
    print("PASS: complete T2 hibernation candidate verified offline: " + str(result))
    if output is None:
      print("Candidate was temporary; pass --output to retain it")


if __name__ == "__main__":
  main()
