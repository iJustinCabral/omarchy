#!/usr/bin/python3
"""Check the upstream-model UKI builder's configuration, input policy and audit rules offline."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "upstream-model/build-upstream-model-uki.py"
spec = importlib.util.spec_from_file_location("upstream_model_builder", script)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
C = build.C


def rejects(action, expected, kind=ValueError):
  try:
    action()
  except kind as error:
    assert expected in str(error), error
  else:
    raise AssertionError("Unsafe builder input accepted: " + expected)


# Private configuration: stock sources with exactly the D1 and D2 deltas.
config = build.private_config()
assert "source /etc/mkinitcpio.conf\n" in config
assert "/etc/mkinitcpio.conf.d/*.conf" in config
assert config.count("MODULES+=(t2bce_audio)") == 1
assert config.count("HOOKS+=(" + C.HOOK + ")") == 1
assert "FILES" not in config and "omarchy-t2-restore-marker" not in config and "cold" not in config
assert "HOOKS=(" not in config
assert "/etc/" not in config.replace("/etc/mkinitcpio.conf", "")
subprocess.run(("bash", "-n", "/dev/stdin"), input=config.encode(), check=True)

# The build-time hook places the blacklist at its fixed destination and has no runtime script.
hook = build.INSTALL_HOOKS / C.HOOK
subprocess.run(("bash", "-n", hook), check=True)
assert "add_runscript" not in hook.read_text()
assert C.BLACKLIST_DESTINATION in hook.read_text()
assert not (build.INSTALL_HOOKS.parent / "hooks").exists()

# Blacklist file covers exactly the brcmfmac family and nothing else.
assert C.blacklist_names(C.blacklist_text()) == {"brcmfmac", "brcmfmac-bca", "brcmfmac-cyw", "brcmfmac-wcc"}
assert "hci_bcm4377" not in C.blacklist_text() and "t2bce" not in C.blacklist_text()

# The four patched modules are the whole t2bce family the builder pins; AVE is never included.
assert set(C.T2BCE_MODULES) == {"t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio"}
assert "t2bce_ave" not in C.T2BCE_MODULES
assert "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd" in C.REJECTED_IMAGE_SHA256

# Root-owned input policy (owner is injectable so the test can run unprivileged).
with tempfile.TemporaryDirectory(prefix="t2-upstream-builder-") as temporary:
  base = Path(temporary)
  tree = base / "candidate"
  tree.mkdir()
  (tree / "provenance.json").write_text("{}")
  owner = os.getuid()
  build.require_root_tree(tree, directory=True, owner=owner)
  rejects(lambda: build.require_root_tree(tree, directory=True), "root-owned")
  (tree / "link").symlink_to("provenance.json")
  rejects(lambda: build.require_root_tree(tree, directory=True, owner=owner), "symlinked")
  (tree / "link").unlink()
  (tree / "provenance.json").chmod(0o666)
  rejects(lambda: build.require_root_tree(tree, directory=True, owner=owner), "writable")
  (tree / "provenance.json").chmod(0o600)
  rejects(lambda: build.require_root_tree(base / "missing", directory=False, owner=owner), "", FileNotFoundError)

  # Candidate validation refuses unqualified provenance before any module is read.
  (tree / "provenance.json").write_text(json.dumps({"candidate_tests": "failed"}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "tests are not recorded")
  (tree / "provenance.json").write_text(json.dumps({"candidate_tests": "passed", "candidate_kernel_release": "other"}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "was not built for")
  (tree / "provenance.json").write_text(json.dumps({
    "candidate_tests": "passed", "candidate_kernel_release": "7.2.7-test", "installed": True, "hardware_qualified": False}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "lifecycle")
  (tree / "provenance.json").write_text(json.dumps({
    "candidate_tests": "passed", "candidate_kernel_release": "7.2.7-test", "installed": False, "hardware_qualified": False,
    "candidate_module_sha256": {}}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "Missing candidate module")

  # Pre-existing output directory is refused before anything is built.
  output = base / "out"
  output.mkdir()
  original_geteuid = build.os.geteuid
  build.os.geteuid = lambda: 0
  saved = sys.argv
  sys.argv = ["build", "--candidate-source", str(tree), "--output", str(output), "--experiment-id", "upstream-test"]
  try:
    rejects(build.main, "Output already exists")
    sys.argv = ["build", "--candidate-source", str(tree), "--output", str(base / "fresh"), "--experiment-id", "upstream-test"]
    rejects(build.main, "root-owned")
    assert not (base / "fresh").exists()
    sys.argv = ["build", "--candidate-source", str(tree), "--output", "/boot/EFI/Linux/new-output", "--experiment-id", "upstream-test"]
    rejects(build.main, "EFI or boot filesystem")
  finally:
    sys.argv = saved
    build.os.geteuid = original_geteuid

# Manifest diff: only the declared deltas pass.
release = "7.2.7-test-t2"
tree_path = "usr/lib/modules/" + release + "/"
stem = tree_path + "kernel/drivers/staging/t2bce/"
production = {
  "init": "file:aa:755",
  "config": "x",
  tree_path + "modules.dep.bin": "file:01:644",
  stem + "t2bce_core/t2bce_core.ko.zst": "file:old1:644",
  stem + "t2bce_dma/t2bce_dma.ko.zst": "file:old2:644",
  stem + "t2bce_vhci/t2bce_vhci.ko.zst": "file:old3:644",
  "etc/modprobe.d/brcmfmac.conf": "file:bb:644",
}
prod_config = 'MODULES="t2bce_vhci hid_apple"\nHOOKS="udev encrypt resume"\nEARLYHOOKS="udev"\nLATEHOOKS="plymouth"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS="plymouth"\n'
cand_config = prod_config.replace('MODULES="t2bce_vhci hid_apple"', 'MODULES="t2bce_vhci hid_apple t2bce_audio"')
audio = stem + "t2bce_audio/t2bce_audio.ko"
snd = tree_path + "kernel/sound/core/snd-pcm.ko"
candidate = {key: value for key, value in production.items() if not key.endswith(".ko.zst")}
candidate.update({
  tree_path + "modules.dep.bin": "file:02:644",
  stem + "t2bce_core/t2bce_core.ko": "file:new1:644",
  stem + "t2bce_dma/t2bce_dma.ko": "file:new2:644",
  stem + "t2bce_vhci/t2bce_vhci.ko": "file:new3:644",
  audio: "file:new4:644", snd: "file:snd:644", C.BLACKLIST_DESTINATION: "file:cc:644",
  "config": "y", "buildconfig": "z",
})
candidate_with_buildconfig = dict(candidate)
production_with_buildconfig = dict(production)
production_with_buildconfig["buildconfig"] = "a"


def diff(candidate_manifest=candidate_with_buildconfig, production_manifest=production_with_buildconfig, **overrides):
  options = {"dependencies": ["/" + audio, "/" + snd], "production_config": prod_config, "candidate_config": cand_config}
  options.update(overrides)
  return build.manifest_diff(production_manifest, candidate_manifest, release, **options)


report = diff()
assert len(report["removed"]) == 3 and audio in report["added"] and C.BLACKLIST_DESTINATION in report["added"]
assert stem + "t2bce_core/t2bce_core.ko" in report["added"] and stem + "t2bce_core/t2bce_core.ko.zst" in report["removed"]

def mutated(**changes):
  value = dict(candidate_with_buildconfig)
  for key, item in changes.items():
    value[key.replace("__", "/")] = item
  return value

rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "init": "file:ab:755"}), "changed: init")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "hooks/omarchy-t2-restore-marker": "file:dd:755"}), "added: hooks/omarchy-t2-restore-marker")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "usr/bin/extra": "file:dd:755"}), "added: usr/bin/extra")
rejects(lambda: diff(candidate_manifest={key: value for key, value in candidate_with_buildconfig.items() if key != "etc/modprobe.d/brcmfmac.conf"}), "removed: etc/modprobe.d/brcmfmac.conf")
rejects(lambda: diff(candidate_config=cand_config.replace('HOOKS="udev encrypt resume"', 'HOOKS="udev encrypt omarchy-t2-restore-marker resume"')), "HOOKS differs")
rejects(lambda: diff(candidate_config=cand_config.replace("t2bce_audio", "brcmfmac")), "MODULES differs")
rejects(lambda: diff(candidate_config=cand_config.replace('MODULES="t2bce_vhci hid_apple t2bce_audio"', 'MODULES="t2bce_vhci"')), "MODULES differs")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "usr/lib/omarchy-t2-restore-marker/marker.ko": "file:dd:600"}, dependencies=["/usr/lib/omarchy-t2-restore-marker/marker.ko"]), "marker/guard-like")
rejects(lambda: diff(dependencies=["/" + audio]), "added: " + snd)

# modprobe --dirname reports /lib/modules paths below the extracted tree; they normalise to usr/lib.
extracted = Path("/tmp/x/initrd-root")
lib = str(extracted) + "/lib/modules/" + release + "/"
assert build.normalize_dependencies([lib + "kernel/sound/core/snd-pcm.ko"], extracted) == ["/" + snd]
assert diff(dependencies=build.normalize_dependencies([lib + "kernel/sound/core/snd-pcm.ko", lib + "kernel/drivers/staging/t2bce/t2bce_audio/t2bce_audio.ko"], extracted))
# A stray .ko.zst removal, or a removal without its matching .ko, is refused.
rejects(lambda: diff(production_manifest={**production_with_buildconfig, tree_path + "kernel/fs/x.ko.zst": "file:q:644"}), "removed: " + tree_path + "kernel/fs/x.ko.zst")
rejects(lambda: diff(production_manifest={**production_with_buildconfig, stem + "t2bce_ave/t2bce_ave.ko.zst": "file:a:644"}), "t2bce_ave.ko.zst")
rejects(lambda: diff(candidate_manifest={key: value for key, value in candidate_with_buildconfig.items() if key != stem + "t2bce_dma/t2bce_dma.ko"}), "removed: " + stem + "t2bce_dma/t2bce_dma.ko.zst")

# Build arrays equal stock plus exactly the declared deltas.
with tempfile.TemporaryDirectory(prefix="t2-upstream-arrays-") as temporary:
  stock_file, private_file = Path(temporary) / "stock.conf", Path(temporary) / "private.conf"
  stock_file.write_text("HOOKS=(base udev)\nFILES=(/a)\nBINARIES=()\nMODULES=(m1)\n")
  good = stock_file.read_text() + "MODULES+=(t2bce_audio)\nHOOKS+=(" + C.HOOK + ")\n"
  private_file.write_text(good)
  assert build.audit_config(private_file, stock_file)["modules"] == ["m1", "t2bce_audio"]
  for extra, expected in (("FILES+=(/b)\n", "FILES"), ("BINARIES+=(x)\n", "BINARIES"), ("HOOKS+=(evil)\n", "HOOKS"), ("MODULES+=(brcmfmac)\n", "MODULES")):
    private_file.write_text(good + extra)
    rejects(lambda: build.audit_config(private_file, stock_file), expected)

# Build configuration values parse the runtime `config` file only.
assert build.config_values(cand_config)["MODULES"] == ["t2bce_vhci", "hid_apple", "t2bce_audio"]

print("PASS: upstream-model builder enforces stock configuration deltas, root-owned inputs and manifest audit")
